//! GHSA-5fp3-pp5p-c4gh — the **native** HTTP/3 reject path (`src/http3/server.rs`
//! and `src/http3/websocket.rs`) must carry a cached synthetic `RejectBinary`
//! payload as shared `Bytes` all the way to QUIC `send_data`, with no per-hit
//! full-body copy.
//!
//! The sibling `h3_cross_protocol_bytes_share_tests` covers the H3→HTTP bridge
//! in `src/http3/cross_protocol.rs`. These tests cover the native senders, which
//! previously took `body: &[u8]` and copied at the QUIC boundary.
//!
//! Transforming boundaries are deliberately still allowed to allocate: gRPC-Web
//! translation re-frames the payload, and the `&str` gateway-error family
//! (`send_h3_response`, `send_h3_error_flavor_aware*`) carries short gateway
//! literals that are not cached bodies. Those are asserted as *permitted*, not
//! forbidden, so a future change cannot quietly widen this guarantee into a
//! claim the code does not make.

use std::collections::HashMap;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use async_trait::async_trait;
use bytes::Bytes;
use ferrum_edge::config::types::HttpFlavor;
use ferrum_edge::plugins::{Plugin, RequestContext};
use http::StatusCode;

/// 256 KiB — far past any small-body inline threshold, so a copy would be an
/// unmistakable pointer change rather than an allocator coincidence.
fn large_cached_body() -> Bytes {
    Bytes::from(vec![0xa7u8; 256 * 1024])
}

/// Slice a named function body out of a source file, asserting that BOTH
/// boundary markers actually matched.
///
/// `split(end).next()` silently yields the whole remaining file when `end` is
/// absent, which would widen every assertion from "this function" to "the rest
/// of the module" and make the test pass for the wrong reason. Comparing the
/// bounded slice against the unbounded tail makes that failure loud.
fn bounded_fn<'a>(source: &'a str, start: &str, end: &str) -> &'a str {
    let tail = source
        .split(start)
        .nth(1)
        .unwrap_or_else(|| panic!("source marker must remain present: {start}"));
    let bounded = tail
        .split(end)
        .next()
        .unwrap_or_else(|| panic!("source boundary must remain present: {end}"));
    assert!(
        bounded.len() < tail.len(),
        "boundary marker never matched, so the window silently widened: {end}"
    );
    bounded
}

#[derive(Default)]
struct BodyPointerCapturePlugin {
    calls: AtomicUsize,
    observed: Mutex<Option<(usize, usize)>>,
}

#[async_trait]
impl Plugin for BodyPointerCapturePlugin {
    fn name(&self) -> &str {
        "h3_native_reject_body_pointer_capture"
    }

    fn requires_response_committed_hook(&self) -> bool {
        true
    }

    async fn on_response_committed(
        &self,
        _ctx: &mut RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        body: &[u8],
    ) {
        self.calls.fetch_add(1, Ordering::SeqCst);
        // Record identity, never the payload: a `to_vec()` here would be the
        // very copy this test exists to detect elsewhere.
        *self.observed.lock().expect("observed lock") = Some((body.as_ptr() as usize, body.len()));
    }
}

/// The native-H3 committed-hook boundary is the first place a cached
/// `RejectBinary` body fans out to plugin observers. It must hand over the same
/// allocation, not a per-hit copy.
#[tokio::test]
async fn native_h3_reject_committed_hook_observes_cached_bytes_without_copy() {
    let capture = Arc::new(BodyPointerCapturePlugin::default());
    let plugins: Vec<Arc<dyn Plugin>> = vec![capture.clone()];
    let mut ctx = RequestContext::new(
        "203.0.113.7".to_string(),
        "GET".to_string(),
        "/cached".to_string(),
    );
    let cached = large_cached_body();
    let cached_ptr = cached.as_ptr() as usize;
    let headers = HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )]);

    ferrum_edge::_test_support::run_h3_reject_response_committed_hooks(
        &plugins,
        &mut ctx,
        HttpFlavor::Plain,
        None,
        StatusCode::FORBIDDEN,
        cached.clone(),
        &headers,
    )
    .await;

    assert_eq!(capture.calls.load(Ordering::SeqCst), 1);
    let observed = *capture.observed.lock().expect("observed lock");
    let (observed_ptr, observed_len) =
        observed.expect("committed observer must run on the native H3 reject path");
    assert_eq!(observed_len, cached.len());
    assert_eq!(
        observed_ptr, cached_ptr,
        "native H3 reject committed-hook handoff must not copy the cached Bytes body"
    );
}

/// Repeated hits on the same cached payload must all share one allocation —
/// this is the actual advisory condition (per-hit copy amplification).
#[tokio::test]
async fn native_h3_reject_shares_one_allocation_across_repeated_cache_hits() {
    let cached = large_cached_body();
    let cached_ptr = cached.as_ptr() as usize;
    let headers = HashMap::from([("content-type".to_string(), "application/json".to_string())]);

    for hit in 0..4 {
        let capture = Arc::new(BodyPointerCapturePlugin::default());
        let plugins: Vec<Arc<dyn Plugin>> = vec![capture.clone()];
        let mut ctx = RequestContext::new(
            "203.0.113.8".to_string(),
            "GET".to_string(),
            "/cached".to_string(),
        );
        ferrum_edge::_test_support::run_h3_reject_response_committed_hooks(
            &plugins,
            &mut ctx,
            HttpFlavor::Plain,
            None,
            StatusCode::TOO_MANY_REQUESTS,
            cached.clone(),
            &headers,
        )
        .await;
        let observed = *capture.observed.lock().expect("observed lock");
        let (observed_ptr, _) = observed.expect("committed observer must run on every cached hit");
        assert_eq!(
            observed_ptr, cached_ptr,
            "cache hit {hit} allocated a fresh copy of the cached reject body"
        );
    }
}

/// Source canary for the native-H3 senders. The QUIC write boundary is the one
/// the advisory names explicitly, so pin its exact shape.
#[test]
fn native_h3_reject_senders_take_owned_bytes_and_never_copy() {
    let server = include_str!("../../../src/http3/server.rs");

    let writer = bounded_fn(
        server,
        "async fn send_h3_finalized_reject_response_with_recv_halt(",
        "async fn send_h3_grpc_web_reject(",
    );
    assert!(
        writer.contains("body: Bytes,"),
        "the final native H3 reject writer must accept owned Bytes"
    );
    assert!(
        writer.contains("stream.send_data(body)"),
        "QUIC delivery must move the owned Bytes into send_data"
    );
    assert!(
        !writer.contains("copy_from_slice") && !writer.contains(".to_vec()"),
        "the final native H3 reject writer must not copy the cached body"
    );

    // Every native sender that feeds that writer must already own its body,
    // otherwise the copy just moves one frame up the stack.
    for signature in [
        "async fn send_h3_reject_response(",
        "async fn send_h3_finalized_reject_response(",
        "async fn send_h3_grpc_web_reject_with_recv_halt(",
        "async fn send_h3_plugin_reject_flavor_aware_with_recv_halt(",
        "async fn send_h3_reject_flavor_aware_with_recv_halt(",
        "async fn send_h3_reject_flavor_aware_with_header_state(",
        "async fn finalize_h3_terminal_body_read_rejection(",
    ] {
        let start = server
            .find(signature)
            .unwrap_or_else(|| panic!("native H3 reject sender must remain present: {signature}"));
        // Bound the window at the parameter list's closing `)`, so a match can
        // never come from the function body or a later declaration.
        let tail = &server[start..];
        let end = tail
            .find("\n) ->")
            .unwrap_or_else(|| panic!("parameter list must remain bounded: {signature}"));
        let params = &tail[..end];
        assert!(
            params.contains("body: Bytes,") || params.contains("http_body: Bytes,"),
            "native H3 reject sender must take an owned Bytes body: {signature}"
        );
    }
}

/// The committed-hook / deadline runner clones `Bytes` (refcount) rather than
/// copying, and still reaches the shared bounded-deadline contract.
#[test]
fn native_h3_committed_hook_runner_clones_bytes_instead_of_copying() {
    let server = include_str!("../../../src/http3/server.rs");
    let runner = bounded_fn(
        server,
        "async fn run_h3_deadline_bounded_reject_committed_hooks_with_policy(",
        "async fn finalize_h3_upload_deadline_rejection(",
    );
    assert!(
        runner.contains("body: Bytes,"),
        "the bounded committed-hook runner must accept owned Bytes"
    );
    assert!(
        !runner.contains("copy_from_slice"),
        "the bounded committed-hook runner must not copy the owned reject body"
    );
    assert!(
        runner.contains("run_response_committed_hook_until_deadline("),
        "committed hooks must stay wired through the bounded deadline contract"
    );
    assert!(
        runner.contains("reject_headers_mark_accept_not_acceptable("),
        "Accept negotiation must stay HTTP 406 for committed observers"
    );
}

/// The H3 WebSocket reject writer shares the same QUIC boundary contract; its
/// body is a `BackendAdmissionRejection` payload already carried as `Bytes`.
#[test]
fn native_h3_websocket_reject_writer_moves_owned_bytes() {
    let websocket = include_str!("../../../src/http3/websocket.rs");
    let writer = bounded_fn(
        websocket,
        "async fn write_h3_finalized_reject_body<S>(",
        "async fn send_h3_backend_admission_rejection<S>(",
    );
    assert!(
        writer.contains("body: Bytes,"),
        "the H3 WebSocket reject writer must accept owned Bytes"
    );
    assert!(
        writer.contains("stream.send_data(body)"),
        "H3 WebSocket QUIC delivery must move the owned Bytes"
    );
    assert!(
        !writer.contains("copy_from_slice"),
        "the H3 WebSocket reject writer must not copy the owned body"
    );
}

/// HEAD / 204 / 205 / 304 must still drop the body entirely — the `Bytes`
/// migration must not turn a suppressed body into an empty DATA frame.
#[test]
fn native_h3_no_body_statuses_still_drop_capacity_before_the_wire() {
    let server = include_str!("../../../src/http3/server.rs");
    let writer = bounded_fn(
        server,
        "async fn send_h3_finalized_reject_response_with_recv_halt(",
        "async fn send_h3_grpc_web_reject(",
    );
    assert!(
        writer.contains("if !body.is_empty() {"),
        "no-body statuses must skip the DATA frame entirely"
    );
    assert!(
        writer.contains("crate::http3::stream_util::halt_request_body(stream)"),
        "the reject writer must keep halting the recv half"
    );
    assert!(
        server.contains("body = Bytes::new();"),
        "HEAD/204/205/304 preparation must drop capacity via Bytes::new()"
    );
}

/// Transforms are still allowed to allocate. gRPC-Web translation produces a
/// genuinely new framed payload, so `Bytes::from(translated.body)` is a move of
/// freshly encoded bytes — not a copy of the cached body — and must stay.
#[test]
fn grpc_web_translation_remains_an_allowed_allocating_transform() {
    let server = include_str!("../../../src/http3/server.rs");
    let sender = bounded_fn(
        server,
        "async fn send_h3_grpc_web_reject_with_recv_halt(",
        "pub(crate) async fn run_h3_reject_response_committed_hooks(",
    );
    assert!(
        sender.contains("error_response_for_content_type("),
        "gRPC-Web rejects must still be re-framed by the shared translator"
    );
    assert!(
        sender.contains("Bytes::from(translated.body)"),
        "the re-framed gRPC-Web payload is newly encoded and must be moved, not copied"
    );
}

/// The `&str` gateway-error family is intentionally NOT migrated: it carries
/// short gateway-authored literals, never a cached `RejectBinary` body. Pin
/// that so the PR's security claim stays scoped to what the code delivers.
#[test]
fn gateway_literal_error_family_is_documented_as_out_of_scope() {
    let server = include_str!("../../../src/http3/server.rs");
    let sender = bounded_fn(
        server,
        "async fn send_h3_response_with_recv_halt(",
        "/// Send an HTTP/3 rejection response with custom headers.",
    );
    assert!(
        sender.contains("body: &str"),
        "the gateway-literal error sender still takes &str by design"
    );
    // A cached RejectBinary payload is binary `Bytes` and can never reach a
    // `&str` parameter, so this boundary is not part of the advisory surface.
    assert!(
        sender.contains("Bytes::copy_from_slice(body.as_bytes())"),
        "the &str literal boundary may still copy; if this is ever migrated, \
         update the advisory scope rather than deleting this assertion"
    );
}

/// Ordinary H3 gRPC rejects must not pay for a full provenance normalization
/// when no `serverless_function` terminate authorization is present.
#[test]
fn native_h3_grpc_reject_skips_normalization_without_authorizing_provenance() {
    let server = include_str!("../../../src/http3/server.rs");
    let writer = bounded_fn(
        server,
        "async fn send_h3_reject_flavor_aware_with_header_state(",
        "pub(crate) fn h3_framed_unary_initial_response(",
    );
    assert!(
        writer.contains("framed_unary_provenance.is_authorizing()"),
        "direct-H3 gRPC reject normalization must be gated on authorizing provenance"
    );
    assert!(
        writer.contains("normalize_reject_response_with_provenance("),
        "authorizing terminate rejects must still normalize for framed emission"
    );
}

/// The shared mesh dispatch-required literal must reach QUIC as a static, not
/// as a per-reject copy.
#[test]
fn mesh_dispatch_required_reject_body_is_static() {
    let server = include_str!("../../../src/http3/server.rs");
    assert!(
        server.contains("pub(crate) const MESH_DISPATCH_REQUIRED_REJECT_BODY: &[u8] ="),
        "the mesh dispatch-required reject body must remain a shared const"
    );
    assert!(
        server.contains("Bytes::from_static(MESH_DISPATCH_REQUIRED_REJECT_BODY)"),
        "the mesh dispatch-required reject must reach the wire as a static Bytes"
    );
    let websocket = include_str!("../../../src/http3/websocket.rs");
    let shared_static =
        "Bytes::from_static(crate::http3::server::MESH_DISPATCH_REQUIRED_REJECT_BODY)";
    assert!(
        websocket.contains(shared_static),
        "the H3 WebSocket mesh reject must share the same static body"
    );
}
