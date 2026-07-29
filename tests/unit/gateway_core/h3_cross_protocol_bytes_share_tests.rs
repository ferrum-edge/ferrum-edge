//! H3 cross-protocol reject boundaries must preserve shared `Bytes` identity from
//! cached synthetic hits through normalization and QUIC delivery.

use bytes::Bytes;
use ferrum_edge::_test_support::h3_normalize_reject_for_client_for_test;
use ferrum_edge::plugins::RequestContext;
use http::StatusCode;
use std::collections::HashMap;

fn large_cached_body() -> Bytes {
    Bytes::from(vec![0x5au8; 256 * 1024])
}

fn binary_headers() -> HashMap<String, String> {
    HashMap::from([(
        "content-type".to_string(),
        "application/octet-stream".to_string(),
    )])
}

#[test]
fn h3_normalize_reject_for_client_shares_cached_bytes_without_copy() {
    let cached = large_cached_body();
    let cached_ptr = cached.as_ptr() as usize;
    let mut ctx = RequestContext::new(
        "203.0.113.10".to_string(),
        "GET".to_string(),
        "/cached".into(),
    );
    let (normalized, _) = h3_normalize_reject_for_client_for_test(
        &mut ctx,
        StatusCode::OK,
        cached.clone(),
        &binary_headers(),
        false,
    );
    assert_eq!(normalized.body.len(), cached.len());
    assert_eq!(
        normalized.body.as_ptr() as usize,
        cached_ptr,
        "H3 cross-protocol reject normalization must not copy owned cached Bytes"
    );
}

#[test]
fn h3_cross_protocol_reject_boundaries_avoid_slice_copies_for_owned_bytes() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");

    let normalize = cross
        .split("fn normalize_reject_for_client(")
        .nth(1)
        .expect("H3 cross-protocol reject normalizer")
        // NOTE: this bound must match the real signature (it carries a lifetime
        // parameter). `split(..).next()` yields the whole remaining file when the
        // pattern is absent, which would silently widen every assertion below
        // from "the normalizer" to "the rest of cross_protocol.rs".
        .split("fn reject_committed_response_view<'a>(")
        .next()
        .expect("bounded H3 cross-protocol reject normalizer");
    assert!(
        normalize.contains("body: Bytes,"),
        "normalize_reject_for_client must accept owned Bytes"
    );
    assert!(
        !normalize.contains("copy_from_slice"),
        "normalize_reject_for_client must not copy an owned Bytes payload"
    );

    let writer = cross
        .split("async fn write_reject_with_headers_and_recv_halt<S>(")
        .nth(1)
        .expect("H3 cross-protocol reject writer")
        .split("struct RejectWriteAccounting")
        .next()
        .expect("bounded H3 cross-protocol reject writer");
    assert!(
        writer.contains("body: Bytes,"),
        "write_reject_with_headers_and_recv_halt must accept owned Bytes"
    );
    assert!(
        writer.contains("stream.send_data(body)"),
        "QUIC delivery must move/cloned Bytes rather than copy_from_slice"
    );
    assert!(
        !writer.contains("copy_from_slice"),
        "final plain H3 reject delivery must not copy owned Bytes"
    );

    let grpc_normalize = cross
        .split("fn normalize_h3_grpc_reject(")
        .nth(1)
        .expect("H3 gRPC reject normalizer")
        .split("fn apply_h3_grpc_reject_metadata(")
        .next()
        .expect("bounded H3 gRPC reject normalizer");
    assert!(
        grpc_normalize.contains("body: Bytes,"),
        "normalize_h3_grpc_reject must accept owned Bytes"
    );
    assert!(
        !grpc_normalize.contains("copy_from_slice"),
        "normalize_h3_grpc_reject must not copy owned Bytes"
    );

    let committed_hooks = cross
        .split("async fn run_cross_protocol_reject_committed_hooks(")
        .nth(1)
        .expect("H3 cross-protocol committed-hook runner")
        .split("async fn write_plain_gateway_error<S>(")
        .next()
        .expect("bounded H3 cross-protocol committed-hook runner");
    assert!(
        committed_hooks.contains("run_response_committed_hook_until_deadline("),
        "committed hooks must remain wired on the cross-protocol reject path"
    );
    assert!(
        !committed_hooks.contains("copy_from_slice"),
        "cross-protocol committed-hook handoff must not copy owned Bytes"
    );
}

#[test]
fn h3_cross_protocol_normalize_reject_omits_framed_provenance() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let normalize = cross
        .split("fn normalize_reject_for_client(")
        .nth(1)
        .expect("H3 cross-protocol reject normalizer")
        .split("fn reject_committed_response_view<'a>(")
        .next()
        .expect("bounded H3 cross-protocol reject normalizer");
    assert!(
        normalize.contains("normalize_reject_response("),
        "cross-protocol rejects must use the provenance-free normalizer"
    );
    assert!(
        !normalize.contains("FramedGrpcUnaryProvenance::from_context"),
        "cross-protocol rejects must not thread framed terminate provenance"
    );
}

#[test]
fn h3_cross_protocol_grpc_reject_writer_is_trailers_only() {
    let cross = include_str!("../../../src/http3/cross_protocol.rs");
    let writer = cross
        .split("async fn write_normalized_grpc_reject_send<S>(")
        .nth(1)
        .expect("H3 cross-protocol gRPC reject writer")
        .split("async fn write_final_grpc_body_reject_send<S>(")
        .next()
        .expect("bounded H3 cross-protocol gRPC reject writer");
    assert!(
        writer.contains("debug_assert!(\n        reject.body.is_empty(),"),
        "cross-protocol gRPC rejects must assert trailers-only"
    );
    assert!(
        !writer.contains("framed_unary_reject_parts"),
        "cross-protocol gRPC rejects must not branch on framed unary parts"
    );
    assert!(
        !writer.contains("stream.send_data("),
        "cross-protocol gRPC rejects must not emit DATA frames"
    );
    assert!(
        writer.contains("apply_response_headers("),
        "cross-protocol gRPC rejects must share the response-header emitter"
    );
}

#[test]
fn h3_cross_protocol_grpc_reject_headers_emit_each_cookie() {
    use ferrum_edge::proxy::headers::apply_response_headers;
    use http::StatusCode;
    use http::header::SET_COOKIE;
    use std::collections::HashMap;

    let headers = HashMap::from([
        ("content-type".to_string(), "application/grpc".to_string()),
        ("grpc-status".to_string(), "7".to_string()),
        (
            "set-cookie".to_string(),
            "a=1; Path=/\nb=2; Path=/".to_string(),
        ),
        ("x-custom".to_string(), "keep".to_string()),
    ]);
    let response = http::Response::builder().status(StatusCode::OK);
    let response = apply_response_headers(response, &headers)
        .body(())
        .expect("cross-protocol gRPC reject header block");
    let cookies = response
        .headers()
        .get_all(SET_COOKIE)
        .iter()
        .map(|value| value.to_str().expect("ASCII cookie"))
        .collect::<Vec<_>>();
    assert_eq!(cookies, vec!["a=1; Path=/", "b=2; Path=/"]);
    assert_eq!(
        response
            .headers()
            .get("x-custom")
            .and_then(|v| v.to_str().ok()),
        Some("keep")
    );
}

#[test]
fn committed_hook_deadline_boundary_accepts_bytes_without_copy() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let hook = proxy
        .split("pub(crate) async fn run_response_committed_hook_until_deadline(")
        .nth(1)
        .expect("response-committed deadline hook")
        .split("pub(crate) fn spawn_detached_response_committed_hooks(")
        .next()
        .expect("bounded response-committed deadline hook");
    assert!(
        hook.contains("response_body: Bytes,"),
        "deadline hook boundary must accept owned Bytes"
    );
    assert!(
        hook.contains("response_body.as_ref()"),
        "fast no-deadline hook path must borrow without forcing a full copy"
    );
    assert!(
        !hook.contains("copy_from_slice"),
        "owned deadline hook state must not copy an existing Bytes body"
    );
}

#[test]
fn buffered_backend_response_from_body_read_keeps_reqwest_bytes() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let reader = proxy
        .split("fn buffered_backend_response_from_body_read(")
        .nth(1)
        .expect("buffered backend body reader")
        .split("fn eager_buffer_body_read_status_and_class(")
        .next()
        .expect("bounded buffered backend body reader");
    assert!(
        reader.contains("Result<bytes::Bytes, reqwest::Error>"),
        "successful reqwest body reads must stay as Bytes"
    );
    assert!(
        reader.contains("ResponseBody::buffered(b)"),
        "buffered backend responses must store Bytes directly"
    );
    assert!(
        !reader.contains("b.to_vec()"),
        "buffered backend responses must not force Vec conversion"
    );
}
