//! Pass-through gRPC-Web responses (issue #5758).
//!
//! A route without the `grpc_web` translator forwards a gRPC-Web backend's
//! body unchanged. The backend's own trailer frame is the only terminal status
//! the client receives, so the relay must not append a synthesized one, and the
//! logged `grpc_status` must come from that frame.

use std::collections::HashMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use bytes::Bytes;
use ferrum_edge::_test_support::{
    GRPC_FRAME_TRAILER, grpc_web_passthrough_body_trailer_status_for_test,
    grpc_web_passthrough_response_text_mode_for_test, grpc_web_trailer_outcome_for_test,
    grpc_web_trailer_status_for_test, parse_grpc_frames,
    proxy_body_into_grpc_web_passthrough_streaming_for_test,
    proxy_body_into_grpc_web_streaming_for_test, proxy_body_streaming_for_test,
    proxy_body_with_client_grpc_deadline_for_test, record_grpc_web_passthrough_status_for_test,
    retain_grpc_web_client_content_type_for_test,
};
use ferrum_edge::plugins::TransactionSummary;
use ferrum_edge::proxy::body::ProxyBodyError;
use futures_util::stream;
use http::{HeaderMap, HeaderValue};
use http_body::{Body, Frame};
use http_body_util::{BodyExt, StreamBody};

use super::plugin_utils::create_test_context;

fn frame(flag: u8, payload: &[u8]) -> Vec<u8> {
    let mut framed = Vec::with_capacity(payload.len() + 5);
    framed.push(flag);
    framed.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    framed.extend_from_slice(payload);
    framed
}

/// A backend's complete gRPC-Web response: one message and its trailer frame.
fn backend_body(trailer: &[u8]) -> Vec<u8> {
    let mut body = frame(0x00, b"hello");
    body.extend_from_slice(&frame(GRPC_FRAME_TRAILER, trailer));
    body
}

/// gRPC-Web text as servers emit it: each flush independently base64-padded.
fn text_body(trailer: &[u8]) -> Vec<u8> {
    let mut body = BASE64.encode(frame(0x00, b"hello")).into_bytes();
    let trailer = BASE64.encode(frame(GRPC_FRAME_TRAILER, trailer));
    body.extend_from_slice(trailer.as_bytes());
    body
}

async fn collect(mut body: ferrum_edge::proxy::ProxyBody) -> (Vec<u8>, Option<HeaderMap>) {
    let mut data = Vec::new();
    let mut trailers = None;
    while let Some(frame) = body.frame().await {
        let frame = frame.expect("pass-through frame");
        match frame.into_data() {
            Ok(chunk) => data.extend_from_slice(&chunk),
            Err(frame) => trailers = frame.into_trailers().ok(),
        }
    }
    (data, trailers)
}

fn response_headers(content_type: &str) -> HashMap<String, String> {
    HashMap::from([("content-type".to_string(), content_type.to_string())])
}

fn source(frames: Vec<Frame<Bytes>>) -> ferrum_edge::proxy::ProxyBody {
    let frames = frames.into_iter().map(Ok::<_, ProxyBodyError>);
    proxy_body_streaming_for_test(Box::pin(StreamBody::new(stream::iter(frames))))
}

#[test]
fn observer_reads_the_final_binary_trailer_frame() {
    let body = backend_body(b"grpc-status: 7\r\ngrpc-message: denied\r\n");
    assert_eq!(grpc_web_trailer_status_for_test(&[&body], false), Some(7));
}

#[test]
fn observer_reads_the_status_across_arbitrary_chunk_boundaries() {
    let body = backend_body(b"grpc-status: 5\r\ngrpc-message: missing\r\n");
    let chunks: Vec<&[u8]> = body.chunks(1).collect();
    assert_eq!(grpc_web_trailer_status_for_test(&chunks, false), Some(5));
    let text = text_body(b"grpc-status: 5\r\n");
    let chunks: Vec<&[u8]> = text.chunks(3).collect();
    assert_eq!(grpc_web_trailer_status_for_test(&chunks, true), Some(5));
}

#[test]
fn observer_reads_padded_text_segments() {
    let body = text_body(b"grpc-status: 0\r\n");
    assert_eq!(grpc_web_trailer_status_for_test(&[&body], true), Some(0));
}

#[test]
fn observer_accepts_an_unterminated_last_line_and_any_name_case() {
    let body = backend_body(b"x-trace: abc\r\nGrpc-Status:  3");
    assert_eq!(grpc_web_trailer_status_for_test(&[&body], false), Some(3));
}

#[test]
fn observer_skips_an_overlong_line_without_losing_the_status() {
    let mut trailer = b"x-padding: ".to_vec();
    trailer.extend(std::iter::repeat_n(b'a', 4096));
    trailer.extend_from_slice(b"\r\ngrpc-status: 14\r\n");
    let body = backend_body(&trailer);
    assert_eq!(grpc_web_trailer_status_for_test(&[&body], false), Some(14));
}

#[test]
fn observer_keeps_the_first_status_line_of_the_frame() {
    let body = backend_body(b"grpc-status: 9\r\ngrpc-status: 0\r\n");
    assert_eq!(grpc_web_trailer_status_for_test(&[&body], false), Some(9));
}

#[test]
fn observer_reports_a_malformed_status_as_the_invalid_sentinel() {
    let body = backend_body(b"grpc-status: ok\r\n");
    assert_eq!(
        grpc_web_trailer_status_for_test(&[&body], false),
        Some(u32::MAX)
    );
}

#[test]
fn observer_reports_nothing_without_a_final_readable_trailer_frame() {
    // No trailer frame at all.
    let message_only = frame(0x00, b"hello");
    assert_eq!(
        grpc_web_trailer_status_for_test(&[&message_only], false),
        None
    );
    // A trailer frame that names no status.
    let no_status = backend_body(b"grpc-message: hi\r\n");
    assert_eq!(grpc_web_trailer_status_for_test(&[&no_status], false), None);
    // A trailer frame followed by another frame is not terminal.
    let mut not_final = backend_body(b"grpc-status: 0\r\n");
    not_final.extend_from_slice(&frame(0x00, b"late"));
    assert_eq!(grpc_web_trailer_status_for_test(&[&not_final], false), None);
    // Truncated inside the trailer frame.
    let full = backend_body(b"grpc-status: 0\r\n");
    assert_eq!(
        grpc_web_trailer_status_for_test(&[&full[..full.len() - 2]], false),
        None
    );
    // A compressed trailer frame cannot be read.
    let mut compressed_trailer = frame(0x00, b"hello");
    compressed_trailer.extend_from_slice(&frame(0x81, b"grpc-status: 0\r\n"));
    assert_eq!(
        grpc_web_trailer_status_for_test(&[&compressed_trailer], false),
        None
    );
    // Text mode: malformed base64 and a partial final group.
    assert_eq!(grpc_web_trailer_status_for_test(&[b"!!!!"], true), None);
    let text = text_body(b"grpc-status: 0\r\n");
    assert_eq!(
        grpc_web_trailer_status_for_test(&[&text[..text.len() - 1]], true),
        None
    );
}

#[test]
fn passthrough_classification_excludes_translated_and_non_grpc_web_requests() {
    let ctx = create_test_context();
    assert_eq!(
        grpc_web_passthrough_response_text_mode_for_test(&ctx, Some("application/grpc-web")),
        None,
        "a request the frontend never classified as gRPC-Web is not pass-through"
    );

    let mut ctx = create_test_context();
    retain_grpc_web_client_content_type_for_test(&mut ctx, "application/grpc-web+proto");
    assert_eq!(
        grpc_web_passthrough_response_text_mode_for_test(&ctx, Some("application/grpc-web+proto")),
        Some(false)
    );
    // The response's own gRPC-Web media type decides the framing.
    assert_eq!(
        grpc_web_passthrough_response_text_mode_for_test(
            &ctx,
            Some("application/grpc-web-text+proto"),
        ),
        Some(true)
    );
    // Without a gRPC-Web response type, the client's representation is used.
    assert_eq!(
        grpc_web_passthrough_response_text_mode_for_test(&ctx, None),
        Some(false)
    );

    ctx.metadata
        .insert("grpc_web_mode".to_string(), "binary".to_string());
    assert_eq!(
        grpc_web_passthrough_response_text_mode_for_test(&ctx, Some("application/grpc-web+proto")),
        None,
        "a translated request's backend answered in native gRPC"
    );
    assert_eq!(
        grpc_web_passthrough_body_trailer_status_for_test(
            &ctx,
            &response_headers("application/grpc-web+proto"),
            &backend_body(b"grpc-status: 7\r\n"),
        ),
        None
    );
}

#[test]
fn passthrough_buffered_body_status_uses_the_response_framing() {
    let mut ctx = create_test_context();
    retain_grpc_web_client_content_type_for_test(&mut ctx, "application/grpc-web-text+proto");
    assert_eq!(
        grpc_web_passthrough_body_trailer_status_for_test(
            &ctx,
            &response_headers("application/grpc-web-text+proto"),
            &text_body(b"grpc-status: 12\r\n"),
        ),
        Some(Ok(12))
    );
    assert_eq!(
        grpc_web_passthrough_body_trailer_status_for_test(
            &ctx,
            &response_headers("application/grpc-web+proto"),
            &backend_body(b"grpc-status: 12\r\n"),
        ),
        Some(Ok(12))
    );
}

#[test]
fn observer_reports_a_final_compressed_trailer_frame_as_unreadable() {
    // The status is present, but compressed: it is neither a status nor absent.
    let mut body = frame(0x00, b"hello");
    body.extend_from_slice(&frame(0x81, b"compressed-trailer-bytes"));
    assert_eq!(
        grpc_web_trailer_outcome_for_test(&[&body], false),
        Some(Err("compressed_trailer_frame"))
    );
    let chunks: Vec<&[u8]> = body.chunks(2).collect();
    assert_eq!(
        grpc_web_trailer_outcome_for_test(&chunks, false),
        Some(Err("compressed_trailer_frame"))
    );
    let text = BASE64.encode(&body).into_bytes();
    assert_eq!(
        grpc_web_trailer_outcome_for_test(&[&text], true),
        Some(Err("compressed_trailer_frame"))
    );

    // Only the FINAL frame counts: a later frame makes the body end without a
    // terminal, and a readable trailer frame after it wins.
    let mut not_final = body.clone();
    not_final.extend_from_slice(&frame(0x00, b"late"));
    assert_eq!(
        grpc_web_trailer_outcome_for_test(&[&not_final], false),
        None
    );
    let mut readable_last = body.clone();
    readable_last.extend_from_slice(&frame(GRPC_FRAME_TRAILER, b"grpc-status: 6\r\n"));
    assert_eq!(
        grpc_web_trailer_outcome_for_test(&[&readable_last], false),
        Some(Ok(6))
    );
    // Truncated inside the compressed frame: nothing is terminal yet.
    assert_eq!(
        grpc_web_trailer_outcome_for_test(&[&body[..body.len() - 1]], false),
        None
    );
}

#[test]
fn observer_skips_a_max_length_prefix_without_allocating_or_panicking() {
    // A hostile 0xFFFFFFFF length prefix must only be counted down: the
    // observer holds fixed-size state, so feeding megabytes of the declared
    // payload neither allocates the declared 4 GiB nor overflows.
    let filler = vec![0x41u8; 64 * 1024];
    for flag in [0x00u8, 0x01, GRPC_FRAME_TRAILER, 0x81] {
        let mut header = vec![flag];
        header.extend_from_slice(&u32::MAX.to_be_bytes());
        let mut chunks: Vec<&[u8]> = vec![header.as_slice()];
        chunks.extend(std::iter::repeat_n(filler.as_slice(), 64));
        assert_eq!(
            grpc_web_trailer_outcome_for_test(&chunks, false),
            None,
            "flag {flag:#04x}: an unfinished frame has no terminal status"
        );

        // A complete earlier trailer frame is no longer final once the
        // oversized frame starts.
        let mut body = backend_body(b"grpc-status: 0\r\n");
        body.extend_from_slice(&header);
        body.extend_from_slice(&filler);
        assert_eq!(grpc_web_trailer_status_for_test(&[&body], false), None);

        // Text framing decodes group by group into the same bounded reader.
        let text = BASE64.encode(&body).into_bytes();
        assert_eq!(grpc_web_trailer_outcome_for_test(&[&text], true), None);
    }

    let mut ctx = create_test_context();
    retain_grpc_web_client_content_type_for_test(&mut ctx, "application/grpc-web+proto");
    let mut body = vec![GRPC_FRAME_TRAILER];
    body.extend_from_slice(&u32::MAX.to_be_bytes());
    body.extend_from_slice(b"grpc-status: 0\r\n");
    assert_eq!(
        grpc_web_passthrough_body_trailer_status_for_test(
            &ctx,
            &response_headers("application/grpc-web+proto"),
            &body,
        ),
        None
    );
}

#[tokio::test]
async fn passthrough_relay_forwards_a_max_length_prefix_unchanged() {
    let mut wire = frame(0x00, b"hello");
    wire.push(0x00);
    wire.extend_from_slice(&u32::MAX.to_be_bytes());
    wire.extend_from_slice(&[0x42; 1024]);
    let body = source(vec![Frame::data(Bytes::from(wire.clone()))]);
    let body = proxy_body_into_grpc_web_passthrough_streaming_for_test(body, false, 200);
    let (data, trailers) = collect(body).await;
    assert_eq!(data, wire, "the relay never reframes the body");
    assert!(trailers.is_none());
}

#[test]
fn passthrough_body_under_a_content_coding_is_unreadable() {
    let mut ctx = create_test_context();
    retain_grpc_web_client_content_type_for_test(&mut ctx, "application/grpc-web+proto");
    let body = backend_body(b"grpc-status: 7\r\n");

    let mut encoded = response_headers("application/grpc-web+proto");
    encoded.insert("content-encoding".to_string(), "gzip".to_string());
    assert_eq!(
        grpc_web_passthrough_body_trailer_status_for_test(&ctx, &encoded, &body),
        Some(Err("content_encoded_body")),
        "a content-coded body's frames cannot be parsed, even when they look readable"
    );

    let mut identity = response_headers("application/grpc-web+proto");
    identity.insert("content-encoding".to_string(), "identity".to_string());
    assert_eq!(
        grpc_web_passthrough_body_trailer_status_for_test(&ctx, &identity, &body),
        Some(Ok(7))
    );
}

#[test]
fn an_unreadable_status_stays_unset_instead_of_unknown() {
    let mut ctx = create_test_context();
    retain_grpc_web_client_content_type_for_test(&mut ctx, "application/grpc-web+proto");
    let mut compressed = frame(0x00, b"hello");
    compressed.extend_from_slice(&frame(0x81, b"compressed-trailer-bytes"));

    let mut metadata = HashMap::from([("request_protocol".to_string(), "grpc".to_string())]);
    record_grpc_web_passthrough_status_for_test(
        &ctx,
        &response_headers("application/grpc-web+proto"),
        &compressed,
        &mut metadata,
    );
    assert!(!metadata.contains_key("grpc_status"));
    assert_eq!(
        metadata.get("grpc_status_unreadable").map(String::as_str),
        Some("compressed_trailer_frame")
    );
    let summary = TransactionSummary {
        metadata: metadata.clone(),
        ..Default::default()
    };
    assert_eq!(
        summary.grpc_status(),
        None,
        "a status present but unreadable is not reported as UNKNOWN"
    );

    // A truly missing final frame is still UNKNOWN.
    let mut missing = HashMap::from([("request_protocol".to_string(), "grpc".to_string())]);
    record_grpc_web_passthrough_status_for_test(
        &ctx,
        &response_headers("application/grpc-web+proto"),
        &frame(0x00, b"hello"),
        &mut missing,
    );
    assert!(!missing.contains_key("grpc_status_unreadable"));
    let summary = TransactionSummary {
        metadata: missing,
        ..Default::default()
    };
    assert_eq!(summary.grpc_status(), Some(2));

    // A gateway-authored terminal keeps the status it already recorded.
    let mut gateway = HashMap::from([("grpc_status".to_string(), "4".to_string())]);
    record_grpc_web_passthrough_status_for_test(
        &ctx,
        &response_headers("application/grpc-web+proto"),
        &backend_body(b"grpc-status: 0\r\n"),
        &mut gateway,
    );
    assert_eq!(gateway.get("grpc_status").map(String::as_str), Some("4"));
}

#[tokio::test]
async fn passthrough_relay_forwards_the_backend_body_byte_for_byte() {
    let wire = backend_body(b"grpc-status: 7\r\ngrpc-message: denied\r\n");
    let (first, second) = wire.split_at(7);
    let body = source(vec![
        Frame::data(Bytes::copy_from_slice(first)),
        Frame::data(Bytes::copy_from_slice(second)),
    ]);
    let body = proxy_body_into_grpc_web_passthrough_streaming_for_test(body, false, 200);

    let (data, trailers) = collect(body).await;
    assert_eq!(data, wire, "pass-through must not re-frame the body");
    assert!(trailers.is_none());
    let trailer_frames = parse_grpc_frames(&data)
        .into_iter()
        .filter(|(flag, _)| *flag == GRPC_FRAME_TRAILER)
        .count();
    assert_eq!(trailer_frames, 1, "exactly the backend's own trailer frame");
}

#[tokio::test]
async fn passthrough_relay_never_synthesizes_a_trailer_at_eof() {
    // Even a backend body without any trailer frame gains nothing: the relay
    // does not author a terminal for a response the backend owns.
    let wire = frame(0x00, b"hello");
    let body = source(vec![Frame::data(Bytes::from(wire.clone()))]);
    let body = proxy_body_into_grpc_web_passthrough_streaming_for_test(body, false, 200);
    let (data, _) = collect(body).await;
    assert_eq!(data, wire);
}

#[tokio::test]
async fn passthrough_relay_forwards_text_bytes_unencoded() {
    let wire = text_body(b"grpc-status: 0\r\n");
    let body = source(vec![Frame::data(Bytes::from(wire.clone()))]);
    let body = proxy_body_into_grpc_web_passthrough_streaming_for_test(body, true, 200);
    let (data, _) = collect(body).await;
    assert_eq!(data, wire, "text bodies must not be base64-encoded again");
}

#[tokio::test]
async fn passthrough_relay_keeps_backend_http_trailers() {
    let wire = backend_body(b"grpc-status: 0\r\n");
    let mut backend_trailers = HeaderMap::new();
    backend_trailers.insert("x-backend", HeaderValue::from_static("kept"));
    let body = source(vec![
        Frame::data(Bytes::from(wire.clone())),
        Frame::trailers(backend_trailers.clone()),
    ]);
    let body = proxy_body_into_grpc_web_passthrough_streaming_for_test(body, false, 200);
    let (data, trailers) = collect(body).await;
    assert_eq!(data, wire);
    assert_eq!(trailers, Some(backend_trailers));
}

#[tokio::test]
async fn passthrough_relay_frames_a_gateway_deadline_terminal_as_grpc_web() {
    // A native deadline wrapper below the relay ends the stream with HTTP
    // trailers; a gRPC-Web client can only read a body trailer frame.
    let pending = StreamBody::new(stream::pending::<Result<Frame<Bytes>, ProxyBodyError>>());
    let body = proxy_body_streaming_for_test(Box::pin(pending));
    let deadline = tokio::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("one second before now is representable");
    let body = proxy_body_with_client_grpc_deadline_for_test(body, deadline, None);
    let mut body = proxy_body_into_grpc_web_passthrough_streaming_for_test(body, false, 200);

    let frame = body
        .frame()
        .await
        .expect("deadline must emit a terminal frame")
        .expect("terminal deadline frame must be readable");
    let data = frame
        .into_data()
        .expect("gRPC-Web terminal status is encoded as DATA");
    let frames = parse_grpc_frames(&data);
    assert_eq!(frames.len(), 1);
    assert_eq!(frames[0].0, GRPC_FRAME_TRAILER);
    assert!(String::from_utf8_lossy(&frames[0].1).contains("grpc-status: 4\r\n"));
    assert!(Body::is_end_stream(&body));
    assert!(body.frame().await.is_none());
}

#[tokio::test]
async fn translated_relay_still_converts_native_trailers_once() {
    // Negative control: the translated adapter keeps its contract.
    let mut trailers = HeaderMap::new();
    trailers.insert("grpc-status", HeaderValue::from_static("5"));
    let message = frame(0x00, b"hello");
    let body = source(vec![
        Frame::data(Bytes::from(message.clone())),
        Frame::trailers(trailers),
    ]);
    let body =
        proxy_body_into_grpc_web_streaming_for_test(body, "application/grpc-web+proto", 200, None);
    let (data, http_trailers) = collect(body).await;
    assert!(http_trailers.is_none());
    let frames = parse_grpc_frames(&data);
    assert_eq!(frames.len(), 2);
    assert_eq!(frames[0], (0x00, b"hello".to_vec()));
    assert_eq!(frames[1].0, GRPC_FRAME_TRAILER);
    assert!(String::from_utf8_lossy(&frames[1].1).contains("grpc-status: 5\r\n"));
}
