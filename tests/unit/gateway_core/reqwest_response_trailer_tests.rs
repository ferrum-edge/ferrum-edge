//! Backend response trailers on the reqwest dispatch path (issue #5760).
//!
//! The reqwest relay used to read `Response::bytes_stream()`, which yields DATA
//! only, so a backend trailer section was dropped whenever the capability
//! registry had not yet classified the backend for the direct HTTP/2 pool, and
//! on every buffered collection. These cases drive the production adapters and
//! collectors over a backend body that ends with a trailer section.

use ferrum_edge::_test_support::buffered_body_with_trailers_frames_for_test as buffered_body;
use ferrum_edge::_test_support::collect_reqwest_buffered_response_for_test as collect_buffered;
use ferrum_edge::_test_support::relay_reqwest_streaming_response_for_test as relay;

const CHUNKS: &[&[u8]] = &[b"hello, ", b"trailers"];
const TRAILERS: &[(&str, &str)] = &[("x-checksum", "abc123"), ("x-timing", "12ms")];

fn owned(lines: &[(&str, &str)]) -> Vec<(String, String)> {
    lines
        .iter()
        .map(|(name, value)| (name.to_string(), value.to_string()))
        .collect()
}

#[tokio::test]
async fn every_reqwest_streaming_adapter_relays_the_backend_trailer_section() {
    for adapter in ["direct", "coalescing", "size_limited"] {
        let (body, trailers) = relay(adapter, CHUNKS, TRAILERS, true, &[]).await;
        assert_eq!(body, b"hello, trailers", "{adapter}");
        assert_eq!(trailers, Some(owned(TRAILERS)), "{adapter}");
    }
}

#[tokio::test]
async fn reqwest_streaming_relay_without_backend_trailers_ends_on_data() {
    for adapter in ["direct", "coalescing", "size_limited"] {
        let (body, trailers) = relay(adapter, CHUNKS, &[], true, &[]).await;
        assert_eq!(body, b"hello, trailers", "{adapter}");
        assert_eq!(trailers, None, "{adapter}");
    }
}

#[tokio::test]
async fn reqwest_streaming_relay_drops_trailers_the_client_cannot_receive() {
    for adapter in ["direct", "coalescing", "size_limited"] {
        let (body, trailers) = relay(adapter, CHUNKS, TRAILERS, false, &[]).await;
        assert_eq!(body, b"hello, trailers", "{adapter}");
        assert_eq!(trailers, None, "{adapter}");
    }
}

#[tokio::test]
async fn reqwest_streaming_relay_strips_hop_by_hop_trailer_names() {
    let backend = [
        ("x-checksum", "abc123"),
        ("keep-alive", "timeout=5"),
        ("proxy-authenticate", "Basic"),
    ];
    for adapter in ["direct", "coalescing", "size_limited"] {
        let (_, trailers) = relay(adapter, CHUNKS, &backend, true, &[]).await;
        assert_eq!(
            trailers,
            Some(owned(&[("x-checksum", "abc123")])),
            "{adapter}"
        );
    }
}

#[tokio::test]
async fn reqwest_streaming_relay_applies_the_response_trailer_policy() {
    let backend = [("x-checksum", "abc123"), ("x-powered-by", "backend")];
    let policy = vec!["x-powered-by".to_string()];
    for adapter in ["direct", "coalescing", "size_limited"] {
        let (_, trailers) = relay(adapter, CHUNKS, &backend, true, &policy).await;
        assert_eq!(
            trailers,
            Some(owned(&[("x-checksum", "abc123")])),
            "{adapter}: a policy-declared trailer name must not reach the client"
        );
    }
}

#[tokio::test]
async fn buffered_reqwest_collectors_keep_the_backend_trailer_section() {
    for eager in [false, true] {
        let (body, trailers) = collect_buffered(CHUNKS, TRAILERS, eager).await;
        assert_eq!(body, b"hello, trailers", "eager={eager}");
        assert_eq!(trailers, Some(owned(TRAILERS)), "eager={eager}");
    }
}

#[tokio::test]
async fn buffered_reqwest_collectors_report_no_section_when_the_backend_sent_none() {
    for eager in [false, true] {
        let (body, trailers) = collect_buffered(CHUNKS, &[], eager).await;
        assert_eq!(body, b"hello, trailers", "eager={eager}");
        assert_eq!(trailers, None, "eager={eager}");
    }
}

#[tokio::test]
async fn buffered_response_body_emits_data_then_trailers() {
    let (body, trailers) = buffered_body(b"hello, trailers", TRAILERS).await;
    assert_eq!(body, b"hello, trailers");
    assert_eq!(trailers, Some(owned(TRAILERS)));

    // An empty buffered entity still carries its trailer section.
    let (body, trailers) = buffered_body(b"", TRAILERS).await;
    assert!(body.is_empty());
    assert_eq!(trailers, Some(owned(TRAILERS)));
}
