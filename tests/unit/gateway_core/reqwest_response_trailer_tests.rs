//! Backend response trailers on the reqwest dispatch path (issue #5760).
//!
//! The reqwest relay used to read `Response::bytes_stream()`, which yields DATA
//! only, so a backend trailer section was dropped whenever the capability
//! registry had not yet classified the backend for the direct HTTP/2 pool, and
//! on every buffered collection. These cases drive the production adapters and
//! collectors over a backend body that ends with a trailer section.

use ferrum_edge::_test_support::buffered_body_with_trailers_frames_for_test as buffered_body;
use ferrum_edge::_test_support::collect_reqwest_buffered_response_for_test as collect_buffered;
use ferrum_edge::_test_support::handler_buffered_body_frames_for_test as handler_buffered;
use ferrum_edge::_test_support::relay_reqwest_streaming_response_for_test as relay;
use ferrum_edge::_test_support::reqwest_response_can_carry_trailers_for_test as can_carry;

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

#[tokio::test]
async fn reqwest_streaming_relay_ends_on_data_when_no_trailer_field_survives() {
    // Only hop-by-hop names: stripping empties the section.
    let hop_by_hop = [("keep-alive", "timeout=5"), ("connection", "close")];
    // Only a policy-declared name: governance empties the section.
    let governed = [("x-powered-by", "backend")];
    let policy = vec!["x-powered-by".to_string()];
    for adapter in ["direct", "coalescing", "size_limited"] {
        let (body, trailers) = relay(adapter, CHUNKS, &hop_by_hop, true, &[]).await;
        assert_eq!(body, b"hello, trailers", "{adapter}");
        assert_eq!(trailers, None, "{adapter}: empty trailer frame sent");

        let (body, trailers) = relay(adapter, CHUNKS, &governed, true, &policy).await;
        assert_eq!(body, b"hello, trailers", "{adapter}");
        assert_eq!(trailers, None, "{adapter}: empty trailer frame sent");
    }
}

#[test]
fn only_backend_responses_that_can_carry_trailers_are_relayed() {
    use http::Version;

    // An HTTP/2 response can always end with a TRAILERS frame.
    assert!(can_carry(Version::HTTP_2, &[]));
    assert!(can_carry(Version::HTTP_2, &[("content-length", "15")]));
    // HTTP/1.1 carries a trailer section only inside chunked framing.
    assert!(can_carry(Version::HTTP_11, &[("transfer-encoding", "chunked")]));
    assert!(can_carry(Version::HTTP_11, &[("transfer-encoding", "gzip, Chunked")]));
    assert!(!can_carry(Version::HTTP_11, &[("content-length", "15")]));
    assert!(!can_carry(Version::HTTP_11, &[]));
    assert!(!can_carry(Version::HTTP_11, &[("transfer-encoding", "gzip")]));
    // HTTP/1.0 has no chunked transfer-coding.
    assert!(!can_carry(Version::HTTP_10, &[("transfer-encoding", "chunked")]));
}

/// A reqwest streaming response whose backend cannot carry a trailer section
/// (for example an HTTP/1.1 response framed by `Content-Length`) must not open
/// the response-trailer governor: that gate is what makes the handler take the
/// pre-policy header snapshot and clone the final header map for the response.
#[test]
fn reqwest_trailer_evidence_capture_is_gated_on_backend_trailer_capability() {
    let proxy = include_str!("../../../src/proxy/mod.rs");
    let gate_start = proxy
        .find("let reqwest_trailers_relayed = match &response_body {")
        .expect("reqwest trailer relay gate");
    let gate = &proxy[gate_start..];
    let gate = &gate[..gate.find("};").expect("relay gate end")];
    assert!(
        gate.contains("&& reqwest_response_can_carry_trailers(response)"),
        "the reqwest relay gate must check the backend response's framing: {gate}"
    );
    let policy_start = proxy
        .find("let streaming_trailer_policy = if hyper_or_h3_streaming_relay")
        .expect("streaming trailer policy gate");
    assert!(
        policy_start > gate_start,
        "the trailer policy capture must be decided after the relay gate"
    );
    let policy_gate = &proxy[policy_start..];
    let policy_gate = &policy_gate[..policy_gate.find('{').expect("policy gate end")];
    assert!(
        policy_gate.contains("|| reqwest_trailers_relayed"),
        "the capture gate must use the capability-aware relay decision: {policy_gate}"
    );
    assert!(
        !proxy.contains("matches!(&response_body, ResponseBody::Streaming { .. })\n        && ("),
        "a bare Streaming match must not open the reqwest trailer governor"
    );
    let governor_build = proxy
        .find("if let Some((pre_policy, section, unbounded)) = streaming_trailer_policy {")
        .expect("governor build site");
    let first_statement = proxy[governor_build..]
        .lines()
        .nth(1)
        .expect("governor body");
    assert_eq!(
        first_statement.trim(),
        "let mut final_headers = response_headers.clone();",
        "the final-header clone must stay behind the trailer policy gate"
    );
}

#[tokio::test]
async fn handler_relays_buffered_backend_trailers_to_an_http2_client() {
    let (body, trailers) =
        handler_buffered(true, false, false, None, false, 200, TRAILERS, &[]).await;
    assert_eq!(body, b"buffered body");
    assert_eq!(trailers, Some(owned(TRAILERS)));
}

#[tokio::test]
async fn handler_drops_buffered_backend_trailers_the_client_cannot_receive() {
    let (body, trailers) =
        handler_buffered(false, false, false, None, false, 200, TRAILERS, &[]).await;
    assert_eq!(body, b"buffered body");
    assert_eq!(trailers, None, "HTTP/1.1 client");
}

#[tokio::test]
async fn handler_drops_buffered_backend_trailers_for_grpc_requests() {
    // Native gRPC folds its buffered terminal metadata into the response
    // headers, and translated gRPC-Web re-encodes it as a body frame.
    for (grpc, grpc_web) in [(true, false), (false, true), (true, true)] {
        let (body, trailers) =
            handler_buffered(true, grpc, grpc_web, None, false, 200, TRAILERS, &[]).await;
        assert_eq!(body, b"buffered body", "grpc={grpc} grpc_web={grpc_web}");
        assert_eq!(trailers, None, "grpc={grpc} grpc_web={grpc_web}");
    }
}

#[tokio::test]
async fn handler_drops_buffered_backend_trailers_when_the_gateway_replaced_the_body() {
    for name in ["deadline", "capacity", "representation"] {
        let selected = Some(name);
        let (_, trailers) =
            handler_buffered(true, false, false, selected, false, 200, TRAILERS, &[]).await;
        assert_eq!(trailers, None, "{name}");
    }
}

#[tokio::test]
async fn handler_drops_buffered_backend_trailers_without_content() {
    let (_, trailers) = handler_buffered(true, false, false, None, true, 200, TRAILERS, &[]).await;
    assert_eq!(trailers, None, "HEAD");
    for status in [204, 304] {
        let (_, trailers) =
            handler_buffered(true, false, false, None, false, status, TRAILERS, &[]).await;
        assert_eq!(trailers, None, "status {status}");
    }
}

#[tokio::test]
async fn handler_buffered_body_ends_on_data_when_no_trailer_field_survives() {
    let hop_by_hop = [("keep-alive", "timeout=5"), ("te", "trailers")];
    let (body, trailers) =
        handler_buffered(true, false, false, None, false, 200, &hop_by_hop, &[]).await;
    assert_eq!(body, b"buffered body");
    assert_eq!(trailers, None, "empty trailer frame sent after stripping");

    let policy = vec!["x-powered-by".to_string()];
    let governed = [("x-powered-by", "backend")];
    let (body, trailers) =
        handler_buffered(true, false, false, None, false, 200, &governed, &policy).await;
    assert_eq!(body, b"buffered body");
    assert_eq!(trailers, None, "empty trailer frame sent after governance");

    let mixed = [("x-checksum", "abc123"), ("x-powered-by", "backend")];
    let (_, trailers) =
        handler_buffered(true, false, false, None, false, 200, &mixed, &policy).await;
    assert_eq!(trailers, Some(owned(&[("x-checksum", "abc123")])));
}
