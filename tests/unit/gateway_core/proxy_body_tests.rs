//! Unit tests for src/proxy/body.rs
//!
//! Tests: ProxyBody variants, StreamingMetrics, size hints, end-of-stream detection

use bytes::Bytes;
use ferrum_edge::proxy::body::{ProxyBody, StreamingMetrics};
use http_body::Body;
use std::sync::Arc;
use std::time::Instant;

// ── ProxyBody constructors ────────────────────────────────────────────────

#[test]
fn test_proxy_body_full_from_bytes() {
    let body = ProxyBody::full(Bytes::from("hello"));
    let hint = body.size_hint();
    assert_eq!(hint.exact(), Some(5));
}

#[test]
fn test_proxy_body_from_string() {
    let body = ProxyBody::from_string("test data");
    let hint = body.size_hint();
    assert_eq!(hint.exact(), Some(9));
}

#[test]
fn test_proxy_body_empty() {
    let body = ProxyBody::empty();
    let hint = body.size_hint();
    assert_eq!(hint.exact(), Some(0));
    assert!(body.is_end_stream());
}

#[test]
fn test_proxy_body_full_not_end_stream_when_has_data() {
    let body = ProxyBody::full(Bytes::from("data"));
    // Full<Bytes> with data is NOT end-of-stream until polled
    assert!(!body.is_end_stream());
}

#[test]
fn test_proxy_body_full_size_hint_large() {
    let data = vec![0u8; 1024 * 1024]; // 1MB
    let body = ProxyBody::full(Bytes::from(data));
    let hint = body.size_hint();
    assert_eq!(hint.exact(), Some(1024 * 1024));
}

// ── StreamingMetrics (public API only) ────────────────────────────────────

#[test]
fn test_streaming_metrics_initial_state() {
    let metrics = StreamingMetrics::new(Instant::now());
    assert!(metrics.last_frame_elapsed_ms().is_none());
    assert!(!metrics.completed());
}

#[test]
fn test_streaming_metrics_shared_initial_state_via_arc() {
    let baseline = Instant::now();
    let metrics = Arc::new(StreamingMetrics::new(baseline));
    let metrics_clone = Arc::clone(&metrics);

    // Both sides should see the same initial state
    assert!(metrics.last_frame_elapsed_ms().is_none());
    assert!(metrics_clone.last_frame_elapsed_ms().is_none());
    assert!(!metrics.completed());
    assert!(!metrics_clone.completed());
}

// ── ProxyBody::Full poll_frame ────────────────────────────────────────────

#[tokio::test]
async fn test_proxy_body_full_poll_produces_data() {
    use http_body_util::BodyExt;

    let body = ProxyBody::full(Bytes::from("hello world"));
    let collected = body.collect().await.unwrap();
    let bytes = collected.to_bytes();
    assert_eq!(bytes, "hello world");
}

#[tokio::test]
async fn test_proxy_body_empty_poll_produces_nothing() {
    use http_body_util::BodyExt;

    let body = ProxyBody::empty();
    let collected = body.collect().await.unwrap();
    let bytes = collected.to_bytes();
    assert!(bytes.is_empty());
}

#[tokio::test]
async fn test_proxy_body_full_large_payload() {
    use http_body_util::BodyExt;

    let data = "a".repeat(10_000);
    let body = ProxyBody::full(Bytes::from(data.clone()));
    let collected = body.collect().await.unwrap();
    assert_eq!(collected.to_bytes().len(), data.len());
}

#[tokio::test]
async fn test_proxy_body_from_string_poll() {
    use http_body_util::BodyExt;

    let body = ProxyBody::from_string("json payload");
    let collected = body.collect().await.unwrap();
    assert_eq!(collected.to_bytes(), "json payload");
}

#[test]
fn test_proxy_body_empty_size_hint_zero() {
    let body = ProxyBody::empty();
    let hint = body.size_hint();
    assert_eq!(hint.lower(), 0);
    assert_eq!(hint.upper(), Some(0));
}

#[test]
fn test_proxy_body_full_size_hint_exact() {
    let body = ProxyBody::full(Bytes::from("12345"));
    let hint = body.size_hint();
    assert_eq!(hint.lower(), 5);
    assert_eq!(hint.upper(), Some(5));
}
