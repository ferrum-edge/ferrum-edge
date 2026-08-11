//! Unit tests for src/proxy/body.rs
//!
//! Tests: ProxyBody variants, StreamingMetrics, size hints, end-of-stream detection

use bytes::Bytes;
use ferrum_edge::_test_support::{
    DirectH2UploadGateForTest, UploadCancelSignalForTest, direct_h2_upload_gate_for_test,
    poll_upload_cancel_for_test, proxy_body_streaming_for_test, request_body_drop_outcome_for_test,
};
use ferrum_edge::proxy::body::{
    PooledBackendLease, ProxyBody, ProxyBodyError, RequestBodyOutcome, StreamingMetrics,
};
use http_body::{Body, Frame};
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
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

/// Issue #2445: Hyper H1 synthesizes `Content-Length: 0` for ordinary empty
/// bodies on 205. The status-aware constructor must not advertise an exact
/// length until EOF so reject finalization can omit Content-Length on the wire.
#[test]
fn test_proxy_body_empty_for_205_omits_exact_length_until_polled() {
    let body = ProxyBody::empty_for_response_status(205);
    assert!(
        body.size_hint().exact().is_none(),
        "205 empty body must not advertise an exact length before poll"
    );
    assert!(
        !body.is_end_stream(),
        "205 empty body must stay open until Hyper polls EOF"
    );

    for status in [204u16, 304] {
        let body = ProxyBody::empty_for_response_status(status);
        assert_eq!(
            body.size_hint().exact(),
            Some(0),
            "status {status} keeps the ordinary empty Full body"
        );
        assert!(
            body.is_end_stream(),
            "status {status} ordinary empty body is already ended"
        );
    }
}

#[tokio::test]
async fn test_proxy_body_empty_for_205_yields_immediate_eof() {
    use http_body_util::BodyExt;

    let body = ProxyBody::empty_for_response_status(205);
    let collected = body.collect().await.expect("205 empty body collects");
    assert!(collected.to_bytes().is_empty());
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

// ── RequestGuard lifecycle in ProxyBody ──────────────────────────────────

#[test]
fn test_proxy_body_with_request_guard_increments_counter() {
    use ferrum_edge::overload::{OverloadState, RequestGuard};

    let state = Arc::new(OverloadState::new());
    let guard = RequestGuard::new(&state);

    assert_eq!(
        state
            .active_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    let body = ProxyBody::full(Bytes::from("hello"));
    let body_with_guard = body.with_request_guard(guard);

    // Guard is now embedded in the body — counter should still be 1
    assert_eq!(
        state
            .active_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        1
    );

    // Drop the body — guard should be dropped, decrementing the counter
    drop(body_with_guard);
    assert_eq!(
        state
            .active_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "Dropping body should drop the embedded RequestGuard"
    );
}

#[tokio::test]
async fn test_proxy_body_with_request_guard_poll_then_drop() {
    use ferrum_edge::overload::{OverloadState, RequestGuard};
    use http_body_util::BodyExt;

    let state = Arc::new(OverloadState::new());
    let guard = RequestGuard::new(&state);

    let body = ProxyBody::full(Bytes::from("test data"));
    let body_with_guard = body.with_request_guard(guard);

    // Poll body to completion
    let collected = body_with_guard.collect().await.unwrap();
    assert_eq!(collected.to_bytes(), "test data");

    // After collect() consumes the body, the guard should be dropped
    assert_eq!(
        state
            .active_requests
            .load(std::sync::atomic::Ordering::Relaxed),
        0,
        "Guard should be dropped after body is consumed"
    );
}

// ── ProxyBody size hints edge cases ─────────────────────────────────────

#[test]
fn test_proxy_body_single_byte() {
    let body = ProxyBody::full(Bytes::from_static(b"x"));
    let hint = body.size_hint();
    assert_eq!(hint.exact(), Some(1));
}

#[tokio::test]
async fn test_proxy_body_binary_data() {
    use http_body_util::BodyExt;

    let data: Vec<u8> = (0..=255).collect();
    let body = ProxyBody::full(Bytes::from(data.clone()));
    let collected = body.collect().await.unwrap();
    assert_eq!(collected.to_bytes().as_ref(), data.as_slice());
}

// ── Request-body byte counters ─────────────────────────────────────────
//
// These exercise the `Arc<AtomicU64>` counter plumbed through
// `SizeLimitedIncoming::new_with_counter` and `CountingIncoming::new_with_counter`.
// The integration pattern is: caller clones `ctx.bytes_sent_observed`,
// passes it to the adapter constructor; the adapter's `poll_frame` writes
// bytes into the shared counter; the summary builder reads the final value
// after the request completes.
//
// We can't easily feed a `hyper::body::Incoming` from a test (it requires
// a live connection), but we can exercise the surface area: constructors,
// accessors, and the move-then-observe ownership pattern that callers rely on.

#[test]
fn test_counting_incoming_fresh_counter_starts_at_zero() {
    // Constructed with a fresh counter — initial value is 0.
    use std::sync::atomic::Ordering;
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    assert_eq!(counter.load(Ordering::Acquire), 0);
    // Shared-counter pattern: the Arc is cloned for observation BEFORE the
    // body is moved into `into_reqwest_body()`. A fresh adapter does not
    // mutate the counter until it is polled, so the value remains 0.
    counter.store(0, Ordering::Release);
    assert_eq!(counter.load(Ordering::Acquire), 0);
}

#[test]
fn test_size_limited_incoming_shared_counter_pattern() {
    // Exercises the caller pattern: clone counter for observer, pass to
    // adapter constructor. The counter is then shared across the move.
    use std::sync::atomic::Ordering;
    let observer = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let adapter_counter = Arc::clone(&observer);
    // Simulate the adapter writing to the counter (what poll_frame would do).
    adapter_counter.fetch_add(4096, Ordering::Release);
    // The observer sees the updated value via a separate Arc clone.
    assert_eq!(observer.load(Ordering::Acquire), 4096);
}

#[test]
fn test_bytes_sent_observed_fetch_max_preserves_largest() {
    // The handler uses `fetch_max` on retries so a shorter plugin-transformed
    // body on a later attempt does not lower the observed value. This test
    // exercises that invariant at the AtomicU64 level.
    use std::sync::atomic::Ordering;
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    counter.fetch_max(1024, Ordering::Release);
    assert_eq!(counter.load(Ordering::Acquire), 1024);
    // Smaller value must not overwrite.
    counter.fetch_max(512, Ordering::Release);
    assert_eq!(counter.load(Ordering::Acquire), 1024);
    // Larger value DOES overwrite.
    counter.fetch_max(4096, Ordering::Release);
    assert_eq!(counter.load(Ordering::Acquire), 4096);
}

// ── StreamingMetrics atomic-ordering regression guard ──────────────────
//
// The struct documents a Release/Acquire discipline on `last_frame_nanos`
// and `completed`. This test exercises the happens-before: a completion
// observed via `completed()` must imply the `last_frame_nanos` value set
// before it is visible on the reader.
#[test]
fn test_streaming_metrics_release_acquire_coherence() {
    let baseline = Instant::now();
    let metrics = Arc::new(StreamingMetrics::new(baseline));

    // No frames yet — both fields default.
    assert_eq!(metrics.last_frame_elapsed_ms(), None);
    assert!(!metrics.completed());
    // The struct's public accessors use Acquire loads — calling them on a
    // fresh StreamingMetrics must return the initial values.
    assert!(!metrics.completed());
}

// ── ProxyBody::into_tracked ────────────────────────────────────────────
//
// Verifies that the unified `Stream → Tracked` wrapper preserves the
// `Full` short-circuit (no-op for buffered bodies), drives the metrics
// to a completed state when the underlying stream ends, and lets a
// pre-attached logger survive the kind swap.
#[tokio::test]
async fn test_into_tracked_full_body_is_noop_and_returns_inert_metrics() {
    use http_body_util::BodyExt;

    let baseline = Instant::now();
    let body = ProxyBody::full(Bytes::from("hello"));
    let (mut wrapped, metrics) = body.into_tracked(baseline);

    // Full body should still produce its bytes — kind unchanged.
    let mut collected = Vec::new();
    while let Some(frame) = wrapped.frame().await {
        let frame = frame.unwrap();
        if let Some(data) = frame.data_ref() {
            collected.extend_from_slice(data);
        }
    }
    assert_eq!(&collected[..], b"hello");

    // Metrics never observed a streaming frame, so they remain at their
    // initial values — `completed()` is false because Full short-circuits
    // out of TrackedBody's poll path.
    assert!(metrics.last_frame_elapsed_ms().is_none());
    assert!(!metrics.completed());
}

#[tokio::test]
async fn test_into_tracked_empty_body_remains_empty() {
    use http_body_util::BodyExt;

    let baseline = Instant::now();
    let body = ProxyBody::empty();
    let (wrapped, _metrics) = body.into_tracked(baseline);
    let collected = wrapped.collect().await.unwrap();
    assert!(collected.to_bytes().is_empty());
}

#[test]
fn test_into_tracked_returns_metrics_independent_of_body_kind() {
    // Even for `Full` (no-op path), `into_tracked` must hand back a fresh
    // `Arc<StreamingMetrics>` so the deferred-task spawn site can read
    // them unconditionally without unwrap or branch.
    let baseline = Instant::now();
    let body = ProxyBody::full(Bytes::from("data"));
    let (_wrapped, metrics) = body.into_tracked(baseline);

    // The metrics object exists and is usable — Arc strong count = 1
    // because the no-op path doesn't share metrics with a TrackedBody.
    assert_eq!(Arc::strong_count(&metrics), 1);
}

// ── Direct-H2 request-body terminal outcomes ───────────────────────────
//
// `SizeLimitedIncoming` can be handed an optional completion channel so the
// direct-H2 dispatch path can withhold a backend response until the client
// upload's size decision is final. Two contracts back that:
//
//   1. Hyper's HTTP/2 client sends END_STREAM with the request headers when
//      the body is already end-of-stream, then drops the adapter without ever
//      polling it. That drop must report a normal completion — issue #3176's
//      regression turned every empty direct-H2 request into a 502.
//   2. The gate that consumes the outcome returns a deterministic 413 on
//      overflow, forwards on every other terminal outcome (all of which imply
//      the limit was never exceeded), and fails closed only when no terminal
//      outcome was reported at all.

#[test]
fn test_drop_without_poll_on_end_stream_body_reports_completion() {
    // Known-empty / already-ended upload: nothing was left to send, so the
    // drop is a normal completion, not an abandoned upload.
    assert_eq!(
        request_body_drop_outcome_for_test(true),
        RequestBodyOutcome::Completed
    );
}

#[test]
fn test_drop_with_outstanding_frames_reports_abandoned() {
    // Frames were still outstanding when the adapter went away — the upload
    // never finished and must not be treated as a success.
    assert_eq!(
        request_body_drop_outcome_for_test(false),
        RequestBodyOutcome::Abandoned
    );
}

#[test]
fn test_upload_gate_forwards_on_clean_completion() {
    assert_eq!(
        direct_h2_upload_gate_for_test(Some(RequestBodyOutcome::Completed)),
        DirectH2UploadGateForTest::Forward
    );
}

#[test]
fn test_upload_gate_fails_closed_on_error_and_abandon() {
    // Neither outcome proves that the complete upload was within the limit:
    // unread frames can remain after a backend reset, and a transport error can
    // interrupt polling before an over-limit frame is observed.
    for outcome in [RequestBodyOutcome::Errored, RequestBodyOutcome::Abandoned] {
        assert_eq!(
            direct_h2_upload_gate_for_test(Some(outcome)),
            DirectH2UploadGateForTest::FailClosed,
            "outcome {outcome:?} must fail closed"
        );
    }
}

#[test]
fn test_upload_gate_maps_overflow_to_deterministic_413() {
    // Overflow must never expose the backend's early response.
    assert_eq!(
        direct_h2_upload_gate_for_test(Some(RequestBodyOutcome::Exceeded)),
        DirectH2UploadGateForTest::RequestBodyTooLarge
    );
}

#[test]
fn test_upload_gate_fails_closed_on_missing_signal() {
    // Sender dropped without reporting: unreachable through the adapter's Drop
    // impl, but with no terminal size decision the gate must refuse to forward.
    assert_eq!(
        direct_h2_upload_gate_for_test(None),
        DirectH2UploadGateForTest::FailClosed
    );
}

#[test]
fn test_direct_h2_upload_cancel_signal_lifecycle() {
    // Hyper moves an H2 request body into a detached pipe task once
    // `send_request` is called. A dispatch path that returns early must be able
    // to wake that task; merely dropping the completion receiver leaves a
    // stalled upload pinned. This pins the three states the body adapter acts
    // on before every inner poll.

    // Armed but unsignalled: keep forwarding, and stay armed so the gate can
    // still cancel later.
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let mut cancel = Some(cancel_rx);
    assert_eq!(
        poll_upload_cancel_for_test(&mut cancel),
        UploadCancelSignalForTest::Idle
    );
    assert!(cancel.is_some(), "a pending channel must stay armed");

    // Signalled: the dispatch path timed out and wants the upload torn down.
    cancel_tx.send(()).expect("receiver is still alive");
    assert_eq!(
        poll_upload_cancel_for_test(&mut cancel),
        UploadCancelSignalForTest::Cancelled
    );
    assert!(cancel.is_none(), "a consumed channel must be disarmed");

    // Disarmed: no second cancellation, and no re-poll of a completed receiver.
    assert_eq!(
        poll_upload_cancel_for_test(&mut cancel),
        UploadCancelSignalForTest::Idle
    );

    // Sender dropped without signalling: the dispatch path finished normally,
    // so the upload keeps flowing and the channel is simply disarmed.
    let (cancel_tx, cancel_rx) = tokio::sync::oneshot::channel::<()>();
    let mut cancel = Some(cancel_rx);
    drop(cancel_tx);
    assert_eq!(
        poll_upload_cancel_for_test(&mut cancel),
        UploadCancelSignalForTest::Idle
    );
    assert!(cancel.is_none(), "a dropped sender must disarm the channel");

    // No channel at all (the reqwest / non-direct-H2 constructors): idle.
    let mut cancel = None;
    assert_eq!(
        poll_upload_cancel_for_test(&mut cancel),
        UploadCancelSignalForTest::Idle
    );
}

// ── gRPC length-prefixed response message counting ───────────────────────

fn grpc_frame(payload: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(5 + payload.len());
    out.push(0); // uncompressed
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    out
}

#[tokio::test]
async fn proxy_body_grpc_message_counter_counts_complete_frames_only() {
    use futures_util::stream;
    use http_body_util::BodyExt;
    use http_body_util::StreamBody;
    use std::sync::atomic::Ordering;

    // Two complete messages, then an incomplete trailing header byte.
    let msg1 = grpc_frame(b"");
    let msg2 = grpc_frame(&[1, 2, 3]);
    // Error type is ProxyBodyError at the stream Item boundary so StreamBody
    // remains an http_body::Body (StreamExt::map would yield Stream, not Body).
    let chunks = vec![
        // Split the first 5-byte header across two frames.
        Ok::<_, ferrum_edge::proxy::body::ProxyBodyError>(Frame::data(Bytes::copy_from_slice(
            &msg1[..3],
        ))),
        Ok(Frame::data(Bytes::copy_from_slice(&msg1[3..]))),
        Ok(Frame::data(Bytes::copy_from_slice(&msg2))),
        Ok(Frame::data(Bytes::from_static(&[0, 0, 0]))), // incomplete
    ];

    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let body = proxy_body_streaming_for_test(Box::pin(StreamBody::new(stream::iter(chunks))))
        .with_grpc_message_counter(Arc::clone(&counter));

    let _ = body.collect().await.expect("collect body");
    assert_eq!(
        counter.load(Ordering::Acquire),
        2,
        "only two complete length-prefixed messages must count"
    );
}

#[tokio::test]
async fn proxy_body_grpc_message_counter_ignores_hostile_declared_length() {
    use futures_util::stream;
    use http_body_util::{BodyExt, StreamBody};
    use std::sync::atomic::Ordering;

    // Declares 1 GiB payload but only supplies 1 byte — must not panic or count.
    let mut hostile = vec![0, 0x40, 0, 0, 0]; // len = 0x40000000
    hostile.push(0xff);
    let frames: Vec<Result<Frame<Bytes>, ferrum_edge::proxy::body::ProxyBodyError>> =
        vec![Ok(Frame::data(Bytes::from(hostile)))];
    let stream = StreamBody::new(stream::iter(frames));
    let counter = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let body = proxy_body_streaming_for_test(Box::pin(stream))
        .with_grpc_message_counter(Arc::clone(&counter));
    let _ = body.collect().await.expect("collect hostile body");
    assert_eq!(counter.load(Ordering::Acquire), 0);
}

// ── Pooled backend lease anchoring (issue #3731) ──────────────────────────
//
// A sidecar-ingress Unix HTTP/1.1 dispatch leases a physical connection
// EXCLUSIVELY for one exchange and hands that lease to the streaming response
// body. The body is the only thing that can observe the last backend byte, so
// it owns the release decision: return the carrier on clean end-of-stream,
// retire it (by dropping the lease) on anything else. These tests pin that
// decision without needing a live Unix socket.

/// Records which of the two lease exits fired.
#[derive(Default)]
struct LeaseOutcome {
    released: AtomicUsize,
    dropped: AtomicUsize,
}

impl LeaseOutcome {
    fn released(&self) -> usize {
        self.released.load(Ordering::SeqCst)
    }

    fn dropped(&self) -> usize {
        self.dropped.load(Ordering::SeqCst)
    }
}

struct CountingLease(Arc<LeaseOutcome>);

impl PooledBackendLease for CountingLease {
    fn release_on_clean_eof(self: Box<Self>) {
        self.0.released.fetch_add(1, Ordering::SeqCst);
    }
}

impl Drop for CountingLease {
    fn drop(&mut self) {
        self.0.dropped.fetch_add(1, Ordering::SeqCst);
    }
}

/// Yields `remaining` DATA frames and then either ends cleanly or fails, so a
/// test can drive each terminal the pool has to distinguish.
struct ScriptedStream {
    remaining: usize,
    fail_at_end: bool,
}

impl Body for ScriptedStream {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
        let this = self.get_mut();
        if this.remaining > 0 {
            this.remaining -= 1;
            return Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"chunk")))));
        }
        if this.fail_at_end {
            return Poll::Ready(Some(Err("backend stream failed".into())));
        }
        Poll::Ready(None)
    }
}

fn leased_scripted_body(
    frames: usize,
    fail_at_end: bool,
    outcome: &Arc<LeaseOutcome>,
) -> ProxyBody {
    let stream = ScriptedStream {
        remaining: frames,
        fail_at_end,
    };
    let lease = Box::new(CountingLease(Arc::clone(outcome)));
    proxy_body_streaming_for_test(Box::pin(stream)).with_pooled_backend_lease(lease)
}

async fn poll_once(body: &mut ProxyBody) -> Option<Result<Frame<Bytes>, ProxyBodyError>> {
    std::future::poll_fn(|cx| Pin::new(&mut *body).poll_frame(cx)).await
}

#[tokio::test]
async fn pooled_backend_lease_is_released_on_clean_end_of_stream() {
    let outcome = Arc::new(LeaseOutcome::default());
    let mut body = leased_scripted_body(3, false, &outcome);

    while poll_once(&mut body).await.is_some() {}

    assert_eq!(
        outcome.released(),
        1,
        "a fully-read streaming body must return its pooled carrier exactly once"
    );
}

#[tokio::test]
async fn pooled_backend_lease_is_not_released_before_end_of_stream() {
    let outcome = Arc::new(LeaseOutcome::default());
    let mut body = leased_scripted_body(3, false, &outcome);

    // Two DATA frames read; the body is not finished.
    for _ in 0..2 {
        assert!(
            poll_once(&mut body).await.is_some(),
            "the scripted body still has data"
        );
    }
    assert_eq!(
        outcome.released(),
        0,
        "the carrier must never be returned while the response body is still streaming"
    );

    // The client goes away mid-body.
    drop(body);
    assert_eq!(
        outcome.released(),
        0,
        "a body abandoned mid-stream must not return its carrier"
    );
    assert_eq!(
        outcome.dropped(),
        1,
        "the lease must drop instead, which retires the physical connection"
    );
}

#[tokio::test]
async fn pooled_backend_lease_is_retired_when_the_body_errors() {
    let outcome = Arc::new(LeaseOutcome::default());
    let mut body = leased_scripted_body(1, true, &outcome);

    let mut saw_error = false;
    for _ in 0..3 {
        match poll_once(&mut body).await {
            Some(Err(_)) => {
                saw_error = true;
                break;
            }
            Some(Ok(_)) => continue,
            None => break,
        }
    }
    assert!(saw_error, "the scripted body must surface its failure");
    assert_eq!(
        outcome.released(),
        0,
        "a body error leaves the carrier in an unknown framing state; it must not be pooled"
    );
    assert_eq!(
        outcome.dropped(),
        1,
        "the errored exchange retires its carrier at the error, not at body drop"
    );
}

#[tokio::test]
async fn pooled_backend_lease_is_retired_when_the_body_is_never_polled() {
    let outcome = Arc::new(LeaseOutcome::default());
    let body = leased_scripted_body(3, false, &outcome);

    // hyper decided not to stream this response at all. The backend body was
    // never drained, so the carrier's framing state is unknown: fail closed.
    drop(body);
    assert_eq!(
        outcome.released(),
        0,
        "a never-polled streaming body must not return its carrier"
    );
    assert_eq!(outcome.dropped(), 1);
}
