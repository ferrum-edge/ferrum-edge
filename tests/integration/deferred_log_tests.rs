//! Integration tests for deferred transaction logging.
//!
//! These tests verify that the `DeferredTransactionLogger` correctly
//! populates `TransactionSummary` body-outcome fields and invokes plugin
//! `log()` hooks when a streaming response reaches a terminal state:
//!
//! 1. Successful body completion → `body_completed=true`, `bytes_streamed_to_client=N`.
//! 2. Streaming errors (e.g. backend RST_STREAM mid-body in gRPC) → populate
//!    `body_error_class` while preserving the already-flushed `response_status_code`.
//! 3. Client disconnect detected mid-stream → `client_disconnected=true`.
//! 4. `Drop` safety net fires a client-disconnect summary when the body is
//!    dropped without ever completing (e.g. hyper cancelled the connection).
//!
//! Additional end-to-end coverage: attach a logger to `ProxyBody::full()` and
//! verify that driving it to completion via `poll_frame` fires exactly one
//! summary, and dropping a wrapped body without polling fires the Drop path.

use std::collections::HashMap;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::Mutex;
use std::task::Context;
use std::task::Poll;
use std::task::Waker;

use async_trait::async_trait;
use bytes::Bytes;
use http_body::Body as _;

use ferrum_edge::plugins::{Plugin, RequestContext, TransactionSummary};
use ferrum_edge::proxy::ProxyBody;
use ferrum_edge::proxy::deferred_log::{BodyOutcome, DeferredTransactionLogger};
use ferrum_edge::retry::ErrorClass;

/// Test plugin that captures every `TransactionSummary` passed to `log()`.
struct CapturingPlugin {
    captured: Arc<Mutex<Vec<TransactionSummary>>>,
}

impl CapturingPlugin {
    fn new() -> (Self, Arc<Mutex<Vec<TransactionSummary>>>) {
        let captured = Arc::new(Mutex::new(Vec::new()));
        (
            Self {
                captured: Arc::clone(&captured),
            },
            captured,
        )
    }
}

#[async_trait]
impl Plugin for CapturingPlugin {
    fn name(&self) -> &str {
        "capturing"
    }

    fn priority(&self) -> u16 {
        9000
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.captured.lock().unwrap().push(summary.clone());
    }
}

fn make_summary_with_status(status: u16) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-04-16T00:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        http_method: "GET".to_string(),
        request_path: "/things/42".to_string(),
        matched_proxy_id: Some("proxy-1".to_string()),
        matched_proxy_name: Some("things".to_string()),
        backend_target_url: Some("http://upstream:8080/things/42".to_string()),
        backend_resolved_ip: Some("127.0.0.1".to_string()),
        response_status_code: status,
        latency_total_ms: 0.0,
        latency_gateway_processing_ms: 0.0,
        latency_backend_ttfb_ms: 0.0,
        latency_backend_total_ms: -1.0,
        latency_plugin_execution_ms: 0.0,
        latency_plugin_external_io_ms: 0.0,
        latency_gateway_overhead_ms: 0.0,
        request_user_agent: None,
        response_streamed: true,
        client_disconnected: false,
        error_class: None,
        body_error_class: None,
        body_completed: false,
        bytes_streamed_to_client: 0,
        mirror: false,
        metadata: HashMap::new(),
    }
}

fn make_ctx() -> Arc<RequestContext> {
    Arc::new(RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/things/42".to_string(),
    ))
}

/// Wait until the spawned `log_with_mirror` task has run and pushed a summary
/// into the shared vec. `DeferredTransactionLogger::fire` spawns a tokio task,
/// so callers must yield before asserting.
async fn wait_for_captures(
    captured: &Arc<Mutex<Vec<TransactionSummary>>>,
    expected: usize,
) -> Vec<TransactionSummary> {
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let guard = captured.lock().unwrap();
        if guard.len() >= expected {
            return guard.clone();
        }
    }
    captured.lock().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn success_outcome_populates_body_fields() {
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    logger.fire(BodyOutcome::success(4096));

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1, "log should fire exactly once");
    let got = &captures[0];
    assert!(got.body_completed, "success outcome sets body_completed");
    assert_eq!(got.bytes_streamed_to_client, 4096);
    assert!(!got.client_disconnected);
    assert!(got.body_error_class.is_none());
    assert_eq!(
        got.response_status_code, 200,
        "status flushed at header time is preserved"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn error_outcome_preserves_status_code() {
    // Models the gRPC mid-body RST case: response headers already flushed with
    // status 200 (trailers-only), body errored out partway through. The log
    // entry must keep status=200 while recording the body error.
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    logger.fire(BodyOutcome::error(ErrorClass::ProtocolError, 1234, false));

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1);
    let got = &captures[0];
    assert_eq!(
        got.response_status_code, 200,
        "status is not rewritten by body error"
    );
    assert!(!got.body_completed);
    assert_eq!(got.bytes_streamed_to_client, 1234);
    assert!(!got.client_disconnected, "error was not a disconnect");
    assert_eq!(got.body_error_class, Some(ErrorClass::ProtocolError));
}

#[tokio::test(flavor = "multi_thread")]
async fn client_disconnect_outcome_sets_flag() {
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    logger.fire(BodyOutcome::client_disconnect(512));

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1);
    let got = &captures[0];
    assert!(got.client_disconnected);
    assert_eq!(got.bytes_streamed_to_client, 512);
    assert!(!got.body_completed);
    assert_eq!(got.body_error_class, Some(ErrorClass::ClientDisconnect));
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_without_fire_is_safety_net() {
    // If hyper cancels the connection right after the header flush but before
    // any body frame is polled, the body — and therefore the logger — is
    // dropped without an explicit fire. The Drop impl must still log a
    // client-disconnect summary.
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());
    drop(logger);

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1, "Drop safety net fires exactly one log");
    let got = &captures[0];
    assert!(got.client_disconnected);
    assert_eq!(got.body_error_class, Some(ErrorClass::ClientDisconnect));
    assert!(!got.body_completed);
    assert_eq!(got.bytes_streamed_to_client, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn double_fire_is_a_no_op() {
    // Single-fire semantics: a stray second fire (e.g. caller bug) must not
    // double-log.
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    logger.fire(BodyOutcome::success(100));
    logger.fire(BodyOutcome::error(ErrorClass::ProtocolError, 9_999, true));

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1, "second fire must be a no-op");
    let got = &captures[0];
    assert!(got.body_completed, "first fire's outcome wins");
    assert_eq!(got.bytes_streamed_to_client, 100);
    assert!(!got.client_disconnected);
}

#[tokio::test(flavor = "multi_thread")]
async fn drop_after_explicit_fire_does_not_double_log() {
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());
    logger.fire(BodyOutcome::success(42));
    drop(logger);

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(
        captures.len(),
        1,
        "Drop after explicit fire must not emit a second log"
    );
    assert!(captures[0].body_completed);
    assert_eq!(captures[0].bytes_streamed_to_client, 42);
}

#[tokio::test(flavor = "multi_thread")]
async fn all_plugins_receive_the_final_summary() {
    let (plugin_a, captured_a) = CapturingPlugin::new();
    let (plugin_b, captured_b) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin_a), Arc::new(plugin_b)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    logger.fire(BodyOutcome::success(777));

    let a = wait_for_captures(&captured_a, 1).await;
    let b = wait_for_captures(&captured_b, 1).await;
    assert_eq!(a.len(), 1);
    assert_eq!(b.len(), 1);
    assert_eq!(a[0].bytes_streamed_to_client, 777);
    assert_eq!(b[0].bytes_streamed_to_client, 777);
    assert!(a[0].body_completed);
    assert!(b[0].body_completed);
}

#[tokio::test(flavor = "multi_thread")]
async fn body_polled_to_completion_fires_logger_once_with_success() {
    // Wire the logger into a real ProxyBody wrapper and verify that driving
    // the body to completion via poll_frame fires the logger with
    // body_completed=true and an accurate byte count.
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    let payload = Bytes::from_static(b"hello world, streaming deferred log");
    let expected_len = payload.len() as u64;
    let mut body = ProxyBody::full(payload).with_logger(logger);

    // Poll until the body returns None (end-of-stream). Full<Bytes> always
    // yields data without Pending, so a synchronous poll loop is sufficient.
    let waker = Waker::noop();
    let mut cx = Context::from_waker(waker);
    loop {
        match Pin::new(&mut body).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(_frame))) => continue,
            Poll::Ready(None) => break,
            Poll::Ready(Some(Err(e))) => panic!("unexpected body error: {e}"),
            Poll::Pending => panic!("Full body should never pend"),
        }
    }
    drop(body);

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(
        captures.len(),
        1,
        "Drop after successful fire must not double-log"
    );
    let got = &captures[0];
    assert!(got.body_completed);
    assert_eq!(got.bytes_streamed_to_client, expected_len);
    assert!(!got.client_disconnected);
    assert!(got.body_error_class.is_none());
}

#[tokio::test(flavor = "multi_thread")]
async fn body_dropped_before_polling_fires_client_disconnect() {
    // Simulates hyper cancelling the connection immediately after header flush:
    // the ProxyBody is dropped before poll_frame ever runs.
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    let body = ProxyBody::full(Bytes::from_static(b"never polled")).with_logger(logger);
    drop(body);

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1);
    let got = &captures[0];
    assert!(got.client_disconnected);
    assert_eq!(got.body_error_class, Some(ErrorClass::ClientDisconnect));
    assert_eq!(
        got.bytes_streamed_to_client, 0,
        "no bytes streamed before drop"
    );
    assert!(!got.body_completed);
}

/// Regression: HEAD / 204 / zero-length responses drop the body without
/// ever polling it — hyper sees from the response metadata that there's
/// nothing to stream. Before the fix, the `Drop` safety net checked
/// `is_end_stream()` on the inner body, which for streaming wrappers
/// (`DirectH3Body`, partially-polled `CoalescingH3Body`) returns `false`
/// even for successful zero-length streams. That misclassified every
/// HEAD / 204 streaming response as `client_disconnected=true`.
///
/// After the fix, the Drop path distinguishes "never polled" from
/// "polled but not drained" via a `polled: AtomicBool` on `ProxyBody`.
/// Never-polled streaming bodies are treated as success — hyper chose
/// not to stream them, which is a healthy zero-length response.
#[tokio::test(flavor = "multi_thread")]
async fn unpolled_empty_streaming_body_is_not_client_disconnect() {
    use http_body_util::Empty;

    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(204);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    // Build a `ProxyBodyKind::Stream`-kind body. The inner body here is
    // `Empty<Bytes>` with `is_end_stream() == true`, but what this test
    // exercises is the STRUCTURAL path — when `kind` is `Stream` and the
    // body is dropped unpolled, the Drop impl MUST treat it as success
    // regardless of `is_end_stream()`, because streaming wrappers like
    // `DirectH3Body` and partially-polled `CoalescingH3Body` return
    // `false` from `is_end_stream()` even for successful zero-length
    // streams. The pre-fix Drop consulted `is_end_stream()` on the inner
    // body and flipped H3 wrappers into `client_disconnect`. The post-fix
    // Drop relies on `polled` (never set here → never-polled → streaming
    // success).
    use http_body_util::BodyExt;
    let inner: Pin<
        Box<
            dyn http_body::Body<Data = Bytes, Error = Box<dyn std::error::Error + Send + Sync>>
                + Send,
        >,
    > = Box::pin(
        Empty::<Bytes>::new()
            .map_err(|never| -> Box<dyn std::error::Error + Send + Sync> { match never {} }),
    );
    let body = ferrum_edge::_test_support::proxy_body_streaming_for_test(inner).with_logger(logger);
    drop(body);

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1);
    let got = &captures[0];
    assert!(
        !got.client_disconnected,
        "never-polled streaming body is a HEAD/204-style success, not a client disconnect"
    );
    assert!(got.body_error_class.is_none(), "no error occurred");
    assert!(
        got.body_completed,
        "Drop path treats never-polled streaming bodies as successful completion"
    );
    assert_eq!(got.bytes_streamed_to_client, 0);
}
