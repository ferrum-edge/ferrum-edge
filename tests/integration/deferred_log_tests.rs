//! Integration tests for deferred transaction logging.
//!
//! These tests verify that the `DeferredTransactionLogger` correctly
//! populates `TransactionSummary` body-outcome fields and invokes plugin
//! `log()` hooks when a streaming response reaches a terminal state:
//!
//! 1. Successful body completion → `body_completed=true`, `bytes_received=N`.
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

use ferrum_edge::plugins::{
    Plugin, RequestContext, ResponseStreamAction, ResponseStreamInspector, TransactionSummary,
    create_plugin, create_response_stream_inspector, log_with_mirror_before_buffered_response,
};
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

/// Test plugin that records the order of stream termination and log hooks.
struct StreamTerminationCapturingPlugin {
    events: Arc<Mutex<Vec<&'static str>>>,
    status: Arc<Mutex<Option<u16>>>,
    outcome: Arc<Mutex<Option<BodyOutcome>>>,
    summaries: Arc<Mutex<Vec<TransactionSummary>>>,
}

struct PassthroughInspector;

struct OrderedLogPlugin {
    label: &'static str,
    events: Arc<Mutex<Vec<&'static str>>>,
    started: Option<Arc<tokio::sync::Notify>>,
    release: Option<Arc<tokio::sync::Notify>>,
}

#[async_trait]
impl ResponseStreamInspector for PassthroughInspector {
    async fn on_chunk(&mut self, chunk: &[u8]) -> ResponseStreamAction {
        ResponseStreamAction::Forward(Bytes::copy_from_slice(chunk))
    }
}

#[async_trait]
impl Plugin for StreamTerminationCapturingPlugin {
    fn name(&self) -> &str {
        "stream-termination-capturing"
    }

    fn priority(&self) -> u16 {
        9000
    }

    fn requires_response_stream_hooks(&self) -> bool {
        true
    }

    fn response_stream_inspector(
        &self,
        _ctx: &RequestContext,
        _response_status: u16,
        _content_type: Option<&str>,
    ) -> Option<Box<dyn ResponseStreamInspector>> {
        Some(Box::new(PassthroughInspector))
    }

    async fn on_response_stream_terminated(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        outcome: &BodyOutcome,
    ) {
        ctx.metadata.insert(
            "stream.finalized".to_string(),
            "before_summary_log".to_string(),
        );
        self.events.lock().unwrap().push("stream_terminated");
        *self.status.lock().unwrap() = Some(response_status);
        *self.outcome.lock().unwrap() = Some(outcome.clone());
    }

    async fn log(&self, summary: &TransactionSummary) {
        self.summaries.lock().unwrap().push(summary.clone());
        self.events.lock().unwrap().push("log");
    }
}

#[async_trait]
impl Plugin for OrderedLogPlugin {
    fn name(&self) -> &str {
        self.label
    }

    async fn log(&self, _summary: &TransactionSummary) {
        self.events.lock().unwrap().push(self.label);
        if let Some(started) = &self.started {
            started.notify_one();
        }
        if let Some(release) = &self.release {
            release.notified().await;
            self.events.lock().unwrap().push("first-finished");
        }
    }
}

fn make_summary_with_status(status: u16) -> TransactionSummary {
    TransactionSummary {
        namespace: "ferrum".to_string(),
        timestamp_received: "2026-04-16T00:00:00Z".to_string(),
        client_ip: "10.0.0.1".to_string(),
        consumer_username: None,
        auth_method: None,
        http_method: "GET".to_string(),
        request_path: "/things/42".to_string(),
        proxy_id: Some("proxy-1".to_string()),
        proxy_name: Some("things".to_string()),
        backend_target: Some("http://upstream:8080/things/42".to_string()),
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
        bytes_sent: 0,
        bytes_received: 0,
        mirror: false,
        metadata: HashMap::new(),
        ai_usage_export: None,
        proxy_lifecycle_generation: None,
    }
}

fn make_ctx() -> RequestContext {
    RequestContext::new(
        "10.0.0.1".to_string(),
        "GET".to_string(),
        "/things/42".to_string(),
    )
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

async fn wait_for_events(
    events: &Arc<Mutex<Vec<&'static str>>>,
    expected: usize,
) -> Vec<&'static str> {
    for _ in 0..100 {
        tokio::time::sleep(std::time::Duration::from_millis(2)).await;
        let guard = events.lock().unwrap();
        if guard.len() >= expected {
            return guard.clone();
        }
    }
    events.lock().unwrap().clone()
}

#[tokio::test(flavor = "multi_thread")]
async fn buffered_logging_without_deadline_awaits_plugins_sequentially() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let plugins: Vec<Arc<dyn Plugin>> = vec![
        Arc::new(OrderedLogPlugin {
            label: "first-started",
            events: Arc::clone(&events),
            started: Some(Arc::clone(&started)),
            release: Some(Arc::clone(&release)),
        }),
        Arc::new(OrderedLogPlugin {
            label: "second-started",
            events: Arc::clone(&events),
            started: None,
            release: None,
        }),
    ];
    let summary = make_summary_with_status(200);
    let ctx = make_ctx();

    let log_task = tokio::spawn(async move {
        log_with_mirror_before_buffered_response(&plugins, summary, &ctx).await;
    });
    started.notified().await;

    assert!(
        !log_task.is_finished(),
        "the caller must await the first hook"
    );
    assert_eq!(events.lock().unwrap().as_slice(), ["first-started"]);

    release.notify_one();
    log_task.await.expect("buffered log task joined");
    assert_eq!(
        events.lock().unwrap().as_slice(),
        ["first-started", "first-finished", "second-started"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn deadline_buffered_logging_does_not_await_a_blocked_sink() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let plugins: Vec<Arc<dyn Plugin>> = vec![Arc::new(OrderedLogPlugin {
        label: "deadline-log-started",
        events: Arc::clone(&events),
        started: Some(Arc::clone(&started)),
        release: Some(Arc::clone(&release)),
    })];
    let summary = make_summary_with_status(200);
    let mut ctx = make_ctx();
    ferrum_edge::_test_support::set_grpc_deadline_budget_for_test(&mut ctx, Some(5_000));

    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        log_with_mirror_before_buffered_response(&plugins, summary, &ctx),
    )
    .await
    .expect("deadline-bearing response must not await the blocked log sink");

    started.notified().await;
    assert_eq!(events.lock().unwrap().as_slice(), ["deadline-log-started"]);
    release.notify_one();
    assert_eq!(
        wait_for_events(&events, 2).await.as_slice(),
        ["deadline-log-started", "first-finished"]
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn streamed_terminal_logging_is_spawned_after_body_completion() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let started = Arc::new(tokio::sync::Notify::new());
    let release = Arc::new(tokio::sync::Notify::new());
    let plugin: Arc<dyn Plugin> = Arc::new(OrderedLogPlugin {
        label: "stream-log-started",
        events: Arc::clone(&events),
        started: Some(Arc::clone(&started)),
        release: Some(Arc::clone(&release)),
    });
    let logger = DeferredTransactionLogger::new(
        make_summary_with_status(200),
        Arc::new(vec![plugin]),
        make_ctx(),
    );

    logger.fire(BodyOutcome::success(64));
    started.notified().await;
    assert_eq!(events.lock().unwrap().as_slice(), ["stream-log-started"]);

    release.notify_one();
    let completed = wait_for_events(&events, 2).await;
    assert_eq!(
        completed.as_slice(),
        ["stream-log-started", "first-finished"]
    );
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
    assert_eq!(got.bytes_received, 4096);
    assert!(!got.client_disconnected);
    assert!(got.body_error_class.is_none());
    assert_eq!(
        got.response_status_code, 200,
        "status flushed at header time is preserved"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn fire_invokes_response_stream_termination_before_log() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let status = Arc::new(Mutex::new(None));
    let outcome = Arc::new(Mutex::new(None));
    let summaries = Arc::new(Mutex::new(Vec::new()));
    let plugin: Arc<dyn Plugin> = Arc::new(StreamTerminationCapturingPlugin {
        events: events.clone(),
        status: status.clone(),
        outcome: outcome.clone(),
        summaries: summaries.clone(),
    });
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![plugin]);
    let mut summary = make_summary_with_status(206);
    summary.response_streamed = true;
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    logger.fire(BodyOutcome::error(ErrorClass::ReadWriteTimeout, 77, false));

    let events = wait_for_events(&events, 2).await;
    assert_eq!(events.as_slice(), ["stream_terminated", "log"]);
    assert_eq!(*status.lock().unwrap(), Some(206));
    let outcome = outcome
        .lock()
        .unwrap()
        .clone()
        .expect("stream termination hook fired");
    assert!(!outcome.body_completed);
    assert_eq!(outcome.body_error_class, Some(ErrorClass::ReadWriteTimeout));
    assert!(!outcome.client_disconnected);
    assert_eq!(outcome.bytes_streamed, 77);
    let summaries = summaries.lock().unwrap();
    assert_eq!(summaries.len(), 1);
    assert_eq!(
        summaries[0]
            .metadata
            .get("stream.finalized")
            .map(String::as_str),
        Some("before_summary_log"),
        "metadata written by the terminal hook must reach TransactionSummary"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn expired_grpc_deadline_still_runs_stream_cleanup_before_log() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let status = Arc::new(Mutex::new(None));
    let outcome = Arc::new(Mutex::new(None));
    let summaries = Arc::new(Mutex::new(Vec::new()));
    let deadline_plugin = create_plugin(
        "grpc_deadline",
        &serde_json::json!({ "default_deadline_ms": 1 }),
    )
    .unwrap()
    .unwrap();
    let capturing_plugin: Arc<dyn Plugin> = Arc::new(StreamTerminationCapturingPlugin {
        events: events.clone(),
        status,
        outcome,
        summaries,
    });
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![deadline_plugin, capturing_plugin]);
    let mut ctx = make_ctx();
    ctx.headers
        .insert("content-type".to_string(), "application/grpc".to_string());
    assert!(matches!(
        ferrum_edge::plugins::grpc_deadline::prepare_request_deadline(plugins.as_slice(), &mut ctx,),
        ferrum_edge::plugins::PluginResult::Continue
    ));
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    let logger = DeferredTransactionLogger::new(make_summary_with_status(200), plugins, ctx);

    logger.fire(BodyOutcome::error(ErrorClass::ReadWriteTimeout, 0, false));

    let events = wait_for_events(&events, 2).await;
    assert_eq!(events.as_slice(), ["stream_terminated", "log"]);
}

#[tokio::test(flavor = "multi_thread")]
async fn deferred_log_waits_for_detached_inspector_completion() {
    let events = Arc::new(Mutex::new(Vec::new()));
    let status = Arc::new(Mutex::new(None));
    let outcome = Arc::new(Mutex::new(None));
    let summaries = Arc::new(Mutex::new(Vec::new()));
    let plugin: Arc<dyn Plugin> = Arc::new(StreamTerminationCapturingPlugin {
        events: events.clone(),
        status,
        outcome,
        summaries,
    });
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![plugin]);
    let mut ctx = make_ctx();
    let inspector = create_response_stream_inspector(
        plugins.as_slice(),
        &mut ctx,
        200,
        Some("text/event-stream"),
    )
    .expect("inspector");
    let logger = DeferredTransactionLogger::new(make_summary_with_status(200), plugins, ctx);

    logger.fire(BodyOutcome::client_disconnect(0));
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    assert!(
        events.lock().unwrap().is_empty(),
        "terminal hooks must wait while the detached inspector is still alive"
    );

    drop(inspector);
    let events = wait_for_events(&events, 2).await;
    assert_eq!(events.as_slice(), ["stream_terminated", "log"]);
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
    assert_eq!(got.bytes_received, 1234);
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
    assert_eq!(got.bytes_received, 512);
    assert!(!got.body_completed);
    assert_eq!(got.body_error_class, Some(ErrorClass::ClientDisconnect));
}

#[tokio::test(flavor = "multi_thread")]
async fn error_outcome_can_also_mark_client_disconnect() {
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    logger.fire(BodyOutcome::error(ErrorClass::ReadWriteTimeout, 321, true));

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1);
    let got = &captures[0];
    assert!(got.client_disconnected);
    assert_eq!(got.bytes_received, 321);
    assert!(!got.body_completed);
    assert_eq!(got.body_error_class, Some(ErrorClass::ReadWriteTimeout));
}

#[tokio::test(flavor = "multi_thread")]
async fn start_time_rederives_gateway_latency_from_backend_total_when_available() {
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let mut summary = make_summary_with_status(200);
    summary.latency_total_ms = 1.0;
    summary.latency_backend_ttfb_ms = 3.0;
    summary.latency_backend_total_ms = 25.0;
    summary.latency_plugin_execution_ms = 7.0;
    summary.latency_gateway_processing_ms = 0.0;
    summary.latency_gateway_overhead_ms = 0.0;
    summary.response_streamed = false;
    let start_time = std::time::Instant::now();
    let logger =
        DeferredTransactionLogger::new_with_start_time(summary, plugins, make_ctx(), start_time);

    tokio::time::sleep(std::time::Duration::from_millis(45)).await;
    logger.fire(BodyOutcome::success(1));

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1);
    let got = &captures[0];
    assert!(
        got.latency_total_ms >= 35.0,
        "total latency should be re-derived at fire time, got {}",
        got.latency_total_ms
    );
    assert_eq!(got.latency_backend_ttfb_ms, 3.0);
    assert_eq!(got.latency_backend_total_ms, 25.0);
    assert_eq!(
        got.latency_gateway_processing_ms,
        (got.latency_total_ms - 25.0).max(0.0)
    );
    assert_eq!(
        got.latency_gateway_overhead_ms,
        (got.latency_total_ms - 25.0 - 7.0).max(0.0)
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn start_time_keeps_gateway_sentinel_when_streaming_backend_total_unknown() {
    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let mut summary = make_summary_with_status(200);
    summary.latency_total_ms = 1.0;
    summary.latency_backend_ttfb_ms = 0.8;
    summary.latency_backend_total_ms = -1.0;
    summary.latency_plugin_execution_ms = 0.5;
    summary.latency_gateway_processing_ms = -1.0;
    summary.latency_gateway_overhead_ms = -1.0;
    summary.response_streamed = true;
    let start_time = std::time::Instant::now();
    let logger =
        DeferredTransactionLogger::new_with_start_time(summary, plugins, make_ctx(), start_time);

    tokio::time::sleep(std::time::Duration::from_millis(45)).await;
    logger.fire(BodyOutcome::success(1));

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1);
    let got = &captures[0];
    assert!(
        got.latency_total_ms >= 35.0,
        "total latency should be re-derived at fire time, got {}",
        got.latency_total_ms
    );
    assert_eq!(got.latency_backend_ttfb_ms, 0.8);
    assert_eq!(got.latency_backend_total_ms, -1.0);
    // Issue #2532: never substitute TTFB and inflate gateway fields.
    assert_eq!(got.latency_gateway_processing_ms, -1.0);
    assert_eq!(got.latency_gateway_overhead_ms, -1.0);
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
    assert_eq!(got.bytes_received, 0);
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
    assert_eq!(got.bytes_received, 100);
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
    assert_eq!(captures[0].bytes_received, 42);
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
    assert_eq!(a[0].bytes_received, 777);
    assert_eq!(b[0].bytes_received, 777);
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
    assert_eq!(got.bytes_received, expected_len);
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
    assert_eq!(got.bytes_received, 0, "no bytes streamed before drop");
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
    assert_eq!(got.bytes_received, 0);
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_web_deadline_terminal_data_logs_deadline_exceeded() {
    use futures_util::stream;
    use http_body::Frame;
    use http_body_util::{BodyExt, StreamBody};

    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    let inner = StreamBody::new(stream::pending::<
        Result<Frame<Bytes>, ferrum_edge::proxy::body::ProxyBodyError>,
    >());
    let body = ferrum_edge::_test_support::proxy_body_streaming_for_test(Box::pin(inner));
    let deadline = tokio::time::Instant::now()
        .checked_sub(std::time::Duration::from_secs(1))
        .expect("one second before now is representable");
    let mut body = ferrum_edge::_test_support::proxy_body_with_client_grpc_deadline_for_test(
        body,
        deadline,
        Some("application/grpc-web+proto"),
    )
    .with_logger(logger);

    let frame = body
        .frame()
        .await
        .expect("deadline must emit a terminal gRPC-Web DATA frame")
        .expect("terminal deadline frame must be readable");
    let data = frame
        .data_ref()
        .expect("gRPC-Web terminal metadata is encoded as DATA");
    assert!(!data.is_empty());

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1, "terminal DATA must fire one log entry");
    let got = &captures[0];
    assert!(got.body_completed);
    assert!(!got.client_disconnected);
    assert!(got.body_error_class.is_none());
    assert_eq!(got.bytes_received, data.len() as u64);
    assert_eq!(
        got.metadata.get("grpc_status").map(String::as_str),
        Some("4"),
        "the delivered terminal gRPC-Web frame must log DEADLINE_EXCEEDED"
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_deadline_after_partial_data_logs_deadline_exceeded() {
    use futures_util::StreamExt as _;
    use futures_util::stream;
    use http_body::Frame;
    use http_body_util::{BodyExt, StreamBody};

    let (plugin, captured) = CapturingPlugin::new();
    let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![Arc::new(plugin)]);
    let summary = make_summary_with_status(200);
    let logger = DeferredTransactionLogger::new(summary, plugins, make_ctx());

    let source = stream::once(async {
        Ok::<_, ferrum_edge::proxy::body::ProxyBodyError>(Frame::data(Bytes::from_static(
            b"partial response",
        )))
    })
    .chain(stream::pending());
    let body = ferrum_edge::_test_support::proxy_body_streaming_for_test(Box::pin(
        StreamBody::new(source),
    ));
    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(1))
        .expect("one second after now is representable");
    let mut body = ferrum_edge::_test_support::proxy_body_with_client_grpc_deadline_for_test(
        body, deadline, None,
    )
    .with_logger(logger);

    let data = body
        .frame()
        .await
        .expect("the first DATA frame must remain visible")
        .expect("the first DATA frame must be readable");
    assert_eq!(
        data.data_ref().map(Bytes::as_ref),
        Some(&b"partial response"[..])
    );
    tokio::time::sleep_until(deadline).await;
    assert!(
        body.frame()
            .await
            .expect("a partial native gRPC response must terminate with an error")
            .is_err(),
        "deadline after DATA must surface a terminal body error"
    );

    let captures = wait_for_captures(&captured, 1).await;
    assert_eq!(captures.len(), 1);
    let got = &captures[0];
    assert!(!got.body_completed);
    assert!(got.client_disconnected);
    assert_eq!(got.body_error_class, Some(ErrorClass::ClientDisconnect));
    assert_eq!(got.bytes_received, b"partial response".len() as u64);
    assert_eq!(
        got.metadata.get("grpc_status").map(String::as_str),
        Some("4"),
        "a deadline error after partial DATA must log DEADLINE_EXCEEDED"
    );
}

struct HoldingResponseInspector {
    saw_backend_chunk: Arc<tokio::sync::Notify>,
    dropped: Arc<tokio::sync::Notify>,
}

#[async_trait]
impl ResponseStreamInspector for HoldingResponseInspector {
    async fn on_chunk(&mut self, _chunk: &[u8]) -> ResponseStreamAction {
        self.saw_backend_chunk.notify_one();
        std::future::pending::<ResponseStreamAction>().await
    }
}

impl Drop for HoldingResponseInspector {
    fn drop(&mut self) {
        self.dropped.notify_one();
    }
}

#[tokio::test(flavor = "multi_thread")]
async fn grpc_deadline_uses_bytes_emitted_after_stream_inspection() {
    use futures_util::StreamExt as _;
    use futures_util::stream;
    use http_body::Frame;
    use http_body_util::{BodyExt, StreamBody};

    let source = stream::once(async {
        Ok::<_, ferrum_edge::proxy::body::ProxyBodyError>(Frame::data(Bytes::from_static(
            b"backend bytes held by inspector",
        )))
    })
    .chain(stream::pending());
    let backend_body = ferrum_edge::_test_support::proxy_body_streaming_for_test(Box::pin(
        StreamBody::new(source),
    ));
    let saw_backend_chunk = Arc::new(tokio::sync::Notify::new());
    let dropped = Arc::new(tokio::sync::Notify::new());
    let dropped_notified = dropped.notified();
    let inspected = ferrum_edge::_test_support::inspected_proxy_body_for_test(
        backend_body,
        Box::new(HoldingResponseInspector {
            saw_backend_chunk: Arc::clone(&saw_backend_chunk),
            dropped: Arc::clone(&dropped),
        }),
    );

    tokio::time::timeout(
        std::time::Duration::from_secs(1),
        saw_backend_chunk.notified(),
    )
    .await
    .expect("inspector must consume and hold the backend chunk");

    let deadline = tokio::time::Instant::now()
        .checked_sub(std::time::Duration::from_millis(1))
        .expect("one millisecond before now is representable");
    let mut body = ferrum_edge::_test_support::proxy_body_with_client_grpc_deadline_for_test(
        inspected, deadline, None,
    );
    let frame = body
        .frame()
        .await
        .expect("zero client-visible bytes must yield terminal deadline trailers")
        .expect("deadline trailer frame must be readable");
    let trailers = frame
        .trailers_ref()
        .expect("native gRPC deadline before emitted DATA uses trailers");
    assert_eq!(
        trailers
            .get("grpc-status")
            .and_then(|value| value.to_str().ok()),
        Some("4")
    );
    tokio::time::timeout(std::time::Duration::from_secs(1), dropped_notified)
        .await
        .expect("dropping the deadline receiver must cancel a blocked inspector");
}

#[tokio::test]
async fn grpc_deadline_body_does_not_restore_stripped_content_length() {
    use http_body_util::{BodyExt as _, Full};

    let exact = Full::new(Bytes::from_static(b"backend representation")).map_err(
        |never: std::convert::Infallible| -> ferrum_edge::proxy::body::ProxyBodyError {
            match never {}
        },
    );
    let body = ferrum_edge::_test_support::proxy_body_streaming_for_test(Box::pin(exact));
    assert_eq!(body.size_hint().exact(), Some(22));

    let deadline = tokio::time::Instant::now()
        .checked_add(std::time::Duration::from_secs(1))
        .expect("one second after now is representable");
    let body = ferrum_edge::_test_support::proxy_body_with_client_grpc_deadline_for_test(
        body, deadline, None,
    );
    assert_eq!(
        body.size_hint().exact(),
        None,
        "the deadline wrapper must not let hyper infer the backend Content-Length"
    );
}
