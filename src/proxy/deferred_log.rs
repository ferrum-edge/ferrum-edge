//! Deferred transaction logging for streaming responses.
//!
//! Problem: `log_with_mirror()` fires synchronously right after response
//! headers are sent. For streaming responses, this is before the body has
//! finished streaming to the client — so mid-stream disconnects, body
//! errors, and partial writes are not reflected in the log entry.
//!
//! Solution: [`DeferredTransactionLogger`] holds the `TransactionSummary`
//! and the plugin/context references needed to emit the log entry, and
//! exposes a [`fire`](DeferredTransactionLogger::fire) method that the
//! response body wrapper invokes on completion or error. A `Drop` safety
//! net ensures the log still fires if the body is dropped without
//! completing (e.g. hyper cancelled the connection after headers flushed).
//!
//! The logger is single-fire (guarded by `AtomicBool` CAS) so a normal
//! body-complete fire and the Drop safety net can never both emit.

use std::sync::Arc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;

use crate::plugins::{Plugin, RequestContext, TransactionSummary, log_with_mirror};
use crate::retry::ErrorClass;

/// Observed outcome of a streaming response body.
///
/// Populated by the body wrapper when it reaches a terminal state (all
/// frames sent, backend error, client disconnect) and passed to
/// [`DeferredTransactionLogger::fire`] so the log entry reflects the
/// actual client-visible outcome rather than the value at header-flush time.
#[derive(Debug, Clone)]
pub struct BodyOutcome {
    /// True when the body finished sending all frames to hyper without error.
    pub body_completed: bool,
    /// Classification of a streaming error, if any. `None` for successful
    /// completion and for client-disconnect cases where the underlying body
    /// never yielded an error frame.
    pub body_error_class: Option<ErrorClass>,
    /// Total bytes of body data passed to hyper for the client.
    pub bytes_streamed: u64,
    /// True when the body did not complete because the client stopped
    /// consuming. Also true for the `Drop` safety-net path.
    pub client_disconnected: bool,
    /// Terminal gRPC application status observed in trailers. This remains
    /// separate from the HTTP response status because gRPC application
    /// failures normally complete under HTTP 200.
    pub grpc_status: Option<u32>,
}

impl BodyOutcome {
    /// Construct an outcome representing successful body completion.
    pub fn success(bytes_streamed: u64) -> Self {
        Self {
            body_completed: true,
            body_error_class: None,
            bytes_streamed,
            client_disconnected: false,
            grpc_status: None,
        }
    }

    /// Construct an outcome representing a streaming error. The body
    /// partially streamed before failing, so `bytes_streamed` may be > 0.
    pub fn error(class: ErrorClass, bytes_streamed: u64, client_disconnected: bool) -> Self {
        Self {
            body_completed: false,
            body_error_class: Some(class),
            bytes_streamed,
            client_disconnected,
            grpc_status: None,
        }
    }

    /// Construct an outcome representing a client disconnect detected via
    /// the `Drop` safety net (no explicit error frame observed).
    pub fn client_disconnect(bytes_streamed: u64) -> Self {
        Self {
            body_completed: false,
            body_error_class: Some(ErrorClass::ClientDisconnect),
            bytes_streamed,
            client_disconnected: true,
            grpc_status: None,
        }
    }

    pub fn with_grpc_status(mut self, grpc_status: Option<u32>) -> Self {
        self.grpc_status = grpc_status;
        self
    }
}

pub async fn run_response_stream_termination_hooks(
    plugins: &[Arc<dyn Plugin>],
    ctx: &mut RequestContext,
    response_status: u16,
    outcome: &BodyOutcome,
) {
    // These hooks finalize gateway-owned stream state after the client-visible
    // body has terminated. In particular, a deadline-expired stream still
    // needs its inspector aggregate, termination hook, and transaction log.
    // Reusing the client deadline here would make timed-out traffic vanish
    // from exactly the cleanup/observability path meant to record it.
    crate::plugins::wait_for_response_stream_inspector(ctx).await;
    for deferred in [false, true] {
        for plugin in plugins.iter().filter(|plugin| {
            plugin.defers_response_stream_termination_until_after_peers() == deferred
        }) {
            plugin
                .on_response_stream_terminated(ctx, response_status, outcome)
                .await;
        }
    }
    crate::plugins::clear_response_stream_inspector_state(ctx);
}

/// Logger that defers a `log_with_mirror()` call until the response body
/// reaches a terminal state. Clone-friendly via [`Arc`].
///
/// Single-fire: the first call to [`fire`](Self::fire) wins; subsequent
/// calls (e.g. a Drop safety net running after an explicit fire) are no-ops.
pub struct DeferredTransactionLogger {
    state: Mutex<Option<LogState>>,
    fired: AtomicBool,
    // Test-only owned delivery lifecycle. Production paths leave this unset and
    // dispatch through the process-global structured lifecycle.
    #[cfg(test)]
    delivery: Option<crate::observability_delivery::OwnedDeliveryLifecycle>,
}

/// Captured log state. Held inside a [`Mutex`] so [`fire`](DeferredTransactionLogger::fire)
/// can `take()` it and move it into the spawned log task. After the first fire
/// the slot is `None`, but the `fired` CAS already prevents a second fire so
/// the `None` state is only visible to no-op callers.
struct LogState {
    summary: TransactionSummary,
    plugins: Arc<Vec<Arc<dyn Plugin>>>,
    ctx: RequestContext,
    /// Request start instant captured by the handler when it first sees the
    /// request. Used at fire time to re-derive `latency_total_ms` so
    /// streaming responses report the wall-clock duration from request
    /// receipt to body completion, not the snapshot value captured when
    /// response headers were flushed. `None` on callers that did not
    /// thread a start time in — in that case the existing
    /// `latency_total_ms` value (captured at summary construction) is
    /// preserved.
    start_time: Option<Instant>,
}

impl DeferredTransactionLogger {
    /// Build a new deferred logger without a start-time reference.
    ///
    /// When constructed via this method, `fire` preserves the
    /// `latency_total_ms` / `latency_gateway_processing_ms` /
    /// `latency_gateway_overhead_ms` values captured at summary construction
    /// time. Prefer [`new_with_start_time`](Self::new_with_start_time) for
    /// streaming-response paths so those latencies reflect the real body
    /// completion time, not the header-flush snapshot.
    ///
    /// Retained as public API surface for external callers (tests and future
    /// non-streaming deferred-log sites). The production HTTP/gRPC streaming
    /// paths use `new_with_start_time` exclusively.
    #[allow(dead_code)]
    pub fn new(
        summary: TransactionSummary,
        plugins: Arc<Vec<Arc<dyn Plugin>>>,
        ctx: RequestContext,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Some(LogState {
                summary,
                plugins,
                ctx,
                start_time: None,
            })),
            fired: AtomicBool::new(false),
            #[cfg(test)]
            delivery: None,
        })
    }

    /// Build a new deferred logger with a start-time anchor.
    ///
    /// At fire time, `fire_once` re-derives `latency_total_ms` from
    /// `start_time.elapsed()` so the summary reflects the wall-clock time
    /// from request receipt to body completion. This closes the
    /// latency-accuracy gap for streaming responses where the summary was
    /// built with header-flush-time latencies but log-with-mirror fires
    /// once the body has actually drained.
    ///
    /// Backend TTFB, plugin execution, and plugin external IO latencies are
    /// preserved as captured (they are defined by events that happen before
    /// the body streams). Backend total latency is likewise left untouched —
    /// for streaming responses the body drives that counter, not the deferred
    /// logger, and [`crate::plugins::LATENCY_UNKNOWN_MS`] remains a meaningful
    /// "no separable backend-total observation" signal.
    ///
    /// Gateway processing and overhead are refreshed via
    /// [`TransactionSummary::refresh_gateway_latencies`]: when backend total
    /// is unknown they stay at [`crate::plugins::LATENCY_UNKNOWN_MS`] instead
    /// of treating TTFB as full backend duration (which would misattribute
    /// streamed body lifetime as gateway work).
    pub fn new_with_start_time(
        summary: TransactionSummary,
        plugins: Arc<Vec<Arc<dyn Plugin>>>,
        ctx: RequestContext,
        start_time: Instant,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Some(LogState {
                summary,
                plugins,
                ctx,
                start_time: Some(start_time),
            })),
            fired: AtomicBool::new(false),
            #[cfg(test)]
            delivery: None,
        })
    }

    /// Fire the deferred log with the given outcome. Only the first call
    /// takes effect; subsequent calls return immediately.
    ///
    /// The actual `log_with_mirror` invocation is performed on a spawned
    /// tokio task so this function does not block hyper's poll loop or a
    /// `Drop` handler. When no tokio runtime is available (process
    /// shutdown), the log is dropped silently — there is no I/O we could
    /// do from outside a runtime anyway.
    pub fn fire(&self, outcome: BodyOutcome) {
        // Single-fire semantics: AcqRel so the winner sees prior writes
        // and the loser sees our take() of state.
        if self
            .fired
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        self.fire_once(outcome);
    }

    fn fire_once(&self, outcome: BodyOutcome) {
        let state = match self.state.lock() {
            Ok(mut guard) => guard.take(),
            // A poisoned mutex means another thread panicked while holding
            // the guard. The state is still valid data, so recover it and
            // proceed — losing a log entry is worse than propagating poison.
            Err(poisoned) => poisoned.into_inner().take(),
        };
        let Some(state) = state else {
            return;
        };
        let LogState {
            mut summary,
            plugins,
            mut ctx,
            start_time,
        } = state;
        summary.body_completed = outcome.body_completed;
        summary.body_error_class = outcome.body_error_class;
        summary.client_disconnected = outcome.client_disconnected;
        // Streaming responses only learn their final byte count when the
        // body wrapper finishes or is dropped. Buffered responses populate
        // `bytes_received` synchronously and never reach the deferred logger.
        summary.bytes_received = outcome.bytes_streamed;
        if let Some(grpc_status) = outcome.grpc_status {
            ctx.metadata
                .insert("grpc_status".to_string(), grpc_status.to_string());
        } else if summary
            .metadata
            .get("request_protocol")
            .or_else(|| ctx.metadata.get("request_protocol"))
            .is_some_and(|protocol| protocol == "grpc")
        {
            // A gRPC stream that ends without terminal status is UNKNOWN, not
            // an unqualified successful HTTP 200. Preserve a Trailers-Only
            // header status when one was captured; otherwise seed code 2.
            ctx.metadata
                .entry("grpc_status".to_string())
                .or_insert_with(|| crate::proxy::grpc_proxy::grpc_status::UNKNOWN.to_string());
        }

        // Re-derive wall-clock total so streaming responses report the real
        // body-completion time instead of the header-flush snapshot.
        //
        // Only applied when the caller threaded a start time in via
        // `new_with_start_time`. Gateway fields follow
        // `TransactionSummary::refresh_gateway_latencies` so an unknown
        // streaming backend total never inflates gateway overhead via TTFB
        // substitution.
        if let Some(start) = start_time {
            summary.latency_total_ms = start.elapsed().as_secs_f64() * 1000.0;
            summary.refresh_gateway_latencies();
        }

        let task = async move {
            let response_status = summary.response_status_code;
            run_response_stream_termination_hooks(
                plugins.as_slice(),
                &mut ctx,
                response_status,
                &outcome,
            )
            .await;
            // The summary skeleton is captured when response headers are
            // committed, but streamed inspectors only know their aggregate
            // decision at body termination. Refresh metadata after the
            // mutable terminal hooks so every log sink sees the finalized
            // per-request values.
            summary.metadata = crate::proxy::clone_log_metadata(&ctx);
            log_with_mirror(plugins.as_slice(), &summary, &ctx).await;
        };
        #[cfg(test)]
        if let Some(delivery) = self.delivery.as_ref() {
            // Owned test lifecycles stay open for the suite; a false return is
            // a test harness bug, not production admission-closed behavior.
            assert!(
                delivery.spawn_terminal(task),
                "owned delivery lifecycle must admit deferred terminal log tasks"
            );
            return;
        }
        let _ = crate::observability_delivery::spawn_terminal(task);
    }
}

impl Drop for DeferredTransactionLogger {
    fn drop(&mut self) {
        // Safety net: if the body was dropped without explicitly firing
        // (e.g. hyper cancelled the connection mid-stream), emit a log
        // entry classified as a client disconnect. Bytes streamed default
        // to 0 because we cannot access the body's atomic counter from here
        // — callers that care about partial-byte accuracy should call
        // `fire` explicitly with the observed count.
        if !self.fired.swap(true, Ordering::AcqRel) {
            self.fire_once(BodyOutcome::client_disconnect(0));
        }
    }
}

#[cfg(test)]
impl DeferredTransactionLogger {
    /// Bind terminal dispatch to an owned lifecycle for deterministic unit tests.
    fn with_owned_delivery(
        delivery: crate::observability_delivery::OwnedDeliveryLifecycle,
        summary: TransactionSummary,
        plugins: Arc<Vec<Arc<dyn Plugin>>>,
        ctx: RequestContext,
        start_time: Option<Instant>,
    ) -> Arc<Self> {
        Arc::new(Self {
            state: Mutex::new(Some(LogState {
                summary,
                plugins,
                ctx,
                start_time,
            })),
            fired: AtomicBool::new(false),
            delivery: Some(delivery),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::observability_delivery::OwnedDeliveryLifecycle;
    use std::sync::atomic::AtomicUsize;
    use std::time::Duration;

    async fn drain(delivery: &OwnedDeliveryLifecycle) {
        assert!(
            delivery.drain_tasks(Duration::from_secs(1)).await,
            "owned delivery lifecycle must drain deferred log tasks"
        );
    }

    fn test_logger(
        delivery: &OwnedDeliveryLifecycle,
        summary: TransactionSummary,
        plugins: Arc<Vec<Arc<dyn Plugin>>>,
        ctx: RequestContext,
    ) -> Arc<DeferredTransactionLogger> {
        DeferredTransactionLogger::with_owned_delivery(
            delivery.clone(),
            summary,
            plugins,
            ctx,
            None,
        )
    }

    fn test_logger_with_start_time(
        delivery: &OwnedDeliveryLifecycle,
        summary: TransactionSummary,
        plugins: Arc<Vec<Arc<dyn Plugin>>>,
        ctx: RequestContext,
        start_time: Instant,
    ) -> Arc<DeferredTransactionLogger> {
        DeferredTransactionLogger::with_owned_delivery(
            delivery.clone(),
            summary,
            plugins,
            ctx,
            Some(start_time),
        )
    }

    #[tokio::test]
    async fn fire_is_single_shot() {
        let delivery = OwnedDeliveryLifecycle::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> =
            Arc::new(vec![Arc::new(CountingPlugin(counter.clone()))]);
        let ctx = RequestContext::new("1.2.3.4".to_string(), "GET".to_string(), "/".to_string());
        let summary = fake_summary();

        let logger = test_logger(&delivery, summary, plugins, ctx);
        logger.fire(BodyOutcome::success(42));
        logger.fire(BodyOutcome::success(1_000_000));

        drain(&delivery).await;
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn drop_safety_net_fires_when_never_fired() {
        let delivery = OwnedDeliveryLifecycle::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> =
            Arc::new(vec![Arc::new(CountingPlugin(counter.clone()))]);
        let ctx = RequestContext::new("1.2.3.4".to_string(), "GET".to_string(), "/".to_string());
        let logger = test_logger(&delivery, fake_summary(), plugins, ctx);
        drop(logger);

        drain(&delivery).await;
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    #[tokio::test]
    async fn fire_patches_bytes_received_from_outcome() {
        // Regression guard for the unified bytes_received field. When
        // fire() fires with a streaming outcome carrying N bytes,
        // `bytes_received` should land at N.
        let delivery = OwnedDeliveryLifecycle::new();
        let captured = Arc::new(Mutex::new(None::<TransactionSummary>));
        let capturer: Arc<dyn Plugin> = Arc::new(CapturingPlugin(captured.clone()));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![capturer]);
        let ctx = RequestContext::new("1.2.3.4".to_string(), "GET".to_string(), "/".to_string());
        let logger = test_logger(&delivery, fake_summary(), plugins, ctx);
        logger.fire(BodyOutcome::success(12345));
        drain(&delivery).await;

        let summary = captured.lock().unwrap().clone().expect("log fired");
        assert_eq!(summary.bytes_received, 12345);
        assert!(summary.body_completed);
    }

    #[tokio::test]
    async fn fire_patches_terminal_grpc_status_from_trailers() {
        let delivery = OwnedDeliveryLifecycle::new();
        let captured = Arc::new(Mutex::new(None::<TransactionSummary>));
        let capturer: Arc<dyn Plugin> = Arc::new(CapturingPlugin(captured.clone()));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![capturer]);
        let ctx = RequestContext::new(
            "1.2.3.4".to_string(),
            "POST".to_string(),
            "/rpc".to_string(),
        );
        let logger = test_logger(&delivery, fake_summary(), plugins, ctx);

        logger.fire(BodyOutcome::success(12).with_grpc_status(Some(14)));
        drain(&delivery).await;

        let summary = captured.lock().unwrap().clone().expect("log fired");
        assert_eq!(
            summary.metadata.get("grpc_status").map(String::as_str),
            Some("14")
        );
        assert_eq!(summary.grpc_status(), Some(14));
        assert!(summary.is_terminal_failure());
        assert_eq!(summary.response_status_code, 200);
    }

    #[tokio::test]
    async fn fire_marks_missing_grpc_terminal_status_unknown() {
        let delivery = OwnedDeliveryLifecycle::new();
        let captured = Arc::new(Mutex::new(None::<TransactionSummary>));
        let capturer: Arc<dyn Plugin> = Arc::new(CapturingPlugin(captured.clone()));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![capturer]);
        let mut ctx = RequestContext::new(
            "1.2.3.4".to_string(),
            "POST".to_string(),
            "/rpc".to_string(),
        );
        ctx.metadata
            .insert("request_protocol".to_string(), "grpc".to_string());
        let logger = test_logger(&delivery, fake_summary(), plugins, ctx);

        logger.fire(BodyOutcome::success(0));
        drain(&delivery).await;

        let summary = captured.lock().unwrap().clone().expect("log fired");
        assert_eq!(
            summary.metadata.get("grpc_status").map(String::as_str),
            Some("2")
        );
        assert_eq!(summary.grpc_status(), Some(2));
        assert!(summary.is_terminal_failure());
    }

    #[tokio::test]
    async fn fire_with_start_time_re_derives_latency_total() {
        // Regression guard for the fire_once latency re-derivation. When
        // the logger is constructed via `new_with_start_time`, fire should
        // replace `latency_total_ms` with the wall-clock elapsed from the
        // captured start (not the stale value in the summary).
        let delivery = OwnedDeliveryLifecycle::new();
        let captured = Arc::new(Mutex::new(None::<TransactionSummary>));
        let capturer: Arc<dyn Plugin> = Arc::new(CapturingPlugin(captured.clone()));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![capturer]);
        let ctx = RequestContext::new("1.2.3.4".to_string(), "GET".to_string(), "/".to_string());

        // Summary captured at "header flush" time has latency_total_ms=1.0,
        // latency_plugin_execution_ms=0.5, latency_backend_ttfb_ms=0.8.
        let mut summary = fake_summary();
        summary.latency_total_ms = 1.0;
        summary.latency_plugin_execution_ms = 0.5;
        summary.latency_backend_ttfb_ms = 0.8;
        summary.latency_backend_total_ms = -1.0; // streaming sentinel
        summary.response_streamed = true;
        summary.latency_gateway_processing_ms = -1.0;
        summary.latency_gateway_overhead_ms = -1.0;

        let start = Instant::now();
        let logger = test_logger_with_start_time(&delivery, summary, plugins, ctx, start);

        // Simulate 50ms of body streaming before the logger fires.
        tokio::time::sleep(Duration::from_millis(50)).await;
        logger.fire(BodyOutcome::success(999));
        drain(&delivery).await;

        let observed = captured.lock().unwrap().clone().expect("log fired");
        // latency_total_ms should reflect the ~50ms body-streaming window,
        // well above the original 1.0ms. Drain no longer adds a post-fire
        // sleep, so keep the floor aligned to the simulated stream delay.
        assert!(
            observed.latency_total_ms >= 40.0,
            "expected re-derived total >= 40ms, got {}",
            observed.latency_total_ms
        );
        // Unknown streaming backend total must not inflate gateway fields via
        // TTFB substitution — both stay at the shared unknown sentinel.
        assert_eq!(observed.latency_gateway_processing_ms, -1.0);
        assert_eq!(observed.latency_gateway_overhead_ms, -1.0);
        assert_eq!(observed.latency_backend_total_ms, -1.0);
        // Fields unrelated to the re-derivation are preserved.
        assert_eq!(observed.latency_backend_ttfb_ms, 0.8);
        assert_eq!(observed.latency_plugin_execution_ms, 0.5);
    }

    #[tokio::test]
    async fn fire_without_start_time_preserves_original_latency() {
        // Regression guard for the non-streaming path. When the logger is
        // constructed via `new` (no start time), fire must NOT touch the
        // latency fields — buffered responses have exact latencies baked in
        // at summary construction time.
        let delivery = OwnedDeliveryLifecycle::new();
        let captured = Arc::new(Mutex::new(None::<TransactionSummary>));
        let capturer: Arc<dyn Plugin> = Arc::new(CapturingPlugin(captured.clone()));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> = Arc::new(vec![capturer]);
        let ctx = RequestContext::new("1.2.3.4".to_string(), "GET".to_string(), "/".to_string());

        let mut summary = fake_summary();
        summary.latency_total_ms = 42.0;
        summary.latency_backend_total_ms = 37.0;
        summary.latency_gateway_processing_ms = 5.0;
        summary.latency_gateway_overhead_ms = 3.0;

        let logger = test_logger(&delivery, summary, plugins, ctx);
        logger.fire(BodyOutcome::success(100));
        drain(&delivery).await;

        let observed = captured.lock().unwrap().clone().expect("log fired");
        assert_eq!(observed.latency_total_ms, 42.0);
        assert_eq!(observed.latency_backend_total_ms, 37.0);
        assert_eq!(observed.latency_gateway_processing_ms, 5.0);
        assert_eq!(observed.latency_gateway_overhead_ms, 3.0);
    }

    struct CapturingPlugin(Arc<Mutex<Option<TransactionSummary>>>);

    #[async_trait::async_trait]
    impl Plugin for CapturingPlugin {
        fn name(&self) -> &str {
            "capturing"
        }

        fn priority(&self) -> u16 {
            9000
        }

        async fn log(&self, summary: &TransactionSummary) {
            *self.0.lock().unwrap() = Some(summary.clone());
        }
    }

    #[tokio::test]
    async fn drop_after_explicit_fire_does_not_double_log() {
        let delivery = OwnedDeliveryLifecycle::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> =
            Arc::new(vec![Arc::new(CountingPlugin(counter.clone()))]);
        let ctx = RequestContext::new("1.2.3.4".to_string(), "GET".to_string(), "/".to_string());
        let logger = test_logger(&delivery, fake_summary(), plugins, ctx);
        logger.fire(BodyOutcome::success(10));
        drop(logger);

        drain(&delivery).await;
        assert_eq!(counter.load(Ordering::Relaxed), 1);
    }

    /// Stress the `AcqRel` CAS guard that makes `fire()` + Drop single-shot.
    ///
    /// For each of `N` loggers, two tokio tasks race:
    ///
    /// * Task A: calls `logger.fire(BodyOutcome::success(...))`.
    /// * Task B: drops its `Arc` clone of the logger, triggering the Drop
    ///   safety net on the last reference.
    ///
    /// The plugin registered on every logger increments a single shared
    /// counter each time `log()` is invoked. After all tasks join, the
    /// counter must equal exactly `N` — one `log()` per logger, regardless
    /// of whether the fire() arm or the Drop arm won the CAS. A value of
    /// `2*N` would indicate a double-fire (CAS bug); less than `N` would
    /// indicate a lost fire (e.g. taking the state twice via a non-atomic
    /// path).
    ///
    /// A `tokio::sync::Barrier` gates both tasks until all `2*N` tasks are
    /// ready, maximising contention on the CAS. The test runs on the
    /// multi-thread runtime so tasks can execute on different threads.
    ///
    /// All `N` loggers share one owned delivery lifecycle so the concurrent
    /// suite stays lightweight while remaining independent of the
    /// process-global singleton.
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_fire_and_drop_is_single_shot() {
        const N: usize = 500;

        let delivery = OwnedDeliveryLifecycle::new();
        let counter = Arc::new(AtomicUsize::new(0));
        let plugins: Arc<Vec<Arc<dyn Plugin>>> =
            Arc::new(vec![Arc::new(CountingPlugin(counter.clone()))]);

        // Gate all tasks so they launch their CAS race simultaneously.
        // 2*N tasks per logger (fire + drop) + 1 for the main task's wait.
        let barrier = Arc::new(tokio::sync::Barrier::new(2 * N));

        let mut handles = Vec::with_capacity(2 * N);

        for _ in 0..N {
            let ctx =
                RequestContext::new("1.2.3.4".to_string(), "GET".to_string(), "/".to_string());
            let logger = test_logger(&delivery, fake_summary(), plugins.clone(), ctx);

            // Two Arc clones — one for each task. Dropping the last clone
            // triggers the Drop safety net.
            let logger_fire = logger.clone();
            let logger_drop = logger; // last clone

            let barrier_fire = barrier.clone();
            let barrier_drop = barrier.clone();

            handles.push(tokio::spawn(async move {
                barrier_fire.wait().await;
                logger_fire.fire(BodyOutcome::success(1));
            }));
            handles.push(tokio::spawn(async move {
                barrier_drop.wait().await;
                drop(logger_drop);
            }));
        }

        for h in handles {
            h.await.unwrap();
        }

        drain(&delivery).await;

        let observed = counter.load(Ordering::Relaxed);
        assert_eq!(
            observed, N,
            "each logger must fire exactly once under concurrent fire/drop; \
             observed {} of {} expected",
            observed, N
        );
    }

    fn fake_summary() -> TransactionSummary {
        TransactionSummary {
            namespace: "ferrum".to_string(),
            timestamp_received: "2026-01-01T00:00:00Z".to_string(),
            client_ip: "1.2.3.4".to_string(),
            http_method: "GET".to_string(),
            request_path: "/".to_string(),
            response_status_code: 200,
            latency_backend_total_ms: -1.0,
            response_streamed: true,
            ..TransactionSummary::default()
        }
    }

    struct CountingPlugin(Arc<AtomicUsize>);

    #[async_trait::async_trait]
    impl Plugin for CountingPlugin {
        fn name(&self) -> &str {
            "counting"
        }

        fn priority(&self) -> u16 {
            9000
        }

        async fn log(&self, _summary: &TransactionSummary) {
            self.0.fetch_add(1, Ordering::Relaxed);
        }
    }
}
