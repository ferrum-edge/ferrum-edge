//! Proxy response body type that supports both buffered and streaming modes.
//!
//! [`ProxyBody`] is a sum type over [`Full<Bytes>`] (buffered) and a boxed
//! streaming body. The buffered variant is zero-cost (no allocation beyond
//! the data itself); the streaming variant allocates one `Box` to erase the
//! concrete stream type.

use bytes::{Bytes, BytesMut};
use http::HeaderMap;
use http_body::Frame;
use http_body_util::Full;
use hyper::body::Incoming;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tracing::debug;

use crate::plugins::BackendAdmissionOutcome;
use crate::proxy::grpc_proxy::{
    GATEWAY_DEADLINE_EXCEEDED_MESSAGE, GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER,
    GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER,
};
use crate::retry::ErrorClass;

pub type ProxyBodyError = Box<dyn std::error::Error + Send + Sync>;

pub(crate) type BoxError = ProxyBodyError;

/// A response body that is either fully buffered or streamed from the backend.
///
/// Optionally carries a [`RequestGuard`] that keeps the `active_requests`
/// overload counter incremented for the lifetime of the response body — not
/// just the handler function scope. This is critical for H2/H3/gRPC streaming
/// responses where hyper drives the body to completion *after*
/// `handle_proxy_request` returns.
///
/// Optionally also carries a [`DeferredTransactionLogger`] that fires
/// `log_with_mirror` when the body reaches a terminal state — success
/// (Ready(None)), streaming error (Ready(Some(Err))), or Drop safety net
/// (client disconnected before completion). `bytes_streamed` is
/// tracked via an atomic counter incremented on each data frame.
pub struct ProxyBody {
    kind: ProxyBodyKind,
    /// Dropped when hyper finishes sending the body (or the connection closes),
    /// decrementing `OverloadState.active_requests`.
    _request_guard: Option<crate::overload::RequestGuard>,
    /// Dropped when a reqwest-backed response body finishes, so the
    /// runtime port-pressure estimate tracks streaming backend sockets too.
    _reqwest_backend_guard: Option<crate::runtime_metrics::ReqwestBackendRequestGuard>,
    /// Dropped when the client-visible response body finishes, decrementing
    /// per-IP in-flight request accounting.
    _per_ip_request_guard: Option<super::PerIpRequestGuard>,
    /// Dropped when a streaming backend response body reaches terminal state
    /// (EOF, error, or client disconnect), ensuring least-connections
    /// accounting decrements when the backend stream actually ends.
    _lb_connection_guard: Option<super::LoadBalancerConnectionGuard>,
    /// Dropped when the client-visible response body finishes, releasing
    /// backend-admission slots such as adaptive concurrency permits.
    _backend_admission_permits: Option<crate::plugins::BackendAdmissionPermitSet>,
    backend_admission_outcome: Option<DeferredBackendAdmissionOutcome>,
    backend_dispatch_outcome: Option<DeferredBackendDispatchOutcome>,
    /// Set by absolute client-RPC deadline wrappers when they synthesize the
    /// terminal deadline frame (or abort after partial DATA). Deferred backend
    /// accounting uses this signal to keep a client-chosen expiry neutral.
    client_grpc_deadline_fired: Option<Arc<AtomicBool>>,
    /// Deferred logger that fires after body completion, allowing
    /// `TransactionSummary.body_completed` / `body_error_class` /
    /// `client_disconnected` / `bytes_streamed` to reflect the
    /// client-visible outcome rather than values at header-flush time.
    logger: Option<Arc<crate::proxy::deferred_log::DeferredTransactionLogger>>,
    /// Monotonic byte count streamed to the client. Updated on each
    /// successful data frame when a deferred logger is attached or a drop-time
    /// declared-length success hint needs it. Otherwise the counter has no
    /// consumer, so the hot path skips the atomic RMW. Read when firing the
    /// deferred logger (on success, streaming error, or Drop
    /// client-disconnect safety net) and when evaluating
    /// `success_on_drop_after_bytes`.
    ///
    /// **Counting invariant**: bytes are counted ONCE per outer frame at this
    /// `ProxyBody::poll_frame` site, never on inner adapter frames and never
    /// on buffer drain. If a future change adds metrics to `CoalescingH2Body`,
    /// `CoalescingH3Body`, `DirectH2Body`, or `DirectH3Body`, those inner
    /// adapters MUST count bytes only on receipt from the backend (never on
    /// the flush side of the coalescing buffer). Double-counting on drain
    /// inflates `bytes_streamed` / `bytes_received` by the
    /// coalescing overlap — matches the design rule preserved from the
    /// original deferred-log investigation.
    bytes_streamed: AtomicU64,
    /// Treat Drop after exactly this many yielded response-body DATA bytes as a
    /// successful backend body completion instead of a client disconnect. Used
    /// for native H3 responses with a trusted `Content-Length` on an HTTP/1.x
    /// downstream: hyper may stop polling once the client receives the declared
    /// byte count, before the H3 source yields its terminal FIN/trailer poll.
    /// Partial or overlong bodies still fall through to the normal
    /// disconnect/error classification.
    success_on_drop_after_bytes: Option<u64>,
    /// Whether `poll_frame` was ever called. Used by the `Drop` safety net
    /// to distinguish "hyper decided not to stream this body" (HEAD / 204 /
    /// zero-length responses where hyper drops without polling) from "hyper
    /// abandoned us mid-stream" (client disconnect). Never polled == success,
    /// polled-but-not-completed == client_disconnect. `is_end_stream()`
    /// cannot be used as the success signal because streaming wrappers may
    /// still report `false` before their terminal poll even when the stream
    /// will complete successfully on the next wake. Cheap — one atomic RMW
    /// on the first poll per body, zero cost thereafter.
    polled: AtomicBool,
    /// Unread frontend gRPC upload retained across a synthesized Trailers-Only
    /// gateway error (#2057). With the pinned h2 0.4.x transport, response
    /// HEADERS are already serialized before the permitted NO_ERROR request
    /// cancellation; retaining the upload couples its lifetime to the response
    /// body as defense-in-depth rather than claiming a stronger wire-order
    /// guarantee. Raw clients must still accept that legal residual reset after
    /// an explicit Trailers-Only `grpc-status`.
    /// Boxed so this rare error-path hold remains pointer-sized on every
    /// ordinary response body. `GrpcBody` contains an `Incoming` or mpsc
    /// receiver and must not inflate the proxy hot-path response envelope.
    _held_frontend_grpc_upload: Option<Box<crate::proxy::grpc_proxy::GrpcBody>>,
}

#[derive(Clone)]
struct DeferredBackendAdmissionOutcome {
    response_status: u16,
    backend_elapsed: Duration,
    /// Set on the gRPC fully-streaming path: a late client-upload overflow
    /// (`> max_grpc_recv_size_bytes`) RSTs the backend response stream after
    /// headers, surfacing as a body error. That is a client/gateway-side size
    /// violation, not a backend fault, so when this flag has tripped the limiter
    /// outcome is forced to `RequestBodyTooLarge` (which the limiter ignores)
    /// rather than letting the body error shrink the limit.
    request_body_exceeded: Option<Arc<std::sync::atomic::AtomicBool>>,
    /// gRPC streaming responses finish HTTP 200 and carry the real outcome in a
    /// `grpc-status` trailer. When set, `poll_frame` inspects forwarded trailer
    /// frames and records the HTTP-mapped status of a non-OK gRPC status into
    /// `grpc_trailer_http_status`, so a backend gRPC failure (e.g. 14 -> 503)
    /// shrinks the limit instead of recording a healthy success at EOF.
    classify_grpc_trailer: bool,
    grpc_trailer_http_status: Option<u16>,
}

/// Notified when a gRPC streaming RESPONSE body reaches its terminal state, with
/// the same `(response_status, connection_error, error_class)` the deferred
/// backend-dispatch outcome would record. Implemented by the gRPC streaming probe
/// recorder (`proxy::mod`), which owns the circuit-breaker outcome and settles it
/// at the join of response completion + request-upload termination (#1649 item 3)
/// — recording a failure promptly but deferring a clean success until upload
/// termination so a late client-upload overflow cannot falsely heal the breaker.
pub(crate) trait GrpcResponseTerminalObserver: Send + Sync {
    fn on_response_terminal(
        &self,
        response_status: u16,
        connection_error: bool,
        error_class: Option<ErrorClass>,
    );
}

struct DeferredBackendDispatchOutcome {
    state: Arc<super::ProxyState>,
    proxy: Arc<crate::config::types::Proxy>,
    lb_snapshot: Arc<crate::load_balancer::LoadBalancerCacheInner>,
    selected_balancer: Option<Arc<crate::load_balancer::LoadBalancer>>,
    upstream_target: Option<Arc<crate::config::types::UpstreamTarget>>,
    final_cb_target_key: Option<String>,
    response_status: u16,
    connection_error: bool,
    error_class: Option<ErrorClass>,
    is_half_open_probe: bool,
    skip_circuit_breaker_record: bool,
    backend_elapsed: Duration,
    request_body_exceeded: Option<Arc<std::sync::atomic::AtomicBool>>,
    classify_grpc_trailer: bool,
    grpc_trailer_http_status: Option<u16>,
    /// gRPC streaming: the recorder that owns the circuit-breaker outcome at the
    /// upload-termination join. When set, the CB is NOT recorded by
    /// `record_backend_outcome_no_conn_end` here (`skip_circuit_breaker_record`
    /// is `true`); instead the terminal `(status, connection_error, error_class)`
    /// is handed to the recorder, which settles the breaker.
    grpc_response_observer: Option<Arc<dyn GrpcResponseTerminalObserver>>,
    /// Direct-H2/HBONE: the breaker's open generation captured at admission. When
    /// `Some`, the deferred CB record is SKIPPED if the breaker has since opened a
    /// new cycle (`open_epoch` advanced) — a stream admitted while the breaker was
    /// CLOSED must not heal/reopen a later HALF_OPEN cycle it never probed (#1649
    /// round-4 B). Passive-health + least-latency still record (per-target, not
    /// per-cycle). `None` on the gRPC path, where the recorder does the check.
    deferred_admission_open_epoch: Option<u64>,
}

/// Inner body variant — buffered, streaming, or tracked-streaming.
enum ProxyBodyKind {
    /// Complete body already in memory.
    Full(Full<Bytes>),
    /// Streaming body passed through without tracking (zero overhead).
    Stream(Pin<Box<dyn http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + 'static>>),
    /// Streaming body with lightweight completion tracking.
    /// Records the timestamp of the last frame via a shared atomic —
    /// no closures, no string cloning, no per-request allocations beyond
    /// a single `Arc<StreamingMetrics>`.
    Tracked(TrackedBody),
}

/// Lightweight metrics shared between a streaming response body and a
/// deferred log task. Only an atomic timestamp and a completion flag —
/// no strings, no closures, no allocations per frame.
///
/// # Atomic ordering discipline
///
/// * `last_frame_nanos` — `Release` on every store (from `TrackedBody::poll_frame`
///   and from `record_bytes_sent`), paired with `Acquire` loads from the
///   observer (`last_frame_elapsed_ms`). `Release`/`Acquire` establishes
///   happens-before so any state the writer produced before the store is
///   visible to a reader that observes the store.
/// * `completed` — `Release` on the single store (from `mark_completed`,
///   or `poll_frame` on `Ready(None)`), paired with `Acquire` loads from
///   the observer (`completed()`). Same rationale as above.
///
/// `Relaxed` is intentionally NOT used: the observer typically reads both
/// `last_frame_nanos` and `completed` in sequence to form a coherent
/// "completion snapshot," and `Release`/`Acquire` ensures the reader sees
/// both values as a consistent pair.
pub struct StreamingMetrics {
    /// Reference `Instant` — stored once at creation. The atomic stores
    /// elapsed nanos relative to this baseline to avoid u64 overflow.
    baseline: Instant,
    /// Elapsed nanos from `baseline` when the last frame was sent (or 0
    /// if no frame has been sent yet).
    last_frame_nanos: AtomicU64,
    /// Whether the body completed successfully (all frames sent).
    completed: AtomicBool,
}

impl StreamingMetrics {
    pub fn new(baseline: Instant) -> Self {
        Self {
            baseline,
            last_frame_nanos: AtomicU64::new(0),
            completed: AtomicBool::new(false),
        }
    }

    /// Total elapsed milliseconds from baseline to the last frame, or `None`
    /// if no frame was ever sent.
    pub fn last_frame_elapsed_ms(&self) -> Option<f64> {
        let nanos = self.last_frame_nanos.load(Ordering::Acquire);
        if nanos == 0 {
            None
        } else {
            Some(nanos as f64 / 1_000_000.0)
        }
    }

    /// Whether the body finished sending all frames (vs client disconnect / drop).
    pub fn completed(&self) -> bool {
        self.completed.load(Ordering::Acquire)
    }
}

/// A streaming body wrapper that records completion timing via a shared
/// `Arc<StreamingMetrics>`. Cost per frame: one `Instant::now()` +
/// one atomic store. No closures, no string cloning, no `tokio::spawn`.
pub struct TrackedBody {
    inner: Pin<Box<dyn http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + 'static>>,
    metrics: Arc<StreamingMetrics>,
}

impl TrackedBody {
    pub fn new(
        inner: Pin<Box<dyn http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + 'static>>,
        metrics: Arc<StreamingMetrics>,
    ) -> Self {
        Self { inner, metrics }
    }
}

impl http_body::Body for TrackedBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match this.inner.as_mut().poll_frame(cx) {
            Poll::Ready(None) => {
                // Body complete — record final timestamp
                let elapsed = this.metrics.baseline.elapsed().as_nanos() as u64;
                this.metrics
                    .last_frame_nanos
                    .store(elapsed, Ordering::Release);
                this.metrics.completed.store(true, Ordering::Release);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                // Frame sent — update last-frame timestamp (one atomic store)
                let elapsed = this.metrics.baseline.elapsed().as_nanos() as u64;
                this.metrics
                    .last_frame_nanos
                    .store(elapsed, Ordering::Release);
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

/// Buffered gRPC response body that preserves wire trailers.
///
/// The proxy may need the full gRPC response body in memory for body plugins or
/// `response_body_mode = Buffer`, but a non-empty gRPC response must still end
/// with an HTTP/2 trailers frame carrying `grpc-status`. `Full<Bytes>` cannot
/// emit that terminal frame, so this tiny body yields the buffered DATA once,
/// then the sanitized trailers collected from the backend.
struct BufferedGrpcBody {
    data: Option<Bytes>,
    trailers: Option<HeaderMap>,
}

impl BufferedGrpcBody {
    fn new(data: Bytes, trailers: HeaderMap) -> Self {
        Self {
            data: Some(data),
            trailers: Some(trailers),
        }
    }
}

impl http_body::Body for BufferedGrpcBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if let Some(data) = this.data.take()
            && !data.is_empty()
        {
            return Poll::Ready(Some(Ok(Frame::data(data))));
        }
        if let Some(trailers) = this.trailers.take() {
            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
        }
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.data.is_none() && self.trailers.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        let mut hint = http_body::SizeHint::new();
        let len = self.data.as_ref().map_or(0, Bytes::len) as u64;
        hint.set_exact(len);
        hint
    }
}

/// Immediately-EOF body that never advertises an exact length.
///
/// Used for HTTP 205 responses so Hyper does not synthesize
/// `Content-Length: 0` the way it does for ordinary empty `Full` bodies.
struct EmptyUnknownLengthBody {
    done: bool,
}

impl http_body::Body for EmptyUnknownLengthBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.done = true;
        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        self.done
    }

    fn size_hint(&self) -> http_body::SizeHint {
        http_body::SizeHint::new()
    }
}

impl ProxyBody {
    /// Create a buffered body from bytes.
    pub fn full(data: impl Into<Bytes>) -> Self {
        Self {
            kind: ProxyBodyKind::Full(Full::new(data.into())),
            _request_guard: None,
            _reqwest_backend_guard: None,
            _per_ip_request_guard: None,
            _lb_connection_guard: None,
            _backend_admission_permits: None,
            backend_admission_outcome: None,
            backend_dispatch_outcome: None,
            client_grpc_deadline_fired: None,
            logger: None,
            bytes_streamed: AtomicU64::new(0),
            success_on_drop_after_bytes: None,
            polled: AtomicBool::new(false),
            _held_frontend_grpc_upload: None,
        }
    }

    /// Create a buffered body from a string slice.
    pub fn from_string(s: &str) -> Self {
        Self::full(Bytes::from(s.to_string()))
    }

    /// Create an empty body.
    pub fn empty() -> Self {
        Self {
            kind: ProxyBodyKind::Full(Full::default()),
            _request_guard: None,
            _reqwest_backend_guard: None,
            _per_ip_request_guard: None,
            _lb_connection_guard: None,
            _backend_admission_permits: None,
            backend_admission_outcome: None,
            backend_dispatch_outcome: None,
            client_grpc_deadline_fired: None,
            logger: None,
            bytes_streamed: AtomicU64::new(0),
            success_on_drop_after_bytes: None,
            polled: AtomicBool::new(false),
            _held_frontend_grpc_upload: None,
        }
    }

    /// Empty body for a finalized response status.
    ///
    /// Hyper's HTTP/1 server auto-inserts `Content-Length: 0` for empty
    /// `is_end_stream()` bodies on every status except 204/304 (and 1xx /
    /// successful CONNECT). RFC 9110 forbids content on 205 as well, and
    /// Ferrum's synthetic contract strips `Content-Length` for 204/205/304.
    /// For 205, use an immediately-EOF body with an unknown size hint so
    /// Hyper frames with chunked TE (H1) or END_STREAM without synthesizing
    /// `Content-Length` (H2) instead of advertising `Content-Length: 0`.
    pub fn empty_for_response_status(status: u16) -> Self {
        if status == 205 {
            Self::streaming(Box::pin(EmptyUnknownLengthBody { done: false }))
        } else {
            Self::empty()
        }
    }

    /// Create a buffered gRPC response body that emits DATA followed by
    /// trailers. Callers should use trailers-only headers instead when `data`
    /// is empty.
    pub(crate) fn buffered_grpc_with_trailers(data: impl Into<Bytes>, trailers: HeaderMap) -> Self {
        Self::streaming(Box::pin(BufferedGrpcBody::new(data.into(), trailers)))
    }

    /// Attach a [`RequestGuard`] to this body so the `active_requests`
    /// counter stays incremented until hyper finishes sending the response.
    pub fn with_request_guard(mut self, guard: crate::overload::RequestGuard) -> Self {
        self._request_guard = Some(guard);
        self
    }

    pub fn with_reqwest_backend_guard(
        mut self,
        guard: crate::runtime_metrics::ReqwestBackendRequestGuard,
    ) -> Self {
        self._reqwest_backend_guard = Some(guard);
        self
    }

    /// Retain an unread frontend gRPC upload until this response body is
    /// dropped. This keeps request ownership coupled to the synthesized
    /// Trailers-Only response lifecycle as an H2 defense-in-depth measure;
    /// the client still handles the legal post-response NO_ERROR reset (#2057).
    pub(crate) fn with_held_frontend_grpc_upload(
        mut self,
        upload: crate::proxy::grpc_proxy::GrpcBody,
    ) -> Self {
        self._held_frontend_grpc_upload = Some(Box::new(upload));
        self
    }

    pub(crate) fn with_per_ip_request_guard(mut self, guard: super::PerIpRequestGuard) -> Self {
        self._per_ip_request_guard = Some(guard);
        self
    }

    pub(crate) fn with_lb_connection_guard(
        mut self,
        guard: super::LoadBalancerConnectionGuard,
    ) -> Self {
        self._lb_connection_guard = Some(guard);
        self
    }

    /// Hold the backend-admission permit for the lifetime of a streamed response
    /// body and record its outcome when the body reaches a terminal state.
    ///
    /// `backend_elapsed` is TTFB (captured at header arrival), so the adaptive
    /// limiter's latency signal is TTFB even though the in-flight slot is held
    /// for the full body. Unlike a WebSocket session this slot is still
    /// transient (it frees at body completion), so this deliberately uses the
    /// growth-allowing `record_backend_outcome`, not the holding variant — see
    /// `AdaptiveConcurrencyPermit::record_success_latency`.
    pub(crate) fn with_deferred_backend_admission_outcome(
        mut self,
        permits: crate::plugins::BackendAdmissionPermitSet,
        response_status: u16,
        backend_elapsed: Duration,
    ) -> Self {
        self._backend_admission_permits = Some(permits);
        self.backend_admission_outcome = Some(DeferredBackendAdmissionOutcome {
            response_status,
            backend_elapsed,
            request_body_exceeded: None,
            classify_grpc_trailer: false,
            grpc_trailer_http_status: None,
        });
        self
    }

    /// Enable gRPC trailer classification for the deferred admission outcome:
    /// `poll_frame` will read the `grpc-status` from forwarded trailer frames and
    /// (for a non-OK status) record the HTTP-mapped status so a backend gRPC
    /// failure on a streaming response shrinks the limit instead of recording a
    /// healthy success at EOF. No-op when no deferred admission outcome is set.
    pub(crate) fn with_grpc_trailer_admission_classification(mut self) -> Self {
        if let Some(outcome) = self.backend_admission_outcome.as_mut() {
            outcome.classify_grpc_trailer = true;
        }
        self
    }

    /// Record backend health and load-balancer latency when a streaming response
    /// reaches a terminal state. Connection-end accounting is still owned by
    /// `LoadBalancerConnectionGuard`, so this uses the no-connection-end outcome
    /// path just like HTTP streaming responses.
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn with_deferred_backend_dispatch_outcome(
        mut self,
        state: Arc<super::ProxyState>,
        proxy: Arc<crate::config::types::Proxy>,
        lb_snapshot: Arc<crate::load_balancer::LoadBalancerCacheInner>,
        selected_balancer: Option<Arc<crate::load_balancer::LoadBalancer>>,
        upstream_target: Option<Arc<crate::config::types::UpstreamTarget>>,
        final_cb_target_key: Option<String>,
        response_status: u16,
        connection_error: bool,
        error_class: Option<ErrorClass>,
        is_half_open_probe: bool,
        skip_circuit_breaker_record: bool,
        backend_elapsed: Duration,
    ) -> Self {
        self.backend_dispatch_outcome = Some(DeferredBackendDispatchOutcome {
            state,
            proxy,
            lb_snapshot,
            selected_balancer,
            upstream_target,
            final_cb_target_key,
            response_status,
            connection_error,
            error_class,
            is_half_open_probe,
            skip_circuit_breaker_record,
            backend_elapsed,
            request_body_exceeded: None,
            classify_grpc_trailer: false,
            grpc_trailer_http_status: None,
            grpc_response_observer: None,
            deferred_admission_open_epoch: None,
        });
        self
    }

    /// Tag the deferred backend-dispatch outcome with the breaker's open
    /// generation captured at admission (direct-H2/HBONE #1649 round-4 B). The CB
    /// is skipped at completion if the breaker has since opened a new cycle.
    /// No-op when no deferred dispatch outcome is attached.
    pub(crate) fn with_deferred_dispatch_admission_open_epoch(mut self, epoch: u64) -> Self {
        if let Some(outcome) = self.backend_dispatch_outcome.as_mut() {
            outcome.deferred_admission_open_epoch = Some(epoch);
        }
        self
    }

    /// Enable gRPC trailer classification for deferred backend dispatch outcome:
    /// passive health and least-latency should see `grpc-status: 14` as a 503
    /// backend result, not a healthy HTTP 200.
    pub(crate) fn with_grpc_trailer_backend_dispatch_classification(mut self) -> Self {
        if let Some(outcome) = self.backend_dispatch_outcome.as_mut() {
            outcome.classify_grpc_trailer = true;
        }
        self
    }

    /// Hand the gRPC streaming circuit-breaker outcome to `observer` (the probe
    /// recorder) at response-body completion instead of recording it here.
    /// Pairs with `skip_circuit_breaker_record = true` so the deferred outcome
    /// still records passive-health + least-latency but the recorder settles the
    /// breaker at the upload-termination join. No-op when no deferred dispatch
    /// outcome is attached.
    pub(crate) fn with_grpc_response_terminal_observer(
        mut self,
        observer: Arc<dyn GrpcResponseTerminalObserver>,
    ) -> Self {
        if let Some(outcome) = self.backend_dispatch_outcome.as_mut() {
            outcome.grpc_response_observer = Some(observer);
        }
        self
    }

    /// Attach the gRPC streaming request-body-overflow flag to an already-set
    /// deferred backend dispatch outcome. A late client upload overflow is not
    /// backend health signal, so dispatch accounting is skipped when this flag
    /// trips before body termination.
    pub(crate) fn with_deferred_dispatch_request_body_exceeded_flag(
        mut self,
        flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        if let Some(outcome) = self.backend_dispatch_outcome.as_mut() {
            outcome.request_body_exceeded = flag;
        }
        self
    }

    /// Classify a dropped, already-polled streaming body as successful if it has
    /// yielded exactly the declared response length. This is intentionally
    /// opt-in: only protocol adapters whose downstream framing can complete from
    /// the declared byte count should use it.
    pub(crate) fn with_success_on_drop_after_response_bytes(mut self, bytes: Option<u64>) -> Self {
        self.success_on_drop_after_bytes = bytes.filter(|bytes| *bytes > 0);
        self
    }

    /// Apply one absolute client gRPC deadline to an already-built streaming
    /// body. Before any response DATA this emits the protocol-appropriate
    /// terminal status: native gRPC uses HTTP trailers, while gRPC-Web uses an
    /// encoded trailer frame in DATA. After partial DATA it aborts safely,
    /// because a complete gRPC message boundary cannot be proven.
    pub(crate) fn with_client_grpc_deadline(
        mut self,
        deadline: tokio::time::Instant,
        grpc_web_response_content_type: Option<&str>,
    ) -> Self {
        let deadline_frame = grpc_web_response_content_type.map(|content_type| {
            let response = crate::plugins::grpc_web::error_response_for_content_type(
                content_type,
                crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED,
                GATEWAY_DEADLINE_EXCEEDED_MESSAGE,
            );
            Frame::data(Bytes::from(response.body))
        });
        let fired = Arc::new(AtomicBool::new(false));
        let placeholder = ProxyBodyKind::Full(Full::default());
        let previous = std::mem::replace(&mut self.kind, placeholder);
        self.kind = match previous {
            ProxyBodyKind::Stream(body) => {
                ProxyBodyKind::Stream(Box::pin(TotalDeadlineBody::with_deadline_frame(
                    body,
                    Some(deadline),
                    deadline_frame,
                    Arc::clone(&fired),
                )))
            }
            ProxyBodyKind::Tracked(body) => {
                ProxyBodyKind::Stream(Box::pin(TotalDeadlineBody::with_deadline_frame(
                    body,
                    Some(deadline),
                    deadline_frame,
                    Arc::clone(&fired),
                )))
            }
            full @ ProxyBodyKind::Full(_) => full,
        };
        self.client_grpc_deadline_fired = Some(fired);
        self
    }

    fn with_client_grpc_deadline_fired_flag(mut self, fired: Arc<AtomicBool>) -> Self {
        self.client_grpc_deadline_fired = Some(fired);
        self
    }

    /// Attach the gRPC streaming request-body-overflow flag to an already-set
    /// deferred backend-admission outcome. When the flag has tripped by the time
    /// the body terminates, the recorded outcome is forced to `RequestBodyTooLarge`
    /// so a client-upload overflow that RSTs the response stream is ignored by the
    /// adaptive limiter instead of being counted as a backend fault. No-op when no
    /// deferred admission outcome is attached or the flag is `None`.
    pub(crate) fn with_deferred_admission_request_body_exceeded_flag(
        mut self,
        flag: Option<Arc<std::sync::atomic::AtomicBool>>,
    ) -> Self {
        if let Some(outcome) = self.backend_admission_outcome.as_mut() {
            outcome.request_body_exceeded = flag;
        }
        self
    }

    /// Attach a [`DeferredTransactionLogger`] to this body so
    /// `log_with_mirror` fires after the body reaches a terminal state
    /// (successful completion, streaming error, or client disconnect)
    /// rather than at the moment response headers are flushed.
    pub fn with_logger(
        mut self,
        logger: Arc<crate::proxy::deferred_log::DeferredTransactionLogger>,
    ) -> Self {
        self.logger = Some(logger);
        self
    }

    /// Detach the deferred logger so the caller can fire it explicitly with a
    /// specific outcome. Used on response-builder failure paths where dropping
    /// the body would otherwise be misclassified as a client disconnect.
    pub fn take_logger(
        &mut self,
    ) -> Option<Arc<crate::proxy::deferred_log::DeferredTransactionLogger>> {
        self.logger.take()
    }

    /// Re-attach a deferred logger to an existing body. Pair with
    /// [`take_logger`] around `http::response::Builder::body()` calls so the
    /// logger survives the detach/rebuild round-trip on success and fires a
    /// caller-supplied outcome on failure.
    pub fn set_logger(
        &mut self,
        logger: Arc<crate::proxy::deferred_log::DeferredTransactionLogger>,
    ) {
        self.logger = Some(logger);
    }

    /// Create a streaming body (no completion tracking).
    pub(crate) fn streaming(
        body: Pin<Box<dyn http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + 'static>>,
    ) -> Self {
        Self {
            kind: ProxyBodyKind::Stream(body),
            _request_guard: None,
            _reqwest_backend_guard: None,
            _per_ip_request_guard: None,
            _lb_connection_guard: None,
            _backend_admission_permits: None,
            backend_admission_outcome: None,
            backend_dispatch_outcome: None,
            client_grpc_deadline_fired: None,
            logger: None,
            bytes_streamed: AtomicU64::new(0),
            success_on_drop_after_bytes: None,
            polled: AtomicBool::new(false),
            _held_frontend_grpc_upload: None,
        }
    }

    /// Wrap a streaming body in lightweight completion tracking.
    ///
    /// Returns the tracked body and a shared `Arc<StreamingMetrics>` that a
    /// deferred task can read to get the final transfer time after
    /// `read_timeout + buffer`. Cost per frame: one `Instant::now()` + one
    /// atomic store.
    ///
    /// Composes with the protocol-agnostic body builders
    /// (`coalescing_body`, `direct_streaming_body`,
    /// `size_limited_streaming_body`, `coalescing_h2_body`,
    /// `direct_streaming_h2_body`, `coalescing_h3_body`,
    /// `direct_streaming_h3_body`) — pick the right base body for the
    /// dispatch path, then call `into_tracked()` so the tracked path inherits
    /// the same coalescing / size-limit / fast-path behaviour as the default
    /// streaming path. No-op (returns unchanged kind) on `Full` or
    /// already-tracked bodies; in those cases the returned `metrics` are
    /// inert.
    pub fn into_tracked(mut self, baseline: Instant) -> (Self, Arc<StreamingMetrics>) {
        let metrics = Arc::new(StreamingMetrics::new(baseline));
        // `ProxyBody: Drop` blocks destructuring, so swap the kind out via
        // `mem::replace` (cheap — `Full(Full::default())` allocates nothing).
        let placeholder = ProxyBodyKind::Full(Full::default());
        let prev = std::mem::replace(&mut self.kind, placeholder);
        self.kind = match prev {
            ProxyBodyKind::Stream(body) => {
                ProxyBodyKind::Tracked(TrackedBody::new(body, Arc::clone(&metrics)))
            }
            other => {
                // Latent-trap diagnostic: production callers should only
                // reach here from `ResponseBody::Streaming` arms (which
                // produce `Stream` variants). If a future refactor passes
                // a `Full` or already-`Tracked` body here, the returned
                // metrics stay inert — the deferred log task will then
                // warn "Streaming response incomplete" after
                // `read_timeout + 5s`. Surfacing it as a debug line makes
                // that failure mode trivial to diagnose.
                debug!(
                    kind = match &other {
                        ProxyBodyKind::Full(_) => "Full",
                        ProxyBodyKind::Tracked(_) => "Tracked",
                        ProxyBodyKind::Stream(_) => "Stream",
                    },
                    "ProxyBody::into_tracked called on non-Stream body — returning unchanged with inert metrics"
                );
                other
            }
        };
        (self, metrics)
    }

    fn record_deferred_backend_admission(
        &mut self,
        error_class: Option<ErrorClass>,
        client_disconnected: bool,
    ) {
        let Some(permits) = self._backend_admission_permits.take() else {
            return;
        };
        let Some(outcome) = self.backend_admission_outcome.take() else {
            return;
        };
        let error_class = if outcome
            .request_body_exceeded
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire))
        {
            // Late gRPC client-upload overflow RST the backend response stream:
            // a client/gateway-side size violation, not a backend fault. Force
            // RequestBodyTooLarge so the limiter ignores it (no shrink), matching
            // how the circuit breaker neutralizes the same overflow.
            Some(ErrorClass::RequestBodyTooLarge)
        } else if client_disconnected {
            Some(ErrorClass::ClientDisconnect)
        } else {
            error_class
        };
        // `connection_error` means exactly "the request body never reached the
        // backend's application layer" (see the Connection-Error Classification
        // Boundary). By the time a streaming body is producing deferred
        // outcomes the response headers have already arrived, so a terminal
        // body error — including the `ReadWriteTimeout` raised by
        // `IdleReadTimeoutBody` — is post-wire and must NOT be flagged as a
        // connection error. Derive it from the canonical `request_reached_wire`
        // predicate instead of "anything that isn't a client disconnect", which
        // wrongly painted mid-stream read timeouts / resets as connect failures.
        let connection_error =
            error_class.is_some_and(|class| !crate::retry::request_reached_wire(class));
        // Prefer the gRPC trailer's mapped status (a non-OK grpc-status finishes
        // HTTP 200) so a backend gRPC failure shrinks the limit; falls back to the
        // header status for non-gRPC streams or an OK/absent trailer.
        let response_status = outcome
            .grpc_trailer_http_status
            .unwrap_or(outcome.response_status);
        permits.record_backend_outcome(BackendAdmissionOutcome {
            response_status,
            connection_error,
            error_class,
            backend_elapsed: outcome.backend_elapsed,
        });
    }

    fn record_deferred_backend_dispatch(
        &mut self,
        error_class: Option<ErrorClass>,
        client_disconnected: bool,
    ) {
        let Some(outcome) = self.backend_dispatch_outcome.take() else {
            return;
        };
        let request_body_exceeded = outcome
            .request_body_exceeded
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));

        let error_class = if client_disconnected {
            Some(ErrorClass::ClientDisconnect)
        } else {
            error_class.or(outcome.error_class)
        };
        // Post-wire body errors (mid-stream read timeout, reset, close) are not
        // connection errors — the request already reached the backend's
        // application layer. Preserve any dispatch-phase connection error
        // recorded at construction, but derive the body-error contribution from
        // the canonical `request_reached_wire` predicate rather than treating
        // every non-disconnect class as a connect failure. See the matching
        // note in `record_deferred_backend_admission`.
        let connection_error = outcome.connection_error
            || error_class.is_some_and(|class| !crate::retry::request_reached_wire(class));
        let response_status = outcome
            .grpc_trailer_http_status
            .unwrap_or(outcome.response_status);

        // gRPC streaming (#1649 item 3): hand the terminal outcome to the probe
        // recorder, which owns the circuit breaker and settles it at the
        // upload-termination join (overflow-aware). Signal it unconditionally —
        // it reads the shared overflow flag itself — even when the overflow short
        // circuit below skips passive-health / least-latency.
        if let Some(observer) = &outcome.grpc_response_observer {
            observer.on_response_terminal(response_status, connection_error, error_class);
        }

        // A late client-upload overflow is a client/gateway-side size violation,
        // not a backend fault — skip passive-health, least-latency, and the
        // breaker (the recorder records NEUTRAL via the shared flag above).
        if request_body_exceeded {
            return;
        }

        // Direct-H2/HBONE (#1649 round-4 B): skip the deferred CB record if the
        // breaker has opened a new generation since this request was admitted —
        // this completion is stale for the current cycle and must not heal/reopen
        // a HALF_OPEN cycle it never probed. Passive-health + least-latency still
        // record (per-target, not per-cycle). The gRPC path leaves this `None`
        // (its recorder does the epoch check).
        let cb_stale = outcome.deferred_admission_open_epoch.is_some_and(|epoch| {
            super::backend_dispatch::deferred_circuit_breaker_is_stale(
                &outcome.state,
                &outcome.proxy,
                outcome.final_cb_target_key.as_deref(),
                epoch,
            )
        });

        super::backend_dispatch::record_backend_outcome_no_conn_end(
            &outcome.state,
            &outcome.proxy,
            &outcome.lb_snapshot,
            outcome.selected_balancer.as_ref(),
            outcome.upstream_target.as_deref(),
            outcome.final_cb_target_key.as_deref(),
            response_status,
            connection_error,
            error_class,
            outcome.is_half_open_probe,
            outcome.skip_circuit_breaker_record || cb_stale,
            outcome.backend_elapsed,
        );
    }
}

impl http_body::Body for ProxyBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // SAFETY: Both `Full<Bytes>` and `Pin<Box<...>>` are `Unpin`, so
        // `get_mut` is safe and we can re-pin the inner value.
        let this = self.get_mut();
        // Mark "polled at least once" so the Drop safety net can distinguish
        // an honest client-disconnect (polled but not drained to Ready(None))
        // from a body hyper never chose to stream (HEAD / 204 / zero-length —
        // dropped without a single poll). Relaxed is safe: Drop happens-after
        // the final poll on the same hyper task, so ordering is guaranteed
        // by the send/await chain even without Acquire/Release.
        this.polled.store(true, Ordering::Relaxed);
        let result = match &mut this.kind {
            ProxyBodyKind::Full(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|opt| opt.map(|result| result.map_err(|never| match never {}))),
            ProxyBodyKind::Stream(body) => body.as_mut().poll_frame(cx),
            ProxyBodyKind::Tracked(body) => Pin::new(body).poll_frame(cx),
        };
        let client_deadline_fired = this
            .client_grpc_deadline_fired
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));

        // Fast path: when no deferred logger is attached, the byte counter
        // has no consumer — skip the atomic fetch_add entirely. The vast
        // majority of requests do not attach a logger (only streaming
        // responses via `with_logger` do), so this saves one atomic RMW per
        // frame on the common path. Error / end-of-stream hooks that fire
        // the logger still observe the counter, because their `take()` only
        // succeeds when a logger was attached.
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if (this.logger.is_some() || this.success_on_drop_after_bytes.is_some())
                    && let Some(data) = frame.data_ref()
                {
                    this.bytes_streamed
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                let is_trailers = frame.trailers_ref().is_some();
                // A client-deadline wrapper emits gRPC-Web terminal metadata as
                // an encoded DATA frame rather than native HTTP trailers. The
                // shared fired flag is set before that frame is returned, and a
                // partial-body expiry returns an error instead, so this signal
                // uniquely identifies the successful terminal deadline frame.
                let is_grpc_web_deadline_terminal =
                    client_deadline_fired && frame.data_ref().is_some();
                let grpc_status = frame
                    .trailers_ref()
                    .and_then(|trailers| trailers.get("grpc-status"))
                    .map(|value| {
                        value.to_str().map_or(u32::MAX, |value| {
                            crate::proxy::grpc_proxy::parse_grpc_status_value(value)
                        })
                    });
                // gRPC streaming: the response can finish HTTP 200 while the real
                // outcome rides in the grpc-status trailer. Capture a non-OK status
                // once and feed both deferred admission and backend dispatch
                // accounting from the same mapped value.
                if let Some(trailers) = frame.trailers_ref()
                    && let Some(code) = trailers.get("grpc-status").map(|value| {
                        value.to_str().map_or(u32::MAX, |value| {
                            crate::proxy::grpc_proxy::parse_grpc_status_value(value)
                        })
                    })
                    && code != 0
                {
                    let status = crate::proxy::grpc_proxy::grpc_status_to_http_status(code);
                    if let Some(outcome) = this.backend_admission_outcome.as_mut()
                        && outcome.classify_grpc_trailer
                    {
                        outcome.grpc_trailer_http_status = Some(status);
                    }
                    if let Some(outcome) = this.backend_dispatch_outcome.as_mut()
                        && outcome.classify_grpc_trailer
                    {
                        outcome.grpc_trailer_http_status = Some(status);
                    }
                }
                if is_trailers || is_grpc_web_deadline_terminal {
                    if let Some(logger) = this.logger.take() {
                        let bytes = this.bytes_streamed.load(Ordering::Relaxed);
                        let terminal_grpc_status = if is_grpc_web_deadline_terminal {
                            Some(crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED)
                        } else {
                            grpc_status
                        };
                        logger.fire(
                            crate::proxy::deferred_log::BodyOutcome::success(bytes)
                                .with_grpc_status(terminal_grpc_status),
                        );
                    }
                    let terminal_class =
                        client_deadline_fired.then_some(ErrorClass::ClientDisconnect);
                    this.record_deferred_backend_admission(terminal_class, client_deadline_fired);
                    this.record_deferred_backend_dispatch(terminal_class, client_deadline_fired);
                }
            }
            Poll::Ready(Some(Err(e))) => {
                let (class, disconnected) = if client_deadline_fired {
                    (ErrorClass::ClientDisconnect, true)
                } else {
                    crate::retry::classify_body_error(&**e as &dyn std::error::Error)
                };
                if let Some(logger) = this.logger.take() {
                    let bytes = this.bytes_streamed.load(Ordering::Relaxed);
                    let grpc_status = client_deadline_fired
                        .then_some(crate::proxy::grpc_proxy::grpc_status::DEADLINE_EXCEEDED);
                    logger.fire(
                        crate::proxy::deferred_log::BodyOutcome::error(class, bytes, disconnected)
                            .with_grpc_status(grpc_status),
                    );
                }
                this.record_deferred_backend_admission(Some(class), disconnected);
                this.record_deferred_backend_dispatch(Some(class), disconnected);
            }
            Poll::Ready(None) => {
                if let Some(logger) = this.logger.take() {
                    let bytes = this.bytes_streamed.load(Ordering::Relaxed);
                    logger.fire(crate::proxy::deferred_log::BodyOutcome::success(bytes));
                }
                let terminal_class = client_deadline_fired.then_some(ErrorClass::ClientDisconnect);
                this.record_deferred_backend_admission(terminal_class, client_deadline_fired);
                this.record_deferred_backend_dispatch(terminal_class, client_deadline_fired);
            }
            Poll::Pending => {}
        }

        result
    }

    fn is_end_stream(&self) -> bool {
        match &self.kind {
            ProxyBodyKind::Full(body) => body.is_end_stream(),
            ProxyBodyKind::Stream(body) => body.is_end_stream(),
            ProxyBodyKind::Tracked(body) => body.inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match &self.kind {
            ProxyBodyKind::Full(body) => body.size_hint(),
            ProxyBodyKind::Stream(body) => body.size_hint(),
            ProxyBodyKind::Tracked(body) => body.inner.size_hint(),
        }
    }
}

impl Drop for ProxyBody {
    fn drop(&mut self) {
        let mut deferred_admission_error_class = None;
        let mut deferred_admission_client_disconnected = false;
        let client_deadline_fired = self
            .client_grpc_deadline_fired
            .as_ref()
            .is_some_and(|flag| flag.load(Ordering::Acquire));
        if let Some(logger) = self.logger.take() {
            let bytes = self.bytes_streamed.load(Ordering::Relaxed);

            // Decide the outcome for a body that was dropped without firing
            // the logger via the poll_frame terminal branches. Two signals:
            //
            // 1. `polled` — was `poll_frame` ever called?
            //    * **Never polled**: hyper chose not to stream this body
            //      (HEAD, 204 No Content, 304 Not Modified, or any response
            //      with a `content-length: 0`/`END_STREAM` known at header
            //      time). These are successful responses; do NOT mark as
            //      client_disconnect.
            //    * **Polled but not drained**: hyper started streaming and
            //      stopped before we yielded `Ready(None)` or `Ready(Some(Err))`.
            //      Either the client dropped the connection or hyper aborted
            //      for another reason we can't observe — treat as client
            //      disconnect.
            //
            // 2. For the never-polled case we also consult `is_end_stream()`
            //    to cover a subtlety for `Full<Bytes>` bodies: a `Full<Bytes>`
            //    with non-empty data reports `is_end_stream() == false`
            //    before its single frame has been yielded. If such a body is
            //    dropped before any poll, that IS a client disconnect —
            //    hyper decided not to send data we had prepared. So for the
            //    never-polled + Full(non-empty) combination we still fire
            //    client_disconnect. For streaming wrappers (Stream / Tracked)
            //    `is_end_stream()` is still unreliable before terminal poll,
            //    so we trust `polled` exclusively and treat never-polled as
            //    success.
            let completed_declared_bytes = self
                .success_on_drop_after_bytes
                .is_some_and(|expected| bytes == expected);
            let outcome = if self.polled.load(Ordering::Relaxed) {
                // Polled at least once but never reached Ready(None) or an
                // error terminal. That's normally a client disconnect
                // mid-stream, except for protocol adapters that can prove the
                // downstream body completed from the declared byte count.
                if completed_declared_bytes {
                    crate::proxy::deferred_log::BodyOutcome::success(bytes)
                } else {
                    crate::proxy::deferred_log::BodyOutcome::client_disconnect(bytes)
                }
            } else {
                match &self.kind {
                    // Never polled + Full: if Full has prepared data we never
                    // sent, that's a client disconnect. If Full is empty or
                    // already yielded, `is_end_stream()` is true and we count
                    // it as a healthy zero-length response.
                    ProxyBodyKind::Full(body) => {
                        if http_body::Body::is_end_stream(body) {
                            crate::proxy::deferred_log::BodyOutcome::success(bytes)
                        } else {
                            crate::proxy::deferred_log::BodyOutcome::client_disconnect(bytes)
                        }
                    }
                    // Never polled + streaming/tracked: hyper decided not to
                    // stream at all (HEAD / 204 / zero-length). Successful.
                    // Do NOT consult `is_end_stream()` — streaming wrappers
                    // may still report false here before their terminal poll,
                    // which would flip HEAD / 204 / zero-length streaming
                    // responses into false-positive client_disconnects.
                    ProxyBodyKind::Stream(_) | ProxyBodyKind::Tracked(_) => {
                        crate::proxy::deferred_log::BodyOutcome::success(bytes)
                    }
                }
            };
            if !outcome.body_completed {
                deferred_admission_error_class = outcome.body_error_class;
                deferred_admission_client_disconnected = outcome.client_disconnected;
            }
            logger.fire(outcome);
        } else if (self._backend_admission_permits.is_some()
            && self.backend_admission_outcome.is_some()
            || self.backend_dispatch_outcome.is_some())
            && self.polled.load(Ordering::Relaxed)
            && self
                .success_on_drop_after_bytes
                .is_none_or(|expected| self.bytes_streamed.load(Ordering::Relaxed) != expected)
        {
            deferred_admission_error_class = Some(ErrorClass::ClientDisconnect);
            deferred_admission_client_disconnected = true;
        }
        if client_deadline_fired {
            deferred_admission_error_class = Some(ErrorClass::ClientDisconnect);
            deferred_admission_client_disconnected = true;
        }
        // A never-polled *streaming* body is ambiguous between a legitimate empty
        // response (HEAD / 204 / zero-length, which the logger above optimistically
        // counts as success) and a client that dropped immediately after headers
        // before hyper polled a single frame. The adaptive limiter must not train
        // on that ambiguity as healthy backend latency — and so grow the limit —
        // so when the outcome would otherwise be recorded as success, ignore it
        // like a client disconnect. A `Full` body that already holds the complete
        // response is a real success and is intentionally left untouched.
        if deferred_admission_error_class.is_none()
            && !deferred_admission_client_disconnected
            && !self.polled.load(Ordering::Relaxed)
            && matches!(
                self.kind,
                ProxyBodyKind::Stream(_) | ProxyBodyKind::Tracked(_)
            )
        {
            deferred_admission_error_class = Some(ErrorClass::ClientDisconnect);
            deferred_admission_client_disconnected = true;
        }
        self.record_deferred_backend_admission(
            deferred_admission_error_class,
            deferred_admission_client_disconnected,
        );
        self.record_deferred_backend_dispatch(
            deferred_admission_error_class,
            deferred_admission_client_disconnected,
        );
    }
}

// -- SyncBody wrapper ---------------------------------------------------------

pin_project! {
    /// Wraps a body that already implements `Send + Sync` so that the
    /// `Sync` bound is preserved through `pin_project!`'s synthesized
    /// generics, enabling use with `reqwest::Body::wrap()` (which requires
    /// `Send + Sync + 'static`).
    ///
    /// The wrapper itself adds no extra concurrency capability beyond what
    /// `B` already provides — it is a thin `#[pin]`-projected newtype. The
    /// `unsafe impl Sync` below delegates the `Sync` claim to `B` at
    /// compile time via the `B: Send + Sync` bound; there is no runtime
    /// invariant required.
    ///
    /// Use [`reqwest::Body::wrap_stream`] instead if `B` is `Send` but
    /// `!Sync`. That path loses the `size_hint()` from the underlying body
    /// (forcing chunked transfer encoding even when `Content-Length` is
    /// known), so it is only worth taking when the inner body genuinely
    /// cannot be made `Sync`.
    pub(crate) struct SyncBody<B> {
        #[pin]
        inner: B,
    }
}

// SAFETY: The bound `B: Send + Sync` makes this `Sync` claim a compile-time
// delegation to the inner body. `SyncBody<B>` is a transparent newtype over
// `B` (one `#[pin]`-projected field, no interior mutability of its own), so
// `&SyncBody<B>` exposes only `&B`'s API surface, which is `Sync`-safe by
// the bound. No runtime invariant (such as "polled from a single task") is
// required for soundness.
unsafe impl<B: Send + Sync> Sync for SyncBody<B> {}

impl<B> SyncBody<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self { inner }
    }
}

impl<B> http_body::Body for SyncBody<B>
where
    B: http_body::Body<Data = Bytes>,
    B::Error: Into<Box<dyn std::error::Error + Send + Sync>>,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        // Security hardening: never forward inbound request trailer frames to
        // upstream backends on the generic streaming path. The gateway's
        // request validation/filtering operates on the initial header map; if
        // trailers are forwarded here, attacker-controlled metadata could
        // bypass those checks and be interpreted by downstream services.
        //
        // Loop until we see a data frame, error, end-of-stream, or Pending.
        // Trailer frames are simply consumed and dropped.
        loop {
            match self.as_mut().project().inner.poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) if frame.is_trailers() => continue,
                other => return other,
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

// -- SizeLimitedIncoming ------------------------------------------------------

/// A size-limited stream adapter over hyper's `Incoming` body.
///
/// Wraps `Incoming` and counts bytes as they flow through. If the
/// accumulated size exceeds `max_bytes`, sets a shared `exceeded` flag
/// and yields an error. This allows streaming request bodies to the
/// backend while still enforcing `max_request_body_size_bytes`.
///
/// The `exceeded` flag is checked after `reqwest::send()` completes
/// to distinguish a size-limit error from other request failures and
/// return the correct HTTP 413 status.
pub struct SizeLimitedIncoming {
    inner: Incoming,
    max_bytes: usize,
    /// Running byte count, atomic so the caller can observe the final value
    /// after `into_reqwest_body()` has moved `self` into the outbound request.
    /// Use [`bytes_seen_handle`](Self::bytes_seen_handle) to clone the `Arc`
    /// before the move; reading the local field afterwards is impossible
    /// because ownership has already transferred to reqwest's request builder.
    bytes_seen: Arc<std::sync::atomic::AtomicU64>,
    exceeded: Arc<AtomicBool>,
}

impl SizeLimitedIncoming {
    /// Construct with a fresh byte counter. Callers that want to observe
    /// `bytes_seen` after `into_reqwest_body()` has moved `self` should use
    /// [`new_with_counter`](Self::new_with_counter) instead and share the
    /// counter with the summary builder.
    ///
    /// Retained as public API; internal callers use `new_with_counter` so
    /// they can plumb `ctx.bytes_sent_observed` directly.
    #[allow(dead_code)]
    pub fn new(incoming: Incoming, max_bytes: usize, exceeded: Arc<AtomicBool>) -> Self {
        Self::new_with_counter(
            incoming,
            max_bytes,
            exceeded,
            Arc::new(std::sync::atomic::AtomicU64::new(0)),
        )
    }

    /// Construct with a caller-supplied byte counter.
    ///
    /// Typical usage pattern (summary builder needing `bytes_sent`):
    /// ```ignore
    /// let limited = SizeLimitedIncoming::new_with_counter(
    ///     body,
    ///     max_bytes,
    ///     exceeded,
    ///     Arc::clone(&ctx.bytes_sent_observed),
    /// );
    /// req_builder.body(limited.into_reqwest_body());
    /// // ... request completes; ctx.bytes_sent_observed now reflects the
    /// // total bytes polled out of the client body.
    /// ```
    ///
    /// The counter uses `Release` on stores (in `poll_frame`) and pairs with
    /// `Acquire` loads by observers. Reading before the final frame has been
    /// polled returns an in-flight snapshot, not the total — callers that
    /// need the total must wait for the backend request to complete (which
    /// implies the body was fully polled).
    pub fn new_with_counter(
        incoming: Incoming,
        max_bytes: usize,
        exceeded: Arc<AtomicBool>,
        bytes_seen: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            inner: incoming,
            max_bytes,
            bytes_seen,
            exceeded,
        }
    }

    /// Clone the internal byte counter so the caller can observe `bytes_seen`
    /// after `into_reqwest_body()` has moved ownership into reqwest.
    /// Prefer [`new_with_counter`](Self::new_with_counter) when the counter
    /// should be shared from the start.
    ///
    /// Retained as public API for callers that cannot supply their own
    /// counter up-front.
    #[allow(dead_code)]
    pub fn bytes_seen_handle(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.bytes_seen)
    }

    /// Current byte count. Equivalent to
    /// `bytes_seen_handle().load(Ordering::Acquire)` but without cloning
    /// the `Arc`. Only useful when `self` is still accessible; after
    /// `into_reqwest_body()` has moved `self`, use the cloned handle.
    #[allow(dead_code)]
    pub fn bytes_seen(&self) -> u64 {
        self.bytes_seen.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Convert this size-limited body into a `reqwest::Body` for streaming
    /// to the backend without collecting the full body into memory.
    ///
    /// Uses `reqwest::Body::wrap()` instead of `wrap_stream()` to preserve
    /// the `size_hint()` from the underlying `Incoming` body. When the client
    /// sends `Content-Length`, this enables reqwest to forward a length-delimited
    /// body instead of chunked Transfer-Encoding — avoiding per-chunk framing
    /// overhead and enabling single-buffer receive on the backend.
    ///
    /// **Ownership caveat**: this method consumes `self`, so any caller that
    /// wants to read `bytes_seen` after the request completes must call
    /// [`bytes_seen_handle`](Self::bytes_seen_handle) *before* this method
    /// and hold onto the returned `Arc`.
    pub fn into_reqwest_body(self) -> reqwest::Body {
        reqwest::Body::wrap(SyncBody::new(self))
    }
}

impl http_body::Body for SizeLimitedIncoming {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match http_body::Body::poll_frame(Pin::new(&mut this.inner), cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    // Single atomic RMW: fetch_add returns the pre-increment
                    // value, so we can cheaply derive the post-increment total
                    // for the threshold check without a separate load. Release
                    // ordering so `bytes_seen_handle().load(Acquire)` from an
                    // external observer sees every write.
                    let data_len = data.len() as u64;
                    let prev = this
                        .bytes_seen
                        .fetch_add(data_len, std::sync::atomic::Ordering::Release);
                    let total = prev.saturating_add(data_len);
                    if total > this.max_bytes as u64 {
                        this.exceeded.store(true, Ordering::Release);
                        return Poll::Ready(Some(Err("request body exceeds maximum size".into())));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

// -- CountingIncoming ---------------------------------------------------------

/// A body adapter that counts bytes as they pass through, without enforcing
/// any size limit.
///
/// Used on streaming request paths where no size cap applies (or where the
/// cap is enforced elsewhere) but the summary builder still needs to observe
/// the total request body size via `TransactionSummary.bytes_sent`.
///
/// Share the counter via [`bytes_seen_handle`](Self::bytes_seen_handle) before
/// moving `self` into a downstream body consumer (e.g., reqwest's request
/// builder). Read the final count once the request has completed — reading
/// while polling is in flight returns a partial snapshot.
///
/// Zero-cost when not observed: `Arc<AtomicU64>` allocation is the only
/// overhead beyond a single `fetch_add(Relaxed)` per frame. The increments
/// use `Release` to pair with external `Acquire` loads on the cloned handle.
pub struct CountingIncoming {
    inner: Incoming,
    bytes_seen: Arc<std::sync::atomic::AtomicU64>,
}

impl CountingIncoming {
    /// Wrap an `Incoming` body with a fresh byte counter. Callers that want
    /// to observe `bytes_seen` after `into_reqwest_body()` has moved `self`
    /// should use [`new_with_counter`](Self::new_with_counter) instead.
    ///
    /// Retained as public API; internal callers use `new_with_counter` so
    /// they can plumb `ctx.bytes_sent_observed` directly.
    #[allow(dead_code)]
    pub fn new(incoming: Incoming) -> Self {
        Self::new_with_counter(incoming, Arc::new(std::sync::atomic::AtomicU64::new(0)))
    }

    /// Wrap an `Incoming` body with a caller-supplied shared byte counter.
    /// Typical usage:
    /// ```ignore
    /// let counting = CountingIncoming::new_with_counter(
    ///     incoming,
    ///     Arc::clone(&ctx.bytes_sent_observed),
    /// );
    /// req_builder.body(counting.into_reqwest_body());
    /// ```
    pub fn new_with_counter(
        incoming: Incoming,
        bytes_seen: Arc<std::sync::atomic::AtomicU64>,
    ) -> Self {
        Self {
            inner: incoming,
            bytes_seen,
        }
    }

    /// Clone the internal byte counter so the caller can observe `bytes_seen`
    /// after the body has been moved into a downstream consumer. Must be
    /// captured before the move.
    ///
    /// Retained as public API for callers that cannot supply their own
    /// counter up-front.
    #[allow(dead_code)]
    pub fn bytes_seen_handle(&self) -> Arc<std::sync::atomic::AtomicU64> {
        Arc::clone(&self.bytes_seen)
    }

    /// Current byte count. See `bytes_seen_handle` caveat.
    #[allow(dead_code)]
    pub fn bytes_seen(&self) -> u64 {
        self.bytes_seen.load(std::sync::atomic::Ordering::Acquire)
    }

    /// Convert into a `reqwest::Body` for streaming to the backend.
    ///
    /// **Ownership caveat**: consumes `self`. Capture
    /// [`bytes_seen_handle`](Self::bytes_seen_handle) first to read the
    /// final byte count after the request completes.
    pub fn into_reqwest_body(self) -> reqwest::Body {
        reqwest::Body::wrap(SyncBody::new(self))
    }
}

impl http_body::Body for CountingIncoming {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match http_body::Body::poll_frame(Pin::new(&mut this.inner), cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    // Release ordering pairs with Acquire on
                    // `bytes_seen_handle().load()` from the summary builder
                    // so the final count is visible across the threads that
                    // may poll the body vs read the handle.
                    this.bytes_seen
                        .fetch_add(data.len() as u64, std::sync::atomic::Ordering::Release);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(Box::new(e)))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

// -- SizeLimitedStreamingResponse ---------------------------------------------

/// A size-limited streaming adapter over a reqwest response byte stream.
///
/// Wraps a reqwest response's `bytes_stream()` and counts bytes as they flow
/// through. If the accumulated size exceeds `max_bytes`, yields an error frame.
/// This allows streaming response bodies to the client while still enforcing
/// `max_response_body_size_bytes` without buffering the entire body into memory.
///
/// Used when Content-Length is absent (chunked/unknown size) and a response
/// size limit is configured. Without this, the entire response would be
/// buffered via `collect_response_with_limit()` to enforce the limit.
pub(crate) struct SizeLimitedStreamingResponse<S> {
    inner: S,
    max_bytes: usize,
    bytes_seen: usize,
}

/// Wraps a reqwest response into a size-limited coalescing body.
///
/// Applies both size limiting and chunk coalescing (128 KB target) in a single
/// adapter chain. The size limiter sits outside the coalescer so the byte count
/// reflects the actual backend payload, not coalesced chunks.
pub(crate) fn size_limited_streaming_body(
    response: reqwest::Response,
    max_bytes: usize,
    content_length: Option<u64>,
) -> ProxyBody {
    use futures_util::StreamExt;

    let stream = response.bytes_stream().map(|r| {
        r.map(Frame::data)
            .map_err(|e| Box::new(e) as ProxyBodyError)
    });
    let limited = SizeLimitedStreamingResponse {
        inner: stream,
        max_bytes,
        bytes_seen: 0,
    };
    let coalescing = Coalescing::new(
        ReqwestFrameSource { inner: limited },
        COALESCE_TARGET,
        content_length,
    );
    ProxyBody::streaming(Box::pin(coalescing))
}

impl<S> futures_util::Stream for SizeLimitedStreamingResponse<S>
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Unpin,
{
    type Item = Result<Frame<Bytes>, ProxyBodyError>;

    fn poll_next(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_next(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes_seen += data.len();
                    if this.bytes_seen > this.max_bytes {
                        return Poll::Ready(Some(Err("response body exceeds maximum size".into())));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }
}

struct SizeLimitedFrameSource<S> {
    inner: S,
    max_bytes: usize,
    bytes_seen: usize,
}

impl<S> SizeLimitedFrameSource<S> {
    fn new(inner: S, max_bytes: usize) -> Self {
        Self {
            inner,
            max_bytes,
            bytes_seen: 0,
        }
    }
}

impl<S: FrameSource + Unpin> FrameSource for SizeLimitedFrameSource<S> {
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(data) = frame.data_ref() {
                    this.bytes_seen = this.bytes_seen.saturating_add(data.len());
                    if this.bytes_seen > this.max_bytes {
                        return Poll::Ready(Some(Err("response body exceeds maximum size".into())));
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            other => other,
        }
    }
}

/// Default flush target for the [`Coalescing`] adapter when no explicit
/// target is supplied (HTTP/1.1 + HTTP/2-via-reqwest path).
const COALESCE_TARGET: usize = 128 * 1024;

pub(crate) trait FrameSource {
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>>;
}

pub(crate) struct ReqwestFrameSource<S> {
    inner: S,
}

impl<S> FrameSource for ReqwestFrameSource<S>
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, BoxError>> + Unpin,
{
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        futures_util::Stream::poll_next(Pin::new(&mut self.get_mut().inner), cx)
    }
}

impl FrameSource for Incoming {
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        http_body::Body::poll_frame(self, cx)
            .map(|opt| opt.map(|r| r.map_err(|e| Box::new(e) as BoxError)))
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3FrameSourceState {
    Data,
    Trailers,
    Done,
}

trait H3RecvStream {
    fn poll_recv_data_bytes(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, BoxError>>;

    fn poll_recv_trailers_map(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, BoxError>>;

    fn peek_recv_trailers_map(&self) -> Result<Option<http::HeaderMap>, BoxError> {
        Ok(None)
    }
}

impl H3RecvStream for crate::http3::client::H3RequestStream {
    fn poll_recv_data_bytes(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, BoxError>> {
        use bytes::Buf;

        match self.poll_recv_data(cx) {
            Poll::Ready(Ok(Some(mut buf))) => {
                let data = buf.copy_to_bytes(buf.remaining());
                Poll::Ready(Ok(Some(data)))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(Ok(None)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Box::new(err) as BoxError)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_recv_trailers_map(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<http::HeaderMap>, BoxError>> {
        match self.poll_recv_trailers(cx) {
            Poll::Ready(Ok(trailers)) => Poll::Ready(Ok(trailers)),
            Poll::Ready(Err(err)) => Poll::Ready(Err(Box::new(err) as BoxError)),
            Poll::Pending => Poll::Pending,
        }
    }

    fn peek_recv_trailers_map(&self) -> Result<Option<http::HeaderMap>, BoxError> {
        self.peek_recv_trailers()
            .map_err(|err| Box::new(err) as BoxError)
    }
}

/// Shared read-progress signal between an [`H3FrameSource`] and the outer
/// [`IdleReadTimeoutBody`] that wraps it.
///
/// Native-H3 coalescing can BUFFER a backend frame (returning `Pending` to the
/// outer wrapper) instead of yielding it downstream, so the outer cannot infer
/// backend progress from its own poll results alone. The source bumps `epoch`
/// on every backend read event — a DATA chunk received, or the FIN that ends the
/// body — so the outer can reset its inactivity deadline on real progress rather
/// than firing a false read timeout while a frame sits buffered. This mirrors the
/// buffered drain, where each `recv_data` / `recv_trailers` gets a fresh
/// `tokio::time::timeout` budget.
#[derive(Default)]
struct H3ReadProgress {
    /// Monotonic counter bumped on each backend read event (data chunk or FIN).
    epoch: AtomicU64,
    /// Set once the DATA body is complete (FIN) and only an OPTIONAL trailer
    /// frame remains. A fired outer deadline then COLLAPSES to a clean EOS
    /// instead of erroring — parity with the buffered drain's
    /// `read_h3_trailers_with_timeout`. Because the FIN also bumps `epoch`, the
    /// outer re-arms a fresh trailer-wait budget first, so trailers arriving
    /// shortly after FIN are still delivered rather than dropped.
    trailer_phase: AtomicBool,
    /// Trailers that h3 has already buffered but is withholding until the
    /// terminal stream FIN arrives. If the caller's trailer-phase timeout fires
    /// before that FIN, the outer timeout wrapper can still forward these
    /// trailers before ending the downstream body.
    pending_trailers: std::sync::Mutex<Option<http::HeaderMap>>,
}

impl H3ReadProgress {
    /// A DATA chunk was read from the backend — reset the inactivity clock.
    fn record_backend_progress(&self) {
        self.epoch.fetch_add(1, Ordering::Release);
    }

    /// FIN seen on a COMPLETE body: re-arm the inactivity clock (epoch bump) for
    /// the trailer wait AND enable collapse-on-timeout. The caller only reaches
    /// this after the Data-phase FIN check has confirmed completeness — a
    /// truncated body surfaces an error there and never enters the trailer phase
    /// — so this is unconditional.
    fn enter_trailer_phase(&self) {
        self.trailer_phase.store(true, Ordering::Release);
        self.epoch.fetch_add(1, Ordering::Release);
    }

    fn store_pending_trailers(&self, trailers: http::HeaderMap) {
        if let Ok(mut slot) = self.pending_trailers.lock()
            && slot.is_none()
        {
            *slot = Some(trailers);
        }
    }

    fn take_pending_trailers(&self) -> Option<http::HeaderMap> {
        self.pending_trailers
            .lock()
            .ok()
            .and_then(|mut slot| slot.take())
    }
}

pub(crate) struct H3FrameSource<S = crate::http3::client::H3RequestStream> {
    recv_stream: S,
    state: H3FrameSourceState,
    /// Request method (`Arc<str>` so construction clones cheaply, not per
    /// frame). Threaded in alongside `status` so the graceful-close recovery
    /// gate can call `is_response_body_complete`, which also treats HEAD/204/304
    /// (no-body) responses as complete when empty.
    method: Arc<str>,
    /// Response status code. See `method`.
    status: u16,
    /// Declared response Content-Length, if any. Used only to recognize a
    /// connection-level graceful close that arrives after a COMPLETE body.
    content_length: Option<u64>,
    /// Total response body bytes yielded so far.
    received: u64,
    /// Shared read-progress signal with the outer [`IdleReadTimeoutBody`]. The
    /// source bumps it on each DATA chunk and on FIN so the outer can reset its
    /// inactivity deadline on backend progress (even when Coalescing buffers the
    /// frame) and collapse — rather than error — a fired deadline once only
    /// optional trailers remain. `None` when no read timeout is configured (the
    /// outer wrapper is absent).
    progress: Option<Arc<H3ReadProgress>>,
}

impl<S> H3FrameSource<S> {
    fn new(
        recv_stream: S,
        method: Arc<str>,
        status: u16,
        content_length: Option<u64>,
        progress: Option<Arc<H3ReadProgress>>,
    ) -> Self {
        Self {
            recv_stream,
            state: H3FrameSourceState::Data,
            method,
            status,
            content_length,
            received: 0,
            progress,
        }
    }

    fn is_done(&self) -> bool {
        matches!(self.state, H3FrameSourceState::Done)
    }

    /// Mark the DATA body complete (a clean FIN that satisfied any declared
    /// Content-Length — the caller runs the truncation check first): re-arm the
    /// outer inactivity deadline (epoch bump) and enable collapse-on-timeout
    /// while only optional trailers remain.
    fn enter_trailer_phase(&mut self) {
        self.state = H3FrameSourceState::Trailers;
        if let Some(p) = &self.progress {
            p.enter_trailer_phase();
        }
    }
}

impl<S: H3RecvStream + Unpin> FrameSource for H3FrameSource<S> {
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let this = self.get_mut();
        loop {
            match this.state {
                H3FrameSourceState::Data => {
                    match Pin::new(&mut this.recv_stream).poll_recv_data_bytes(cx) {
                        Poll::Ready(Ok(Some(data))) => {
                            this.received = this.received.saturating_add(data.len() as u64);
                            // Backend progress — reset the outer inactivity clock
                            // even if Coalescing buffers this chunk instead of
                            // yielding it downstream.
                            if let Some(p) = &this.progress {
                                p.record_backend_progress();
                            }
                            return Poll::Ready(Some(Ok(Frame::data(data))));
                        }
                        Poll::Ready(Ok(None)) => {
                            // Clean FIN. If a declared Content-Length was NOT
                            // satisfied (truncation or overlong), that is a framing
                            // violation: surface it as a backend error rather than
                            // entering the trailer phase, where a subsequent
                            // Ok(None) / trailers / graceful-close / read-timeout
                            // branch would emit a clean EOS to the client. With
                            // native-H3 dispatch accounting intentionally eager
                            // until #1901, this streaming check is about framing
                            // correctness: the client must see the truncated body
                            // as an error instead of a complete response. An absent
                            // Content-Length is FIN-delimited and complete here.
                            if !crate::http3::client::is_response_body_complete_after_fin(
                                this.received,
                                &this.method,
                                this.status,
                                this.content_length,
                            ) {
                                this.state = H3FrameSourceState::Done;
                                return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                                    std::io::ErrorKind::UnexpectedEof,
                                    format!(
                                        "h3 backend FIN after {} of {} declared Content-Length bytes",
                                        this.received,
                                        this.content_length.map_or_else(
                                            || "unknown".to_string(),
                                            |c| c.to_string(),
                                        ),
                                    ),
                                ))
                                    as BoxError)));
                            }
                            // Complete body: flag the trailer phase so a fired outer
                            // read-timeout collapses to a clean EOS instead of
                            // erroring while only optional trailers remain.
                            this.enter_trailer_phase();
                        }
                        Poll::Ready(Err(err)) => {
                            this.state = H3FrameSourceState::Done;
                            // Recover a connection-level graceful close that arrives
                            // AFTER a complete body, matching the buffered path
                            // (drain_h3_response_body): CONNECTION_CLOSE(H3_NO_ERROR)
                            // or a coalesced GOAWAY/RemoteClosing is not a real
                            // stream error once the body is complete, so emit clean
                            // EOS instead of a spurious mid-stream error.
                            //
                            // `is_response_body_complete` is the SAME completeness
                            // predicate the buffered path uses, so the two paths
                            // recover identically:
                            //   * Content-Length known: recovers ONLY on exact
                            //     satisfaction. `received < cl` (truncation) never
                            //     recovers, so no truncation is masked; `received >
                            //     cl` (overlong) never recovers either — an
                            //     over-declared body is a framing violation that must
                            //     surface, not be laundered into a clean EOS.
                            //   * HEAD / 204 / 304: no-body responses are complete
                            //     when `received == 0`, so a graceful close after the
                            //     (empty) body recovers here too.
                            //   * Unknown length (chunked, no Content-Length) stays
                            //     OUT OF SCOPE: completeness can't be proven without
                            //     the FIN, so the close still surfaces as an error.
                            if crate::http3::client::is_response_body_complete(
                                this.received,
                                &this.method,
                                this.status,
                                this.content_length,
                            ) && err
                                .downcast_ref::<h3::error::StreamError>()
                                .is_some_and(crate::http3::client::is_h3_graceful_close)
                            {
                                return Poll::Ready(None);
                            }
                            return Poll::Ready(Some(Err(err)));
                        }
                        Poll::Pending => return Poll::Pending,
                    }
                }
                H3FrameSourceState::Trailers => {
                    // DATA body already finished (a clean FIN took us here), so a
                    // missing/slow optional trailer frame must NOT fail the
                    // response. The TIMING is owned by the single outer
                    // `IdleReadTimeoutBody`: while we wait here it sees `Pending`,
                    // and if its deadline fires it COLLAPSES to a clean EOS (rather
                    // than erroring) because `trailer_phase` is set — parity with
                    // the buffered drain's `read_h3_trailers_with_timeout`. Using
                    // that one deadline (instead of a second source-level timer)
                    // avoids a race where a data-phase deadline armed before the
                    // FIN expires mid-trailer-wait. A trailer frame that has
                    // already arrived is still delivered here (we poll it before
                    // ever yielding `Pending`), so a delayed final poll cannot drop
                    // valid trailers.
                    match Pin::new(&mut this.recv_stream).poll_recv_trailers_map(cx) {
                        Poll::Ready(Ok(Some(mut trailers))) => {
                            this.state = H3FrameSourceState::Done;
                            crate::proxy::headers::strip_response_hop_by_hop_trailers(
                                &mut trailers,
                            );
                            return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                        }
                        Poll::Ready(Ok(None)) => {
                            this.state = H3FrameSourceState::Done;
                            return Poll::Ready(None);
                        }
                        Poll::Ready(Err(err)) => {
                            this.state = H3FrameSourceState::Done;
                            // The body is already COMPLETE here — truncation is
                            // surfaced at the DATA-phase FIN check before this state
                            // is ever entered — so a graceful connection-level close
                            // (H3_NO_ERROR / GOAWAY) at the trailer phase just means
                            // the backend finished without trailers: emit a clean
                            // EOS rather than a spurious stream error, matching the
                            // buffered drain's `read_h3_trailers_with_timeout` ("no
                            // trailers"). Any non-graceful error still surfaces.
                            if err
                                .downcast_ref::<h3::error::StreamError>()
                                .is_some_and(crate::http3::client::is_h3_graceful_close)
                            {
                                return Poll::Ready(None);
                            }
                            return Poll::Ready(Some(Err(err)));
                        }
                        Poll::Pending => {
                            if let Some(p) = &this.progress {
                                match this.recv_stream.peek_recv_trailers_map() {
                                    Ok(Some(mut trailers)) => {
                                        crate::proxy::headers::strip_response_hop_by_hop_trailers(
                                            &mut trailers,
                                        );
                                        p.store_pending_trailers(trailers);
                                    }
                                    Ok(None) => {}
                                    Err(err) => {
                                        this.state = H3FrameSourceState::Done;
                                        return Poll::Ready(Some(Err(err)));
                                    }
                                }
                            }
                            return Poll::Pending;
                        }
                    }
                }
                H3FrameSourceState::Done => return Poll::Ready(None),
            }
        }
    }
}

pub(crate) struct Coalescing<S: FrameSource> {
    inner: S,
    target_bytes: usize,
    buffer: BytesMut,
    stashed_trailer: Option<Frame<Bytes>>,
    stashed_error: Option<BoxError>,
    done: bool,
    content_length: Option<u64>,
    flush_after: Option<Duration>,
    flush_timer: Option<Pin<Box<tokio::time::Sleep>>>,
    flush_timer_armed: bool,
}

impl<S: FrameSource> Coalescing<S> {
    fn new(inner: S, target_bytes: usize, content_length: Option<u64>) -> Self {
        Self::with_flush_after(inner, target_bytes, content_length, None)
    }

    fn with_flush_after(
        inner: S,
        target_bytes: usize,
        content_length: Option<u64>,
        flush_after: Option<Duration>,
    ) -> Self {
        Self {
            inner,
            target_bytes,
            buffer: BytesMut::with_capacity(target_bytes.min(COALESCE_TARGET)),
            stashed_trailer: None,
            stashed_error: None,
            done: false,
            content_length,
            flush_after,
            flush_timer: None,
            flush_timer_armed: false,
        }
    }

    fn with_flush_after_and_capacity(
        inner: S,
        target_bytes: usize,
        buffer_capacity: usize,
        content_length: Option<u64>,
        flush_after: Option<Duration>,
    ) -> Self {
        Self {
            inner,
            target_bytes,
            buffer: BytesMut::with_capacity(buffer_capacity),
            stashed_trailer: None,
            stashed_error: None,
            done: false,
            content_length,
            flush_after,
            flush_timer: None,
            flush_timer_armed: false,
        }
    }

    fn arm_flush_timer(&mut self) {
        let Some(flush_after) = self.flush_after else {
            return;
        };
        let deadline = tokio::time::Instant::now() + flush_after;
        if let Some(timer) = self.flush_timer.as_mut() {
            timer.as_mut().reset(deadline);
        } else {
            self.flush_timer = Some(Box::pin(tokio::time::sleep_until(deadline)));
        }
        self.flush_timer_armed = true;
    }

    fn poll_flush_timer(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if !self.flush_timer_armed {
            debug_assert!(
                self.buffer.is_empty() || self.flush_after.is_none(),
                "non-empty coalescing buffer must arm a flush timer when flush_after is configured",
            );
            return Poll::Pending;
        }

        match self.flush_timer.as_mut() {
            Some(timer) => match std::future::Future::poll(timer.as_mut(), cx) {
                Poll::Ready(()) => {
                    self.flush_timer_armed = false;
                    Poll::Ready(())
                }
                Poll::Pending => Poll::Pending,
            },
            None => Poll::Pending,
        }
    }

    fn flush_buffer(&mut self) -> Option<Frame<Bytes>> {
        if self.buffer.is_empty() {
            self.flush_timer_armed = false;
            return None;
        }

        self.flush_timer_armed = false;
        Some(Frame::data(self.buffer.split().freeze()))
    }

    fn buffer_data(&mut self, data: &Bytes) {
        if data.is_empty() {
            return;
        }
        self.buffer.extend_from_slice(data);
        if self.flush_after.is_some() && !self.flush_timer_armed {
            self.arm_flush_timer();
        }
    }
}

impl<S: FrameSource + Unpin> http_body::Body for Coalescing<S> {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        if let Some(trailer) = this.stashed_trailer.take() {
            this.done = true;
            return Poll::Ready(Some(Ok(trailer)));
        }

        if this.done {
            if let Some(frame) = this.flush_buffer() {
                return Poll::Ready(Some(Ok(frame)));
            }
            if let Some(err) = this.stashed_error.take() {
                return Poll::Ready(Some(Err(err)));
            }
            return Poll::Ready(None);
        }

        if !this.buffer.is_empty()
            && matches!(this.poll_flush_timer(cx), Poll::Ready(()))
            && let Some(frame) = this.flush_buffer()
        {
            return Poll::Ready(Some(Ok(frame)));
        }

        loop {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        if this.buffer.is_empty() && data.len() >= this.target_bytes {
                            return Poll::Ready(Some(Ok(frame)));
                        }

                        this.buffer_data(data);
                        if this.buffer.len() >= this.target_bytes
                            && let Some(flushed) = this.flush_buffer()
                        {
                            return Poll::Ready(Some(Ok(flushed)));
                        }
                        continue;
                    }

                    if !this.buffer.is_empty() {
                        this.stashed_trailer = Some(frame);
                        let flushed = this
                            .flush_buffer()
                            .expect("non-empty buffer must flush before stashed trailer");
                        return Poll::Ready(Some(Ok(flushed)));
                    }

                    this.done = true;
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(err))) => {
                    this.done = true;
                    if !this.buffer.is_empty() {
                        this.stashed_error = Some(err);
                        let flushed = this
                            .flush_buffer()
                            .expect("non-empty buffer must flush before stashed error");
                        return Poll::Ready(Some(Ok(flushed)));
                    }
                    return Poll::Ready(Some(Err(err)));
                }
                Poll::Ready(None) => {
                    this.done = true;
                    if let Some(flushed) = this.flush_buffer() {
                        return Poll::Ready(Some(Ok(flushed)));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    if this.buffer.is_empty() {
                        return Poll::Pending;
                    }
                    if this.flush_after.is_some() {
                        if matches!(this.poll_flush_timer(cx), Poll::Ready(()))
                            && let Some(flushed) = this.flush_buffer()
                        {
                            return Poll::Ready(Some(Ok(flushed)));
                        }
                        return Poll::Pending;
                    }
                    if let Some(flushed) = this.flush_buffer() {
                        return Poll::Ready(Some(Ok(flushed)));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
            && self.buffer.is_empty()
            && self.stashed_trailer.is_none()
            && self.stashed_error.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        content_length_hint(self.content_length)
    }
}

#[rustfmt::skip]
fn content_length_hint(content_length: Option<u64>) -> http_body::SizeHint {
    content_length.map(http_body::SizeHint::with_exact).unwrap_or_default()
}

struct DirectStreamBody<S> {
    inner: S,
    content_length: Option<u64>,
}

impl<S> http_body::Body for DirectStreamBody<S>
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, BoxError>> + Unpin,
{
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        futures_util::Stream::poll_next(Pin::new(&mut self.get_mut().inner), cx)
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> http_body::SizeHint {
        content_length_hint(self.content_length)
    }
}

struct DirectH2Body {
    inner: Incoming,
    content_length: Option<u64>,
}

impl http_body::Body for DirectH2Body {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        http_body::Body::poll_frame(Pin::new(&mut self.get_mut().inner), cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.content_length
            .map(http_body::SizeHint::with_exact)
            .unwrap_or_else(|| self.inner.size_hint())
    }
}

/// Wraps a streaming HTTP/2 response body with a per-frame idle read deadline.
///
/// After the response headers have arrived, a backend can stop producing body
/// frames while keeping the H2 connection alive. Without a deadline the
/// streaming relay stays parked on the next `poll_frame`, pinning the request's
/// lifetime guards (overload `RequestGuard`, per-IP request accounting, the
/// least-connections LB guard, backend-admission permits) until the client
/// disconnects or the backend eventually resumes.
///
/// This wrapper arms a pinned `Sleep` only while it is actually waiting on the
/// backend (a `Pending` inner poll); if no frame arrives within
/// `backend_read_timeout_ms` of beginning that wait, `poll_frame` yields a
/// `std::io::Error` of kind `TimedOut`. That kind is mapped to
/// `ErrorClass::ReadWriteTimeout` (post-wire) by `retry::classify_typed_chain`,
/// so deferred backend/admission accounting records a read timeout (and, being
/// post-wire, NOT a connection error) rather than an indefinite in-flight
/// stream — matching the buffered H2 body collection
/// (`collect_hyper_body_with_limit`) and the native-H3 streaming read timeout.
///
/// The deadline is (re)armed only on the transition from "have a frame" to
/// "waiting on the backend" — NOT on every received frame. A slow downstream
/// client can keep the relay from polling this body for an arbitrary interval
/// (H2 flow-control backpressure), and that interval is the client's latency,
/// not the backend's. Arming on the false→true `waiting` edge measures
/// contiguous backend-read latency and avoids charging downstream stalls to the
/// backend, which would spuriously time out a healthy-but-flow-controlled
/// stream.
///
/// `backend_read_timeout_ms == 0` keeps the unbounded opt-out: the call sites
/// skip this wrapper entirely in that case.
struct IdleReadTimeoutBody<B> {
    inner: B,
    timeout: std::time::Duration,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    /// Set after the wrapper has returned EOF. This fuses synthetic EOFs (the
    /// H3 trailer-timeout collapse) so a re-poll does not touch the still-live
    /// source and `is_end_stream()` reports terminal state.
    done: bool,
    /// `true` once an inner `Pending` poll has begun a backend-read wait, reset
    /// to `false` whenever a frame is delivered. The deadline is re-armed only
    /// on the `false -> true` edge so it never counts downstream-drain time.
    waiting: bool,
    /// Shared read-progress signal with the inner native-H3 `H3FrameSource`
    /// (`None` for non-H3 paths). Two roles: (1) `epoch` lets the wrapper RESET
    /// its inactivity deadline whenever the backend made progress — a DATA chunk
    /// the coalescer buffered, or FIN — even though no frame was yielded, so a
    /// buffered-but-not-flushed frame is never misread as a stall; (2)
    /// `trailer_phase` makes a fired deadline COLLAPSE to a clean EOS (rather than
    /// error) once the body is complete and only an optional trailer remains
    /// (parity with the buffered drain's `read_h3_trailers_with_timeout`).
    progress: Option<Arc<H3ReadProgress>>,
    /// Last `progress.epoch` observed; a change means backend progress, so the
    /// deadline is reset before the next inactivity wait.
    last_progress_epoch: u64,
}

impl<B> IdleReadTimeoutBody<B> {
    fn new(inner: B, timeout_ms: u64) -> Self {
        Self::with_progress(inner, timeout_ms, None)
    }

    /// Like [`Self::new`] but shares an [`H3ReadProgress`] with the inner
    /// `H3FrameSource`: the deadline resets on backend progress and a fired
    /// deadline collapses to a clean EOS while only optional trailers remain.
    /// See the `progress` field.
    fn with_progress(inner: B, timeout_ms: u64, progress: Option<Arc<H3ReadProgress>>) -> Self {
        let timeout = std::time::Duration::from_millis(timeout_ms);
        let deadline = tokio::time::Instant::now()
            .checked_add(timeout)
            .map(tokio::time::sleep_until)
            .map(Box::pin);
        let last_progress_epoch = progress
            .as_ref()
            .map(|p| p.epoch.load(Ordering::Acquire))
            .unwrap_or(0);
        Self {
            inner,
            timeout,
            deadline,
            done: false,
            waiting: false,
            progress,
            last_progress_epoch,
        }
    }

    fn reset_deadline(&mut self) {
        // `reset_deadline` runs on every "delivered a frame → waiting on the
        // backend again" transition, i.e. once per inter-frame gap on a
        // streaming response — the proxy hot path. Reuse the already-pinned
        // `Sleep` in place (no per-rearm `Box` allocation or timer-wheel
        // churn), matching the original `reset()` behavior, while keeping the
        // overflow guard: a pathologically large client-controlled deadline
        // that exceeds Tokio's representable `Instant` range collapses to
        // `None` (effectively unbounded) instead of panicking the proxy path.
        match tokio::time::Instant::now().checked_add(self.timeout) {
            Some(deadline_at) => match self.deadline.as_mut() {
                Some(sleep) => sleep.as_mut().reset(deadline_at),
                None => self.deadline = Some(Box::pin(tokio::time::sleep_until(deadline_at))),
            },
            None => self.deadline = None,
        }
    }
}

impl<B> http_body::Body for IdleReadTimeoutBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    // `BoxError` (not a concrete enum) because this wrapper is placed OUTERMOST
    // — directly around the `Coalescing` adapter (whose `Error` is already
    // `BoxError`) — rather than inside it. The outermost placement keeps the
    // deadline from elapsing while a buffered sub-target frame waits on a SLOW
    // DOWNSTREAM CLIENT: under client backpressure hyper stops polling this
    // wrapper entirely, and when polling resumes the coalescer delivers the
    // buffered frame as `Ready` (resetting `waiting`) before any deadline check.
    // Placing the timer INSIDE the coalescer would instead let a client-drain
    // stall elapse a deadline armed during an earlier backend-pending — a false
    // positive the outermost placement avoids.
    //
    // Outermost placement cannot see backend progress that the H3 coalescer
    // BUFFERS instead of yielding (a sub-target DATA chunk, or the FIN that ends
    // the body), so the inner `H3FrameSource` shares an `H3ReadProgress` epoch
    // with this wrapper: the `Pending` arm resets the deadline whenever that
    // epoch advances, mirroring the buffered drain where each `recv_data` /
    // `recv_trailers` gets a fresh timeout budget. The epoch advances at chunk
    // RECEIPT, but the coalescer may then hold that chunk for `flush_after`
    // before yielding it (no further epoch bump in that window), so the H3
    // builders ALSO clamp the flush interval below the read timeout
    // (`h3_effective_flush_interval`); the two together ensure a buffered frame
    // is never timed out while it is ready to send. A boxed `dyn Error` does not
    // implement `Error`, but that no
    // longer matters: the wrapper is no longer a `FrameSource` inner, so it needs
    // no concrete error type. The timeout is emitted as a boxed `io::Error` of
    // kind `TimedOut`, which `retry::classify_typed_chain` maps to
    // `ErrorClass::ReadWriteTimeout`.
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                // A backend frame arrived — we are no longer waiting on the
                // backend. Do NOT arm the deadline here: the interval until the
                // next `poll_frame` can be dominated by a slow client draining
                // this frame (H2 flow-control backpressure), which is downstream
                // latency, not backend latency. The deadline is armed on the
                // next `Pending` instead, so it only ever measures contiguous
                // backend-read wait time.
                this.waiting = false;
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => Poll::Ready(Some(Err(e.into()))),
            Poll::Ready(None) => {
                this.done = true;
                Poll::Ready(None)
            }
            Poll::Pending => {
                // Reset the inactivity deadline if the backend made progress
                // since the last poll — a DATA chunk Coalescing BUFFERED (so no
                // frame was yielded above) or the FIN that ends the body —
                // otherwise a frame sitting buffered while the backend is briefly
                // idle would be misread as a stall. Mirrors the buffered drain,
                // where each recv_data / recv_trailers gets a fresh budget.
                if let Some(p) = &this.progress {
                    let epoch = p.epoch.load(Ordering::Acquire);
                    if epoch != this.last_progress_epoch {
                        this.last_progress_epoch = epoch;
                        this.waiting = false;
                    }
                }
                if !this.waiting {
                    // First `Pending` since the last delivered frame or backend
                    // progress: begin the backend-read wait now so any
                    // downstream-drain interval that just elapsed is excluded from
                    // the timeout budget.
                    this.waiting = true;
                    this.reset_deadline();
                }
                match this.deadline.as_mut() {
                    Some(deadline) => match std::future::Future::poll(deadline.as_mut(), cx) {
                        Poll::Ready(()) => {
                            // Collapse to a clean EOS instead of erroring when the
                            // inner H3 source signals the body is complete and only
                            // an optional trailer frame is still pending — parity
                            // with the buffered drain's trailer-timeout collapse.
                            if this
                                .progress
                                .as_ref()
                                .is_some_and(|p| p.trailer_phase.load(Ordering::Acquire))
                            {
                                if let Some(trailers) = this
                                    .progress
                                    .as_ref()
                                    .and_then(|p| p.take_pending_trailers())
                                {
                                    this.done = true;
                                    return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                                }
                                this.done = true;
                                return Poll::Ready(None);
                            }
                            Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                                std::io::ErrorKind::TimedOut,
                                format!(
                                    "backend response body read timeout after {}ms",
                                    this.timeout.as_millis()
                                ),
                            )) as BoxError)))
                        }
                        Poll::Pending => Poll::Pending,
                    },
                    // A pathologically large client-controlled deadline can
                    // exceed Tokio's representable `Instant` range. Treat it as
                    // effectively unbounded rather than panicking the proxy path.
                    None => Poll::Pending,
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done || self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if self.done {
            http_body::SizeHint::with_exact(0)
        } else {
            self.inner.size_hint()
        }
    }
}

/// Wraps a streaming response body with an ABSOLUTE end-to-end deadline that
/// fires at a fixed [`tokio::time::Instant`] regardless of frame cadence.
///
/// Used for the gRPC client-`grpc-timeout` regime (issue #1649). `grpc-timeout`
/// is an end-to-end RPC deadline, so a backend that sends response headers just
/// before the deadline then trickles body frames — each inter-frame gap under a
/// per-frame idle timeout — must still be cut at the client's deadline. The
/// per-frame [`IdleReadTimeoutBody`] cannot bound that: it only measures
/// inter-frame gaps and re-arms on every delivered frame, so a steady trickle
/// (or a continuous fast stream) never trips it. This wrapper arms the timer
/// ONCE and never re-arms, bounding the total streaming duration. The
/// `backend_read_timeout_ms` fallback regime (no client deadline) keeps the
/// per-frame `IdleReadTimeoutBody` instead — the two regimes are distinguished
/// by the dispatch handler from `grpc_proxy::parse_grpc_timeout_ms`.
///
/// `deadline == None` means the client deadline was unrepresentable (a
/// pathologically large `grpc-timeout` overflowing Tokio's `Instant` range);
/// the timer is inert (effectively unbounded) rather than panicking the proxy
/// path, matching the buffered gRPC path's `tokio::time::timeout` behavior.
struct TotalDeadlineBody<B> {
    inner: Option<B>,
    deadline: Option<Pin<Box<tokio::time::Sleep>>>,
    deadline_frame: Option<Frame<Bytes>>,
    deadline_fired: Arc<AtomicBool>,
    saw_data: bool,
    done: bool,
}

impl<B> TotalDeadlineBody<B> {
    fn new(inner: B, deadline: Option<tokio::time::Instant>) -> Self {
        Self::with_deadline_frame(inner, deadline, None, Arc::new(AtomicBool::new(false)))
    }

    fn with_deadline_frame(
        inner: B,
        deadline: Option<tokio::time::Instant>,
        deadline_frame: Option<Frame<Bytes>>,
        deadline_fired: Arc<AtomicBool>,
    ) -> Self {
        Self {
            inner: Some(inner),
            deadline: deadline.map(tokio::time::sleep_until).map(Box::pin),
            deadline_frame,
            deadline_fired,
            saw_data: false,
            done: false,
        }
    }

    fn deadline_fired_handle(&self) -> Arc<AtomicBool> {
        Arc::clone(&self.deadline_fired)
    }
}

impl<B> http_body::Body for TotalDeadlineBody<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: Into<BoxError>,
{
    type Data = Bytes;
    // Boxed error for the same reason as `IdleReadTimeoutBody`: this wrapper sits
    // OUTERMOST around the coalescer (whose `Error` is already `BoxError`). The
    // deadline is emitted as a boxed `io::Error` of kind `TimedOut`, which
    // retains the transport-level timeout signal after partial DATA. The shared
    // `deadline_fired` flag lets the outer `ProxyBody` override that generic
    // classification to a health-neutral client expiry for deferred backend and
    // admission accounting.
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        if this.done {
            return Poll::Ready(None);
        }
        // Check the absolute deadline FIRST and on EVERY poll. Unlike the
        // per-frame idle timer it is armed once and never reset, so it must fire
        // at the client deadline even for a backend that streams frames
        // continuously (which would never yield a `Pending` inner poll to drive
        // an idle check). A `None` deadline (unrepresentable) is inert.
        if let Some(deadline) = this.deadline.as_mut()
            && std::future::Future::poll(deadline.as_mut(), cx).is_ready()
        {
            this.done = true;
            this.deadline = None;
            this.deadline_fired.store(true, Ordering::Release);
            // Cancel upstream work and release its stream/accounting guards as
            // soon as the deadline fires, before the downstream polls again.
            this.inner.take();
            if !this.saw_data {
                if let Some(frame) = this.deadline_frame.take() {
                    return Poll::Ready(Some(Ok(frame)));
                }
                let mut trailers = http::HeaderMap::new();
                trailers.insert(
                    "grpc-status",
                    http::HeaderValue::from_static(GATEWAY_DEADLINE_EXCEEDED_STATUS_HEADER),
                );
                trailers.insert(
                    "grpc-message",
                    http::HeaderValue::from_static(GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER),
                );
                return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
            }
            return Poll::Ready(Some(Err(Box::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "gRPC streaming response exceeded the client grpc-timeout deadline after response data",
            )) as BoxError)));
        }
        let Some(inner) = this.inner.as_mut() else {
            this.done = true;
            return Poll::Ready(None);
        };
        match Pin::new(inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.data_ref().is_some_and(|data| !data.is_empty()) {
                    this.saw_data = true;
                }
                if frame.trailers_ref().is_some() {
                    this.done = true;
                    this.deadline = None;
                    this.inner.take();
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                this.done = true;
                this.deadline = None;
                this.inner.take();
                Poll::Ready(Some(Err(e.into())))
            }
            Poll::Ready(None) => {
                this.done = true;
                this.deadline = None;
                this.inner.take();
                Poll::Ready(None)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done
            || self
                .inner
                .as_ref()
                .is_none_or(http_body::Body::is_end_stream)
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if self.done {
            http_body::SizeHint::with_exact(0)
        } else if self.deadline.is_some() {
            // The deadline may replace the remaining body with native trailers
            // or a differently-sized gRPC-Web terminal DATA frame. Do not let
            // hyper reconstruct the stripped backend Content-Length from an
            // exact inner size hint before that decision is known.
            http_body::SizeHint::default()
        } else {
            self.inner
                .as_ref()
                .map(http_body::Body::size_hint)
                .unwrap_or_else(|| http_body::SizeHint::with_exact(0))
        }
    }
}

struct DirectH3Body<S = crate::http3::client::H3RequestStream> {
    source: H3FrameSource<S>,
    content_length: Option<u64>,
}

impl<S: H3RecvStream + Unpin> http_body::Body for DirectH3Body<S> {
    type Data = Bytes;
    type Error = BoxError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().source).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.source.is_done()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        content_length_hint(self.content_length)
    }
}

pub(crate) fn coalescing_body(
    response: reqwest::Response,
    content_length: Option<u64>,
) -> ProxyBody {
    use futures_util::StreamExt;

    let stream = response
        .bytes_stream()
        .map(|r| r.map(Frame::data).map_err(|e| Box::new(e) as BoxError));
    let body = Coalescing::new(
        ReqwestFrameSource { inner: stream },
        COALESCE_TARGET,
        content_length,
    );
    ProxyBody::streaming(Box::pin(body))
}

pub(crate) fn direct_streaming_body(
    response: reqwest::Response,
    content_length: Option<u64>,
) -> ProxyBody {
    use futures_util::StreamExt;

    let stream = response
        .bytes_stream()
        .map(|r| r.map(Frame::data).map_err(|e| Box::new(e) as BoxError));
    let body = DirectStreamBody {
        inner: stream,
        content_length,
    };
    ProxyBody::streaming(Box::pin(body))
}

/// Build a streaming response body fed by [`run_response_inspection`] over an
/// mpsc channel.
///
/// The inspection task drives a plugin's per-chunk [`ResponseStreamInspector`]
/// and sends the bytes to release; this body passes them through to the client
/// unmodified — **no coalescing**, because the inspector already releases
/// coherent windows and `inspect` mode exists to preserve low-latency streaming
/// (re-coalescing would batch windows and defeat that). It is the poll/async
/// bridge for H1/H2: the async inspection runs in a detached task while this
/// poll-based body just drains the channel.
pub(crate) fn inspected_streaming_body(
    rx: tokio::sync::mpsc::Receiver<Result<Frame<Bytes>, BoxError>>,
) -> ProxyBody {
    let stream = tokio_stream::wrappers::ReceiverStream::new(rx);
    let body = DirectStreamBody {
        inner: stream,
        content_length: None,
    };
    ProxyBody::streaming(Box::pin(body))
}

/// Drive a streaming-response [`crate::plugins::ResponseStreamInspector`] over a
/// reqwest backend response, forwarding released bytes to `tx` (which backs an
/// [`inspected_streaming_body`]).
///
/// Spawned as a detached task so async inspection (which may call the embedding
/// provider) runs independently of the poll-based downstream body. Owns the
/// backend connection guards, so they release exactly when streaming ends —
/// backend EOF, a policy `Terminate`, a backend error, or the client dropping
/// the receiver (`tx.send` then fails and the task returns, dropping the backend
/// stream). A policy cut ends the body cleanly (EOF), not as an error.
///
/// `max_response_body_size_bytes` (`0` = unlimited) bounds total bytes received
/// from the backend, mirroring the non-inspected `size_limited_streaming_body`
/// path: an SSE response that exceeds it is terminated with a body error rather
/// than forwarded unbounded just because each window was clean.
pub(crate) async fn run_response_inspection(
    response: reqwest::Response,
    mut inspector: Box<dyn crate::plugins::ResponseStreamInspector>,
    tx: tokio::sync::mpsc::Sender<Result<Frame<Bytes>, BoxError>>,
    max_response_body_size_bytes: usize,
    _reqwest_backend_guard: Option<crate::runtime_metrics::ReqwestBackendRequestGuard>,
    _lb_connection_guard: super::LoadBalancerConnectionGuard,
) {
    use crate::plugins::ResponseStreamAction;
    use futures_util::StreamExt;

    let mut stream = response.bytes_stream();
    let mut total_received: usize = 0;
    loop {
        // Watch for client disconnect WHILE awaiting the next backend chunk: an
        // idle long-lived SSE stream may not produce another chunk for a long
        // time (or ever), and without this the backend connection + LB guard would
        // stay open until a chunk or read timeout arrives. `tx.closed()` resolves
        // as soon as the downstream body drops the receiver; returning here drops
        // `stream` (cancelling the backend request) and the guards.
        let chunk = tokio::select! {
            biased;
            _ = tx.closed() => return,
            next = stream.next() => next,
        };
        let Some(chunk) = chunk else { break };
        match chunk {
            Ok(bytes) => {
                total_received = total_received.saturating_add(bytes.len());
                if max_response_body_size_bytes > 0 && total_received > max_response_body_size_bytes
                {
                    // Operator response-size cap exceeded: stop and surface a body
                    // error, instead of forwarding an unbounded stream. Use the
                    // SAME message as the non-inspected size-limited path so
                    // `classify_body_error` tags it `ResponseBodyTooLarge`.
                    let _ = tx
                        .send(Err(Box::<dyn std::error::Error + Send + Sync>::from(
                            "response body exceeds maximum size",
                        ) as BoxError))
                        .await;
                    return;
                }
                let action = tokio::select! {
                    biased;
                    _ = tx.closed() => return,
                    action = inspector.on_chunk(&bytes) => action,
                };
                match action {
                    ResponseStreamAction::Forward(out) => {
                        if !out.is_empty() && tx.send(Ok(Frame::data(out))).await.is_err() {
                            return; // client dropped the receiver
                        }
                    }
                    ResponseStreamAction::Terminate(final_bytes) => {
                        if let Some(fb) = final_bytes
                            && !fb.is_empty()
                        {
                            let _ = tx.send(Ok(Frame::data(fb))).await;
                        }
                        return; // drop tx → downstream EOF; drop stream → cancel backend
                    }
                }
            }
            Err(e) => {
                let _ = tx.send(Err(Box::new(e) as BoxError)).await;
                return;
            }
        }
    }
    // Backend stream ended cleanly: flush / inspect the trailing partial window.
    let action = tokio::select! {
        biased;
        _ = tx.closed() => return,
        action = inspector.on_end() => action,
    };
    match action {
        ResponseStreamAction::Forward(out) => {
            if !out.is_empty() {
                let _ = tx.send(Ok(Frame::data(out))).await;
            }
        }
        ResponseStreamAction::Terminate(final_bytes) => {
            if let Some(fb) = final_bytes
                && !fb.is_empty()
            {
                let _ = tx.send(Ok(Frame::data(fb))).await;
            }
        }
    }
}

/// Drive a response-stream inspector over an already constructed proxy body.
///
/// This is the transport-independent counterpart of [`run_response_inspection`]
/// for direct HTTP/2 and native HTTP/3 backend responses. The source body keeps
/// its protocol-specific timeout and trailer filtering (plus source-side size
/// limiting where that transport builder requires it); this task owns it and
/// the least-connections guard until backend EOF, policy termination, error, or
/// downstream cancellation. Deferred admission and dispatch outcomes remain on
/// the client-visible outer body. DATA frames are held until the inspector
/// releases them, while sanitized trailer frames pass through unchanged on a
/// clean stream. This driver independently caps released inspector output, so
/// expansion and terminal events cannot bypass the operator limit.
pub(crate) async fn run_proxy_body_response_inspection(
    mut body: ProxyBody,
    mut inspector: Box<dyn crate::plugins::ResponseStreamInspector>,
    tx: tokio::sync::mpsc::Sender<Result<Frame<Bytes>, BoxError>>,
    max_response_body_size_bytes: usize,
    _lb_connection_guard: super::LoadBalancerConnectionGuard,
) {
    use crate::plugins::ResponseStreamAction;
    use http_body_util::BodyExt;

    let mut trailing_frame: Option<Frame<Bytes>> = None;
    let mut emitted_bytes: usize = 0;
    loop {
        let frame = tokio::select! {
            biased;
            _ = tx.closed() => return,
            next = body.frame() => next,
        };
        let Some(frame) = frame else { break };
        match frame {
            Ok(frame) => match frame.into_data() {
                Ok(bytes) => match tokio::select! {
                    biased;
                    _ = tx.closed() => return,
                    action = inspector.on_chunk(&bytes) => action,
                } {
                    ResponseStreamAction::Forward(out) => {
                        if !out.is_empty() {
                            if max_response_body_size_bytes > 0
                                && emitted_bytes.saturating_add(out.len())
                                    > max_response_body_size_bytes
                            {
                                let _ = tx
                                    .send(Err(Box::<dyn std::error::Error + Send + Sync>::from(
                                        "response body exceeds maximum size",
                                    ) as BoxError))
                                    .await;
                                return;
                            }
                            emitted_bytes = emitted_bytes.saturating_add(out.len());
                            if tx.send(Ok(Frame::data(out))).await.is_err() {
                                return;
                            }
                        }
                    }
                    ResponseStreamAction::Terminate(final_bytes) => {
                        if let Some(bytes) = final_bytes
                            && !bytes.is_empty()
                        {
                            if max_response_body_size_bytes > 0
                                && emitted_bytes.saturating_add(bytes.len())
                                    > max_response_body_size_bytes
                            {
                                let _ = tx
                                    .send(Err(Box::<dyn std::error::Error + Send + Sync>::from(
                                        "response body exceeds maximum size",
                                    ) as BoxError))
                                    .await;
                                return;
                            }
                            let _ = tx.send(Ok(Frame::data(bytes))).await;
                        }
                        return;
                    }
                },
                Err(frame) => {
                    // A trailing frame must stay behind bytes the inspector is
                    // still holding for `on_end()`. Sending trailers now and a
                    // final released DATA frame afterward would violate HTTP
                    // frame ordering. Policy termination deliberately drops it.
                    trailing_frame = Some(frame);
                }
            },
            Err(error) => {
                let _ = tx.send(Err(error)).await;
                return;
            }
        }
    }

    let action = tokio::select! {
        biased;
        _ = tx.closed() => return,
        action = inspector.on_end() => action,
    };
    match action {
        ResponseStreamAction::Forward(out) => {
            if !out.is_empty() {
                if max_response_body_size_bytes > 0
                    && emitted_bytes.saturating_add(out.len()) > max_response_body_size_bytes
                {
                    let _ = tx
                        .send(Err(Box::<dyn std::error::Error + Send + Sync>::from(
                            "response body exceeds maximum size",
                        ) as BoxError))
                        .await;
                    return;
                }
                if tx.send(Ok(Frame::data(out))).await.is_err() {
                    return;
                }
            }
            if let Some(frame) = trailing_frame {
                let _ = tx.send(Ok(frame)).await;
            }
        }
        ResponseStreamAction::Terminate(final_bytes) => {
            if let Some(bytes) = final_bytes
                && !bytes.is_empty()
            {
                if max_response_body_size_bytes > 0
                    && emitted_bytes.saturating_add(bytes.len()) > max_response_body_size_bytes
                {
                    let _ = tx
                        .send(Err(Box::<dyn std::error::Error + Send + Sync>::from(
                            "response body exceeds maximum size",
                        ) as BoxError))
                        .await;
                    return;
                }
                let _ = tx.send(Ok(Frame::data(bytes))).await;
            }
        }
    }
}

/// HTTP/2 streaming body wrapped in a [`StripHopByHopTrailers`] filter so
/// hop-by-hop names (RFC 9110 §7.6.1, response-direction set) cannot leak
/// downstream via TRAILERS frames. Used for the gRPC streaming response path
/// — gRPC always rides on HTTP/2 and the backend's `grpc-status` /
/// `grpc-message` arrive as trailers, so a backend that puts `connection`,
/// `keep-alive`, `proxy-authenticate`, or `proxy-connection` in the trailer
/// map would otherwise punch a hole in the proxy boundary. See
/// `proxy::headers::is_backend_response_strip_header`.
///
/// The wrapper is interposed BEFORE the `Coalescing` adapter so the stash-
/// then-flush trailer logic in `Coalescing<Incoming>` still works on the
/// already-filtered map.
pub(crate) fn coalescing_h2_body_strip_hop_by_hop_trailers(
    body: Incoming,
    content_length: Option<u64>,
    coalesce_target: usize,
    read_timeout_ms: u64,
    total_deadline: Option<tokio::time::Instant>,
) -> ProxyBody {
    // Bound the backend read so a backend that sends headers then stalls cannot
    // pin the streaming relay indefinitely. Two mutually-exclusive regimes
    // (issue #1649): `total_deadline` (a client `grpc-timeout`) is an ABSOLUTE
    // end-to-end deadline via `TotalDeadlineBody`; otherwise `read_timeout_ms`
    // (`backend_read_timeout_ms`) is a PER-FRAME idle timeout via
    // `IdleReadTimeoutBody`. Either deadline wraps the coalescer OUTERMOST (not
    // the raw body inside it): the coalescer only reports `Pending` once it has
    // no buffered frame left to flush AND the backend is pending, so a per-frame
    // idle deadline measures genuine backend-read waits and never fires while a
    // sub-target frame is buffered waiting on a slow downstream client.
    let stripped = StripHopByHopTrailers::new(body);
    let coalescing = Coalescing::new(stripped, coalesce_target, content_length);
    if let Some(deadline) = total_deadline {
        let timed = TotalDeadlineBody::new(coalescing, Some(deadline));
        let fired = timed.deadline_fired_handle();
        ProxyBody::streaming(Box::pin(timed)).with_client_grpc_deadline_fired_flag(fired)
    } else if read_timeout_ms > 0 {
        ProxyBody::streaming(Box::pin(IdleReadTimeoutBody::new(
            coalescing,
            read_timeout_ms,
        )))
    } else {
        ProxyBody::streaming(Box::pin(coalescing))
    }
}

/// Size-limited coalescing HTTP/2 streaming body with hop-by-hop trailer
/// stripping. Used by the gRPC streaming response path when
/// `max_response_body_size_bytes > 0` to enforce the operator's size cap on
/// streaming gRPC responses.
pub(crate) fn size_limited_coalescing_h2_body_strip_hop_by_hop_trailers(
    body: Incoming,
    max_bytes: usize,
    content_length: Option<u64>,
    coalesce_target: usize,
    read_timeout_ms: u64,
    total_deadline: Option<tokio::time::Instant>,
) -> ProxyBody {
    // See `coalescing_h2_body_strip_hop_by_hop_trailers` for the two
    // mutually-exclusive deadline regimes (issue #1649). Either wraps the
    // coalescer OUTERMOST so a per-frame idle deadline never fires while a
    // buffered sub-target frame is waiting on a slow downstream client.
    let stripped = StripHopByHopTrailers::new(body);
    let limited = SizeLimitedFrameSource::new(stripped, max_bytes);
    let coalescing = Coalescing::new(limited, coalesce_target, content_length);
    if let Some(deadline) = total_deadline {
        let timed = TotalDeadlineBody::new(coalescing, Some(deadline));
        let fired = timed.deadline_fired_handle();
        ProxyBody::streaming(Box::pin(timed)).with_client_grpc_deadline_fired_flag(fired)
    } else if read_timeout_ms > 0 {
        ProxyBody::streaming(Box::pin(IdleReadTimeoutBody::new(
            coalescing,
            read_timeout_ms,
        )))
    } else {
        ProxyBody::streaming(Box::pin(coalescing))
    }
}

/// Direct (non-coalesced) HTTP/2 streaming body wrapped in
/// [`StripHopByHopTrailers`]. Counterpart of
/// [`coalescing_h2_body_strip_hop_by_hop_trailers`] for the gRPC streaming
/// path's `response_buffer_cutoff_bytes == 0 && max_response_body_size_bytes
/// == 0` zero-buffering branch.
pub(crate) fn direct_streaming_h2_body_strip_hop_by_hop_trailers(
    body: Incoming,
    content_length: Option<u64>,
    read_timeout_ms: u64,
    total_deadline: Option<tokio::time::Instant>,
) -> ProxyBody {
    use http_body_util::BodyExt;

    let direct = DirectH2Body {
        inner: body,
        content_length,
    };
    // The direct path has no coalescing buffer, so the deadline can wrap the
    // direct body directly — `Strip` forwards frames without buffering. Both
    // `TotalDeadlineBody` (absolute client `grpc-timeout`, issue #1649) and
    // `IdleReadTimeoutBody` (per-frame `backend_read_timeout_ms`) already yield
    // `BoxError`, so no `map_err` is needed in those branches.
    if let Some(deadline) = total_deadline {
        let timed = TotalDeadlineBody::new(direct, Some(deadline));
        let fired = timed.deadline_fired_handle();
        let stripped = StripHopByHopTrailers::new(timed);
        ProxyBody::streaming(Box::pin(stripped)).with_client_grpc_deadline_fired_flag(fired)
    } else if read_timeout_ms > 0 {
        let timed = IdleReadTimeoutBody::new(direct, read_timeout_ms);
        let stripped = StripHopByHopTrailers::new(timed);
        ProxyBody::streaming(Box::pin(stripped))
    } else {
        let stripped = StripHopByHopTrailers::new(direct);
        ProxyBody::streaming(Box::pin(stripped.map_err(|e| Box::new(e) as BoxError)))
    }
}

/// A body wrapper that filters hop-by-hop response headers out of any
/// [`Frame::trailers`] frames as they pass through. DATA frames pass
/// through unchanged. The predicate is
/// [`crate::proxy::headers::is_backend_response_strip_header`] (RFC 9110
/// §7.6.1, response-direction set: `connection`, `keep-alive`,
/// `proxy-authenticate`, `proxy-connection`, `te`, `trailer`,
/// `transfer-encoding`, `upgrade`).
///
/// This is intentionally generic over any body whose `Data` is `Bytes` so
/// the same wrapper can be composed over `hyper::body::Incoming`,
/// `DirectH2Body`, or future stream types — there is one strip predicate
/// and one filter implementation, regardless of dispatch path.
///
/// The wrapper preserves the `Frame::trailers` shape even when the strip
/// would leave the trailer map empty, because hyper's HTTP/2 server-side
/// writer still needs the END_STREAM trailers signal. An empty trailer
/// frame is functionally equivalent to "no trailers" on the wire and
/// matches what hyper does when a backend emits an empty trailer frame
/// natively, so this is safe.
pub(crate) struct StripHopByHopTrailers<B> {
    inner: B,
}

impl<B> StripHopByHopTrailers<B> {
    pub(crate) fn new(inner: B) -> Self {
        Self { inner }
    }
}

impl<B> http_body::Body for StripHopByHopTrailers<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
{
    type Data = Bytes;
    type Error = B::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(Some(Ok(frame))) => {
                if frame.is_trailers() {
                    let mut trailers = match frame.into_trailers() {
                        Ok(map) => map,
                        // Frame reported `is_trailers()` so this branch is
                        // unreachable; preserve the frame defensively.
                        Err(other) => return Poll::Ready(Some(Ok(other))),
                    };
                    crate::proxy::headers::strip_response_hop_by_hop_trailers(&mut trailers);
                    Poll::Ready(Some(Ok(Frame::trailers(trailers))))
                } else {
                    Poll::Ready(Some(Ok(frame)))
                }
            }
            other => other,
        }
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        self.inner.size_hint()
    }
}

// `StripHopByHopTrailers<B>` is also a `FrameSource` so it composes
// directly into `Coalescing<S>`. The production wrapper interposes
// `StripHopByHopTrailers<Incoming>` before `Coalescing` on the gRPC
// streaming response path; the test harness composes it over
// `FrameSourceAsBody<MockSource>`. Both satisfy the `B::Error: Error`
// bound (`hyper::Error` and `std::io::Error` respectively), so the
// single generic impl covers both call sites.
impl<B> FrameSource for StripHopByHopTrailers<B>
where
    B: http_body::Body<Data = Bytes> + Unpin,
    B::Error: std::error::Error + Send + Sync + 'static,
{
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        match http_body::Body::poll_frame(self, cx) {
            Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
            Poll::Ready(Some(Err(err))) => Poll::Ready(Some(Err(Box::new(err) as BoxError))),
            Poll::Ready(None) => Poll::Ready(None),
            Poll::Pending => Poll::Pending,
        }
    }
}

/// Clamp the H3 coalescer flush interval so a buffered sub-target frame always
/// flushes BEFORE the outer [`IdleReadTimeoutBody`] read deadline could fire.
///
/// `Coalescing` (with `flush_after`) returns `Pending` while holding a sub-target
/// frame awaiting its flush timer; the outer idle timer treats that as a
/// backend-read wait. With `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` configured
/// at/above `backend_read_timeout_ms`, the deadline could fire before the flush
/// timer releases an already-ready frame, aborting the response as a backend
/// read timeout even though a frame was ready to send (#1940 review). Capping the
/// flush at half the read timeout guarantees the flush wins. `read_timeout_ms == 0`
/// (unbounded) keeps the configured interval; sane configs (e.g. a 2 ms flush vs
/// a 30 s timeout) are unaffected.
///
/// This is kept ALONGSIDE the `H3ReadProgress` epoch reset, not in place of it:
/// the epoch re-arms the deadline when a chunk is RECEIVED, but `Coalescing` can
/// then hold that chunk for up to `flush_after` before yielding it, and no new
/// backend event bumps the epoch during that window — so the clamp is what keeps
/// a late-arriving sub-target frame from being timed out while it sits buffered
/// (#1940 round-5 review).
fn h3_effective_flush_interval(flush_interval: Duration, read_timeout_ms: u64) -> Duration {
    if read_timeout_ms == 0 {
        return flush_interval;
    }
    flush_interval.min(Duration::from_millis(read_timeout_ms) / 2)
}

/// Allocate the [`H3ReadProgress`] shared between `H3FrameSource` and the outer
/// [`IdleReadTimeoutBody`]. `Some` only when a read timeout is configured (and
/// thus an `IdleReadTimeoutBody` actually wraps the body); `None` otherwise,
/// since with no timeout there is no deadline to reset or collapse.
fn h3_read_progress(read_timeout_ms: u64) -> Option<Arc<H3ReadProgress>> {
    (read_timeout_ms > 0).then(|| Arc::new(H3ReadProgress::default()))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn coalescing_h3_body(
    recv_stream: crate::http3::client::H3RequestStream,
    method: Arc<str>,
    status: u16,
    content_length: Option<u64>,
    coalesce_min_bytes: usize,
    coalesce_max_bytes: usize,
    flush_interval: Duration,
    read_timeout_ms: u64,
) -> ProxyBody {
    let progress = h3_read_progress(read_timeout_ms);
    let source = H3FrameSource::new(
        recv_stream,
        method,
        status,
        content_length,
        progress.clone(),
    );
    let buffer_capacity = coalesce_max_bytes.clamp(
        crate::http3::config::H3_COALESCE_MIN_FLOOR,
        crate::http3::config::H3_COALESCE_MAX_CAP,
    );
    let target_bytes =
        coalesce_min_bytes.clamp(crate::http3::config::H3_COALESCE_MIN_FLOOR, buffer_capacity);
    let body = Coalescing::with_flush_after_and_capacity(
        source,
        target_bytes,
        buffer_capacity,
        content_length,
        Some(h3_effective_flush_interval(flush_interval, read_timeout_ms)),
    );
    match progress {
        Some(p) => ProxyBody::streaming(Box::pin(IdleReadTimeoutBody::with_progress(
            body,
            read_timeout_ms,
            Some(p),
        ))),
        None => ProxyBody::streaming(Box::pin(body)),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn size_limited_streaming_h3_body(
    recv_stream: crate::http3::client::H3RequestStream,
    max_bytes: usize,
    method: Arc<str>,
    status: u16,
    content_length: Option<u64>,
    coalesce_min_bytes: usize,
    coalesce_max_bytes: usize,
    flush_interval: Duration,
    read_timeout_ms: u64,
) -> ProxyBody {
    let progress = h3_read_progress(read_timeout_ms);
    let source = H3FrameSource::new(
        recv_stream,
        method,
        status,
        content_length,
        progress.clone(),
    );
    let limited = SizeLimitedFrameSource::new(source, max_bytes);
    let buffer_capacity = coalesce_max_bytes.clamp(
        crate::http3::config::H3_COALESCE_MIN_FLOOR,
        crate::http3::config::H3_COALESCE_MAX_CAP,
    );
    let target_bytes =
        coalesce_min_bytes.clamp(crate::http3::config::H3_COALESCE_MIN_FLOOR, buffer_capacity);
    let body = Coalescing::with_flush_after_and_capacity(
        limited,
        target_bytes,
        buffer_capacity,
        content_length,
        Some(h3_effective_flush_interval(flush_interval, read_timeout_ms)),
    );
    match progress {
        Some(p) => ProxyBody::streaming(Box::pin(IdleReadTimeoutBody::with_progress(
            body,
            read_timeout_ms,
            Some(p),
        ))),
        None => ProxyBody::streaming(Box::pin(body)),
    }
}

pub(crate) fn direct_streaming_h3_body(
    recv_stream: crate::http3::client::H3RequestStream,
    method: Arc<str>,
    status: u16,
    content_length: Option<u64>,
    read_timeout_ms: u64,
) -> ProxyBody {
    let progress = h3_read_progress(read_timeout_ms);
    let body = DirectH3Body {
        source: H3FrameSource::new(
            recv_stream,
            method,
            status,
            content_length,
            progress.clone(),
        ),
        content_length,
    };
    match progress {
        Some(p) => ProxyBody::streaming(Box::pin(IdleReadTimeoutBody::with_progress(
            body,
            read_timeout_ms,
            Some(p),
        ))),
        None => ProxyBody::streaming(Box::pin(body)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::Stream;
    use futures_util::task::noop_waker;
    use http_body::Body;
    use std::collections::VecDeque;

    enum MockStep {
        Frame(Result<Frame<Bytes>, BoxError>),
        End,
        Pending,
    }

    struct MockSource {
        steps: VecDeque<MockStep>,
    }

    impl MockSource {
        fn new(steps: Vec<MockStep>) -> Self {
            Self {
                steps: steps.into(),
            }
        }
    }

    struct DropTrackedPendingBody {
        drops: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl Drop for DropTrackedPendingBody {
        fn drop(&mut self) {
            self.drops
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        }
    }

    impl http_body::Body for DropTrackedPendingBody {
        type Data = Bytes;
        type Error = BoxError;

        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            Poll::Pending
        }
    }

    enum MockH3DataStep {
        Data(Bytes),
        End,
        Pending,
    }

    enum MockH3TrailerStep {
        Trailers(http::HeaderMap),
        End,
        Pending,
        PendingWithBuffered(http::HeaderMap),
    }

    struct MockH3RecvStream {
        data_steps: VecDeque<MockH3DataStep>,
        trailer_steps: VecDeque<MockH3TrailerStep>,
        buffered_trailers: Option<http::HeaderMap>,
    }

    impl MockH3RecvStream {
        fn new(data_steps: Vec<MockH3DataStep>, trailer_steps: Vec<MockH3TrailerStep>) -> Self {
            Self {
                data_steps: data_steps.into(),
                trailer_steps: trailer_steps.into(),
                buffered_trailers: None,
            }
        }
    }

    impl H3RecvStream for MockH3RecvStream {
        fn poll_recv_data_bytes(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Option<Bytes>, BoxError>> {
            match self
                .get_mut()
                .data_steps
                .pop_front()
                .unwrap_or(MockH3DataStep::End)
            {
                MockH3DataStep::Data(bytes) => Poll::Ready(Ok(Some(bytes))),
                MockH3DataStep::End => Poll::Ready(Ok(None)),
                MockH3DataStep::Pending => Poll::Pending,
            }
        }

        fn poll_recv_trailers_map(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Result<Option<http::HeaderMap>, BoxError>> {
            let this = self.get_mut();
            match this
                .trailer_steps
                .pop_front()
                .unwrap_or(MockH3TrailerStep::End)
            {
                MockH3TrailerStep::Trailers(trailers) => Poll::Ready(Ok(Some(trailers))),
                MockH3TrailerStep::End => Poll::Ready(Ok(None)),
                MockH3TrailerStep::Pending => Poll::Pending,
                MockH3TrailerStep::PendingWithBuffered(trailers) => {
                    this.buffered_trailers = Some(trailers);
                    Poll::Pending
                }
            }
        }

        fn peek_recv_trailers_map(&self) -> Result<Option<http::HeaderMap>, BoxError> {
            Ok(self.buffered_trailers.clone())
        }
    }

    impl FrameSource for MockSource {
        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
            match self.get_mut().steps.pop_front().unwrap_or(MockStep::End) {
                MockStep::Frame(frame) => Poll::Ready(Some(frame)),
                MockStep::End => Poll::Ready(None),
                MockStep::Pending => Poll::Pending,
            }
        }
    }

    impl Stream for MockSource {
        type Item = Result<Frame<Bytes>, BoxError>;

        fn poll_next(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
            match self.get_mut().steps.pop_front().unwrap_or(MockStep::End) {
                MockStep::Frame(frame) => Poll::Ready(Some(frame)),
                MockStep::End => Poll::Ready(None),
                MockStep::Pending => Poll::Pending,
            }
        }
    }

    #[rustfmt::skip]
    fn poll_all<B: http_body::Body<Data = Bytes, Error = BoxError> + Unpin>(body: &mut B) -> Vec<Result<Frame<Bytes>, BoxError>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut frames = Vec::new();
        while let Poll::Ready(Some(frame)) = Pin::new(&mut *body).poll_frame(&mut cx) {
            frames.push(frame);
        }
        frames
    }

    #[rustfmt::skip]
    fn poll_source<S: FrameSource + Unpin>(
        source: &mut S,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        Pin::new(source).poll_frame(&mut cx)
    }

    #[test]
    fn reqwest_frame_source_forwards_data_trailer_and_end() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());

        let mut source = ReqwestFrameSource {
            inner: MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from("hello")))),
                MockStep::Frame(Ok(Frame::trailers(trailers))),
                MockStep::End,
            ]),
        };

        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"hello");
            }
            other => panic!("expected first data frame, got {other:?}"),
        }

        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                let trailers = frame.trailers_ref().expect("expected trailers frame");
                assert_eq!(trailers.get("grpc-status").unwrap(), "0");
            }
            other => panic!("expected trailer frame, got {other:?}"),
        }

        assert!(matches!(poll_source(&mut source), Poll::Ready(None)));
    }

    #[test]
    fn size_limited_frame_source_errors_before_forwarding_oversized_frame() {
        let mut source = SizeLimitedFrameSource::new(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from_static(b"1234")))),
                MockStep::Frame(Ok(Frame::data(Bytes::from_static(b"5678")))),
                MockStep::End,
            ]),
            6,
        );

        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"1234");
            }
            other => panic!("expected first frame within limit, got {other:?}"),
        }

        match poll_source(&mut source) {
            Poll::Ready(Some(Err(err))) => {
                assert_eq!(err.to_string(), "response body exceeds maximum size");
            }
            other => panic!("expected size-limit error before oversized frame, got {other:?}"),
        }
    }

    #[test]
    fn coalescing_buffer_fills_to_threshold() {
        let mut body = Coalescing::new(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from(vec![1u8; 4])))),
                MockStep::Frame(Ok(Frame::data(Bytes::from(vec![2u8; 4])))),
                MockStep::Frame(Ok(Frame::data(Bytes::from(vec![3u8; 4])))),
                MockStep::End,
            ]),
            10,
            None,
        );

        let frames = poll_all(&mut body);
        assert_eq!(frames.len(), 1);
        let first = frames[0].as_ref().unwrap().data_ref().unwrap().len();
        assert_eq!(first, 12);
        assert!(first >= 10);
    }

    #[test]
    fn coalescing_trailer_with_buffered_data_flushes_data_first() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());

        let mut body = Coalescing::new(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from("hello")))),
                MockStep::Frame(Ok(Frame::trailers(trailers))),
                MockStep::End,
            ]),
            100,
            None,
        );

        let frames = poll_all(&mut body);
        assert_eq!(frames.len(), 2);
        assert!(frames[0].as_ref().unwrap().data_ref().is_some());
        let trailer_map = frames[1]
            .as_ref()
            .unwrap()
            .trailers_ref()
            .expect("expected trailer frame");
        assert_eq!(trailer_map.get("grpc-status").unwrap(), "0");
    }

    #[test]
    fn coalescing_trailer_with_empty_buffer_emits_immediately() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());

        let mut body = Coalescing::new(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::trailers(trailers))),
                MockStep::End,
            ]),
            100,
            None,
        );

        let frames = poll_all(&mut body);
        assert_eq!(frames.len(), 1);
        assert!(frames[0].as_ref().unwrap().trailers_ref().is_some());
    }

    #[test]
    fn coalescing_error_with_buffered_data_flushes_data_first() {
        let err = std::io::Error::other("backend reset");
        let mut body = Coalescing::new(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from("hello")))),
                MockStep::Frame(Err(Box::new(err))),
            ]),
            100,
            None,
        );

        let frames = poll_all(&mut body);
        assert_eq!(frames.len(), 2);
        assert_eq!(
            frames[0].as_ref().unwrap().data_ref().unwrap().as_ref(),
            b"hello"
        );
        let err = frames[1].as_ref().expect_err("expected stashed error");
        assert_eq!(err.to_string(), "backend reset");
    }

    #[test]
    fn coalescing_end_of_stream_flushes_partial_buffer() {
        let mut body = Coalescing::new(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from("partial")))),
                MockStep::End,
            ]),
            1_000,
            None,
        );

        let frames = poll_all(&mut body);
        assert_eq!(frames.len(), 1);
        assert_eq!(
            frames[0].as_ref().unwrap().data_ref().unwrap().as_ref(),
            b"partial"
        );
    }

    #[tokio::test]
    async fn coalescing_flush_after_waits_for_timer() {
        let mut body = Box::pin(Coalescing::with_flush_after(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from("tail")))),
                MockStep::Pending,
            ]),
            1_000,
            None,
            Some(Duration::from_millis(2)),
        ));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(body.as_mut().poll_frame(&mut cx), Poll::Pending));

        tokio::time::sleep(Duration::from_millis(5)).await;

        match body.as_mut().poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"tail");
            }
            other => panic!("expected timer-driven flush, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn coalescing_flush_timer_rearms_after_expiry() {
        // Simulate: frame A arrives (timer armed), timer fires, buffer flushed,
        // then frames B+C arrive into a non-empty buffer. The timer must be
        // re-armed after the first flush so B+C are flushed by the timer
        // rather than sitting in the buffer indefinitely.
        let mut body = Box::pin(Coalescing::with_flush_after(
            MockSource::new(vec![
                // Phase 1: single frame, then source stalls.
                MockStep::Frame(Ok(Frame::data(Bytes::from("aaa")))),
                MockStep::Pending,
                // Phase 2: two frames in rapid succession, then source stalls.
                MockStep::Frame(Ok(Frame::data(Bytes::from("bbb")))),
                MockStep::Frame(Ok(Frame::data(Bytes::from("ccc")))),
                MockStep::Pending,
            ]),
            1_000, // high threshold — never hit by these small frames
            None,
            Some(Duration::from_millis(2)),
        ));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Phase 1: poll buffers "aaa", returns Pending (timer not yet expired).
        assert!(matches!(body.as_mut().poll_frame(&mut cx), Poll::Pending));

        // Let the timer fire.
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Timer-driven flush of "aaa".
        match body.as_mut().poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"aaa");
            }
            other => panic!("expected timer-driven flush of phase-1 data, got {other:?}"),
        }

        // Phase 2: next poll picks up "bbb" and "ccc", then source stalls.
        // Timer must be re-armed for this new batch.
        assert!(matches!(body.as_mut().poll_frame(&mut cx), Poll::Pending));

        // Let the re-armed timer fire.
        tokio::time::sleep(Duration::from_millis(5)).await;

        // Timer-driven flush of "bbb"+"ccc".
        match body.as_mut().poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"bbbccc");
            }
            other => panic!("expected timer-driven flush of phase-2 data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn coalescing_empty_frame_does_not_stale_arm_flush_timer() {
        let mut body = Box::pin(Coalescing::with_flush_after(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::new()))),
                MockStep::Pending,
                MockStep::Frame(Ok(Frame::data(Bytes::from("real")))),
                MockStep::Pending,
            ]),
            1_000,
            None,
            Some(Duration::from_millis(2)),
        ));

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(body.as_mut().poll_frame(&mut cx), Poll::Pending));
        tokio::time::sleep(Duration::from_millis(5)).await;

        assert!(
            matches!(body.as_mut().poll_frame(&mut cx), Poll::Pending),
            "real data after an empty frame must arm a fresh timer instead of inheriting the stale one"
        );

        tokio::time::sleep(Duration::from_millis(5)).await;
        match body.as_mut().poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"real");
            }
            other => panic!("expected timer-driven flush of real data, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn coalescing_append_to_unarmed_non_empty_buffer_arms_flush_timer() {
        let mut body = Box::pin(Coalescing::with_flush_after(
            MockSource::new(vec![MockStep::Pending]),
            1_000,
            None,
            Some(Duration::from_millis(2)),
        ));

        body.buffer.extend_from_slice(b"stashed-");
        assert!(!body.buffer.is_empty());
        assert!(!body.flush_timer_armed);

        body.buffer_data(&Bytes::from_static(b"tail"));
        assert!(body.flush_timer_armed);

        tokio::time::sleep(Duration::from_millis(5)).await;

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        match body.as_mut().poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"stashed-tail");
            }
            other => panic!("expected timer-driven flush from rearmed buffer, got {other:?}"),
        }
    }

    #[test]
    fn into_tracked_swaps_stream_kind_to_tracked_and_drives_metrics() {
        use std::time::Instant;

        // Build a streaming ProxyBody from a coalescing source over the
        // shared MockSource — this is the same path the production
        // reqwest dispatch takes (`coalescing_body` → `Coalescing<S>`).
        let mock = MockSource::new(vec![
            MockStep::Frame(Ok(Frame::data(Bytes::from("alpha")))),
            MockStep::Frame(Ok(Frame::data(Bytes::from("beta")))),
            MockStep::End,
        ]);
        let inner = Coalescing::new(mock, COALESCE_TARGET, None);
        let base = ProxyBody::streaming(Box::pin(inner));
        assert!(matches!(base.kind, ProxyBodyKind::Stream(_)));

        let baseline = Instant::now();
        let (mut tracked, metrics) = base.into_tracked(baseline);

        // Kind transitioned Stream → Tracked.
        assert!(matches!(tracked.kind, ProxyBodyKind::Tracked(_)));

        // Drive the body to completion via repeated polls.
        let mut frames: Vec<Bytes> = Vec::new();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        loop {
            match Pin::new(&mut tracked).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        frames.push(data.clone());
                    }
                }
                Poll::Ready(Some(Err(e))) => panic!("unexpected error: {e:?}"),
                Poll::Ready(None) => break,
                Poll::Pending => panic!("MockSource never returns Pending here"),
            }
        }

        // Coalescer batched both data frames into a single buffered output.
        assert_eq!(frames.len(), 1, "coalescer should fold both frames");
        assert_eq!(&frames[0][..], b"alphabeta");

        // Metrics observed completion via TrackedBody's poll_frame.
        assert!(metrics.completed());
        assert!(metrics.last_frame_elapsed_ms().is_some());
    }

    #[test]
    fn into_tracked_on_already_tracked_body_is_noop() {
        use std::time::Instant;

        // First wrap: Stream → Tracked drives the original metrics.
        let mock = MockSource::new(vec![MockStep::End]);
        let inner = Coalescing::new(mock, COALESCE_TARGET, None);
        let base = ProxyBody::streaming(Box::pin(inner));

        let baseline_a = Instant::now();
        let (tracked, metrics_a) = base.into_tracked(baseline_a);
        assert!(matches!(tracked.kind, ProxyBodyKind::Tracked(_)));

        // Second wrap: Tracked → Tracked must be a no-op. The kind stays
        // `Tracked` (the inner `TrackedBody` keeps reporting into
        // `metrics_a`); the freshly-allocated `metrics_b` is inert.
        let baseline_b = Instant::now();
        let (rewrapped, metrics_b) = tracked.into_tracked(baseline_b);
        assert!(matches!(rewrapped.kind, ProxyBodyKind::Tracked(_)));
        assert!(!Arc::ptr_eq(&metrics_a, &metrics_b));
        assert_eq!(Arc::strong_count(&metrics_b), 1);
    }

    #[test]
    fn h3_frame_source_transitions_from_data_to_trailers_to_done() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());

        let mut source = H3FrameSource::new(
            MockH3RecvStream::new(
                vec![
                    MockH3DataStep::Pending,
                    MockH3DataStep::Data(Bytes::from("chunk")),
                    MockH3DataStep::End,
                ],
                vec![
                    MockH3TrailerStep::Pending,
                    MockH3TrailerStep::Trailers(trailers),
                ],
            ),
            Arc::from("GET"),
            200,
            None,
            None,
        );

        assert!(matches!(poll_source(&mut source), Poll::Pending));
        assert!(!source.is_done());

        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"chunk");
                assert!(!source.is_done());
            }
            other => panic!("expected first data frame, got {other:?}"),
        }

        assert!(matches!(poll_source(&mut source), Poll::Pending));
        assert!(!source.is_done());

        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                let trailers = frame.trailers_ref().expect("expected trailers frame");
                assert_eq!(trailers.get("grpc-status").unwrap(), "0");
                assert!(source.is_done());
            }
            other => panic!("expected trailer frame, got {other:?}"),
        }

        assert!(matches!(poll_source(&mut source), Poll::Ready(None)));
    }

    #[test]
    fn h3_frame_source_strips_hop_by_hop_trailers_and_preserves_frame() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("x-custom-trailer", "ok".parse().unwrap());
        trailers.insert("connection", "close".parse().unwrap());
        trailers.insert("keep-alive", "timeout=5".parse().unwrap());
        trailers.insert(
            "proxy-authenticate",
            "Basic realm=internal".parse().unwrap(),
        );
        trailers.insert("transfer-encoding", "chunked".parse().unwrap());

        let mut source = H3FrameSource::new(
            MockH3RecvStream::new(
                vec![MockH3DataStep::End],
                vec![MockH3TrailerStep::Trailers(trailers)],
            ),
            Arc::from("GET"),
            200,
            None,
            None,
        );

        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                let trailers = frame.trailers_ref().expect("expected trailers frame");
                assert_eq!(trailers.get("grpc-status").unwrap(), "0");
                assert_eq!(trailers.get("x-custom-trailer").unwrap(), "ok");
                for hop_by_hop in [
                    "connection",
                    "keep-alive",
                    "proxy-authenticate",
                    "transfer-encoding",
                ] {
                    assert!(
                        trailers.get(hop_by_hop).is_none(),
                        "hop-by-hop H3 trailer `{hop_by_hop}` must be stripped",
                    );
                }
                assert!(source.is_done());
            }
            other => panic!("expected stripped trailer frame, got {other:?}"),
        }
    }

    #[test]
    fn h3_frame_source_emits_empty_trailer_frame_when_all_hop_by_hop() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("connection", "close".parse().unwrap());
        trailers.insert("keep-alive", "timeout=5".parse().unwrap());

        let mut source = H3FrameSource::new(
            MockH3RecvStream::new(
                vec![MockH3DataStep::End],
                vec![MockH3TrailerStep::Trailers(trailers)],
            ),
            Arc::from("GET"),
            200,
            None,
            None,
        );

        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                let trailers = frame.trailers_ref().expect("expected trailers frame");
                assert!(trailers.is_empty(), "all hop-by-hop trailers stripped");
            }
            other => panic!("expected empty trailer frame, got {other:?}"),
        }
    }

    #[test]
    fn h3_frame_source_bumps_progress_and_flags_trailer_phase_on_fin() {
        // Each DATA chunk bumps `epoch` (so a buffered chunk resets the outer
        // inactivity clock), and a clean FIN bumps `epoch` AND sets
        // `trailer_phase` (so the outer re-arms a fresh trailer budget and a fired
        // deadline then collapses to a clean EOS). An available trailer is still
        // delivered (polled before any collapse).
        let progress = Arc::new(H3ReadProgress::default());
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trace", "abc".parse().unwrap());
        let mut source = H3FrameSource::new(
            MockH3RecvStream::new(
                vec![
                    MockH3DataStep::Data(Bytes::from("body")),
                    MockH3DataStep::End,
                ],
                vec![
                    MockH3TrailerStep::Pending,
                    MockH3TrailerStep::Trailers(trailers),
                ],
            ),
            Arc::from("GET"),
            200,
            Some(4),
            Some(Arc::clone(&progress)),
        );

        // DATA frame: bumps epoch, still in the DATA phase (no collapse flag).
        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"body");
            }
            other => panic!("expected data frame, got {other:?}"),
        }
        assert_eq!(
            progress.epoch.load(Ordering::Acquire),
            1,
            "a DATA chunk must bump the progress epoch",
        );
        assert!(
            !progress.trailer_phase.load(Ordering::Acquire),
            "DATA phase must not flag trailer-collapse",
        );

        // recv_data End → Trailers: FIN bumps epoch AND sets trailer_phase.
        assert!(matches!(poll_source(&mut source), Poll::Pending));
        assert_eq!(
            progress.epoch.load(Ordering::Acquire),
            2,
            "FIN must bump the progress epoch (re-arm the trailer budget)",
        );
        assert!(
            progress.trailer_phase.load(Ordering::Acquire),
            "a clean FIN must flag the trailer phase for collapse-on-timeout",
        );

        // The now-available trailer frame is delivered, never dropped.
        match poll_source(&mut source) {
            Poll::Ready(Some(Ok(frame))) => {
                let t = frame.trailers_ref().expect("trailer frame");
                assert_eq!(t.get("x-trace").unwrap(), "abc");
            }
            other => panic!("expected trailer frame, got {other:?}"),
        }
        assert!(source.is_done());
    }

    #[test]
    fn h3_frame_source_truncated_fin_surfaces_error() {
        // A backend that declares Content-Length but FINs early (fewer bytes) is a
        // framing violation: the FIN must surface a backend error (not enter the
        // trailer phase and be laundered into a clean EOS). Native-H3 dispatch
        // accounting is intentionally eager until #1901, so this streaming
        // validation preserves client-visible framing correctness rather than
        // training backend health.
        let progress = Arc::new(H3ReadProgress::default());
        let mut source = H3FrameSource::new(
            MockH3RecvStream::new(
                vec![
                    MockH3DataStep::Data(Bytes::from("body")),
                    MockH3DataStep::End,
                ],
                vec![MockH3TrailerStep::Pending],
            ),
            Arc::from("GET"),
            200,
            Some(8), // declares 8 bytes but only 4 ("body") are sent → truncated
            Some(Arc::clone(&progress)),
        );

        // DATA frame (4 bytes) is delivered, then the FIN surfaces the truncation.
        assert!(matches!(poll_source(&mut source), Poll::Ready(Some(Ok(_)))));
        match poll_source(&mut source) {
            Poll::Ready(Some(Err(e))) => {
                let io = e
                    .downcast_ref::<std::io::Error>()
                    .expect("truncated FIN surfaces an io::Error");
                assert_eq!(io.kind(), std::io::ErrorKind::UnexpectedEof);
            }
            other => panic!("expected truncation error, got {other:?}"),
        }
        // The truncation never enters the trailer phase.
        assert!(
            !progress.trailer_phase.load(Ordering::Acquire),
            "a truncated FIN must surface an error, not flag the trailer phase",
        );
        assert!(source.is_done());
    }

    #[test]
    fn h3_frame_source_fin_delimited_body_flags_trailer_collapse() {
        // A FIN-delimited body (no Content-Length, i.e. chunked/streaming) is
        // COMPLETE once it cleanly FINs, so collapse-on-timeout IS enabled — a
        // subsequent trailer timeout / graceful close forwards the complete
        // response without trailers, matching the buffered drain (#1940 review).
        let progress = Arc::new(H3ReadProgress::default());
        let mut source = H3FrameSource::new(
            MockH3RecvStream::new(
                vec![
                    MockH3DataStep::Data(Bytes::from("body")),
                    MockH3DataStep::End,
                ],
                vec![MockH3TrailerStep::Pending],
            ),
            Arc::from("GET"),
            200,
            None, // no Content-Length → FIN-delimited, complete on FIN
            Some(Arc::clone(&progress)),
        );
        assert!(matches!(poll_source(&mut source), Poll::Ready(Some(Ok(_)))));
        assert!(matches!(poll_source(&mut source), Poll::Pending));
        assert!(
            progress.trailer_phase.load(Ordering::Acquire),
            "a FIN-delimited (no Content-Length) body must enable trailer-collapse",
        );
    }

    #[tokio::test]
    async fn idle_read_timeout_collapses_to_eos_in_trailer_phase() {
        // With `trailer_phase` set (H3 body complete, only an optional trailer
        // still pending), a fired read deadline COLLAPSES to a clean EOS instead
        // of erroring — parity with the buffered drain's trailer-timeout collapse.
        let progress = Arc::new(H3ReadProgress::default());
        progress.enter_trailer_phase(); // body complete, only trailers pending
        let inner = Coalescing::new(
            MockSource::new(vec![
                MockStep::Pending,
                MockStep::Pending,
                MockStep::Pending,
            ]),
            100,
            None,
        );
        let mut body = IdleReadTimeoutBody::with_progress(inner, 1, Some(Arc::clone(&progress)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Pending
        ));
        // Real-time margin; Tokio timers never fire early (no `test-util`).
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(None)
        ));
        assert!(
            body.is_end_stream(),
            "collapsed trailer-timeout EOF must report terminal state"
        );
        assert_eq!(body.size_hint().exact(), Some(0));
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[tokio::test]
    async fn idle_read_timeout_forwards_buffered_h3_trailers_before_delayed_fin() {
        let progress = Arc::new(H3ReadProgress::default());
        let mut trailers = http::HeaderMap::new();
        trailers.insert("x-trace", "abc".parse().unwrap());
        trailers.insert("transfer-encoding", "chunked".parse().unwrap());

        let source = H3FrameSource::new(
            MockH3RecvStream::new(
                vec![
                    MockH3DataStep::Data(Bytes::from("body")),
                    MockH3DataStep::End,
                ],
                vec![
                    MockH3TrailerStep::PendingWithBuffered(trailers),
                    MockH3TrailerStep::Pending,
                ],
            ),
            Arc::from("GET"),
            200,
            Some(4),
            Some(Arc::clone(&progress)),
        );
        let direct = DirectH3Body {
            source,
            content_length: Some(4),
        };
        let mut body = IdleReadTimeoutBody::with_progress(direct, 1, Some(Arc::clone(&progress)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        match Pin::new(&mut body).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                assert_eq!(frame.data_ref().unwrap().as_ref(), b"body");
            }
            other => panic!("expected data frame, got {other:?}"),
        }
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Pending
        ));
        assert!(
            progress.trailer_phase.load(Ordering::Acquire),
            "body FIN must put the source into trailer phase",
        );

        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        match Pin::new(&mut body).poll_frame(&mut cx) {
            Poll::Ready(Some(Ok(frame))) => {
                let trailers = frame.trailers_ref().expect("expected trailer frame");
                assert_eq!(trailers.get("x-trace").unwrap(), "abc");
                assert!(
                    trailers.get("transfer-encoding").is_none(),
                    "hop-by-hop trailers must still be stripped before timeout forwarding",
                );
            }
            other => panic!("expected buffered trailers on timeout, got {other:?}"),
        }
        assert!(body.is_end_stream());
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(None)
        ));
    }

    #[tokio::test]
    async fn idle_read_timeout_errors_on_data_phase_stall() {
        // No trailer phase (a genuine DATA-phase stall, or a non-H3 path) → a
        // fired deadline is a real read-timeout error, not a silent EOS.
        let progress = Arc::new(H3ReadProgress::default()); // trailer_phase = false
        let inner = Coalescing::new(
            MockSource::new(vec![
                MockStep::Pending,
                MockStep::Pending,
                MockStep::Pending,
            ]),
            100,
            None,
        );
        let mut body = IdleReadTimeoutBody::with_progress(inner, 1, Some(Arc::clone(&progress)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Pending
        ));
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        let Poll::Ready(Some(Err(e))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("expected a read-timeout error on a DATA-phase stall");
        };
        let io = e
            .downcast_ref::<std::io::Error>()
            .expect("read timeout must be an io::Error");
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn idle_read_timeout_resets_deadline_on_buffered_backend_progress() {
        // Backend progress the coalescer BUFFERS (no frame yielded) bumps the
        // shared epoch; the wrapper must reset its inactivity deadline so the
        // progress is not misread as a stall (#1940 review). Without the reset, a
        // 30ms deadline would fire at ~40ms despite real progress at ~20ms.
        let progress = Arc::new(H3ReadProgress::default());
        let inner = Coalescing::new(
            MockSource::new(vec![
                MockStep::Pending,
                MockStep::Pending,
                MockStep::Pending,
                MockStep::Pending,
            ]),
            100,
            None,
        );
        let mut body = IdleReadTimeoutBody::with_progress(inner, 30, Some(Arc::clone(&progress)));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        // Arm the 30ms deadline.
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Pending
        ));
        // Backend makes progress (a chunk the coalescer buffered) at ~20ms...
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        progress.record_backend_progress();
        // ...then wait past the ORIGINAL 30ms deadline (now ~40ms total).
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
        // The epoch advance reset the deadline, so this is still Pending — NOT a
        // false read-timeout error.
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Pending
        ));
    }

    // ── StripHopByHopTrailers ───────────────────────────────────────────────
    //
    // The wrapper sits between the backend body (`Incoming`, `DirectH2Body`,
    // any `Body<Data = Bytes>`) and the downstream-facing layer (`Coalescing`
    // for the gRPC streaming response, or directly into `ProxyBody` for the
    // small-buffer fast path). It must:
    //
    //   1. Strip RFC 9110 §7.6.1 response-direction hop-by-hop names from
    //      `Frame::trailers` frames as they pass through.
    //   2. Pass DATA frames through unchanged — no copy, no reorder.
    //   3. Preserve legitimate gRPC trailers (`grpc-status`, `grpc-message`,
    //      `grpc-status-details-bin`, custom `x-*` trailers).
    //
    // We exercise it via a small helper that wraps a `MockSource`-backed body.
    // `MockSource` only impls `FrameSource`, not `http_body::Body`, so we use
    // a thin shim that adapts `FrameSource` to `Body`. The shim is local to
    // the test mod — it would be unused in production.

    use std::marker::PhantomData;

    /// Adapter: any `FrameSource` becomes a `Body<Data = Bytes>`. Used by
    /// tests to feed a synthetic frame stream into `StripHopByHopTrailers`
    /// without needing a real `Incoming`. Errors use `std::io::Error` —
    /// `Sized + Error + Send + Sync` — so the wrapper composes with
    /// `Coalescing<S>` via the test-only `FrameSource` impl below.
    struct FrameSourceAsBody<S> {
        inner: S,
        _marker: PhantomData<()>,
    }

    impl<S: FrameSource + Unpin> http_body::Body for FrameSourceAsBody<S> {
        type Data = Bytes;
        type Error = std::io::Error;

        fn poll_frame(
            self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
            match Pin::new(&mut self.get_mut().inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => Poll::Ready(Some(Ok(frame))),
                Poll::Ready(Some(Err(_))) => {
                    Poll::Ready(Some(Err(std::io::Error::other("test FrameSource error"))))
                }
                Poll::Ready(None) => Poll::Ready(None),
                Poll::Pending => Poll::Pending,
            }
        }
    }

    fn make_strip_wrapper(
        steps: Vec<MockStep>,
    ) -> StripHopByHopTrailers<FrameSourceAsBody<MockSource>> {
        let body = FrameSourceAsBody {
            inner: MockSource::new(steps),
            _marker: PhantomData,
        };
        StripHopByHopTrailers::new(body)
    }

    /// Drive a `Body` to `Ready(None)`, returning the collected frames.
    /// Generic over `Error: Display` so the same helper handles both
    /// `Error = std::io::Error` (the test `FrameSourceAsBody`) and
    /// `Error = BoxError` (the Coalescing wrapper). Errors are recorded as
    /// their `Display` rendering — none of the tests below intentionally
    /// emit errors.
    fn poll_all_strip<B>(body: &mut B) -> Vec<Frame<Bytes>>
    where
        B: http_body::Body<Data = Bytes> + Unpin,
        B::Error: std::fmt::Display,
    {
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let mut frames = Vec::new();
        loop {
            match Pin::new(&mut *body).poll_frame(&mut cx) {
                Poll::Ready(Some(Ok(frame))) => frames.push(frame),
                Poll::Ready(Some(Err(e))) => panic!("unexpected body error: {e}"),
                Poll::Ready(None) => return frames,
                Poll::Pending => panic!("MockSource never returns Pending here"),
            }
        }
    }

    // --- SyncBody trait-bound assertions -------------------------------------
    //
    // The `unsafe impl<B: Send + Sync> Sync for SyncBody<B>` claim below is
    // future-proofed by these compile-time assertions. They will fail to
    // build if either:
    //   1. The bound on `SyncBody`'s `Sync` impl is loosened back to just
    //      `B: Send` AND a future caller wraps a `!Sync` body (latent UB).
    //   2. A current call-site type (`SizeLimitedIncoming`, `CountingIncoming`)
    //      gains a `!Sync` field, breaking the assumption that all current
    //      callers happen to satisfy the tighter bound.
    //
    // The negative case is enforced by a `must_be_sync<T: Sync>` helper that
    // would refuse to monomorphize over a `!Sync` body. See `phantom_not_sync`
    // below for the local witness type used by the tests.
    fn must_be_sync<T: Sync>() {}
    fn must_be_send<T: Send>() {}

    #[test]
    fn sync_body_preserves_send_sync_for_current_callers() {
        // Both wrapped types must remain `Send + Sync` — they are the only
        // current consumers of `SyncBody::new(...)` (in `into_reqwest_body`).
        must_be_send::<SyncBody<SizeLimitedIncoming>>();
        must_be_sync::<SyncBody<SizeLimitedIncoming>>();
        must_be_send::<SyncBody<CountingIncoming>>();
        must_be_sync::<SyncBody<CountingIncoming>>();
    }

    #[test]
    fn per_ip_request_guard_releases_only_when_proxy_body_drops() {
        // F15 regression: streaming gRPC now attaches the PerIpRequestGuard to
        // the ProxyBody (via with_per_ip_request_guard) so the per-IP concurrency
        // slot is held for the FULL streaming-response lifetime instead of being
        // released at response-header time (the limit-evasion this PR closes).
        // This pins the guard->body lifetime coupling that the fix relies on: the
        // count must stay held while the body is alive and decrement exactly once
        // when the body drops (stream completion or client-disconnect Drop).
        use std::sync::Arc;
        use std::sync::atomic::{AtomicU64, Ordering};

        let ip = "203.0.113.7".to_string();
        let counts: Arc<dashmap::DashMap<String, AtomicU64>> = Arc::new(dashmap::DashMap::new());
        counts.insert(ip.clone(), AtomicU64::new(1));
        let load = || counts.get(&ip).unwrap().value().load(Ordering::Relaxed);

        let guard = crate::proxy::PerIpRequestGuard {
            ip: ip.clone(),
            counts: Arc::clone(&counts),
        };

        // Attaching the guard to the body must NOT release the slot.
        let body = ProxyBody::full(Bytes::from_static(b"streaming-grpc-response"))
            .with_per_ip_request_guard(guard);
        assert_eq!(load(), 1, "slot must stay held while the body is alive");

        // The slot is released only when the body (and thus its guard) drops.
        drop(body);
        assert_eq!(
            load(),
            0,
            "dropping the body must release the per-IP slot exactly once"
        );
    }

    /// A `Send`-but-`!Sync` witness body. Used purely for compile-time
    /// negative tests below — the inclusion of a `Cell<()>` field makes
    /// the type `!Sync` while leaving it `Send`.
    ///
    /// If the `Sync` bound on `SyncBody` is ever loosened to `B: Send`,
    /// `must_be_sync::<SyncBody<NotSyncBody>>()` would compile, signaling
    /// the latent unsoundness has returned.
    struct NotSyncBody {
        _marker: std::cell::Cell<()>,
    }

    impl http_body::Body for NotSyncBody {
        type Data = Bytes;
        type Error = BoxError;
        fn poll_frame(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
        ) -> Poll<Option<Result<Frame<Bytes>, Self::Error>>> {
            Poll::Ready(None)
        }
    }

    #[test]
    fn strip_hop_by_hop_trailers_passes_through_data_frames_unchanged() {
        let mut body = make_strip_wrapper(vec![
            MockStep::Frame(Ok(Frame::data(Bytes::from("hello")))),
            MockStep::Frame(Ok(Frame::data(Bytes::from(" world")))),
            MockStep::End,
        ]);

        let frames = poll_all_strip(&mut body);
        assert_eq!(frames.len(), 2);
        assert_eq!(frames[0].data_ref().unwrap().as_ref(), b"hello");
        assert_eq!(frames[1].data_ref().unwrap().as_ref(), b" world");
    }

    #[test]
    fn sync_body_drops_trailer_frames_on_request_streaming_path() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("authorization", "Bearer attacker".parse().unwrap());

        let inner = FrameSourceAsBody {
            inner: MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from("body")))),
                MockStep::Frame(Ok(Frame::trailers(trailers))),
                MockStep::End,
            ]),
            _marker: PhantomData,
        };
        let mut body = SyncBody::new(inner);

        let frames = poll_all_strip(&mut body);
        assert_eq!(
            frames.len(),
            1,
            "request trailer frames must not be forwarded by SyncBody",
        );
        assert_eq!(frames[0].data_ref().unwrap().as_ref(), b"body");
    }

    #[test]
    fn strip_hop_by_hop_trailers_removes_connection_close_from_trailer_map() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("grpc-message", "ok".parse().unwrap());
        // Hop-by-hop directives a malicious / misbehaving backend might emit:
        trailers.insert("connection", "close".parse().unwrap());
        trailers.insert(
            "proxy-authenticate",
            "Basic realm=internal".parse().unwrap(),
        );
        trailers.insert("keep-alive", "timeout=5".parse().unwrap());
        trailers.insert("transfer-encoding", "chunked".parse().unwrap());
        trailers.insert("upgrade", "h2c".parse().unwrap());
        trailers.insert("proxy-connection", "close".parse().unwrap());
        trailers.insert("te", "trailers".parse().unwrap());
        trailers.insert("trailer", "grpc-status".parse().unwrap());

        let mut body = make_strip_wrapper(vec![
            MockStep::Frame(Ok(Frame::trailers(trailers))),
            MockStep::End,
        ]);

        let frames = poll_all_strip(&mut body);
        assert_eq!(frames.len(), 1, "exactly one trailer frame after strip");
        let trailer_map = frames[0].trailers_ref().expect("expected trailer frame");
        assert_eq!(
            trailer_map.get("grpc-status").map(|v| v.to_str().unwrap()),
            Some("0"),
            "grpc-status must be preserved",
        );
        assert_eq!(
            trailer_map.get("grpc-message").map(|v| v.to_str().unwrap()),
            Some("ok"),
            "grpc-message must be preserved",
        );
        for hop_by_hop in [
            "connection",
            "proxy-authenticate",
            "keep-alive",
            "transfer-encoding",
            "upgrade",
            "proxy-connection",
            "te",
            "trailer",
        ] {
            assert!(
                trailer_map.get(hop_by_hop).is_none(),
                "hop-by-hop trailer `{hop_by_hop}` must be stripped",
            );
        }
    }

    #[test]
    fn strip_hop_by_hop_trailers_preserves_grpc_and_custom_trailers() {
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("grpc-message", "ok".parse().unwrap());
        trailers.insert("grpc-status-details-bin", "abc==".parse().unwrap());
        trailers.insert("x-custom-trailer", "v".parse().unwrap());
        trailers.insert("x-trace-id", "abc-123".parse().unwrap());

        let mut body = make_strip_wrapper(vec![
            MockStep::Frame(Ok(Frame::trailers(trailers))),
            MockStep::End,
        ]);

        let frames = poll_all_strip(&mut body);
        assert_eq!(frames.len(), 1);
        let trailer_map = frames[0].trailers_ref().expect("expected trailer frame");
        assert_eq!(trailer_map.len(), 5, "all legitimate trailers preserved");
        for name in [
            "grpc-status",
            "grpc-message",
            "grpc-status-details-bin",
            "x-custom-trailer",
            "x-trace-id",
        ] {
            assert!(
                trailer_map.get(name).is_some(),
                "legitimate trailer `{name}` must be preserved",
            );
        }
    }

    #[test]
    fn strip_hop_by_hop_trailers_emits_empty_trailer_frame_when_all_stripped() {
        // Edge case: backend trailer map contained ONLY hop-by-hop names.
        // After strip, the trailer map is empty. We still emit the trailer
        // frame so hyper signals END_STREAM to the client; an empty trailer
        // map is functionally equivalent to "no trailers" on the wire.
        let mut trailers = http::HeaderMap::new();
        trailers.insert("connection", "close".parse().unwrap());
        trailers.insert("keep-alive", "timeout=5".parse().unwrap());

        let mut body = make_strip_wrapper(vec![
            MockStep::Frame(Ok(Frame::trailers(trailers))),
            MockStep::End,
        ]);

        let frames = poll_all_strip(&mut body);
        assert_eq!(frames.len(), 1);
        let trailer_map = frames[0].trailers_ref().expect("expected trailer frame");
        assert!(trailer_map.is_empty(), "all hop-by-hop names stripped");
    }

    #[test]
    fn strip_hop_by_hop_trailers_composes_with_coalescing() {
        // The production gRPC streaming dispatch wraps `Incoming` in
        // `StripHopByHopTrailers`, then in `Coalescing<S>`. Verify the
        // stash-then-flush trailer logic in `Coalescing` still works on the
        // already-stripped trailer map: data frames must be flushed BEFORE
        // the trailer frame is emitted, even when the strip leaves the
        // trailer map non-empty.
        let mut trailers = http::HeaderMap::new();
        trailers.insert("grpc-status", "0".parse().unwrap());
        trailers.insert("connection", "close".parse().unwrap()); // stripped

        let stripped = make_strip_wrapper(vec![
            MockStep::Frame(Ok(Frame::data(Bytes::from("first")))),
            MockStep::Frame(Ok(Frame::data(Bytes::from("second")))),
            MockStep::Frame(Ok(Frame::trailers(trailers))),
            MockStep::End,
        ]);
        let mut body = Coalescing::new(stripped, 100, None);

        let frames = poll_all_strip(&mut body);
        // Coalescer batched both data frames into one buffered output, then
        // emitted the (stripped) trailer frame.
        assert_eq!(frames.len(), 2, "data flushed before trailer frame");
        assert_eq!(frames[0].data_ref().unwrap().as_ref(), b"firstsecond",);
        let trailer_map = frames[1].trailers_ref().expect("expected trailer frame");
        assert_eq!(trailer_map.get("grpc-status").unwrap(), "0");
        assert!(
            trailer_map.get("connection").is_none(),
            "hop-by-hop name stripped before reaching Coalescing",
        );
    }

    #[tokio::test]
    async fn idle_read_timeout_pathological_deadline_never_panics() {
        // A client-controlled `grpc-timeout` (e.g. `18446744073709551615m`)
        // reaches the streaming response body as `u64::MAX` ms. Whether
        // `Instant::now() + Duration::from_millis(u64::MAX)` overflows is
        // platform-dependent: it overflows on macOS/Windows (where `Instant`
        // spans only ~584 years) but NOT on Linux (where `Instant` is backed by
        // `CLOCK_MONOTONIC` and spans billions of years). The guard must never
        // panic on either platform — an unrepresentable deadline collapses to
        // `None` (effectively unbounded), a representable one arms a live timer.
        let overflows = tokio::time::Instant::now()
            .checked_add(std::time::Duration::from_millis(u64::MAX))
            .is_none();

        let inner = Coalescing::new(MockSource::new(vec![MockStep::Pending]), 100, None);
        let mut body = IdleReadTimeoutBody::new(inner, u64::MAX);
        assert_eq!(
            body.deadline.is_none(),
            overflows,
            "deadline must be None exactly when the platform `Instant` range overflows",
        );

        // Polling a pending inner must stay live (Pending) without panicking on
        // either platform: either the (far-future) timer is pending, or the
        // unbounded `None` arm returns Pending and relies on the inner waker.
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(Pin::new(&mut body).poll_frame(&mut cx), Poll::Pending),
            "pathological deadline must poll Pending, never panic or time out",
        );
        // The first `Pending` poll began the backend-read wait and re-armed the
        // deadline via `reset_deadline()`, which must hold the same
        // representability invariant without panicking.
        assert!(
            body.waiting,
            "first Pending poll must begin the backend-read wait",
        );
        assert_eq!(
            body.deadline.is_none(),
            overflows,
            "reset_deadline() must preserve the representability invariant",
        );
    }

    #[tokio::test]
    async fn idle_read_timeout_representable_deadline_arms_live_timer() {
        // A normal, representable timeout must still arm a live deadline so the
        // idle-read watchdog continues to bound stalled backends.
        let inner = Coalescing::new(MockSource::new(vec![MockStep::Pending]), 100, None);
        let body = IdleReadTimeoutBody::new(inner, 1_000);
        assert!(
            body.deadline.is_some(),
            "a representable timeout must arm a live deadline",
        );
    }

    #[tokio::test]
    async fn total_deadline_body_emits_status_four_trailers_before_response_data() {
        // A deadline already in the past fires on the first poll regardless of
        // the inner's state — the absolute cap is checked before the inner, so
        // it bounds the stream independent of frame cadence, the case a per-frame
        // idle timer can never catch because it re-arms on every frame (#1649).
        // (Uses an already-elapsed instant rather than Tokio's paused-time test
        // clock, which requires the `test-util` feature this crate does not
        // enable.)
        let deadline = tokio::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(3600))
            .expect("an hour before now is representable");
        let inner = Coalescing::new(MockSource::new(vec![MockStep::Pending]), 100, None);
        let mut body = TotalDeadlineBody::new(inner, Some(deadline));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let polled = Pin::new(&mut body).poll_frame(&mut cx);
        let Poll::Ready(Some(Ok(frame))) = polled else {
            panic!("expected terminal gRPC trailers for an already-elapsed deadline");
        };
        let trailers = frame.trailers_ref().expect("deadline frame is trailers");
        assert_eq!(trailers.get("grpc-status").unwrap(), "4");
        assert_eq!(
            trailers.get("grpc-message").unwrap(),
            GATEWAY_DEADLINE_EXCEEDED_MESSAGE_HEADER
        );
        assert!(body.is_end_stream(), "deadline trailers terminate the body");
    }

    #[tokio::test]
    async fn total_deadline_body_cancels_upstream_exactly_once_before_emitting_trailers() {
        let drops = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let deadline = tokio::time::Instant::now()
            .checked_sub(std::time::Duration::from_secs(1))
            .expect("one second before now is representable");
        let mut body = TotalDeadlineBody::new(
            DropTrackedPendingBody {
                drops: std::sync::Arc::clone(&drops),
            },
            Some(deadline),
        );
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);

        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("elapsed deadline must emit terminal trailers");
        };
        assert!(frame.trailers_ref().is_some());
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "upstream body must be cancelled before the trailer is returned"
        );
        assert!(matches!(
            Pin::new(&mut body).poll_frame(&mut cx),
            Poll::Ready(None)
        ));
        drop(body);
        assert_eq!(
            drops.load(std::sync::atomic::Ordering::Relaxed),
            1,
            "terminal polls and wrapper drop must not cancel upstream twice"
        );
    }

    #[tokio::test]
    async fn total_deadline_body_errors_after_response_data() {
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
        let inner = Coalescing::new(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from_static(b"partial")))),
                MockStep::Pending,
            ]),
            100,
            None,
        );
        let mut body = TotalDeadlineBody::new(inner, Some(deadline));
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("expected the response data before deadline expiry");
        };
        assert_eq!(frame.data_ref().unwrap(), &Bytes::from_static(b"partial"));

        body.deadline = Some(Box::pin(tokio::time::sleep_until(
            tokio::time::Instant::now()
                .checked_sub(std::time::Duration::from_secs(1))
                .expect("one second before now is representable"),
        )));
        let Poll::Ready(Some(Err(error))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("partial response expiry must abort with a transport error");
        };
        let io = error
            .downcast_ref::<std::io::Error>()
            .expect("deadline error must be an io::Error");
        assert_eq!(io.kind(), std::io::ErrorKind::TimedOut);
    }

    #[tokio::test]
    async fn total_deadline_body_none_is_unbounded() {
        // An unrepresentable client deadline collapses to None and must be inert
        // (effectively unbounded): the wrapper injects no timeout and simply
        // reflects the inner's Pending.
        let inner = Coalescing::new(MockSource::new(vec![MockStep::Pending]), 100, None);
        let mut body = TotalDeadlineBody::new(inner, None);
        assert!(body.deadline.is_none());

        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(
            matches!(Pin::new(&mut body).poll_frame(&mut cx), Poll::Pending),
            "a None deadline must never inject a timeout",
        );
    }

    #[tokio::test]
    async fn total_deadline_body_passes_frames_before_deadline() {
        // A stream that completes before a far-future deadline forwards its
        // frames and ends cleanly — the deadline never interferes.
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(3600);
        let inner = Coalescing::new(
            MockSource::new(vec![
                MockStep::Frame(Ok(Frame::data(Bytes::from("hello")))),
                MockStep::End,
            ]),
            100,
            None,
        );
        let mut body = TotalDeadlineBody::new(inner, Some(deadline));
        let frames = poll_all(&mut body);
        assert_eq!(frames.len(), 1, "one data frame, then clean end-of-stream");
        assert_eq!(
            frames[0].as_ref().unwrap().data_ref().unwrap().as_ref(),
            b"hello",
        );
    }

    #[test]
    fn not_sync_body_is_indeed_send_but_not_sync() {
        // Sanity: confirm the witness type has the expected trait shape.
        // (`NotSyncBody` is `Send` because `Cell<()>` is `Send`, but `!Sync`.)
        must_be_send::<NotSyncBody>();
        // The next line would refuse to compile — it is the negative test:
        //
        //     must_be_sync::<NotSyncBody>();
        //     must_be_sync::<SyncBody<NotSyncBody>>();
        //
        // Both are commented out. Uncommenting them will produce
        // `the trait bound `std::cell::Cell<()>: Sync` is not satisfied`,
        // which is the desired guarantee: the tightened bound on the
        // `unsafe impl Sync for SyncBody<B>` block correctly refuses to
        // synthesize `Sync` for a `!Sync` inner body.
    }

    /// Compile-fail witness: forcibly attempting `SyncBody<NotSyncBody>: Sync`
    /// must NOT compile. Gated under `#[cfg(any())]` so it is parsed for
    /// syntactic correctness but never actually monomorphized — the gate
    /// keeps the test in source as documentation of the bound's intent
    /// without breaking `cargo test`. Flip the gate to `#[cfg(test)]` (or
    /// remove it) to manually verify the bound's negative case: it should
    /// produce `the trait bound `std::cell::Cell<()>: Sync` is not satisfied`.
    #[cfg(any())]
    fn _compile_fail_sync_body_over_not_sync() {
        must_be_sync::<SyncBody<NotSyncBody>>();
    }
}
