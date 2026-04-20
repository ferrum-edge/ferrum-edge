//! Proxy response body type that supports both buffered and streaming modes.
//!
//! [`ProxyBody`] is a sum type over [`Full<Bytes>`] (buffered) and a boxed
//! streaming body. The buffered variant is zero-cost (no allocation beyond
//! the data itself); the streaming variant allocates one `Box` to erase the
//! concrete stream type.

use bytes::{Bytes, BytesMut};
use http_body::Frame;
use http_body_util::{Full, StreamBody};
use hyper::body::Incoming;
use pin_project_lite::pin_project;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

/// Error type for streaming response bodies.
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
/// (client disconnected before completion). `bytes_streamed_to_client` is
/// tracked via an atomic counter incremented on each data frame.
pub struct ProxyBody {
    kind: ProxyBodyKind,
    /// Dropped when hyper finishes sending the body (or the connection closes),
    /// decrementing `OverloadState.active_requests`.
    _request_guard: Option<crate::overload::RequestGuard>,
    /// Deferred logger that fires after body completion, allowing
    /// `TransactionSummary.body_completed` / `body_error_class` /
    /// `client_disconnected` / `bytes_streamed_to_client` to reflect the
    /// client-visible outcome rather than values at header-flush time.
    logger: Option<Arc<crate::proxy::deferred_log::DeferredTransactionLogger>>,
    /// Monotonic byte count streamed to the client. Updated on each
    /// successful data frame **only when a deferred logger is attached** —
    /// the counter has no consumer without a logger, so the hot path skips
    /// the atomic RMW in that case. Read when firing the deferred logger
    /// (on success, streaming error, or Drop client-disconnect safety net).
    ///
    /// **Counting invariant**: bytes are counted ONCE per outer frame at this
    /// `ProxyBody::poll_frame` site, never on inner adapter frames and never
    /// on buffer drain. If a future change adds metrics to `CoalescingH2Body`,
    /// `CoalescingH3Body`, `DirectH2Body`, or `DirectH3Body`, those inner
    /// adapters MUST count bytes only on receipt from the backend (never on
    /// the flush side of the coalescing buffer). Double-counting on drain
    /// inflates `bytes_streamed_to_client` / `response_bytes` by the
    /// coalescing overlap — matches the design rule preserved from the
    /// original deferred-log investigation.
    bytes_streamed: AtomicU64,
    /// Whether `poll_frame` was ever called. Used by the `Drop` safety net
    /// to distinguish "hyper decided not to stream this body" (HEAD / 204 /
    /// zero-length responses where hyper drops without polling) from "hyper
    /// abandoned us mid-stream" (client disconnect). Never polled == success,
    /// polled-but-not-completed == client_disconnect. `is_end_stream()`
    /// cannot be used as the success signal because streaming wrappers
    /// (`DirectH3Body`, partially-polled `CoalescingH3Body`) may report
    /// `false` even for bodies that will complete successfully on the next
    /// poll. Cheap — one atomic RMW on the first poll per body, zero cost
    /// thereafter.
    polled: AtomicBool,
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

impl ProxyBody {
    /// Create a buffered body from bytes.
    pub fn full(data: impl Into<Bytes>) -> Self {
        Self {
            kind: ProxyBodyKind::Full(Full::new(data.into())),
            _request_guard: None,
            logger: None,
            bytes_streamed: AtomicU64::new(0),
            polled: AtomicBool::new(false),
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
            logger: None,
            bytes_streamed: AtomicU64::new(0),
            polled: AtomicBool::new(false),
        }
    }

    /// Attach a [`RequestGuard`] to this body so the `active_requests`
    /// counter stays incremented until hyper finishes sending the response.
    pub fn with_request_guard(mut self, guard: crate::overload::RequestGuard) -> Self {
        self._request_guard = Some(guard);
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
            logger: None,
            bytes_streamed: AtomicU64::new(0),
            polled: AtomicBool::new(false),
        }
    }

    /// Create a streaming body with lightweight completion tracking.
    ///
    /// Returns the body and a shared `Arc<StreamingMetrics>` that a deferred
    /// task can read to get the final transfer time after `read_timeout + buffer`.
    pub fn streaming_tracked(
        response: reqwest::Response,
        baseline: Instant,
    ) -> (Self, Arc<StreamingMetrics>) {
        use futures_util::StreamExt;

        let metrics = Arc::new(StreamingMetrics::new(baseline));

        let stream = response.bytes_stream().map(|result| {
            result
                .map(Frame::data)
                .map_err(|e| Box::new(e) as ProxyBodyError)
        });
        let inner = Box::pin(StreamBody::new(stream));
        let tracked = TrackedBody::new(inner, Arc::clone(&metrics));
        (
            Self {
                kind: ProxyBodyKind::Tracked(tracked),
                _request_guard: None,
                logger: None,
                bytes_streamed: AtomicU64::new(0),
                polled: AtomicBool::new(false),
            },
            metrics,
        )
    }

    /// Create a streaming body with both completion tracking and frame-by-frame
    /// size enforcement. Used when `enable_streaming_latency_tracking=true` AND
    /// `max_response_body_size_bytes > 0` AND Content-Length is absent.
    pub fn streaming_tracked_with_size_limit(
        response: reqwest::Response,
        baseline: Instant,
        max_bytes: usize,
    ) -> (Self, Arc<StreamingMetrics>) {
        use futures_util::StreamExt;

        let metrics = Arc::new(StreamingMetrics::new(baseline));

        let stream = response.bytes_stream().map(|result| {
            result
                .map(Frame::data)
                .map_err(|e| Box::new(e) as ProxyBodyError)
        });
        let limited = SizeLimitedStreamingResponse {
            inner: stream,
            max_bytes,
            bytes_seen: 0,
        };
        let inner = Box::pin(StreamBody::new(limited));
        let tracked = TrackedBody::new(inner, Arc::clone(&metrics));
        (
            Self {
                kind: ProxyBodyKind::Tracked(tracked),
                _request_guard: None,
                logger: None,
                bytes_streamed: AtomicU64::new(0),
                polled: AtomicBool::new(false),
            },
            metrics,
        )
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

        // Fast path: when no deferred logger is attached, the byte counter
        // has no consumer — skip the atomic fetch_add entirely. The vast
        // majority of requests do not attach a logger (only streaming
        // responses via `with_logger` do), so this saves one atomic RMW per
        // frame on the common path. Error / end-of-stream hooks that fire
        // the logger still observe the counter, because their `take()` only
        // succeeds when a logger was attached.
        match &result {
            Poll::Ready(Some(Ok(frame))) => {
                if this.logger.is_some()
                    && let Some(data) = frame.data_ref()
                {
                    this.bytes_streamed
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
            }
            Poll::Ready(Some(Err(e))) => {
                if let Some(logger) = this.logger.take() {
                    let bytes = this.bytes_streamed.load(Ordering::Relaxed);
                    let (class, disconnected) =
                        crate::retry::classify_body_error(&**e as &dyn std::error::Error);
                    logger.fire(crate::proxy::deferred_log::BodyOutcome::error(
                        class,
                        bytes,
                        disconnected,
                    ));
                }
            }
            Poll::Ready(None) => {
                if let Some(logger) = this.logger.take() {
                    let bytes = this.bytes_streamed.load(Ordering::Relaxed);
                    logger.fire(crate::proxy::deferred_log::BodyOutcome::success(bytes));
                }
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
            //    `is_end_stream()` is unreliable (notably `DirectH3Body` and
            //    partially-polled `CoalescingH3Body` always report false), so
            //    we trust `polled` exclusively and treat never-polled as
            //    success.
            let outcome = if self.polled.load(Ordering::Relaxed) {
                // Polled at least once but never reached Ready(None) or an
                // error terminal. That's a client disconnect mid-stream.
                crate::proxy::deferred_log::BodyOutcome::client_disconnect(bytes)
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
                    // Do NOT consult `is_end_stream()` — H3 wrappers
                    // (`DirectH3Body`, partially-polled `CoalescingH3Body`)
                    // always report false here even for successful streams,
                    // which would flip every HEAD / 204 / zero-length
                    // streaming response into a false-positive
                    // client_disconnect — the exact misclassification
                    // Codex P2 flagged.
                    ProxyBodyKind::Stream(_) | ProxyBodyKind::Tracked(_) => {
                        crate::proxy::deferred_log::BodyOutcome::success(bytes)
                    }
                }
            };
            logger.fire(outcome);
        }
    }
}

// -- SyncBody wrapper ---------------------------------------------------------

pin_project! {
    /// Wraps a `Send` body to also implement `Sync`, enabling use with
    /// `reqwest::Body::wrap()` which requires `Send + Sync + 'static`.
    ///
    /// # Safety
    /// Bodies are only polled from a single tokio task (`poll_frame` takes
    /// `Pin<&mut Self>`). The `&self` methods (`is_end_stream`, `size_hint`)
    /// only read immutable state. There are no concurrent mutable accesses
    /// from different threads.
    pub(crate) struct SyncBody<B> {
        #[pin]
        inner: B,
    }
}

// SAFETY: See doc comment on `SyncBody`. The body is only ever mutated
// through `Pin<&mut Self>` (poll_frame) from a single task. The immutable
// accessors (is_end_stream, size_hint) are safe to call concurrently.
unsafe impl<B: Send> Sync for SyncBody<B> {}

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
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        self.project().inner.poll_frame(cx)
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
    /// they can plumb `ctx.request_bytes_observed` directly.
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
    /// Typical usage pattern (summary builder needing `request_bytes`):
    /// ```ignore
    /// let limited = SizeLimitedIncoming::new_with_counter(
    ///     body,
    ///     max_bytes,
    ///     exceeded,
    ///     Arc::clone(&ctx.request_bytes_observed),
    /// );
    /// req_builder.body(limited.into_reqwest_body());
    /// // ... request completes; ctx.request_bytes_observed now reflects the
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
        match Pin::new(&mut this.inner).poll_frame(cx) {
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
/// the total request body size via `TransactionSummary.request_bytes`.
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
    /// they can plumb `ctx.request_bytes_observed` directly.
    #[allow(dead_code)]
    pub fn new(incoming: Incoming) -> Self {
        Self::new_with_counter(incoming, Arc::new(std::sync::atomic::AtomicU64::new(0)))
    }

    /// Wrap an `Incoming` body with a caller-supplied shared byte counter.
    /// Typical usage:
    /// ```ignore
    /// let counting = CountingIncoming::new_with_counter(
    ///     incoming,
    ///     Arc::clone(&ctx.request_bytes_observed),
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
        match Pin::new(&mut this.inner).poll_frame(cx) {
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

pub(crate) trait FrameSource {
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>>;
}

#[rustfmt::skip]
pub(crate) struct ReqwestFrameSource<S> { inner: S }

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

#[rustfmt::skip]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum H3FrameSourceState { Data, Trailers, Done }

#[rustfmt::skip]
pub(crate) struct H3FrameSource { recv_stream: crate::http3::client::H3RequestStream, state: H3FrameSourceState }

impl H3FrameSource {
    #[rustfmt::skip]
    fn new(recv_stream: crate::http3::client::H3RequestStream) -> Self {
        Self { recv_stream, state: H3FrameSourceState::Data }
    }
}

impl FrameSource for H3FrameSource {
    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, BoxError>>> {
        use bytes::Buf;

        let this = self.get_mut();
        loop {
            match this.state {
                H3FrameSourceState::Data => match this.recv_stream.poll_recv_data(cx) {
                    Poll::Ready(Ok(Some(mut buf))) => {
                        let data = buf.copy_to_bytes(buf.remaining());
                        return Poll::Ready(Some(Ok(Frame::data(data))));
                    }
                    Poll::Ready(Ok(None)) => {
                        this.state = H3FrameSourceState::Trailers;
                    }
                    Poll::Ready(Err(e)) => {
                        this.state = H3FrameSourceState::Done;
                        return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
                H3FrameSourceState::Trailers => match this.recv_stream.poll_recv_trailers(cx) {
                    Poll::Ready(Ok(Some(trailers))) => {
                        this.state = H3FrameSourceState::Done;
                        return Poll::Ready(Some(Ok(Frame::trailers(trailers))));
                    }
                    Poll::Ready(Ok(None)) => {
                        this.state = H3FrameSourceState::Done;
                        return Poll::Ready(None);
                    }
                    Poll::Ready(Err(e)) => {
                        this.state = H3FrameSourceState::Done;
                        return Poll::Ready(Some(Err(Box::new(e) as BoxError)));
                    }
                    Poll::Pending => return Poll::Pending,
                },
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
            return None;
        }

        self.flush_timer_armed = false;
        Some(Frame::data(self.buffer.split().freeze()))
    }

    fn buffer_data(&mut self, data: &Bytes) {
        let buffer_was_empty = self.buffer.is_empty();
        self.buffer.extend_from_slice(data);
        if buffer_was_empty {
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
                        if let Some(flushed) = this.flush_buffer() {
                            return Poll::Ready(Some(Ok(flushed)));
                        }
                        return Poll::Pending;
                    }

                    this.done = true;
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(err))) => {
                    this.done = true;
                    if !this.buffer.is_empty() {
                        this.stashed_error = Some(err);
                        if let Some(flushed) = this.flush_buffer() {
                            return Poll::Ready(Some(Ok(flushed)));
                        }
                        return Poll::Pending;
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

const COALESCE_TARGET: usize = 128 * 1024;

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

/// Wraps a reqwest response into a direct streaming body without coalescing.
///
/// Skips the `CoalescingBody` buffering adapter for zero-overhead passthrough.
/// Use when no plugins require response body buffering and no size limits apply.
/// `content_length` propagates an exact size hint for Content-Length forwarding.
pub(crate) fn direct_streaming_body(
    response: reqwest::Response,
    content_length: Option<u64>,
) -> ProxyBody {
    use futures_util::StreamExt;

    let stream = response.bytes_stream().map(|r| {
        r.map(Frame::data)
            .map_err(|e| Box::new(e) as ProxyBodyError)
    });
    let body = DirectStreamBody {
        inner: stream,
        content_length,
    };
    ProxyBody::streaming(Box::pin(body))
}

/// A zero-overhead streaming body that passes frames directly from the backend
/// without coalescing. Used on the fast path when no plugins need body buffering.
struct DirectStreamBody<S> {
    inner: S,
    content_length: Option<u64>,
}

impl<S> http_body::Body for DirectStreamBody<S>
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Unpin,
{
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        Pin::new(&mut self.get_mut().inner).poll_next(cx)
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if let Some(len) = self.content_length {
            http_body::SizeHint::with_exact(len)
        } else {
            http_body::SizeHint::default()
        }
    }
}

impl<S> http_body::Body for CoalescingBody<S>
where
    S: futures_util::Stream<Item = Result<Frame<Bytes>, ProxyBodyError>> + Unpin,
{
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        if this.done {
            // Flush any remaining buffered data after stream ended
            if !this.buffer.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
            }
            // Return stashed error (set when an error arrived with buffered data).
            if let Some(err) = this.stashed_error.take() {
                return Poll::Ready(Some(Err(err)));
            }
            return Poll::Ready(None);
        }

        loop {
            match Pin::new(&mut this.inner).poll_next(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        if this.buffer.is_empty() && data.len() >= COALESCE_TARGET {
                            // Fast path: chunk is already large enough, pass through
                            // without copying into the buffer.
                            return Poll::Ready(Some(Ok(frame)));
                        }
                        this.buffer.extend_from_slice(data);
                        if this.buffer.len() >= COALESCE_TARGET {
                            // Buffer reached target — yield it
                            return Poll::Ready(Some(Ok(Frame::data(
                                this.buffer.split().freeze(),
                            ))));
                        }
                        // Buffer not full yet — continue polling for more
                        continue;
                    }
                    // Non-data frame (trailers), pass through
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    // Flush any buffered data before surfacing the error so
                    // already-received bytes aren't silently dropped. The
                    // error is stashed and returned on the next poll_frame()
                    // call after the buffer has been drained.
                    if !this.buffer.is_empty() {
                        this.stashed_error = Some(e);
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    this.done = true;
                    if !this.buffer.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    // Inner stream has no more data right now — flush what we have
                    if !this.buffer.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.buffer.is_empty() && self.stashed_error.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if let Some(len) = self.content_length {
            http_body::SizeHint::with_exact(len)
        } else {
            http_body::SizeHint::default()
        }
    }
}

// -- CoalescingH2Body ---------------------------------------------------------

/// A response body adapter that coalesces small HTTP/2 DATA frames from a
/// hyper `Incoming` body into larger frames for efficient forwarding.
///
/// This is the HTTP/2 equivalent of [`CoalescingBody`] (which wraps reqwest
/// byte streams). The adapter accumulates small DATA frames until the buffer
/// reaches the coalesce target or the inner body returns `Pending`/`None`,
/// then yields the accumulated data as a single frame.
///
/// **Trailer-safe**: When a non-data frame (TRAILERS) arrives while the buffer
/// has unflushed data, the adapter stashes the trailer, flushes the buffer on
/// the current poll, and returns the stashed trailer on the next poll. This
/// preserves gRPC trailer semantics (grpc-status, grpc-message) without
/// buffering the entire response.
pub(crate) struct CoalescingH2Body {
    inner: Incoming,
    buffer: BytesMut,
    done: bool,
    /// Stashed non-data frame (trailer) that arrived while buffer was non-empty.
    /// Returned on the next poll_frame call after the buffer is flushed.
    stashed_trailer: Option<Frame<Bytes>>,
    /// Error stashed while flushing buffered data. Returned on the next
    /// `poll_frame` call after the buffer has been drained.
    stashed_error: Option<hyper::Error>,
    /// Exact body length from Content-Length (if known). Forwarded via
    /// `size_hint()` so hyper can write a Content-Length response.
    content_length: Option<u64>,
    /// Coalesce target in bytes. Configurable via `FERRUM_H2_COALESCE_TARGET_BYTES`.
    coalesce_target: usize,
}

/// Wraps a hyper `Incoming` body into a coalescing adapter.
///
/// `content_length` should be the value of the backend's Content-Length header
/// (if present) so the adapter can propagate an exact size hint.
/// `coalesce_target` is the minimum chunk size before yielding (from env config).
pub(crate) fn coalescing_h2_body(
    body: Incoming,
    content_length: Option<u64>,
    coalesce_target: usize,
) -> ProxyBody {
    use http_body_util::BodyExt;

    let coalescing = CoalescingH2Body {
        inner: body,
        buffer: BytesMut::new(),
        done: false,
        stashed_trailer: None,
        stashed_error: None,
        content_length,
        coalesce_target,
    };
    let mapped = coalescing.map_err(|e| Box::new(e) as ProxyBodyError);
    ProxyBody::streaming(Box::pin(mapped))
}

/// Wraps a hyper `Incoming` body into a direct streaming body without coalescing.
///
/// Skips the `CoalescingH2Body` buffering adapter for zero-overhead passthrough.
/// Use when no plugins require response body buffering and no size limits apply.
pub(crate) fn direct_streaming_h2_body(body: Incoming, content_length: Option<u64>) -> ProxyBody {
    use http_body_util::BodyExt;

    let direct = DirectH2Body {
        inner: body,
        content_length,
    };
    let mapped = direct.map_err(|e| Box::new(e) as ProxyBodyError);
    ProxyBody::streaming(Box::pin(mapped))
}

/// A zero-overhead streaming body that passes H2 frames directly from the
/// backend without coalescing. Used on the fast path for gRPC and HTTP/2 direct
/// pool responses when no plugins need body buffering.
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
        Pin::new(&mut self.get_mut().inner).poll_frame(cx)
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if let Some(len) = self.content_length {
            http_body::SizeHint::with_exact(len)
        } else {
            self.inner.size_hint()
        }
    }
}

impl http_body::Body for CoalescingH2Body {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();

        // Return stashed trailer from a previous poll (buffer was flushed first).
        if let Some(trailer) = this.stashed_trailer.take() {
            this.done = true;
            return Poll::Ready(Some(Ok(trailer)));
        }

        if this.done {
            // Flush any remaining buffered data after stream ended
            if !this.buffer.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
            }
            // Return stashed error (set when an error arrived with buffered data).
            if let Some(err) = this.stashed_error.take() {
                return Poll::Ready(Some(Err(err)));
            }
            return Poll::Ready(None);
        }

        loop {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        if this.buffer.is_empty() && data.len() >= this.coalesce_target {
                            // Fast path: chunk is already large enough, pass through
                            // without copying into the buffer.
                            return Poll::Ready(Some(Ok(frame)));
                        }
                        this.buffer.extend_from_slice(data);
                        if this.buffer.len() >= this.coalesce_target {
                            // Buffer reached target — yield it
                            return Poll::Ready(Some(Ok(Frame::data(
                                this.buffer.split().freeze(),
                            ))));
                        }
                        // Buffer not full yet — continue polling for more
                        continue;
                    }
                    // Non-data frame (trailers). If buffer has unflushed data,
                    // stash the trailer and flush the buffer first. The stashed
                    // trailer is returned on the next poll_frame call.
                    if !this.buffer.is_empty() {
                        // Convert the frame to our output type (Bytes) for stashing.
                        // Trailers don't carry data, so this is just the trailer map.
                        if let Ok(trailers) = frame.into_trailers() {
                            this.stashed_trailer = Some(Frame::trailers(trailers));
                        }
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    // Buffer is empty — pass through trailer directly
                    return Poll::Ready(Some(Ok(frame)));
                }
                Poll::Ready(Some(Err(e))) => {
                    this.done = true;
                    // Flush any buffered data before surfacing the error so
                    // already-received bytes aren't silently dropped. The
                    // error is stashed and returned on the next poll_frame()
                    // call after the buffer has been drained.
                    if !this.buffer.is_empty() {
                        this.stashed_error = Some(e);
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Ready(Some(Err(e)));
                }
                Poll::Ready(None) => {
                    this.done = true;
                    if !this.buffer.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Pending => {
                    // Inner body has no more data right now — flush what we have
                    if !this.buffer.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
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
        if let Some(len) = self.content_length {
            http_body::SizeHint::with_exact(len)
        } else {
            http_body::SizeHint::default()
        }
    }
}

// -- CoalescingH3Body ---------------------------------------------------------

/// A response body adapter that reads chunks from an h3 `RequestStream` and
/// coalesces them into larger frames before yielding.
///
/// Follows the same pattern as [`CoalescingH2Body`] — small chunks are buffered
/// until reaching the coalesce target, large chunks pass through directly.
/// Unlike H2, h3 `RequestStream` uses an async `recv_data()` method rather
/// than implementing `http_body::Body`, so this adapter bridges the API gap.
pub(crate) struct CoalescingH3Body {
    recv_stream: crate::http3::client::H3RequestStream,
    buffer: BytesMut,
    done: bool,
    /// Error stashed while flushing buffered data. Returned on the next
    /// `poll_frame` call after the buffer has been drained, preventing
    /// silent response truncation.
    stashed_error: Option<ProxyBodyError>,
    content_length: Option<u64>,
    coalesce_target: usize,
}

/// Wraps an h3 `RequestStream` into a coalescing streaming body.
///
/// `content_length` should be the value of the backend's Content-Length header
/// (if present) so the adapter can propagate an exact size hint.
pub(crate) fn coalescing_h3_body(
    recv_stream: crate::http3::client::H3RequestStream,
    content_length: Option<u64>,
    coalesce_target: usize,
) -> ProxyBody {
    let body = CoalescingH3Body {
        recv_stream,
        buffer: BytesMut::new(),
        done: false,
        stashed_error: None,
        content_length,
        coalesce_target,
    };
    ProxyBody::streaming(Box::pin(body))
}

/// Wraps an h3 `RequestStream` into a direct streaming body without coalescing.
pub(crate) fn direct_streaming_h3_body(
    recv_stream: crate::http3::client::H3RequestStream,
    content_length: Option<u64>,
) -> ProxyBody {
    let body = DirectH3Body {
        recv_stream,
        content_length,
    };
    ProxyBody::streaming(Box::pin(body))
}

/// Zero-overhead streaming body that passes h3 response data directly without
/// coalescing. Used on the fast path when no plugins need body buffering.
struct DirectH3Body {
    recv_stream: crate::http3::client::H3RequestStream,
    content_length: Option<u64>,
}

impl http_body::Body for DirectH3Body {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use bytes::Buf;
        let this = self.get_mut();
        let mut fut = std::pin::pin!(this.recv_stream.recv_data());
        match fut.as_mut().poll(cx) {
            Poll::Ready(Ok(Some(mut buf))) => {
                let data = buf.copy_to_bytes(buf.remaining());
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Ok(None)) => Poll::Ready(None),
            Poll::Ready(Err(e)) => Poll::Ready(Some(Err(Box::new(e) as ProxyBodyError))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn is_end_stream(&self) -> bool {
        false
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if let Some(len) = self.content_length {
            http_body::SizeHint::with_exact(len)
        } else {
            http_body::SizeHint::default()
        }
    }
}

impl http_body::Body for CoalescingH3Body {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        use bytes::Buf;
        let this = self.get_mut();

        if this.done {
            // Flush any remaining buffered data after stream ended
            if !this.buffer.is_empty() {
                return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
            }
            // Return stashed error (set when an error arrived with buffered data).
            if let Some(err) = this.stashed_error.take() {
                return Poll::Ready(Some(Err(err)));
            }
            return Poll::Ready(None);
        }

        loop {
            let mut fut = std::pin::pin!(this.recv_stream.recv_data());
            match fut.as_mut().poll(cx) {
                Poll::Ready(Ok(Some(mut buf))) => {
                    let len = buf.remaining();
                    if this.buffer.is_empty() && len >= this.coalesce_target {
                        // Fast path: chunk already large enough — zero-copy passthrough.
                        let data = buf.copy_to_bytes(len);
                        return Poll::Ready(Some(Ok(Frame::data(data))));
                    }
                    // Coalescing path: copy directly from Buf into BytesMut,
                    // avoiding an intermediate Bytes allocation.
                    this.buffer.reserve(len);
                    while buf.has_remaining() {
                        let chunk = buf.chunk();
                        this.buffer.extend_from_slice(chunk);
                        buf.advance(chunk.len());
                    }
                    if this.buffer.len() >= this.coalesce_target {
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    continue;
                }
                Poll::Ready(Ok(None)) => {
                    this.done = true;
                    if !this.buffer.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(e)) => {
                    this.done = true;
                    // Flush any buffered data before surfacing the error so
                    // already-received bytes aren't silently dropped. The
                    // error is stashed and returned on the next poll_frame()
                    // call after the buffer has been drained.
                    if !this.buffer.is_empty() {
                        this.stashed_error = Some(Box::new(e) as ProxyBodyError);
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Ready(Some(Err(Box::new(e) as ProxyBodyError)));
                }
                Poll::Pending => {
                    if !this.buffer.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Pending;
                }
            }
        }
    }

    fn is_end_stream(&self) -> bool {
        self.done && self.buffer.is_empty() && self.stashed_error.is_none()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if let Some(len) = self.content_length {
            http_body::SizeHint::with_exact(len)
        } else {
            http_body::SizeHint::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use futures_util::Stream;
    use futures_util::task::noop_waker;
    use http_body::Body;
    use std::collections::VecDeque;

    #[rustfmt::skip]
    enum MockStep { Frame(Result<Frame<Bytes>, BoxError>), End, Pending }

    #[rustfmt::skip]
    struct MockSource { steps: VecDeque<MockStep> }

    impl MockSource {
        #[rustfmt::skip]
        fn new(steps: Vec<MockStep>) -> Self {
            Self { steps: steps.into() }
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
}
