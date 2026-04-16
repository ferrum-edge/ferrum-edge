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
use std::time::Instant;

/// Error type for streaming response bodies.
pub type ProxyBodyError = Box<dyn std::error::Error + Send + Sync>;

/// A response body that is either fully buffered or streamed from the backend.
///
/// Optionally carries a [`RequestGuard`] that keeps the `active_requests`
/// overload counter incremented for the lifetime of the response body — not
/// just the handler function scope. This is critical for H2/H3/gRPC streaming
/// responses where hyper drives the body to completion *after*
/// `handle_proxy_request` returns.
pub struct ProxyBody {
    kind: ProxyBodyKind,
    /// Dropped when hyper finishes sending the body (or the connection closes),
    /// decrementing `OverloadState.active_requests`.
    _request_guard: Option<crate::overload::RequestGuard>,
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
/// deferred log task. Atomic counters only — no strings, no closures, no
/// allocations per frame.
///
/// **Ordering discipline**:
/// - `bytes_sent`: Relaxed (single writer: `TrackedBody::poll_frame`; single
///   reader: deferred task, synchronized via spawn happens-before).
/// - `last_frame_nanos`: Acquire/Release (preserves existing invariant).
/// - `completed`: Acquire/Release (ensures `last_frame_nanos` is visible when
///   reader sees `completed == true`).
/// - `client_disconnected`: Acquire/Release (consistent with `completed`).
pub struct StreamingMetrics {
    /// Reference `Instant` — stored once at creation. The atomic stores
    /// elapsed nanos relative to this baseline to avoid u64 overflow.
    baseline: Instant,
    /// Elapsed nanos from `baseline` when the last frame was sent (or 0
    /// if no frame has been sent yet).
    last_frame_nanos: AtomicU64,
    /// Whether the body completed successfully (all frames sent).
    completed: AtomicBool,
    /// Total bytes of response data forwarded to the client so far.
    /// Accumulates across all DATA frames; non-data frames (trailers) do
    /// not contribute. Populated by [`TrackedBody::poll_frame`].
    bytes_sent: AtomicU64,
    /// Set to `true` when a streaming-body adapter observes a
    /// client-disconnect-class error (broken pipe, connection reset, early
    /// EOF, etc.) while writing a frame. Stays `false` for clean completion
    /// or non-disconnect errors (timeout, TLS failure, etc.). Populated by
    /// [`TrackedBody::poll_frame`].
    client_disconnected: AtomicBool,
}

impl StreamingMetrics {
    pub fn new(baseline: Instant) -> Self {
        Self {
            baseline,
            last_frame_nanos: AtomicU64::new(0),
            completed: AtomicBool::new(false),
            bytes_sent: AtomicU64::new(0),
            client_disconnected: AtomicBool::new(false),
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

    /// Total response body bytes forwarded to the client.
    pub fn bytes_sent(&self) -> u64 {
        self.bytes_sent.load(Ordering::Relaxed)
    }

    /// Whether a client-disconnect-class error was observed during streaming.
    pub fn client_disconnected(&self) -> bool {
        self.client_disconnected.load(Ordering::Acquire)
    }

    /// Record that `n` bytes were forwarded to the client and update the
    /// last-frame timestamp. Used by synchronous streaming loops (H3 frontend)
    /// that write bytes directly to the transport rather than yielding
    /// `http_body::Frame` values. One `fetch_add` + one `store` per call.
    pub fn record_bytes_sent(&self, n: u64) {
        self.bytes_sent.fetch_add(n, Ordering::Relaxed);
        let elapsed = self.baseline.elapsed().as_nanos() as u64;
        self.last_frame_nanos.store(elapsed, Ordering::Release);
    }

    /// Mark the stream as completed (all frames forwarded). Idempotent.
    pub fn mark_completed(&self) {
        self.completed.store(true, Ordering::Release);
    }

    /// Mark the stream as terminated by a client-disconnect-class error
    /// (broken pipe, connection reset, early EOF, etc.). Idempotent.
    pub fn mark_client_disconnected(&self) {
        self.client_disconnected.store(true, Ordering::Release);
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
                // Frame sent — update last-frame timestamp (one atomic store).
                let elapsed = this.metrics.baseline.elapsed().as_nanos() as u64;
                this.metrics
                    .last_frame_nanos
                    .store(elapsed, Ordering::Release);
                // Count bytes for DATA frames. Trailers (non-data frames)
                // contribute nothing — `data_ref()` returns `None` for them.
                // Relaxed is correct: single writer (this `poll_frame`),
                // and the deferred reader happens-after via the spawn
                // happens-before relation.
                if let Some(data) = frame.data_ref() {
                    this.metrics
                        .bytes_sent
                        .fetch_add(data.len() as u64, Ordering::Relaxed);
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                // Classify the error: client-disconnect-class errors
                // (broken pipe, connection reset, early EOF, etc.) set a
                // dedicated flag so the deferred log task can distinguish
                // "client bailed" from "backend timeout" in the summary.
                // `err.to_string()` only happens on the error path, which
                // is rare — no hot-path allocation.
                if super::is_client_disconnect_error(&e.to_string()) {
                    this.metrics
                        .client_disconnected
                        .store(true, Ordering::Release);
                }
                Poll::Ready(Some(Err(e)))
            }
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

impl ProxyBody {
    /// Create a buffered body from bytes.
    pub fn full(data: impl Into<Bytes>) -> Self {
        Self {
            kind: ProxyBodyKind::Full(Full::new(data.into())),
            _request_guard: None,
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
        }
    }

    /// Attach a [`RequestGuard`] to this body so the `active_requests`
    /// counter stays incremented until hyper finishes sending the response.
    pub fn with_request_guard(mut self, guard: crate::overload::RequestGuard) -> Self {
        self._request_guard = Some(guard);
        self
    }

    /// Create a streaming body (no completion tracking).
    fn streaming(
        body: Pin<Box<dyn http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + 'static>>,
    ) -> Self {
        Self {
            kind: ProxyBodyKind::Stream(body),
            _request_guard: None,
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
        match &mut self.get_mut().kind {
            ProxyBodyKind::Full(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|opt| opt.map(|result| result.map_err(|never| match never {}))),
            ProxyBodyKind::Stream(body) => body.as_mut().poll_frame(cx),
            ProxyBodyKind::Tracked(body) => Pin::new(body).poll_frame(cx),
        }
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
    bytes_seen: usize,
    exceeded: Arc<AtomicBool>,
}

impl SizeLimitedIncoming {
    pub fn new(incoming: Incoming, max_bytes: usize, exceeded: Arc<AtomicBool>) -> Self {
        Self {
            inner: incoming,
            max_bytes,
            bytes_seen: 0,
            exceeded,
        }
    }

    /// Convert this size-limited body into a `reqwest::Body` for streaming
    /// to the backend without collecting the full body into memory.
    ///
    /// Uses `reqwest::Body::wrap()` instead of `wrap_stream()` to preserve
    /// the `size_hint()` from the underlying `Incoming` body. When the client
    /// sends `Content-Length`, this enables reqwest to forward a length-delimited
    /// body instead of chunked Transfer-Encoding — avoiding per-chunk framing
    /// overhead and enabling single-buffer receive on the backend.
    pub fn into_reqwest_body(self) -> reqwest::Body {
        reqwest::Body::wrap(SyncBody::new(self))
    }

    /// Expose the running total of bytes observed so the proxy handler can
    /// populate `TransactionSummary::request_bytes` after the body has been
    /// consumed. Note: `into_reqwest_body(self)` moves this value, so callers
    /// must read it only when they still own the `SizeLimitedIncoming`.
    ///
    /// For the streaming-forward path where ownership is handed to reqwest
    /// before the body is drained, a shared `Arc<AtomicU64>` counter is the
    /// preferred mechanism — see `CountingIncoming` (added in a later commit).
    #[allow(dead_code)] // consumed by request-bytes plumbing in a follow-up commit
    pub fn bytes_seen(&self) -> usize {
        self.bytes_seen
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
                    this.bytes_seen += data.len();
                    if this.bytes_seen > this.max_bytes {
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
    // Wrap in coalescing adapter for efficient frame batching.
    let coalescing = CoalescingBody {
        inner: limited,
        buffer: BytesMut::new(),
        done: false,
        stashed_error: None,
        content_length,
    };
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

// -- CoalescingBody -----------------------------------------------------------

/// Minimum chunk size (bytes) before yielding a frame to hyper's H1 encoder.
///
/// Small response chunks from reqwest's byte stream (typically 8–32 KB from
/// hyper's HTTP/1.1 client) cause excessive write syscalls when forwarded
/// one-at-a-time. This adapter collects contiguous chunks into a single
/// [`Bytes`] of at least `COALESCE_TARGET` bytes before yielding, reducing
/// the number of frames hyper writes by ~8–16× for large bodies.
///
/// The target is chosen to balance syscall reduction against memory latency:
/// 128 KB fits comfortably in L2 cache on modern CPUs and has a
/// default read reservation (8 × 16 KB slices).
const COALESCE_TARGET: usize = 128 * 1024;

/// A response body adapter that coalesces small chunks from a reqwest byte
/// stream into larger frames for efficient forwarding.
///
/// When the inner stream yields a chunk smaller than [`COALESCE_TARGET`],
/// the adapter buffers it and immediately re-polls for more data. Once the
/// buffer reaches the target size or the inner stream returns `Pending`/`None`,
/// the accumulated buffer is yielded as a single frame.
///
/// For chunks that already meet or exceed the target, they pass through
/// without copying (zero-overhead fast path).
pub(crate) struct CoalescingBody<S> {
    inner: S,
    buffer: BytesMut,
    done: bool,
    /// Error stashed while flushing buffered data. Returned on the next
    /// `poll_frame` call after the buffer has been drained.
    stashed_error: Option<ProxyBodyError>,
    /// Exact body length from Content-Length (if known). Forwarded via
    /// `size_hint()` so hyper writes a Content-Length response instead of
    /// chunked encoding.
    content_length: Option<u64>,
}

/// Wraps a reqwest response into a coalescing body.
///
/// `content_length` should be the value of the backend's Content-Length header
/// (if present) so the adapter can propagate an exact size hint.
pub(crate) fn coalescing_body(
    response: reqwest::Response,
    content_length: Option<u64>,
) -> ProxyBody {
    use futures_util::StreamExt;

    let stream = response.bytes_stream().map(|r| {
        r.map(Frame::data)
            .map_err(|e| Box::new(e) as ProxyBodyError)
    });
    let body = CoalescingBody {
        inner: stream,
        buffer: BytesMut::new(),
        done: false,
        stashed_error: None,
        content_length,
    };
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
    /// Optional streaming metrics shared with a deferred log task. When
    /// present, the adapter records `bytes_sent` once per inner `Ok(frame)`
    /// with data (never on buffer drain), `last_frame_nanos`/`completed`
    /// on inner end-of-stream, and `client_disconnected` on errors
    /// classified as client-disconnect-class.
    metrics: Option<Arc<StreamingMetrics>>,
}

/// Wraps a hyper `Incoming` body into a coalescing adapter.
///
/// `content_length` should be the value of the backend's Content-Length header
/// (if present) so the adapter can propagate an exact size hint.
/// `coalesce_target` is the minimum chunk size before yielding (from env config).
/// `metrics` is `Some` when the caller will defer the log via a background
/// task that reads the shared atomics after `read_timeout + buffer`.
pub(crate) fn coalescing_h2_body(
    body: Incoming,
    content_length: Option<u64>,
    coalesce_target: usize,
    metrics: Option<Arc<StreamingMetrics>>,
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
        metrics,
    };
    let mapped = coalescing.map_err(|e| Box::new(e) as ProxyBodyError);
    ProxyBody::streaming(Box::pin(mapped))
}

/// Wraps a hyper `Incoming` body into a direct streaming body without coalescing.
///
/// Skips the `CoalescingH2Body` buffering adapter for zero-overhead passthrough.
/// Use when no plugins require response body buffering and no size limits apply.
/// `metrics` is `Some` when the caller will defer the log via a background
/// task that reads the shared atomics after `read_timeout + buffer`.
pub(crate) fn direct_streaming_h2_body(
    body: Incoming,
    content_length: Option<u64>,
    metrics: Option<Arc<StreamingMetrics>>,
) -> ProxyBody {
    use http_body_util::BodyExt;

    let direct = DirectH2Body {
        inner: body,
        content_length,
        metrics,
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
    /// Optional streaming metrics shared with a deferred log task. When
    /// present, the adapter records `bytes_sent` per DATA frame,
    /// `last_frame_nanos`/`completed` on end-of-stream, and
    /// `client_disconnected` on errors classified as client-disconnect-class.
    metrics: Option<Arc<StreamingMetrics>>,
}

impl http_body::Body for DirectH2Body {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                if let Some(m) = this.metrics.as_ref() {
                    let elapsed = m.baseline.elapsed().as_nanos() as u64;
                    m.last_frame_nanos.store(elapsed, Ordering::Release);
                    m.completed.store(true, Ordering::Release);
                }
                Poll::Ready(None)
            }
            Poll::Ready(Some(Ok(frame))) => {
                if let Some(m) = this.metrics.as_ref() {
                    let elapsed = m.baseline.elapsed().as_nanos() as u64;
                    m.last_frame_nanos.store(elapsed, Ordering::Release);
                    if let Some(data) = frame.data_ref() {
                        m.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                    }
                }
                Poll::Ready(Some(Ok(frame)))
            }
            Poll::Ready(Some(Err(e))) => {
                if let Some(m) = this.metrics.as_ref()
                    && super::is_client_disconnect_error(&e.to_string())
                {
                    m.client_disconnected.store(true, Ordering::Release);
                }
                Poll::Ready(Some(Err(e)))
            }
            Poll::Pending => Poll::Pending,
        }
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
            // Final end-of-stream — record completion timestamp for the
            // deferred log task if metrics are attached.
            if let Some(m) = this.metrics.as_ref() {
                let elapsed = m.baseline.elapsed().as_nanos() as u64;
                m.last_frame_nanos.store(elapsed, Ordering::Release);
                m.completed.store(true, Ordering::Release);
            }
            return Poll::Ready(None);
        }

        loop {
            match Pin::new(&mut this.inner).poll_frame(cx) {
                Poll::Ready(Some(Ok(frame))) => {
                    if let Some(data) = frame.data_ref() {
                        // Count bytes ONCE per inner data frame, here at receipt
                        // from the backend — never on buffer drain. This avoids
                        // double-counting when a buffered chunk is later yielded
                        // on flush (Pending/None/Err). The buffered chunk's
                        // bytes were already counted when received.
                        if let Some(m) = this.metrics.as_ref() {
                            m.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                            let elapsed = m.baseline.elapsed().as_nanos() as u64;
                            m.last_frame_nanos.store(elapsed, Ordering::Release);
                        }
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
                    // Non-data frame (trailers). Touch last-frame timestamp but
                    // do NOT count bytes (trailers carry no payload).
                    if let Some(m) = this.metrics.as_ref() {
                        let elapsed = m.baseline.elapsed().as_nanos() as u64;
                        m.last_frame_nanos.store(elapsed, Ordering::Release);
                    }
                    // If buffer has unflushed data, stash the trailer and flush
                    // the buffer first. The stashed trailer is returned on the
                    // next poll_frame call.
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
                    // Classify the error: client-disconnect-class errors set a
                    // dedicated flag so the deferred log task can distinguish
                    // "client bailed" from "backend timeout" in the summary.
                    if let Some(m) = this.metrics.as_ref()
                        && super::is_client_disconnect_error(&e.to_string())
                    {
                        m.client_disconnected.store(true, Ordering::Release);
                    }
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
                    // Record completion once the inner stream ends cleanly.
                    // This may be followed by a buffer-flush poll; the second
                    // invocation (done=true, buffer empty, no stashed err)
                    // will re-record, which is idempotent for these atomics.
                    if let Some(m) = this.metrics.as_ref() {
                        let elapsed = m.baseline.elapsed().as_nanos() as u64;
                        m.last_frame_nanos.store(elapsed, Ordering::Release);
                        m.completed.store(true, Ordering::Release);
                    }
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
    /// Optional streaming metrics shared with a deferred log task. When
    /// present, the adapter records `bytes_sent` once per inner `Ok(Some)`
    /// chunk (never on buffer drain), `last_frame_nanos`/`completed` on
    /// inner end-of-stream, and `client_disconnected` on errors classified
    /// as client-disconnect-class.
    metrics: Option<Arc<StreamingMetrics>>,
}

/// Wraps an h3 `RequestStream` into a coalescing streaming body.
///
/// `content_length` should be the value of the backend's Content-Length header
/// (if present) so the adapter can propagate an exact size hint.
/// `metrics` is `Some` when the caller will defer the log via a background
/// task that reads the shared atomics after `read_timeout + buffer`.
pub(crate) fn coalescing_h3_body(
    recv_stream: crate::http3::client::H3RequestStream,
    content_length: Option<u64>,
    coalesce_target: usize,
    metrics: Option<Arc<StreamingMetrics>>,
) -> ProxyBody {
    let body = CoalescingH3Body {
        recv_stream,
        buffer: BytesMut::new(),
        done: false,
        stashed_error: None,
        content_length,
        coalesce_target,
        metrics,
    };
    ProxyBody::streaming(Box::pin(body))
}

/// Wraps an h3 `RequestStream` into a direct streaming body without coalescing.
///
/// `metrics` is `Some` when the caller will defer the log via a background
/// task that reads the shared atomics after `read_timeout + buffer`.
pub(crate) fn direct_streaming_h3_body(
    recv_stream: crate::http3::client::H3RequestStream,
    content_length: Option<u64>,
    metrics: Option<Arc<StreamingMetrics>>,
) -> ProxyBody {
    let body = DirectH3Body {
        recv_stream,
        content_length,
        metrics,
    };
    ProxyBody::streaming(Box::pin(body))
}

/// Zero-overhead streaming body that passes h3 response data directly without
/// coalescing. Used on the fast path when no plugins need body buffering.
struct DirectH3Body {
    recv_stream: crate::http3::client::H3RequestStream,
    content_length: Option<u64>,
    /// Optional streaming metrics shared with a deferred log task. When
    /// present, the adapter records `bytes_sent` per DATA chunk,
    /// `last_frame_nanos`/`completed` on end-of-stream, and
    /// `client_disconnected` on errors classified as client-disconnect-class.
    metrics: Option<Arc<StreamingMetrics>>,
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
        // Poll the recv_data future within a scope so the &mut borrow on
        // recv_stream ends before we touch this.metrics (field-splitting is
        // fine in principle, but scoping the future makes intent explicit
        // and avoids any self-referential borrow surprises).
        let outcome = {
            let mut fut = std::pin::pin!(this.recv_stream.recv_data());
            fut.as_mut().poll(cx)
        };
        match outcome {
            Poll::Ready(Ok(Some(mut buf))) => {
                let data = buf.copy_to_bytes(buf.remaining());
                if let Some(m) = this.metrics.as_ref() {
                    m.bytes_sent.fetch_add(data.len() as u64, Ordering::Relaxed);
                    let elapsed = m.baseline.elapsed().as_nanos() as u64;
                    m.last_frame_nanos.store(elapsed, Ordering::Release);
                }
                Poll::Ready(Some(Ok(Frame::data(data))))
            }
            Poll::Ready(Ok(None)) => {
                if let Some(m) = this.metrics.as_ref() {
                    let elapsed = m.baseline.elapsed().as_nanos() as u64;
                    m.last_frame_nanos.store(elapsed, Ordering::Release);
                    m.completed.store(true, Ordering::Release);
                }
                Poll::Ready(None)
            }
            Poll::Ready(Err(e)) => {
                if let Some(m) = this.metrics.as_ref()
                    && super::is_client_disconnect_error(&e.to_string())
                {
                    m.client_disconnected.store(true, Ordering::Release);
                }
                Poll::Ready(Some(Err(Box::new(e) as ProxyBodyError)))
            }
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
            // Final end-of-stream — record completion timestamp for the
            // deferred log task if metrics are attached.
            if let Some(m) = this.metrics.as_ref() {
                let elapsed = m.baseline.elapsed().as_nanos() as u64;
                m.last_frame_nanos.store(elapsed, Ordering::Release);
                m.completed.store(true, Ordering::Release);
            }
            return Poll::Ready(None);
        }

        loop {
            // Poll the recv_data future within a scope so the &mut borrow on
            // recv_stream ends before we touch this.metrics on inner outcomes.
            let outcome = {
                let mut fut = std::pin::pin!(this.recv_stream.recv_data());
                fut.as_mut().poll(cx)
            };
            match outcome {
                Poll::Ready(Ok(Some(mut buf))) => {
                    let len = buf.remaining();
                    // Count bytes ONCE per inner chunk, here at receipt from
                    // the backend — never on buffer drain. This avoids
                    // double-counting when a buffered chunk is later yielded
                    // on flush (Pending/None/Err).
                    if let Some(m) = this.metrics.as_ref() {
                        m.bytes_sent.fetch_add(len as u64, Ordering::Relaxed);
                        let elapsed = m.baseline.elapsed().as_nanos() as u64;
                        m.last_frame_nanos.store(elapsed, Ordering::Release);
                    }
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
                    // Record completion; a subsequent buffer-flush poll will
                    // re-record (idempotent for these atomics).
                    if let Some(m) = this.metrics.as_ref() {
                        let elapsed = m.baseline.elapsed().as_nanos() as u64;
                        m.last_frame_nanos.store(elapsed, Ordering::Release);
                        m.completed.store(true, Ordering::Release);
                    }
                    if !this.buffer.is_empty() {
                        return Poll::Ready(Some(Ok(Frame::data(this.buffer.split().freeze()))));
                    }
                    return Poll::Ready(None);
                }
                Poll::Ready(Err(e)) => {
                    this.done = true;
                    // Classify the error so the deferred log task can
                    // distinguish client disconnect from backend failure.
                    if let Some(m) = this.metrics.as_ref()
                        && super::is_client_disconnect_error(&e.to_string())
                    {
                        m.client_disconnected.store(true, Ordering::Release);
                    }
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
