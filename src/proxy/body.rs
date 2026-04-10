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
pub enum ProxyBody {
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
        Self::Full(Full::new(data.into()))
    }

    /// Create a buffered body from a string slice.
    pub fn from_string(s: &str) -> Self {
        Self::full(Bytes::from(s.to_string()))
    }

    /// Create an empty body.
    pub fn empty() -> Self {
        Self::Full(Full::default())
    }

    /// Create a streaming body from a hyper HTTP/2 response (Incoming body).
    pub fn streaming_h2(response: hyper::Response<hyper::body::Incoming>) -> Self {
        use http_body_util::BodyExt;

        let body = response.into_body();
        let mapped = body.map_err(|e| Box::new(e) as ProxyBodyError);
        Self::Stream(Box::pin(mapped))
    }

    /// Create a streaming body directly from a hyper `Incoming` body.
    ///
    /// Used when the response headers and body have already been separated,
    /// e.g. in the gRPC streaming path where status and headers are extracted
    /// before the body is passed through.
    pub fn streaming_incoming(body: hyper::body::Incoming) -> Self {
        use http_body_util::BodyExt;

        let mapped = body.map_err(|e| Box::new(e) as ProxyBodyError);
        Self::Stream(Box::pin(mapped))
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
        (Self::Tracked(tracked), metrics)
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
        match self.get_mut() {
            ProxyBody::Full(body) => Pin::new(body)
                .poll_frame(cx)
                .map(|opt| opt.map(|result| result.map_err(|never| match never {}))),
            ProxyBody::Stream(body) => body.as_mut().poll_frame(cx),
            ProxyBody::Tracked(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Full(body) => body.is_end_stream(),
            ProxyBody::Stream(body) => body.is_end_stream(),
            ProxyBody::Tracked(body) => body.inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            ProxyBody::Full(body) => body.size_hint(),
            ProxyBody::Stream(body) => body.size_hint(),
            ProxyBody::Tracked(body) => body.inner.size_hint(),
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
        content_length,
    };
    ProxyBody::Stream(Box::pin(body))
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
                    // error will be returned on the next poll_frame() call
                    // (done=true causes the body to end).
                    if !this.buffer.is_empty() {
                        // Store the error for the next poll — we can't return
                        // both data and error in one frame. Since done=true,
                        // the next poll will return None (stream end). The
                        // client sees a truncated body which hyper will detect
                        // as a content-length mismatch and surface as an error.
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
        self.done && self.buffer.is_empty()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        if let Some(len) = self.content_length {
            http_body::SizeHint::with_exact(len)
        } else {
            http_body::SizeHint::default()
        }
    }
}
