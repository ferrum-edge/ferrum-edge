//! Proxy response body type that supports both buffered and streaming modes.
//!
//! [`ProxyBody`] is a sum type over [`Full<Bytes>`] (buffered) and a boxed
//! streaming body. The buffered variant is zero-cost (no allocation beyond
//! the data itself); the streaming variant allocates one `Box` to erase the
//! concrete stream type.

use bytes::Bytes;
use http_body::Frame;
use http_body_util::{Full, StreamBody};
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
            ProxyBody::Tracked(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Full(body) => body.is_end_stream(),
            ProxyBody::Tracked(body) => body.inner.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            ProxyBody::Full(body) => body.size_hint(),
            ProxyBody::Tracked(body) => body.inner.size_hint(),
        }
    }
}
