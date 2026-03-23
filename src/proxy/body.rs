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
use std::task::{Context, Poll};

/// Error type for streaming response bodies.
pub type ProxyBodyError = Box<dyn std::error::Error + Send + Sync>;

/// A response body that is either fully buffered or streamed from the backend.
/// The `Logged` variant wraps any body with a post-completion callback for
/// deferred logging (fires after the last byte is sent or on client disconnect).
pub enum ProxyBody {
    /// Complete body already in memory.
    Full(Full<Bytes>),
    /// Body streamed chunk-by-chunk from the backend.
    Stream(Pin<Box<dyn http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + 'static>>),
    /// Body with a post-completion logging callback.
    Logged(LoggingBody),
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

    /// Create a streaming body from a reqwest response.
    ///
    /// The response body is forwarded chunk-by-chunk to the client without
    /// being collected into memory first.
    pub fn streaming(response: reqwest::Response) -> Self {
        use futures_util::StreamExt;

        let stream = response.bytes_stream().map(|result| {
            result
                .map(Frame::data)
                .map_err(|e| Box::new(e) as ProxyBodyError)
        });
        Self::Stream(Box::pin(StreamBody::new(stream)))
    }

    /// Wrap this body with a post-completion logging callback.
    ///
    /// The callback fires exactly once after the body is fully consumed
    /// (success), errors (backend failure), or is dropped (client disconnect).
    pub fn with_logging(self, on_complete: impl FnOnce(bool) + Send + 'static) -> Self {
        Self::Logged(LoggingBody::new(self, on_complete))
    }
}

/// A response body wrapper that fires a callback when the body is fully
/// consumed, errors, or is dropped (client disconnect).
///
/// This enables post-response logging: the callback fires after the last
/// byte is sent to the client (or when the client disconnects mid-stream),
/// providing accurate total latency and client disconnect detection.
///
/// The callback fires exactly once:
/// - `true` = body completed successfully (client received full response)
/// - `false` = body errored or was dropped (client disconnected, stream error)
pub struct LoggingBody {
    inner: Box<ProxyBody>,
    on_complete: Option<Box<dyn FnOnce(bool) + Send + 'static>>,
    finished: bool,
}

impl LoggingBody {
    pub fn new(inner: ProxyBody, on_complete: impl FnOnce(bool) + Send + 'static) -> Self {
        Self {
            inner: Box::new(inner),
            on_complete: Some(Box::new(on_complete)),
            finished: false,
        }
    }

    fn fire_callback(&mut self, completed: bool) {
        if let Some(cb) = self.on_complete.take() {
            cb(completed);
        }
    }
}

impl http_body::Body for LoggingBody {
    type Data = Bytes;
    type Error = ProxyBodyError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Self::Data>, Self::Error>>> {
        let this = self.get_mut();
        match Pin::new(&mut this.inner).poll_frame(cx) {
            Poll::Ready(None) => {
                this.finished = true;
                this.fire_callback(true);
                Poll::Ready(None)
            }
            Poll::Ready(Some(Err(e))) => {
                this.finished = true;
                this.fire_callback(false);
                Poll::Ready(Some(Err(e)))
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

impl Drop for LoggingBody {
    fn drop(&mut self) {
        if !self.finished {
            self.fire_callback(false);
        }
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
            ProxyBody::Logged(body) => Pin::new(body).poll_frame(cx),
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Full(body) => body.is_end_stream(),
            ProxyBody::Stream(body) => body.is_end_stream(),
            ProxyBody::Logged(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            ProxyBody::Full(body) => body.size_hint(),
            ProxyBody::Stream(body) => body.size_hint(),
            ProxyBody::Logged(body) => body.size_hint(),
        }
    }
}
