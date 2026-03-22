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
pub enum ProxyBody {
    /// Complete body already in memory.
    Full(Full<Bytes>),
    /// Body streamed chunk-by-chunk from the backend.
    Stream(Pin<Box<dyn http_body::Body<Data = Bytes, Error = ProxyBodyError> + Send + 'static>>),
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
        }
    }

    fn is_end_stream(&self) -> bool {
        match self {
            ProxyBody::Full(body) => body.is_end_stream(),
            ProxyBody::Stream(body) => body.is_end_stream(),
        }
    }

    fn size_hint(&self) -> http_body::SizeHint {
        match self {
            ProxyBody::Full(body) => body.size_hint(),
            ProxyBody::Stream(body) => body.size_hint(),
        }
    }
}
