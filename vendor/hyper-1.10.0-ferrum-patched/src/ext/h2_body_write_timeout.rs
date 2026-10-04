//! FERRUM PATCH 004: a per-request bound on how long an HTTP/2 client request
//! body may wait to be written.

use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

/// Request extension that bounds how long an HTTP/2 client request body may
/// stall while it has data to write.
///
/// Insert it into a request sent on an HTTP/2 client connection
/// (`hyper::client::conn::http2`) that was built with a
/// [`Timer`](crate::rt::Timer). While the body pipe holds a chunk it cannot
/// yet send (the stream or connection flow-control window is exhausted, or
/// h2's send buffer is full), a timer runs. Each chunk handed to h2 disarms
/// it. If it fires, the stream is reset with `CANCEL`, the request body
/// fails, and [`expired`](Self::expired) reports `true` on every clone.
///
/// Time spent waiting for the request body itself (a slow client) never
/// counts: the timer only runs while a chunk is ready and cannot be written.
/// This is the HTTP/2 equivalent of a send timeout "between two successive
/// write operations".
///
/// The extension is removed from the request before it is sent. A request
/// that carries it on a connection built without a timer fails with a body
/// write error rather than running unbounded.
#[derive(Clone, Debug)]
pub struct Http2BodyWriteTimeout {
    timeout: Duration,
    expired: Arc<AtomicBool>,
}

impl Http2BodyWriteTimeout {
    /// A bound of `timeout` between successive body writes.
    pub fn new(timeout: Duration) -> Self {
        Self {
            timeout,
            expired: Arc::new(AtomicBool::new(false)),
        }
    }

    /// The configured bound.
    pub fn timeout(&self) -> Duration {
        self.timeout
    }

    /// Whether the bound fired and reset the stream.
    pub fn expired(&self) -> bool {
        self.expired.load(Ordering::Acquire)
    }

    pub(crate) fn mark_expired(&self) {
        self.expired.store(true, Ordering::Release);
    }
}
