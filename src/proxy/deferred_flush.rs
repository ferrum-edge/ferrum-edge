//! Deferred first write for an HTTP/2 connection's transport (issue #5588).
//!
//! An h2 connection task flushes whatever its streams have queued each time it
//! is polled. Behind a multiplexed connection the streams' responses complete
//! on different worker threads, so the connection task often wakes for the
//! first ready stream and writes it alone, a moment before the next stream's
//! frames arrive. The peer then reads and decrypts many small writes.
//!
//! This adapter yields once, through Tokio's deferred `yield_now`, before the
//! first write of each batch. Every task that is already runnable (typically
//! the other streams finishing their responses) gets to queue its frames first,
//! and the connection writes them together. The batch ends at the next
//! completed flush. Only the first write of a batch yields, so a write that
//! cannot complete (socket full) never yields again.

use std::future::Future;
use std::io;
use std::pin::{Pin, pin};
use std::sync::LazyLock;
use std::task::{Context, Poll, ready};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Which sides defer their first write. EXPERIMENT ONLY (not for merge):
/// `FERRUM_BENCH_DEFER_FLUSH` = `frontend`, `backend`, `both`, or unset.
static DEFER_FLUSH: LazyLock<(bool, bool)> =
    LazyLock::new(
        || match std::env::var("FERRUM_BENCH_DEFER_FLUSH").as_deref() {
            Ok("frontend") => (true, false),
            Ok("backend") => (false, true),
            Ok("both") => (true, true),
            _ => (false, false),
        },
    );

pub(crate) fn frontend_enabled() -> bool {
    DEFER_FLUSH.0
}

pub(crate) fn backend_enabled() -> bool {
    DEFER_FLUSH.1
}

pub(crate) struct DeferredFlushIo<T> {
    inner: T,
    enabled: bool,
    /// The current batch has already yielded once.
    yielded: bool,
}

impl<T> DeferredFlushIo<T> {
    pub(crate) fn new(inner: T, enabled: bool) -> Self {
        Self {
            inner,
            enabled,
            yielded: false,
        }
    }

    fn poll_defer(&mut self, cx: &mut Context<'_>) -> Poll<()> {
        if !self.enabled || self.yielded {
            return Poll::Ready(());
        }
        self.yielded = true;
        // The first poll registers the waker on Tokio's deferred list, which is
        // woken after the worker has run its other ready tasks.
        let mut yielding = pin!(tokio::task::yield_now());
        yielding.as_mut().poll(cx)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for DeferredFlushIo<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for DeferredFlushIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_defer(cx));
        Pin::new(&mut this.inner).poll_write(cx, buf)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        ready!(this.poll_defer(cx));
        Pin::new(&mut this.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let flushed = ready!(Pin::new(&mut this.inner).poll_flush(cx));
        this.yielded = false;
        Poll::Ready(flushed)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}
