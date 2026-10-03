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

/// EXPERIMENT ONLY (not for merge): `FERRUM_BENCH_GRPC_CONN_AFFINITY=1` starts
/// a gRPC request's backend shard probe at the shard its frontend connection
/// maps to, so one frontend connection's streams share a backend connection.
static GRPC_CONN_AFFINITY: LazyLock<bool> =
    LazyLock::new(|| std::env::var("FERRUM_BENCH_GRPC_CONN_AFFINITY").as_deref() == Ok("1"));

static NEXT_FRONTEND_CONNECTION: std::sync::atomic::AtomicUsize =
    std::sync::atomic::AtomicUsize::new(0);

tokio::task_local! {
    static FRONTEND_CONNECTION: usize;
}

/// A fresh frontend connection number, or `None` when affinity is off.
pub(crate) fn next_frontend_connection() -> Option<usize> {
    GRPC_CONN_AFFINITY
        .then(|| NEXT_FRONTEND_CONNECTION.fetch_add(1, std::sync::atomic::Ordering::Relaxed))
}

/// Run a request future with its frontend connection number in scope.
pub(crate) async fn with_frontend_connection<F: Future>(id: Option<usize>, fut: F) -> F::Output {
    match id {
        Some(id) => FRONTEND_CONNECTION.scope(id, fut).await,
        None => fut.await,
    }
}

/// The affinity shard for the current request, if affinity is on.
pub(crate) fn affinity_shard(shard_count: usize) -> Option<usize> {
    FRONTEND_CONNECTION
        .try_with(|id| *id % shard_count.max(1))
        .ok()
}
