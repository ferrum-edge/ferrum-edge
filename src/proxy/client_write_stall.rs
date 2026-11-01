//! Downstream write-stall bound for HTTP/1.1 and HTTP/2 client connections.
//!
//! # The gap this closes
//!
//! Every backend-facing bound on a streaming response deliberately ignores
//! time spent waiting on the client. `IdleReadTimeoutBody` arms only on a
//! backend `Pending` (a slow client must never look like a slow backend), and
//! hyper stops polling the response body at all while the client's socket is
//! full. The authenticated-stream watchdog (`response_watchdog`) bounds that
//! wait by the credential lifetime, but an unauthenticated response had no
//! bound at all: a client that requests a large or endless body and then
//! stops reading its socket parks the connection task, the response body, the
//! backend connection it holds, and every admission permit and guard that
//! `ProxyBody` carries for as long as it keeps the TCP connection open. Many
//! such clients are the classic slow-read exhaustion attack, and the backend
//! sees one stuck connection per client.
//!
//! # The bound
//!
//! [`ClientWriteStallIo`] wraps the accepted client socket: below hyper on
//! plaintext listeners and below rustls on TLS listeners, so every byte the
//! kernel accepts (ciphertext, on TLS) counts as progress.
//! It is the transport-level analogue of nginx's `send_timeout`: the timer
//! runs only while the gateway has bytes to write and the transport refuses
//! all of them (`poll_write` / `poll_write_vectored` / `poll_flush` /
//! `poll_shutdown` returned `Pending`). Any write the transport accepts, and
//! any flush or shutdown that completes, disarms it. So:
//!
//! * a backend that is slow to produce bytes never arms it (there is nothing
//!   to write);
//! * a client that reads slowly but keeps reading re-arms it on every write
//!   the kernel accepts. The window measures send-buffer acceptance, not the
//!   client's application reads, and TCP zero-window persist probing can hold
//!   the send buffer full for several seconds even while the client is still
//!   reading (about 5–7 s measured on macOS loopback for a 40 KiB/s reader),
//!   which is why the default is nginx's 60 s rather than a few seconds;
//! * a client that stops reading for the whole window gets the connection
//!   closed with an `io::ErrorKind::TimedOut` write error, which ends the
//!   hyper connection and drops every response body on it.
//!
//! The wrapper is armed only on a `Pending` write, so the fast path is one
//! branch per write. The [`Sleep`](tokio::time::Sleep) is allocated lazily on
//! the first stall of a connection and re-armed with `reset` afterwards.
//!
//! # Scope
//!
//! This bounds **transport** progress, so it is complete for HTTP/1.1 (one
//! response per connection at a time, written straight to the socket) and for
//! upgraded WebSocket transports. On HTTP/2 it fires only when the socket
//! itself stops accepting bytes: a client whose stream or connection
//! flow-control window is smaller than what the socket buffers can absorb (the
//! RFC 9113 default window is 65,535 bytes) parks hyper's response pipe on
//! send capacity before any transport write blocks, and a client that keeps
//! reading its socket but withholds one stream's `WINDOW_UPDATE` never stalls
//! the transport at all. The same setting bounds those HTTP/2 stream-capacity
//! stalls one layer up: the frontends pass
//! [`h2_response_write_timeout`] to hyper's response pipe (hyper patch 008),
//! which resets a stream whose ready chunk the client grants no window for.
//! HTTP/3 has its own QUIC idle timeout and flow control and does not use
//! this wrapper. Admin and injector listeners are not wrapped.
//!
//! The connection-close log line (`error_kind=client_write_stall`) is emitted
//! by the HTTP connection handlers. A WebSocket that was already upgraded when
//! the stall fired ends through the WebSocket relay's own close path instead.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// The HTTP/2 response flow-control stall bound for the same setting
/// (hyper patch 008): `0` disables it, as it disables the transport bound.
pub fn h2_response_write_timeout(timeout_seconds: u64) -> Option<Duration> {
    (timeout_seconds > 0).then(|| Duration::from_secs(timeout_seconds))
}

/// Fixed message for the stall error. Compiled in; echoes nothing from the
/// client.
pub const CLIENT_WRITE_STALL_MESSAGE: &str =
    "client write stalled: no write progress within FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS";

/// Typed marker carried inside the `io::Error` so connection-close logging can
/// recognize a stall by walking the error source chain instead of matching
/// strings.
#[derive(Debug)]
pub struct ClientWriteStalled;

impl std::fmt::Display for ClientWriteStalled {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(CLIENT_WRITE_STALL_MESSAGE)
    }
}

impl std::error::Error for ClientWriteStalled {}

fn stalled_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, ClientWriteStalled)
}

/// `true` when `err` (or anything in its source chain) is the write-stall
/// close produced by [`ClientWriteStallIo`].
///
/// HTTP/1.1 errors keep the typed [`ClientWriteStalled`] marker inside the
/// `io::Error`. h2 converts an I/O error into its own `proto::Error::Io(kind,
/// message)` and rebuilds the `io::Error` from the inner error's *message*,
/// so on HTTP/2 only the compiled-in [`CLIENT_WRITE_STALL_MESSAGE`] survives;
/// h2's `Error` also exposes no `source()`, so it is unwrapped with `get_io`.
/// Runs only on the connection-close path, never per request.
pub fn is_client_write_stall(err: &(dyn std::error::Error + 'static)) -> bool {
    let mut cur: Option<&(dyn std::error::Error + 'static)> = Some(err);
    while let Some(e) = cur {
        if e.is::<ClientWriteStalled>() {
            return true;
        }
        if let Some(io_err) = e.downcast_ref::<io::Error>()
            && io_error_is_stall(io_err)
        {
            return true;
        }
        if let Some(io_err) = e.downcast_ref::<h2::Error>().and_then(h2::Error::get_io)
            && io_error_is_stall(io_err)
        {
            return true;
        }
        cur = e.source();
    }
    false
}

fn io_error_is_stall(err: &io::Error) -> bool {
    err.kind() == io::ErrorKind::TimedOut
        && err.get_ref().is_some_and(|inner| {
            inner.is::<ClientWriteStalled>() || inner.to_string() == CLIENT_WRITE_STALL_MESSAGE
        })
}

/// Client transport wrapper that fails writes once the transport has refused
/// every write for a whole `timeout` window. See the module docs.
pub struct ClientWriteStallIo<T> {
    inner: T,
    /// `None` disables the bound (`FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS=0`).
    timeout: Option<Duration>,
    /// Lazily allocated on the first stall, then re-armed with `reset`.
    timer: Option<Pin<Box<tokio::time::Sleep>>>,
    /// A stall episode is in progress: the timer holds its deadline.
    armed: bool,
    /// The bound fired. Sticky: every later write fails the same way.
    expired: bool,
}

impl<T> ClientWriteStallIo<T> {
    /// Wrap `inner`. `timeout_seconds == 0` disables the bound.
    pub fn new(inner: T, timeout_seconds: u64) -> Self {
        Self {
            inner,
            timeout: (timeout_seconds > 0).then(|| Duration::from_secs(timeout_seconds)),
            timer: None,
            armed: false,
            expired: false,
        }
    }

    /// `true` once the bound has fired on this connection.
    pub fn is_expired(&self) -> bool {
        self.expired
    }

    #[inline]
    fn progress(&mut self) {
        self.armed = false;
    }

    /// The inner transport refused the write. Start (or continue) the stall
    /// episode and report whether its deadline has passed.
    fn on_pending<R>(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<R>> {
        let Some(timeout) = self.timeout else {
            return Poll::Pending;
        };
        if !self.armed {
            self.armed = true;
            let now = tokio::time::Instant::now();
            // `checked_add` keeps an unrepresentable timeout from panicking.
            // `EnvConfig::validate` refuses anything above
            // `MAX_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS`, so this is unreachable
            // from configuration.
            let Some(deadline) = now.checked_add(timeout) else {
                return Poll::Pending;
            };
            match self.timer.as_mut() {
                Some(timer) => timer.as_mut().reset(deadline),
                None => self.timer = Some(Box::pin(tokio::time::sleep_until(deadline))),
            }
        }
        let Some(timer) = self.timer.as_mut() else {
            return Poll::Pending;
        };
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => {
                self.expired = true;
                Poll::Ready(Err(stalled_error()))
            }
            Poll::Pending => Poll::Pending,
        }
    }

    #[inline]
    fn settle<R>(
        &mut self,
        cx: &mut Context<'_>,
        polled: Poll<io::Result<R>>,
    ) -> Poll<io::Result<R>> {
        match polled {
            Poll::Ready(Ok(v)) => {
                self.progress();
                Poll::Ready(Ok(v))
            }
            // An error is the transport's own terminal, not a stall.
            Poll::Ready(Err(e)) => {
                self.progress();
                Poll::Ready(Err(e))
            }
            Poll::Pending => self.on_pending(cx),
        }
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for ClientWriteStallIo<T> {
    #[inline]
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for ClientWriteStallIo<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.expired {
            return Poll::Ready(Err(stalled_error()));
        }
        let polled = Pin::new(&mut this.inner).poll_write(cx, buf);
        this.settle(cx, polled)
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        if this.expired {
            return Poll::Ready(Err(stalled_error()));
        }
        let polled = Pin::new(&mut this.inner).poll_write_vectored(cx, bufs);
        this.settle(cx, polled)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.expired {
            return Poll::Ready(Err(stalled_error()));
        }
        let polled = Pin::new(&mut this.inner).poll_flush(cx);
        this.settle(cx, polled)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.expired {
            // The connection is being torn down after the stall; let the
            // close proceed without waiting on a peer that will not read.
            return Poll::Ready(Ok(()));
        }
        let polled = Pin::new(&mut this.inner).poll_shutdown(cx);
        this.settle(cx, polled)
    }
}
