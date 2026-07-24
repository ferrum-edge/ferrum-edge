//! Idle-read timeout wrapper for admin listener I/O.
//!
//! Hyper's `header_read_timeout` covers HTTP/1.1 incomplete headers only. For
//! HTTP/2, incomplete HEADERS/CONTINUATION streams never reach the service
//! layer, so a stalled peer can retain stream state until the connection is
//! torn down. Wrapping the accepted stream with an idle-read deadline closes
//! that gap: any pending read that waits longer than the configured idle
//! window fails, which aborts incomplete H2 header assembly and also bounds
//! connection-level stalls when no other multiplexed traffic is active.

use std::io::{self, ErrorKind};
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::{Instant, Sleep, sleep_until};

/// Wraps an async stream and fails reads that idle longer than `idle`.
///
/// Writes are forwarded unchanged. `idle == Duration::ZERO` disables the
/// deadline (pass-through), matching the admin header-timeout `0 = off`
/// convention.
pub(crate) struct IdleTimeoutStream<S> {
    inner: S,
    idle: Duration,
    deadline: Option<Pin<Box<Sleep>>>,
    waiting: bool,
}

impl<S> IdleTimeoutStream<S> {
    pub(crate) fn new(inner: S, idle: Duration) -> Self {
        Self {
            inner,
            idle,
            deadline: None,
            waiting: false,
        }
    }

    fn enabled(&self) -> bool {
        !self.idle.is_zero()
    }

    fn arm_deadline(&mut self) {
        if !self.enabled() {
            self.deadline = None;
            return;
        }
        match Instant::now().checked_add(self.idle) {
            Some(at) => match self.deadline.as_mut() {
                Some(sleep) => sleep.as_mut().reset(at),
                None => self.deadline = Some(Box::pin(sleep_until(at))),
            },
            None => self.deadline = None,
        }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for IdleTimeoutStream<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let filled_before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                self.waiting = false;
                // Any successful read (including EOF) clears the idle wait.
                let _ = filled_before;
                Poll::Ready(Ok(()))
            }
            Poll::Ready(Err(err)) => {
                self.waiting = false;
                Poll::Ready(Err(err))
            }
            Poll::Pending => {
                if !self.enabled() {
                    return Poll::Pending;
                }
                if !self.waiting {
                    self.waiting = true;
                    self.arm_deadline();
                }
                if let Some(deadline) = self.deadline.as_mut() {
                    match deadline.as_mut().poll(cx) {
                        Poll::Ready(()) => {
                            self.waiting = false;
                            return Poll::Ready(Err(io::Error::new(
                                ErrorKind::TimedOut,
                                "admin connection idle read timeout",
                            )));
                        }
                        Poll::Pending => {}
                    }
                }
                Poll::Pending
            }
        }
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for IdleTimeoutStream<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
