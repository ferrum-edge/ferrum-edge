//! `DelayedStream` — pause every read and write by a fixed `Duration`.
//!
//! The wrapper pokes a `tokio::time::sleep` into the read / write path
//! so tests can model "backend RTT = 200 ms" without touching the
//! kernel. Delays are enforced on a per-poll basis via
//! `pin_project_lite` and `tokio::time::Sleep` state kept alive across
//! polls — the usual crate of async-stream adapters.
//!
//! ## Semantics
//!
//! - The first `poll_read` on an empty buffer is delayed by the full
//!   `Duration`, then calls the inner `poll_read`. If the inner returns
//!   `Poll::Pending`, the next poll will delay again — so the delay is
//!   applied once per *scheduler pass*, not once per byte. Good enough
//!   for the per-chunk semantics the test catalog models.
//! - `poll_write` likewise delays once per pass. After the inner write
//!   returns, the wrapper resets the timer so subsequent writes are
//!   also delayed.
//! - `poll_shutdown` is forwarded without delay.
//!
//! If you need a *rate limit* (bytes per second), use
//! [`super::bandwidth::BandwidthLimitedStream`] instead; latency just
//! slows the tempo, it does not cap throughput.

use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

// Sleep is `!Unpin` (it has internal `PhantomPinned`); storing it as
// `Option<Sleep>` poisons pin_project's generated `Unpin` impl and in
// turn breaks `.await` on common tokio extension futures like
// `write_all` / `flush` that expect `Self: Unpin`. `Pin<Box<Sleep>>` is
// always `Unpin` regardless of `Sleep`'s own pinning, at the cost of
// one allocation when the timer arms.
type BoxedSleep = Pin<Box<Sleep>>;

pin_project! {
    pub struct DelayedStream<T> {
        #[pin]
        inner: T,
        read_delay: Duration,
        write_delay: Duration,
        read_sleep: Option<BoxedSleep>,
        write_sleep: Option<BoxedSleep>,
    }
}

impl<T> DelayedStream<T> {
    /// Delay reads and writes by the same `Duration` — the common
    /// "simulate RTT" case.
    pub fn new(inner: T, delay: Duration) -> Self {
        Self::with_split(inner, delay, delay)
    }

    /// Set different delays for read vs write. Useful for modelling
    /// asymmetric links (e.g., slow uplink, fast downlink).
    pub fn with_split(inner: T, read_delay: Duration, write_delay: Duration) -> Self {
        Self {
            inner,
            read_delay,
            write_delay,
            read_sleep: None,
            write_sleep: None,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsyncRead for DelayedStream<T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        if this.read_delay.is_zero() {
            return this.inner.poll_read(cx, buf);
        }

        // Arm the sleep lazily on first poll and on each completed read.
        if this.read_sleep.is_none() {
            let delay = *this.read_delay;
            *this.read_sleep = Some(Box::pin(tokio::time::sleep(delay)));
        }

        // Poll the sleep; if still pending, bail.
        if let Some(sleep) = this.read_sleep.as_mut() {
            match sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            }
        }
        *this.read_sleep = None;
        let pre_len = buf.filled().len();
        let res = this.inner.poll_read(cx, buf);
        // If we actually read something, re-arm the delay so the next
        // chunk also waits.
        if matches!(res, Poll::Ready(Ok(()))) && buf.filled().len() > pre_len {
            let delay = *this.read_delay;
            *this.read_sleep = Some(Box::pin(tokio::time::sleep(delay)));
        }
        res
    }
}

impl<T> AsyncWrite for DelayedStream<T>
where
    T: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();

        if this.write_delay.is_zero() {
            return this.inner.poll_write(cx, buf);
        }

        if this.write_sleep.is_none() {
            let delay = *this.write_delay;
            *this.write_sleep = Some(Box::pin(tokio::time::sleep(delay)));
        }

        if let Some(sleep) = this.write_sleep.as_mut() {
            match sleep.as_mut().poll(cx) {
                Poll::Pending => return Poll::Pending,
                Poll::Ready(()) => {}
            }
        }
        *this.write_sleep = None;
        let res = this.inner.poll_write(cx, buf);
        if matches!(res, Poll::Ready(Ok(_))) {
            let delay = *this.write_delay;
            *this.write_sleep = Some(Box::pin(tokio::time::sleep(delay)));
        }
        res
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        self.project().inner.poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn delayed_write_takes_at_least_delay() {
        // Duplex pipe: A writes to B.
        let (a, mut b) = tokio::io::duplex(1024);
        let mut a = DelayedStream::new(a, Duration::from_millis(100));
        let started = Instant::now();
        a.write_all(b"hello").await.unwrap();
        a.flush().await.unwrap();
        assert!(started.elapsed() >= Duration::from_millis(100));

        let mut buf = [0u8; 8];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"hello");
    }

    #[tokio::test]
    async fn delayed_read_takes_at_least_delay() {
        let (mut a, b) = tokio::io::duplex(1024);
        a.write_all(b"pong").await.unwrap();
        a.flush().await.unwrap();

        let mut b = DelayedStream::new(b, Duration::from_millis(100));
        let started = Instant::now();
        let mut buf = [0u8; 8];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"pong");
        assert!(started.elapsed() >= Duration::from_millis(100));
    }

    #[tokio::test]
    async fn zero_delay_is_passthrough() {
        let (a, mut b) = tokio::io::duplex(1024);
        let mut a = DelayedStream::new(a, Duration::ZERO);
        a.write_all(b"fast").await.unwrap();
        a.flush().await.unwrap();
        let mut buf = [0u8; 8];
        let n = b.read(&mut buf).await.unwrap();
        assert_eq!(&buf[..n], b"fast");
    }
}
