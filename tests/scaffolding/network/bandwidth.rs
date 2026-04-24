//! `BandwidthLimitedStream` — enforce a bytes-per-second ceiling on
//! reads and writes.
//!
//! Implemented as a simple token-bucket: each stream holds a clock
//! `last_refill` and a `tokens` count (in bytes). Before doing I/O, the
//! wrapper refills tokens based on elapsed time at the configured rate.
//! If the current `poll_write`/`poll_read` wants more than is in the
//! bucket, the wrapper sleeps until enough tokens accrue. Refill is
//! linear in `bps * elapsed_seconds`; the bucket's capacity is
//! `bps` bytes so there's a 1-second burst allowance.
//!
//! This is the same shape as `tokio::time::Interval`-based rate
//! limiters, but inline in the I/O trait so any adapter above us
//! (framed, line-by-line, etc.) automatically respects the limit.
//!
//! ## What this models vs. what it doesn't
//!
//! - **Models**: "backend uplink caps at 1 MiB/s" for sending and
//!   receiving.
//! - **Does NOT model**: per-direction TCP window stalls, kernel
//!   `SO_SNDBUF` pressure, or traffic shapers with burst tolerance.
//!   Those belong in a Phase-7 scenario catalog.

use pin_project_lite::pin_project;
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::time::Sleep;

// Sleep is `!Unpin`; boxing it keeps the outer type `Unpin` so the
// standard tokio extension futures (`read`, `write_all`, etc.) work.
type BoxedSleep = Pin<Box<Sleep>>;

/// Internal token bucket. Refills at `rate_bps` bytes per second up to
/// a 1-second burst.
#[derive(Debug)]
struct TokenBucket {
    rate_bps: u64,
    tokens: f64,
    last_refill: Instant,
}

impl TokenBucket {
    fn new(rate_bps: u64) -> Self {
        Self {
            rate_bps,
            // Start at full capacity so the first I/O isn't penalised.
            tokens: rate_bps as f64,
            last_refill: Instant::now(),
        }
    }

    fn refill(&mut self) {
        let now = Instant::now();
        let elapsed = now.saturating_duration_since(self.last_refill);
        self.last_refill = now;
        let add = self.rate_bps as f64 * elapsed.as_secs_f64();
        let cap = self.rate_bps as f64;
        self.tokens = (self.tokens + add).min(cap);
    }

    /// Try to consume `n` tokens. Returns `Ok(())` if available.
    /// Otherwise returns the `Duration` we'd have to wait to accumulate
    /// enough.
    fn try_consume(&mut self, n: u64) -> Result<(), Duration> {
        self.refill();
        if self.tokens >= n as f64 {
            self.tokens -= n as f64;
            return Ok(());
        }
        let deficit = n as f64 - self.tokens;
        let seconds = deficit / self.rate_bps as f64;
        Err(Duration::from_secs_f64(seconds))
    }
}

pin_project! {
    pub struct BandwidthLimitedStream<T> {
        #[pin]
        inner: T,
        read_bucket: TokenBucket,
        write_bucket: TokenBucket,
        read_sleep: Option<BoxedSleep>,
        write_sleep: Option<BoxedSleep>,
    }
}

impl<T> BandwidthLimitedStream<T> {
    /// Same rate for reads and writes (the common "1 MiB/s link" case).
    pub fn new(inner: T, rate_bps: u64) -> Self {
        Self::with_split(inner, rate_bps, rate_bps)
    }

    /// Different rates for each direction.
    pub fn with_split(inner: T, read_bps: u64, write_bps: u64) -> Self {
        Self {
            inner,
            read_bucket: TokenBucket::new(read_bps.max(1)),
            write_bucket: TokenBucket::new(write_bps.max(1)),
            read_sleep: None,
            write_sleep: None,
        }
    }

    pub fn into_inner(self) -> T {
        self.inner
    }
}

impl<T> AsyncRead for BandwidthLimitedStream<T>
where
    T: AsyncRead,
{
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let this = self.project();

        // Only gate based on how many bytes the caller is willing to
        // receive — `buf.remaining()`. In practice most buf sizes are
        // 8k/64k; the bucket caps them.
        let want = buf.remaining().max(1) as u64;
        let allowed = want.min(this.read_bucket.rate_bps);

        loop {
            // If we have a timer armed and it hasn't fired, bail.
            if this.read_sleep.is_some() {
                if let Some(sleep) = this.read_sleep.as_mut() {
                    match sleep.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => {}
                    }
                }
                *this.read_sleep = None;
            }
            match this.read_bucket.try_consume(allowed) {
                Ok(()) => break,
                Err(wait) => {
                    *this.read_sleep = Some(Box::pin(tokio::time::sleep(wait)));
                    // Loop back to poll the sleep we just armed.
                    continue;
                }
            }
        }

        // Temporarily shrink the read buf so the inner stream doesn't
        // read more than `allowed` tokens authorised. `ReadBuf::take`
        // produces a sub-buf bounded to `allowed` bytes; then we commit
        // whatever got filled back to the caller's buf.
        let mut limit = [0u8; 65535];
        let slice_len = (allowed as usize).min(buf.remaining()).min(limit.len());
        let mut sub = ReadBuf::new(&mut limit[..slice_len]);
        let res = this.inner.poll_read(cx, &mut sub);
        if let Poll::Ready(Ok(())) = res {
            let filled = sub.filled();
            buf.put_slice(filled);
            // Refund any unused tokens (we paid `allowed`, used `filled.len()`).
            let refund = allowed.saturating_sub(filled.len() as u64);
            this.read_bucket.tokens += refund as f64;
        }
        res
    }
}

impl<T> AsyncWrite for BandwidthLimitedStream<T>
where
    T: AsyncWrite,
{
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.project();
        let want = buf.len() as u64;
        if want == 0 {
            return this.inner.poll_write(cx, buf);
        }
        let allowed = want.min(this.write_bucket.rate_bps);

        loop {
            if this.write_sleep.is_some() {
                if let Some(sleep) = this.write_sleep.as_mut() {
                    match sleep.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => {}
                    }
                }
                *this.write_sleep = None;
            }
            match this.write_bucket.try_consume(allowed) {
                Ok(()) => break,
                Err(wait) => {
                    *this.write_sleep = Some(Box::pin(tokio::time::sleep(wait)));
                    continue;
                }
            }
        }

        let slice = &buf[..(allowed as usize).min(buf.len())];
        let res = this.inner.poll_write(cx, slice);
        if let Poll::Ready(Ok(n)) = res {
            let refund = allowed.saturating_sub(n as u64);
            this.write_bucket.tokens += refund as f64;
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
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[tokio::test]
    async fn bandwidth_limited_write_takes_longer_than_payload_div_rate() {
        // 1 KB/s rate; 2 KB payload → ≥1 second.
        let (a, mut b) = tokio::io::duplex(4096);
        let mut a = BandwidthLimitedStream::new(a, 1024);

        let reader = tokio::spawn(async move {
            let mut total = 0;
            let mut buf = [0u8; 256];
            loop {
                match b.read(&mut buf).await {
                    Ok(0) => break,
                    Ok(n) => total += n,
                    Err(_) => break,
                }
                if total >= 2048 {
                    break;
                }
            }
            total
        });

        let started = Instant::now();
        let data = vec![0u8; 2048];
        a.write_all(&data).await.unwrap();
        a.flush().await.unwrap();
        // Drop to signal EOF to the reader.
        drop(a);

        let total = reader.await.unwrap();
        assert_eq!(total, 2048);
        // Allow some slack for wall-clock noise; the point is that it
        // cannot be near-instant.
        assert!(
            started.elapsed() >= Duration::from_millis(700),
            "elapsed was {:?}",
            started.elapsed()
        );
    }
}
