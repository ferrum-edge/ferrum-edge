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
//!   Model those inline in the test that needs them.

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

        // Charge only bytes that actually move. We don't reserve tokens
        // upfront — instead we wait until at least one token is
        // available, poll the inner stream, and then decrement the
        // bucket by whatever bytes came back. A `Pending` or error
        // result therefore never drains the bucket, so a backend that's
        // simply slow to respond doesn't add artificial sleeps on top
        // of its own latency.
        loop {
            if this.read_sleep.is_some() {
                if let Some(sleep) = this.read_sleep.as_mut() {
                    match sleep.as_mut().poll(cx) {
                        Poll::Pending => return Poll::Pending,
                        Poll::Ready(()) => {}
                    }
                }
                *this.read_sleep = None;
            }
            this.read_bucket.refill();
            if this.read_bucket.tokens >= 1.0 {
                break;
            }
            // Bucket fully drained. Wait for one token to accrue so we
            // can deliver at least one byte — this bounds the spin at
            // the configured rate without requiring a per-byte poll.
            let wait = Duration::from_secs_f64(1.0 / this.read_bucket.rate_bps as f64);
            *this.read_sleep = Some(Box::pin(tokio::time::sleep(wait)));
        }

        // Cap the inner read to what the bucket can afford right now,
        // plus the caller's buffer. A caller asking for 8 KiB on a
        // 1 KiB/s bucket will see at most ~1 KiB back per call.
        let available = this.read_bucket.tokens as u64;
        let mut scratch = [0u8; 65535];
        let slice_len = (available as usize)
            .max(1)
            .min(buf.remaining())
            .min(scratch.len());
        let mut sub = ReadBuf::new(&mut scratch[..slice_len]);
        let res = this.inner.poll_read(cx, &mut sub);
        if let Poll::Ready(Ok(())) = &res {
            let filled = sub.filled();
            buf.put_slice(filled);
            this.read_bucket.tokens -= filled.len() as f64;
            if this.read_bucket.tokens < 0.0 {
                this.read_bucket.tokens = 0.0;
            }
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
        if buf.is_empty() {
            return this.inner.poll_write(cx, buf);
        }

        // Same "charge only bytes actually moved" discipline as the
        // read path — see the comment in `poll_read`. A `Pending` write
        // to a backed-up peer never drains the bucket, so the limiter
        // tracks real throughput rather than poll scheduling.
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
            this.write_bucket.refill();
            if this.write_bucket.tokens >= 1.0 {
                break;
            }
            let wait = Duration::from_secs_f64(1.0 / this.write_bucket.rate_bps as f64);
            *this.write_sleep = Some(Box::pin(tokio::time::sleep(wait)));
        }

        // Slice the caller's buffer to what the bucket can afford.
        let available = this.write_bucket.tokens as usize;
        let slice = &buf[..available.max(1).min(buf.len())];
        let res = this.inner.poll_write(cx, slice);
        if let Poll::Ready(Ok(n)) = &res {
            this.write_bucket.tokens -= *n as f64;
            if this.write_bucket.tokens < 0.0 {
                this.write_bucket.tokens = 0.0;
            }
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

    /// Regression: `Pending` polls must not drain the token bucket.
    /// A backend that's simply slow to respond should not eat into the
    /// caller's rate budget; only bytes that actually move should
    /// charge the bucket. The "charge only bytes actually moved"
    /// discipline in `poll_read` guarantees this.
    ///
    /// Setup: 64 B/s rate (1 s burst ⇒ bucket starts at 64 tokens).
    /// Poll a read while the peer has nothing on the wire, cancel that
    /// read, then write a single byte. If `Pending` had drained the
    /// bucket, the follow-up read would stall ~1 s waiting for tokens
    /// to refill. Under the correct discipline it serves the byte
    /// immediately out of the untouched burst.
    #[tokio::test]
    async fn pending_poll_does_not_drain_tokens() {
        let (mut peer, receiver) = tokio::io::duplex(4096);
        let mut stream = BandwidthLimitedStream::new(receiver, 64);

        let mut buf = [0u8; 1024];
        tokio::select! {
            r = AsyncReadExt::read(&mut stream, &mut buf) => {
                panic!("unexpected early read result: {:?}", r);
            }
            _ = tokio::time::sleep(Duration::from_millis(50)) => {}
        }

        peer.write_all(&[7u8]).await.unwrap();

        let started = Instant::now();
        let n = AsyncReadExt::read(&mut stream, &mut buf).await.unwrap();
        let elapsed = started.elapsed();
        assert_eq!(n, 1);
        assert_eq!(buf[0], 7);
        // If `Pending` had drained the bucket, this would block ~1 s.
        assert!(
            elapsed < Duration::from_millis(200),
            "expected instant read (Pending must not drain the bucket), got {elapsed:?}"
        );
    }
}
