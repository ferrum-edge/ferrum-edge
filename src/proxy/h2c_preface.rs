//! Positive proof that an h2c peer completed the HTTP/2 connection preface.
//!
//! `hyper::client::conn::http2::Builder::handshake` resolves as soon as the
//! **client** side is bound: it writes the 24-byte client connection preface
//! and buffers the client `SETTINGS` frame. It never reads from the peer, so it
//! completes against any socket that merely accepted the connection — including
//! one whose peer speaks a different protocol, or nothing at all. Wrapping that
//! call in a timeout therefore bounds only the client's own preface write and
//! proves nothing about the peer.
//!
//! Cleartext h2c has no ALPN to fall back on, so establishment has to be
//! observed on the wire. RFC 9113 §3.4 makes a `SETTINGS` frame the first frame
//! the server sends, so [`H2cPrefaceIo`] watches the bytes the connection driver
//! reads and flips a flag once a complete, structurally plausible initial
//! `SETTINGS` frame has arrived. Hyper stays the authoritative frame parser:
//! [`await_peer_settings`] gives it a final poll so a protocol error it finds in
//! that same frame wins over the raw observation.
//!
//! Two facts shape [`await_peer_settings`]'s recheck loop rather than a plain
//! await. `handshake()` returns the h2 connection-driver future, which must be
//! polled to drive reads and surface connection errors; and a healthy driver
//! stays pending after peer `SETTINGS` rather than resolving with a separate
//! readiness result. The short recheck cadence therefore lets the transport's
//! observation flag end establishment while the same polls keep driving Hyper.
//!
//! The wait itself is deliberately unbounded here — the caller owns the bound,
//! because each caller derives it differently (a per-candidate share of the
//! connect budget for pooled TCP, the remainder of one end-to-end connect budget
//! for a Unix socket, and the whole-acquisition deadline the Ambient HBONE gRPC
//! transport wraps around its nested HTTP/2 client).

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Observes the first server frame without interfering with hyper's parser.
/// HTTP/2 requires a structurally valid initial SETTINGS frame, so completing
/// one and giving Hyper a final validation poll proves the peer preface even
/// when MAX_CONCURRENT_STREAMS is zero.
pub(crate) struct H2cPrefaceIo<T> {
    inner: T,
    settings_received: Arc<AtomicBool>,
    first_frame_header: [u8; 9],
    header_len: usize,
    frame_remaining: Option<usize>,
}

impl<T> H2cPrefaceIo<T> {
    pub(crate) fn new(inner: T, settings_received: Arc<AtomicBool>) -> Self {
        Self {
            inner,
            settings_received,
            first_frame_header: [0; 9],
            header_len: 0,
            frame_remaining: None,
        }
    }

    fn observe(&mut self, mut bytes: &[u8]) {
        if self.settings_received.load(Ordering::Relaxed) {
            return;
        }
        if self.header_len < self.first_frame_header.len() {
            let copied = bytes
                .len()
                .min(self.first_frame_header.len() - self.header_len);
            self.first_frame_header[self.header_len..self.header_len + copied]
                .copy_from_slice(&bytes[..copied]);
            self.header_len += copied;
            bytes = &bytes[copied..];
            if self.header_len == self.first_frame_header.len() {
                let payload_len = (usize::from(self.first_frame_header[0]) << 16)
                    | (usize::from(self.first_frame_header[1]) << 8)
                    | usize::from(self.first_frame_header[2]);
                self.frame_remaining = Some(payload_len);
            }
        }
        if let Some(remaining) = self.frame_remaining.as_mut() {
            *remaining = remaining.saturating_sub(bytes.len());
            if *remaining == 0 && self.initial_settings_header_is_well_formed() {
                self.settings_received.store(true, Ordering::Release);
            }
        }
    }

    /// Validate the peer's initial SETTINGS frame header before treating the
    /// raw frame as establishment proof. Hyper remains the authoritative frame
    /// parser; these checks prevent a complete but obviously invalid SETTINGS
    /// frame from winning the readiness race before Hyper surfaces its protocol
    /// error.
    fn initial_settings_header_is_well_formed(&self) -> bool {
        const DEFAULT_MAX_FRAME_SIZE: usize = 16_384;

        let payload_len = (usize::from(self.first_frame_header[0]) << 16)
            | (usize::from(self.first_frame_header[1]) << 8)
            | usize::from(self.first_frame_header[2]);
        let stream_id = u32::from_be_bytes([
            self.first_frame_header[5],
            self.first_frame_header[6],
            self.first_frame_header[7],
            self.first_frame_header[8],
        ]) & 0x7fff_ffff;

        self.first_frame_header[3] == 0x4
            && self.first_frame_header[4] & 0x1 == 0
            && stream_id == 0
            && payload_len <= DEFAULT_MAX_FRAME_SIZE
            && payload_len % 6 == 0
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for H2cPrefaceIo<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let filled_before = buf.filled().len();
        match Pin::new(&mut self.inner).poll_read(cx, buf) {
            Poll::Ready(Ok(())) => {
                self.observe(&buf.filled()[filled_before..]);
                Poll::Ready(Ok(()))
            }
            result => result,
        }
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for H2cPrefaceIo<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[std::io::IoSlice<'_>],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write_vectored(cx, bufs)
    }

    fn is_write_vectored(&self) -> bool {
        self.inner.is_write_vectored()
    }
}

/// Why an h2c connection never became a usable HTTP/2 connection.
///
/// Every variant is observed BEFORE any request byte is written, so a caller may
/// treat all of them as pre-wire and replay-safe.
#[derive(Debug)]
pub(crate) enum H2cPrefaceFailure {
    /// The connection ended without error before the peer's initial SETTINGS
    /// frame completed, so the peer never proved it speaks HTTP/2 here.
    ClosedBeforeSettings,
    /// Hyper ended the connection on the same poll that validated the observed
    /// SETTINGS frame; the sender would already be dead.
    ClosedAfterSettings,
    /// Hyper surfaced a connection-level error while the peer preface was
    /// pending — including its own rejection of the frame just observed.
    Connection(hyper::Error),
}

impl std::fmt::Display for H2cPrefaceFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ClosedBeforeSettings => f.write_str("h2c connection closed before peer SETTINGS"),
            Self::ClosedAfterSettings => f.write_str("h2c connection closed after peer SETTINGS"),
            Self::Connection(error) => write!(f, "h2c handshake failed: {error}"),
        }
    }
}

/// Wait for positive proof that an h2c peer completed the HTTP/2 preface.
///
/// `conn` is the connection-driver future `handshake()` returned. Polling it
/// drives the peer's preface and SETTINGS processing and surfaces a protocol
/// error or close, but a healthy connection remains pending after SETTINGS
/// arrives. The short timeout therefore supplies a bounded recheck cadence for
/// the transport observation flag while also continuing to drive the same
/// connection future.
///
/// There is no timeout here by design; the CALLER owns the bound. The gRPC pool
/// runs inside `dns::connect_candidates`, whose per-candidate share of
/// `backend_connect_timeout_ms` bounds this wait and moves on to the next
/// address. The Unix h2c transport bounds it with whatever remains of its one
/// end-to-end connect budget. The Ambient HBONE gRPC transport bounds it with
/// the whole-acquisition deadline `GrpcDispatchTransport::get_sender` wraps
/// around its nested HTTP/2 client (issue #3284).
pub(crate) async fn await_peer_settings<C>(
    conn: &mut C,
    settings_received: &AtomicBool,
) -> Result<(), H2cPrefaceFailure>
where
    C: Future<Output = hyper::Result<()>> + Unpin,
{
    // First re-read delay; the common case resolves on the first or second
    // pass over a loopback or same-datacenter RTT.
    const FIRST_RECHECK: Duration = Duration::from_millis(1);
    // Ceiling for the doubling backoff, so a peer that accepts and then stalls
    // costs a bounded number of timer wakeups per attempt.
    const MAX_RECHECK: Duration = Duration::from_millis(20);

    let mut recheck = FIRST_RECHECK;
    loop {
        if settings_received.load(Ordering::Acquire) {
            // The transport observer fires while Hyper is consuming the read.
            // Poll the connection once more before accepting the peer so a
            // protocol error discovered from that same frame wins over the raw
            // readiness flag instead of leaving an invalid sender cached and
            // suppressing DNS-candidate failover.
            let post_observation = std::future::poll_fn(|cx| {
                Poll::Ready(match Pin::new(&mut *conn).poll(cx) {
                    Poll::Ready(Ok(())) => Some(H2cPrefaceFailure::ClosedAfterSettings),
                    Poll::Ready(Err(error)) => Some(H2cPrefaceFailure::Connection(error)),
                    Poll::Pending => None,
                })
            })
            .await;
            return match post_observation {
                Some(failure) => Err(failure),
                None => Ok(()),
            };
        }
        match tokio::time::timeout(recheck, &mut *conn).await {
            Ok(Ok(())) => return Err(H2cPrefaceFailure::ClosedBeforeSettings),
            Ok(Err(error)) => return Err(H2cPrefaceFailure::Connection(error)),
            Err(_elapsed) => recheck = (recheck * 2).min(MAX_RECHECK),
        }
    }
}
