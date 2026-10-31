//! `ClientWriteStallIo`: the downstream write-stall bound
//! (`FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS`).
//!
//! A `tokio::io::duplex` pipe with a tiny buffer stands in for a client socket:
//! once the buffer is full, writes return `Pending` until the "client" reads.
//! Time is paused, so the bound's 60s windows run instantly and exactly.

use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use ferrum_edge::proxy::client_write_stall::{
    CLIENT_WRITE_STALL_MESSAGE, ClientWriteStallIo, is_client_write_stall,
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::time::Instant;

const PIPE: usize = 64;
const TIMEOUT_SECS: u64 = 60;

/// Spawns a writer that pushes `total` bytes through the wrapper and reports
/// the outcome together with the paused-clock instant it finished at.
fn spawn_writer(
    io: ClientWriteStallIo<tokio::io::DuplexStream>,
    total: usize,
) -> tokio::task::JoinHandle<(
    io::Result<()>,
    Instant,
    ClientWriteStallIo<tokio::io::DuplexStream>,
)> {
    tokio::spawn(async move {
        let mut io = io;
        let data = vec![b'x'; total];
        let res = io.write_all(&data).await;
        (res, Instant::now(), io)
    })
}

#[tokio::test(start_paused = true)]
async fn client_that_stops_reading_is_cut_after_the_timeout_not_before() {
    let (server, _client) = tokio::io::duplex(PIPE);
    let start = Instant::now();
    let writer = spawn_writer(ClientWriteStallIo::new(server, TIMEOUT_SECS), PIPE * 4);

    tokio::time::sleep(Duration::from_secs(TIMEOUT_SECS - 1)).await;
    assert!(
        !writer.is_finished(),
        "the bound fired before a whole window without write progress"
    );

    let (res, finished_at, io) = tokio::time::timeout(Duration::from_secs(5), writer)
        .await
        .expect("a stalled client must be cut shortly after the window")
        .expect("writer task");
    let err = res.expect_err("a client that never reads must fail the write");
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    assert!(is_client_write_stall(&err), "stall must be recognizable");
    assert_eq!(finished_at - start, Duration::from_secs(TIMEOUT_SECS));
    assert!(io.is_expired());
}

#[tokio::test(start_paused = true)]
async fn slow_reader_that_keeps_reading_is_never_cut() {
    let (server, mut client) = tokio::io::duplex(PIPE);
    let total = PIPE * 20;
    let writer = spawn_writer(ClientWriteStallIo::new(server, TIMEOUT_SECS), total);

    // Read one pipe-full every 45s: each read frees space, the next write is
    // accepted, and the window re-arms. The whole transfer takes far longer
    // than one window (~15 minutes of paused time).
    let mut buf = [0u8; PIPE];
    let mut got = 0;
    while got < total {
        tokio::time::sleep(Duration::from_secs(45)).await;
        let n = client.read(&mut buf).await.expect("read");
        assert!(n > 0, "writer closed early");
        got += n;
    }
    let (res, _, io) = writer.await.expect("writer task");
    res.expect("progressing reader must not be cut");
    assert!(!io.is_expired());
}

#[tokio::test(start_paused = true)]
async fn idle_gateway_with_nothing_to_write_never_arms_the_bound() {
    // A slow backend: the gateway writes nothing for a long time. No write is
    // pending, so the bound must not fire when bytes finally flow.
    let (server, mut client) = tokio::io::duplex(PIPE);
    let mut io = ClientWriteStallIo::new(server, TIMEOUT_SECS);
    tokio::time::sleep(Duration::from_secs(TIMEOUT_SECS * 10)).await;
    io.write_all(b"late but fine").await.expect("write");
    io.flush().await.expect("flush");
    let mut buf = [0u8; 13];
    client.read_exact(&mut buf).await.expect("read");
    assert_eq!(&buf, b"late but fine");
}

#[tokio::test(start_paused = true)]
async fn separate_short_stalls_do_not_accumulate() {
    // Two 40s stalls separated by progress must not add up to one 60s window.
    let (server, mut client) = tokio::io::duplex(PIPE);
    let writer = spawn_writer(ClientWriteStallIo::new(server, TIMEOUT_SECS), PIPE * 3);
    let mut buf = [0u8; PIPE];
    for _ in 0..3 {
        tokio::time::sleep(Duration::from_secs(40)).await;
        client.read_exact(&mut buf).await.expect("read");
    }
    let (res, _, _) = writer.await.expect("writer task");
    res.expect("stall episodes separated by progress must not accumulate");
}

#[tokio::test(start_paused = true)]
async fn zero_disables_the_bound() {
    let (server, _client) = tokio::io::duplex(PIPE);
    let writer = spawn_writer(ClientWriteStallIo::new(server, 0), PIPE * 4);
    tokio::time::sleep(Duration::from_secs(TIMEOUT_SECS * 100)).await;
    assert!(!writer.is_finished(), "0 must disable the bound");
    writer.abort();
}

#[tokio::test(start_paused = true)]
async fn expiry_is_sticky_for_later_writes_and_flushes() {
    let (server, _client) = tokio::io::duplex(PIPE);
    let writer = spawn_writer(ClientWriteStallIo::new(server, 1), PIPE * 4);
    let (res, _, mut io) = writer.await.expect("writer task");
    assert!(is_client_write_stall(&res.expect_err("stall")));
    let err = io.write(b"x").await.expect_err("later write must fail");
    assert!(is_client_write_stall(&err));
    let err = io.flush().await.expect_err("later flush must fail");
    assert!(is_client_write_stall(&err));
    io.shutdown()
        .await
        .expect("shutdown after a stall must not wait on the peer");
}

#[test]
fn stall_detection_survives_message_rebuild_and_rejects_other_timeouts() {
    // h2 rebuilds an I/O error from its inner error's *message*, dropping the
    // typed marker; the detector must still recognize it.
    let rebuilt = io::Error::new(
        io::ErrorKind::TimedOut,
        CLIENT_WRITE_STALL_MESSAGE.to_string(),
    );
    assert!(is_client_write_stall(&rebuilt));

    let other = io::Error::new(io::ErrorKind::TimedOut, "some other timeout");
    assert!(!is_client_write_stall(&other));
    let bare = io::Error::from(io::ErrorKind::TimedOut);
    assert!(!is_client_write_stall(&bare));
    let wrong_kind = io::Error::other(CLIENT_WRITE_STALL_MESSAGE.to_string());
    assert!(!is_client_write_stall(&wrong_kind));
}

/// Transport whose writes and flushes park while the matching flag is set,
/// to drive the `poll_flush` / `poll_write_vectored` arms directly (the TLS
/// session and hyper's vectored H1 writes use them).
struct GatedIo {
    write_blocked: Arc<AtomicBool>,
    flush_blocked: Arc<AtomicBool>,
}

impl AsyncRead for GatedIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for GatedIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.write_blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(buf.len()))
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        if self.write_blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(bufs.iter().map(|b| b.len()).sum()))
        }
    }

    fn is_write_vectored(&self) -> bool {
        true
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.flush_blocked.load(Ordering::SeqCst) {
            Poll::Pending
        } else {
            Poll::Ready(Ok(()))
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

fn gated(write: bool, flush: bool) -> (GatedIo, Arc<AtomicBool>, Arc<AtomicBool>) {
    let write_blocked = Arc::new(AtomicBool::new(write));
    let flush_blocked = Arc::new(AtomicBool::new(flush));
    (
        GatedIo {
            write_blocked: Arc::clone(&write_blocked),
            flush_blocked: Arc::clone(&flush_blocked),
        },
        write_blocked,
        flush_blocked,
    )
}

#[tokio::test(start_paused = true)]
async fn parked_flush_arms_the_bound_and_fires_after_the_window() {
    let (inner, _w, _f) = gated(false, true);
    let mut io = ClientWriteStallIo::new(inner, TIMEOUT_SECS);
    let start = Instant::now();
    let err = io
        .flush()
        .await
        .expect_err("a flush that never completes must be cut");
    assert!(is_client_write_stall(&err));
    assert_eq!(Instant::now() - start, Duration::from_secs(TIMEOUT_SECS));
}

#[tokio::test(start_paused = true)]
async fn parked_vectored_write_arms_the_bound_and_fires_after_the_window() {
    let (inner, _w, _f) = gated(true, false);
    let mut io = ClientWriteStallIo::new(inner, TIMEOUT_SECS);
    assert!(
        io.is_write_vectored(),
        "vectored capability must be forwarded"
    );
    let start = Instant::now();
    let bufs = [io::IoSlice::new(b"head"), io::IoSlice::new(b"body")];
    let err = io
        .write_vectored(&bufs)
        .await
        .expect_err("a vectored write that never completes must be cut");
    assert!(is_client_write_stall(&err));
    assert_eq!(Instant::now() - start, Duration::from_secs(TIMEOUT_SECS));
}

#[tokio::test(start_paused = true)]
async fn completed_flush_ends_the_stall_episode() {
    // A parked flush that completes before the window is progress: a later
    // stall gets a fresh window rather than the remainder of the old one.
    let (inner, _w, flush_blocked) = gated(false, true);
    let mut io = ClientWriteStallIo::new(inner, TIMEOUT_SECS);
    let releaser = {
        let flush_blocked = Arc::clone(&flush_blocked);
        tokio::spawn(async move {
            tokio::time::sleep(Duration::from_secs(TIMEOUT_SECS - 10)).await;
            flush_blocked.store(false, Ordering::SeqCst);
        })
    };
    // The gate has no waker, so poll the flush on a short cadence the way a
    // transport readiness wakeup would.
    let started = Instant::now();
    loop {
        match tokio::time::timeout(Duration::from_secs(1), io.flush()).await {
            Ok(res) => {
                res.expect("flush completed before the window");
                break;
            }
            Err(_) => continue,
        }
    }
    releaser.await.expect("releaser");
    assert!(Instant::now() - started < Duration::from_secs(TIMEOUT_SECS));

    flush_blocked.store(true, Ordering::SeqCst);
    let second = Instant::now();
    let err = io
        .flush()
        .await
        .expect_err("second stall must still be cut");
    assert!(is_client_write_stall(&err));
    assert_eq!(
        Instant::now() - second,
        Duration::from_secs(TIMEOUT_SECS),
        "the second stall must get a full fresh window"
    );
}
