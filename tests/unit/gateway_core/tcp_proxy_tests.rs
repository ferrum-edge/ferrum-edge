use ferrum_edge::_test_support::{
    StreamIoSide, bidirectional_copy_for_test, classify_stream_error, disconnect_cause_for_failure,
};
use ferrum_edge::plugins::{Direction, DisconnectCause};
use ferrum_edge::retry::ErrorClass;
use std::io;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

#[test]
fn test_classify_stream_error_preserves_tls_failures() {
    let error =
        anyhow::anyhow!("Backend TLS handshake failed to 127.0.0.1:443: invalid peer certificate");
    assert_eq!(classify_stream_error(&error), ErrorClass::TlsError);
}

#[test]
fn test_classify_stream_error_preserves_dns_failures() {
    let error = anyhow::anyhow!("DNS resolution failed for backend.local: no record found");
    assert_eq!(classify_stream_error(&error), ErrorClass::DnsLookupError);
}

// ── Test helpers for bidirectional_copy direction tracking ───────────────────

/// Stream wrapper that returns `io::ErrorKind::ConnectionReset` on the first
/// `poll_read`. Writes are accepted (discarded).
struct ResetOnReadStream;

impl AsyncRead for ResetOnReadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(
            io::ErrorKind::ConnectionReset,
            "simulated read reset",
        )))
    }
}

impl AsyncWrite for ResetOnReadStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

// ── bidirectional_copy direction tests ───────────────────────────────────────
//
// These tests exercise the **direction-tracking path** (idle_timeout = Some).
// When BOTH `idle_timeout` and `half_close_cap` are `None`/zero, the relay
// takes a zero-overhead fast path that delegates to
// `tokio::io::copy_bidirectional_with_sizes` and cannot report
// `first_failure` direction (see `bidirectional_copy` docs). These tests
// are specifically verifying direction attribution, so they opt in via a
// long idle_timeout that never actually fires.
const TEST_IDLE_TIMEOUT: Option<Duration> = Some(Duration::from_secs(300));

#[tokio::test]
async fn test_bidirectional_copy_client_read_error_marks_client_to_backend() {
    let client = ResetOnReadStream;
    let (backend, _peer) = tokio::io::duplex(1024);

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    let (dir, class, _side, _msg) = result
        .first_failure
        .as_ref()
        .expect("first_failure should be set when client read errors");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ConnectionReset);
}

#[tokio::test]
async fn test_bidirectional_copy_backend_read_error_marks_backend_to_client() {
    let (client, _peer) = tokio::io::duplex(1024);
    let backend = ResetOnReadStream;

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    let (dir, class, _side, _msg) = result
        .first_failure
        .as_ref()
        .expect("first_failure should be set when backend read errors");
    assert_eq!(*dir, Direction::BackendToClient);
    assert_eq!(*class, ErrorClass::ConnectionReset);
}

#[tokio::test]
async fn test_bidirectional_copy_clean_close_no_failure() {
    let (client, client_peer) = tokio::io::duplex(1024);
    let (backend, backend_peer) = tokio::io::duplex(1024);

    drop(client_peer);
    drop(backend_peer);

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    assert!(
        result.first_failure.is_none(),
        "clean close must leave first_failure == None, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, 0);
    assert_eq!(result.bytes_backend_to_client, 0);
}

#[tokio::test]
async fn test_bidirectional_copy_preserves_bytes_across_errors() {
    let (client, mut client_peer) = tokio::io::duplex(1024);
    let backend = ResetOnReadStream;

    let payload = b"hello-world-42";
    tokio::spawn(async move {
        let _ = client_peer.write_all(payload).await;
        let _ = client_peer.shutdown().await;
    });

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    let (dir, _class, _side, _msg) = result
        .first_failure
        .as_ref()
        .expect("first_failure should be set — backend read half errored");
    assert_eq!(*dir, Direction::BackendToClient);

    assert_eq!(result.bytes_backend_to_client, 0);
    // c2b counter must never exceed the payload (key invariant — no zeroing).
    assert!(
        result.bytes_client_to_backend <= payload.len() as u64,
        "c2b bytes must not exceed payload size, got {}",
        result.bytes_client_to_backend
    );
}

/// Regression: verify the fast path is selected when both timeouts are `None`.
/// Per the documented trade-off, the fast path reports `Direction::Unknown`
/// on error — this test locks that in so future refactors notice if the
/// fast path stops being taken (direction would become specific) OR if the
/// slow path regresses to the fast path's behavior (slow-path tests above
/// would start seeing `Unknown`).
#[tokio::test]
async fn test_bidirectional_copy_fast_path_reports_unknown_direction_on_error() {
    let client = ResetOnReadStream;
    let (backend, _peer) = tokio::io::duplex(1024);

    // Both timeouts None = fast-path path via copy_bidirectional_with_sizes.
    let result = bidirectional_copy_for_test(client, backend, None, None, 8 * 1024).await;

    let (dir, _class, side, _msg) = result
        .first_failure
        .as_ref()
        .expect("fast-path error must still surface first_failure");
    assert_eq!(
        *dir,
        Direction::Unknown,
        "fast path cannot attribute direction — must report Unknown"
    );
    assert!(
        side.is_none(),
        "fast path cannot attribute IO side either — must be None"
    );
}

#[tokio::test]
async fn test_bidirectional_copy_c2b_bytes_preserved_on_clean_close() {
    let (client, mut client_peer) = tokio::io::duplex(4096);
    let (backend, mut backend_peer) = tokio::io::duplex(4096);

    let payload: Vec<u8> = (0..512u16).map(|i| (i & 0xFF) as u8).collect();
    let payload_clone = payload.clone();

    tokio::spawn(async move {
        let _ = client_peer.write_all(&payload_clone).await;
        let _ = client_peer.shutdown().await;
    });

    tokio::spawn(async move {
        let mut sink = Vec::new();
        let _ = backend_peer.read_to_end(&mut sink).await;
    });

    let result = bidirectional_copy_for_test(
        client,
        backend,
        Some(Duration::from_secs(5)),
        None,
        8 * 1024,
    )
    .await;

    assert!(
        result.first_failure.is_none(),
        "both halves EOF cleanly → first_failure should be None, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, payload.len() as u64);
    assert_eq!(result.bytes_backend_to_client, 0);
}

/// Regression: request/response protocols where the client finishes sending
/// first (half-closes) and the backend then takes significantly longer than
/// `BIDIRECTIONAL_DRAIN_GRACE` (100ms) to generate the response must not be
/// truncated. Before the fix, Phase 2 applied a 100ms timeout to the still-
/// running direction after the first side completed cleanly — this cut off
/// legitimate slow responses on SMTP, IMAP, and HTTP-over-TCP passthrough.
/// With the fix, clean EOF on one side transitions to an unbounded wait on
/// the other (still bounded by the overall idle timeout).
#[tokio::test]
async fn test_bidirectional_copy_half_close_delayed_response_not_truncated() {
    let (client, mut client_peer) = tokio::io::duplex(4096);
    let (backend, mut backend_peer) = tokio::io::duplex(4096);

    // Client sends a small request, then half-closes its write side.
    let request = b"REQUEST";
    tokio::spawn(async move {
        let _ = client_peer.write_all(request).await;
        // Half-close write side so the backend sees EOF on its read side.
        // This corresponds to shutdown(Shutdown::Write) on a real TcpStream.
        let _ = client_peer.shutdown().await;
        // Drain whatever the backend sends so the copy doesn't block on
        // write backpressure.
        let mut sink = Vec::new();
        let _ = client_peer.read_to_end(&mut sink).await;
    });

    // Backend reads the request, delays well past BIDIRECTIONAL_DRAIN_GRACE
    // (300ms > 100ms), then sends a full response and closes.
    let response_len: usize = 1024;
    tokio::spawn(async move {
        // Drain the request up to EOF (client half-closes).
        let mut req_buf = vec![0u8; 16];
        loop {
            match backend_peer.read(&mut req_buf).await {
                Ok(0) => break, // peer EOF (client half-closed write)
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        // Simulate backend processing time — 300ms is 3x the 100ms grace.
        tokio::time::sleep(Duration::from_millis(300)).await;
        let response = vec![0xAAu8; response_len];
        let _ = backend_peer.write_all(&response).await;
        let _ = backend_peer.shutdown().await;
    });

    // Use a generous idle timeout (5s) so it never fires during the 300ms delay.
    let result = bidirectional_copy_for_test(
        client,
        backend,
        Some(Duration::from_secs(5)),
        None,
        8 * 1024,
    )
    .await;

    assert!(
        result.first_failure.is_none(),
        "half-close + delayed response should complete cleanly, got {:?}",
        result.first_failure
    );
    // The entire backend response must reach the client — this is the bug
    // the fix prevents. Without the fix, b2c would be cut off at 100ms.
    assert_eq!(
        result.bytes_backend_to_client, response_len as u64,
        "full backend response must be relayed; got {} of {} bytes",
        result.bytes_backend_to_client, response_len
    );
    assert_eq!(result.bytes_client_to_backend, request.len() as u64);
}

/// Verify the idle-timeout fallback is still honored during the unbounded
/// Phase 2 wait. After the client half-closes cleanly, if the backend never
/// responds, the idle timeout must fire and terminate the connection.
#[tokio::test]
async fn test_bidirectional_copy_half_close_idle_timeout_fires_in_phase2() {
    let (client, mut client_peer) = tokio::io::duplex(4096);
    let (backend, mut backend_peer) = tokio::io::duplex(4096);

    // Client sends and half-closes immediately.
    tokio::spawn(async move {
        let _ = client_peer.write_all(b"PING").await;
        let _ = client_peer.shutdown().await;
        let mut sink = Vec::new();
        let _ = client_peer.read_to_end(&mut sink).await;
    });

    // Backend reads but NEVER responds — keeps its end open so b2c hangs.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16];
        loop {
            match backend_peer.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        // Hold the connection open forever — exit only when the test drops it.
        std::future::pending::<()>().await;
    });

    // Very short idle timeout so the test completes quickly.
    let result = bidirectional_copy_for_test(
        client,
        backend,
        Some(Duration::from_millis(500)),
        None,
        8 * 1024,
    )
    .await;

    // Idle timeout must fire — either during Phase 1 or Phase 2.
    let (dir, class, _side, _msg) = result
        .first_failure
        .as_ref()
        .expect("idle timeout on stalled backend must produce first_failure");
    assert_eq!(*dir, Direction::Unknown);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
}

/// Regression: when `FERRUM_TCP_IDLE_TIMEOUT_SECONDS=0` the session idle
/// watchdog is disabled entirely. Without a separate hard cap on Phase 2,
/// a client half-close followed by a stalled backend would wedge the
/// relay task forever. `FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS` is the
/// safety net — it fires even when the idle timeout is disabled, and
/// classifies the outcome as `ReadWriteTimeout` → `IdleTimeout` in the
/// disconnect-cause mapping so operators see a timeout label, not a
/// generic unknown.
#[tokio::test]
async fn test_bidirectional_copy_half_close_hard_cap_fires_with_idle_disabled() {
    let (client, mut client_peer) = tokio::io::duplex(4096);
    let (backend, mut backend_peer) = tokio::io::duplex(4096);

    // Client sends a small request, then half-closes cleanly — Phase 2
    // will be entered because c2b ends in clean EOF.
    tokio::spawn(async move {
        let _ = client_peer.write_all(b"REQUEST").await;
        let _ = client_peer.shutdown().await;
        // Drain whatever the backend writes so the copy task doesn't
        // block on write backpressure.
        let mut sink = Vec::new();
        let _ = client_peer.read_to_end(&mut sink).await;
    });

    // Backend stalls forever without responding — b2c never completes.
    tokio::spawn(async move {
        let mut buf = vec![0u8; 16];
        loop {
            match backend_peer.read(&mut buf).await {
                Ok(0) => break,
                Ok(_) => continue,
                Err(_) => break,
            }
        }
        std::future::pending::<()>().await;
    });

    // Critical: idle timeout is `None` (disabled). Only the hard cap can
    // terminate Phase 2 here.
    let start = std::time::Instant::now();
    let result = bidirectional_copy_for_test(
        client,
        backend,
        None,                             // idle_timeout disabled
        Some(Duration::from_millis(150)), // hard cap
        8 * 1024,
    )
    .await;
    let elapsed = start.elapsed();

    // The hard cap must fire and return within a reasonable window of the
    // cap value. Phase 2 is polled every second for idle/cap checks, so
    // the cap fires at the next tick after expiry — allow generous upper
    // bound to account for tokio scheduling.
    assert!(
        elapsed < Duration::from_secs(3),
        "hard cap must fire promptly even with idle disabled; elapsed = {:?}",
        elapsed
    );

    let (dir, class, _side, msg) = result
        .first_failure
        .as_ref()
        .expect("hard cap expiration must produce first_failure");
    assert_eq!(*dir, Direction::Unknown);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert!(
        msg.contains("half-close") || msg.contains("idle timeout"),
        "failure message should reflect a timeout, got: {}",
        msg
    );

    // Bytes already relayed through c2b must still be reported.
    assert_eq!(result.bytes_client_to_backend, b"REQUEST".len() as u64);
    assert_eq!(result.bytes_backend_to_client, 0);
}

/// Regression: when BOTH the idle timeout AND the hard cap are disabled
/// (`None`), the relay preserves the pre-PR behaviour of waiting forever.
/// This test exercises the clean-EOF branch with a race so the drain
/// completes naturally — the relay must return as soon as the backend
/// sends its response and closes, with no artificial cap firing.
#[tokio::test]
async fn test_bidirectional_copy_both_disabled_allows_clean_completion() {
    let (client, mut client_peer) = tokio::io::duplex(4096);
    let (backend, mut backend_peer) = tokio::io::duplex(4096);

    tokio::spawn(async move {
        let _ = client_peer.write_all(b"PING").await;
        let _ = client_peer.shutdown().await;
        let mut sink = Vec::new();
        let _ = client_peer.read_to_end(&mut sink).await;
    });

    tokio::spawn(async move {
        let mut buf = vec![0u8; 32];
        let _ = backend_peer.read(&mut buf).await;
        // 50ms processing then respond and close.
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = backend_peer.write_all(b"PONG-RESPONSE").await;
        let _ = backend_peer.shutdown().await;
    });

    let result = bidirectional_copy_for_test(
        client,
        backend,
        None,     // idle_timeout disabled
        None,     // hard cap disabled
        8 * 1024, // buf_size
    )
    .await;

    assert!(
        result.first_failure.is_none(),
        "both timeouts disabled + clean completion should leave first_failure=None, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, b"PING".len() as u64);
    assert_eq!(
        result.bytes_backend_to_client,
        b"PONG-RESPONSE".len() as u64
    );
}

// ── bidirectional_splice direction tests (Linux only) ────────────────────────

/// Helper: returns two real connected `TcpStream`s over the loopback interface.
/// Needed because splice(2) operates on raw file descriptors and cannot be
/// driven through `tokio::io::duplex`.
#[cfg(target_os = "linux")]
async fn connected_tcp_pair() -> (tokio::net::TcpStream, tokio::net::TcpStream) {
    use tokio::net::{TcpListener, TcpStream};
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let (client_res, server_res) =
        tokio::join!(TcpStream::connect(addr), async { listener.accept().await });
    let client = client_res.unwrap();
    let (server, _peer_addr) = server_res.unwrap();
    (client, server)
}

/// Regression test for the Linux splice path — mirror of
/// `test_bidirectional_copy_half_close_delayed_response_not_truncated`.
///
/// Before the fix, `bidirectional_splice`'s Phase 2 unconditionally wrapped the
/// remaining direction in a 100ms grace timeout, truncating slow backend
/// responses on plaintext TCP passthrough (SMTP, IMAP, HTTP-over-TCP).
/// With the fix, clean EOF on one side transitions to an unbounded wait on
/// the other (still bounded by the overall idle timeout).
///
/// Note: this test does not rely on half-close FIN propagation across the
/// proxy (which `splice_one_direction_no_guard` does not do — unlike the
/// `copy_one_direction` path, which calls `writer.shutdown()` on EOF). The
/// backend reads a fixed request length, then starts its response delay.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_bidirectional_splice_half_close_delayed_response_not_truncated() {
    use ferrum_edge::_test_support::bidirectional_splice_for_test;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (proxy_client_side, mut external_client) = connected_tcp_pair().await;
    let (proxy_backend_side, mut external_backend) = connected_tcp_pair().await;

    let request = b"REQUEST";

    // External client sends the request, then half-closes its write side so
    // the proxy sees EOF on its c2b read. The splice c2b direction completes
    // cleanly (clean_eof path) while b2c is still pending.
    tokio::spawn(async move {
        let _ = external_client.write_all(request).await;
        let _ = external_client.shutdown().await;
        // Hold the read side open to receive the response.
        let mut sink = Vec::new();
        let _ = external_client.read_to_end(&mut sink).await;
    });

    // External backend reads exactly `request.len()` bytes, then delays past
    // BIDIRECTIONAL_DRAIN_GRACE (300ms > 100ms) before writing the response.
    let response_len: usize = 1024;
    let expected_request_len = request.len();
    tokio::spawn(async move {
        let mut received = 0usize;
        let mut buf = [0u8; 32];
        while received < expected_request_len {
            match external_backend.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => received += n,
                Err(_) => break,
            }
        }
        tokio::time::sleep(Duration::from_millis(300)).await;
        let response = vec![0xAAu8; response_len];
        let _ = external_backend.write_all(&response).await;
        let _ = external_backend.shutdown().await;
    });

    // Generous idle timeout so it never fires during the 300ms delay.
    let result = bidirectional_splice_for_test(
        proxy_client_side,
        proxy_backend_side,
        Some(Duration::from_secs(5)),
        None,
        64 * 1024,
    )
    .await;

    assert!(
        result.first_failure.is_none(),
        "half-close + delayed response on splice path should complete cleanly, got {:?}",
        result.first_failure
    );
    // The entire backend response must reach the client — without the fix,
    // b2c would be cut off at 100ms.
    assert_eq!(
        result.bytes_backend_to_client, response_len as u64,
        "full backend response must be relayed on splice path; got {} of {} bytes",
        result.bytes_backend_to_client, response_len
    );
    assert_eq!(result.bytes_client_to_backend, request.len() as u64);
}

/// Verify the idle-timeout fallback still fires on the splice path during the
/// unbounded Phase 2 wait when the backend never responds after a clean
/// client half-close.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_bidirectional_splice_half_close_idle_timeout_fires_in_phase2() {
    use ferrum_edge::_test_support::bidirectional_splice_for_test;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (proxy_client_side, mut external_client) = connected_tcp_pair().await;
    let (proxy_backend_side, mut external_backend) = connected_tcp_pair().await;

    let request = b"PING";

    // External client sends and half-closes immediately.
    tokio::spawn(async move {
        let _ = external_client.write_all(request).await;
        let _ = external_client.shutdown().await;
        let mut sink = Vec::new();
        let _ = external_client.read_to_end(&mut sink).await;
    });

    // External backend reads the fixed-length request, then holds the
    // connection open without writing anything — forces b2c to stall.
    let expected_request_len = request.len();
    tokio::spawn(async move {
        let mut received = 0usize;
        let mut buf = [0u8; 32];
        while received < expected_request_len {
            match external_backend.read(&mut buf).await {
                Ok(0) => break,
                Ok(n) => received += n,
                Err(_) => break,
            }
        }
        std::future::pending::<()>().await;
    });

    // Short idle timeout so the test completes quickly.
    let result = bidirectional_splice_for_test(
        proxy_client_side,
        proxy_backend_side,
        Some(Duration::from_millis(500)),
        None,
        64 * 1024,
    )
    .await;

    let (dir, class, _side, _msg) = result
        .first_failure
        .as_ref()
        .expect("idle timeout on stalled backend (splice path) must produce first_failure");
    assert_eq!(*dir, Direction::Unknown);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
}

// ── disconnect_cause_for_failure — Direction + Side → DisconnectCause ────────
//
// Codex flagged that the old mapping attributed every `ClientToBackend` failure
// to `RecvError`, even when the failing syscall was the *write* on the backend
// socket (e.g., backend RST while client was still sending). These tests lock
// in the side-aware mapping that replaces the ambiguous direction-only match.

#[test]
fn test_disconnect_cause_ctb_read_is_recv_error() {
    // Client → Backend, read side = reading from CLIENT failed = frontend/client side.
    assert_eq!(
        disconnect_cause_for_failure(
            Direction::ClientToBackend,
            &ErrorClass::ConnectionReset,
            Some(StreamIoSide::Read),
        ),
        DisconnectCause::RecvError,
    );
}

#[test]
fn test_disconnect_cause_ctb_write_is_backend_error() {
    // Client → Backend, write side = writing to BACKEND failed = backend side.
    // This is the exact miscategorized case Codex called out: the old code
    // returned `RecvError` here; the new mapping returns `BackendError`.
    assert_eq!(
        disconnect_cause_for_failure(
            Direction::ClientToBackend,
            &ErrorClass::ConnectionReset,
            Some(StreamIoSide::Write),
        ),
        DisconnectCause::BackendError,
    );
}

#[test]
fn test_disconnect_cause_btc_read_is_backend_error() {
    // Backend → Client, read side = reading from BACKEND failed = backend side.
    assert_eq!(
        disconnect_cause_for_failure(
            Direction::BackendToClient,
            &ErrorClass::ConnectionReset,
            Some(StreamIoSide::Read),
        ),
        DisconnectCause::BackendError,
    );
}

#[test]
fn test_disconnect_cause_btc_write_is_recv_error() {
    // Backend → Client, write side = writing to CLIENT failed = frontend side.
    // Old mapping returned `BackendError`; new mapping returns `RecvError`.
    assert_eq!(
        disconnect_cause_for_failure(
            Direction::BackendToClient,
            &ErrorClass::ConnectionReset,
            Some(StreamIoSide::Write),
        ),
        DisconnectCause::RecvError,
    );
}

#[test]
fn test_disconnect_cause_timeout_beats_direction() {
    // ReadWriteTimeout is always IdleTimeout regardless of direction/side.
    for dir in [
        Direction::ClientToBackend,
        Direction::BackendToClient,
        Direction::Unknown,
    ] {
        for side in [None, Some(StreamIoSide::Read), Some(StreamIoSide::Write)] {
            assert_eq!(
                disconnect_cause_for_failure(dir, &ErrorClass::ReadWriteTimeout, side),
                DisconnectCause::IdleTimeout,
                "timeout with dir={:?} side={:?} should map to IdleTimeout",
                dir,
                side,
            );
        }
    }
}

#[test]
fn test_disconnect_cause_unknown_direction_falls_back_to_recv_error() {
    // Unknown direction (pipe creation, kTLS install, spawn-join failure) —
    // conservative fallback is RecvError, matching prior log-consumer convention.
    assert_eq!(
        disconnect_cause_for_failure(Direction::Unknown, &ErrorClass::RequestError, None),
        DisconnectCause::RecvError,
    );
}

#[test]
fn test_disconnect_cause_missing_side_falls_back_to_recv_error() {
    // Side-less failures (e.g., spawn-join errors attributed to a direction but
    // without side info) fall back to RecvError rather than mis-assigning to
    // BackendError.
    assert_eq!(
        disconnect_cause_for_failure(
            Direction::ClientToBackend,
            &ErrorClass::ConnectionReset,
            None,
        ),
        DisconnectCause::RecvError,
    );
}
