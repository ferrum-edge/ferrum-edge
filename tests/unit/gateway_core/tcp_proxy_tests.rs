use ferrum_edge::_test_support::{
    StreamIoSide, bidirectional_copy_for_test, bidirectional_copy_for_test_with_timeouts,
    classify_stream_error, disconnect_cause_for_failure,
};
use ferrum_edge::plugins::{Direction, DisconnectCause};
use ferrum_edge::retry::ErrorClass;
use std::collections::VecDeque;
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
/// The backend reads a fixed request length, then starts its response delay.
/// The sibling test below pins the explicit EOF propagation contract.
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

/// Regression: splice must propagate a clean read EOF as a write-side
/// half-close to the opposite socket. Without this, backends that read until
/// EOF before responding never see the client's half-close, so the connection
/// task can stall and stream-disconnect hooks never run.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn test_bidirectional_splice_client_eof_half_closes_backend_write_side() {
    use ferrum_edge::_test_support::bidirectional_splice_for_test;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let (proxy_client_side, mut external_client) = connected_tcp_pair().await;
    let (proxy_backend_side, mut external_backend) = connected_tcp_pair().await;

    let request = b"REQUEST-EOF";
    let response = b"EOF-OBSERVED".to_vec();
    let expected_response = response.clone();

    let client_task = tokio::spawn(async move {
        external_client.write_all(request).await?;
        external_client.shutdown().await?;

        let mut received = Vec::new();
        tokio::time::timeout(
            Duration::from_secs(5),
            external_client.read_to_end(&mut received),
        )
        .await
        .map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "client read timed out"))??;
        Ok::<_, io::Error>(received)
    });

    let backend_task = tokio::spawn(async move {
        let mut received = Vec::new();
        let saw_eof = match tokio::time::timeout(
            Duration::from_secs(2),
            external_backend.read_to_end(&mut received),
        )
        .await
        {
            Ok(Ok(_)) => true,
            Ok(Err(e)) => return Err(e),
            Err(_) => false,
        };

        if saw_eof {
            external_backend.write_all(&response).await?;
            external_backend.shutdown().await?;
        }

        Ok::<_, io::Error>((saw_eof, received))
    });

    let result = tokio::time::timeout(
        Duration::from_secs(6),
        bidirectional_splice_for_test(
            proxy_client_side,
            proxy_backend_side,
            Some(Duration::from_secs(5)),
            Some(Duration::from_secs(5)),
            64 * 1024,
        ),
    )
    .await
    .expect("splice relay should complete after backend observes EOF");

    let (backend_saw_eof, backend_received) = backend_task.await.unwrap().unwrap();
    assert!(
        backend_saw_eof,
        "backend must observe EOF from the splice relay after client half-closes"
    );
    assert_eq!(backend_received, request);

    let client_received = client_task.await.unwrap().unwrap();
    assert_eq!(
        client_received, expected_response,
        "client must still receive backend response after propagated half-close"
    );
    assert!(
        result.first_failure.is_none(),
        "clean half-close relay should complete without first_failure, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, request.len() as u64);
    assert_eq!(
        result.bytes_backend_to_client,
        expected_response.len() as u64
    );
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

// ── backend_read_timeout / backend_write_timeout tests ──────────────────────

/// Stream that accepts writes but never produces a read — `poll_read` always
/// returns `Pending`. Used to simulate a silent peer that holds the TCP
/// connection open without sending any bytes.
struct NeverReadStream;

impl AsyncRead for NeverReadStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for NeverReadStream {
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

/// Stream that produces bytes forever on read (one payload per call) but
/// never completes a write — `poll_write` always returns `Pending`. Used to
/// simulate a peer whose TCP send buffer is stuck (we're writing to them,
/// they're not draining).
struct NeverWriteStream;

impl AsyncRead for NeverWriteStream {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let n = buf.remaining().min(1024);
        buf.initialize_unfilled_to(n);
        buf.advance(n);
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for NeverWriteStream {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Pending
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// backend_read_timeout fires when the backend stops producing bytes — even
/// with idle_timeout disabled. The inactivity watchdog polls per-direction
/// watermarks once per second, so a configured 1500ms timeout fires within
/// ~2.5s (timeout + one watchdog tick).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_backend_read_timeout_fires_on_silent_backend() {
    let client = NeverReadStream;
    let backend = NeverReadStream;

    let start = std::time::Instant::now();
    let result = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        None,
        None,
        Some(Duration::from_millis(1500)),
        None,
        8 * 1024,
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(4),
        "backend_read_timeout must fire within timeout + watchdog tick; elapsed = {:?}",
        elapsed
    );
    assert!(
        elapsed >= Duration::from_millis(1000),
        "backend_read_timeout should not fire before the configured duration; elapsed = {:?}",
        elapsed
    );

    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("backend_read_timeout must produce first_failure");
    assert_eq!(
        *dir,
        Direction::BackendToClient,
        "b2c direction reads from backend — timeout should be attributed there"
    );
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Read));
    assert!(
        msg.contains("backend read inactivity"),
        "failure message should reflect inactivity, got: {}",
        msg
    );
    assert_eq!(
        disconnect_cause_for_failure(*dir, class, *side),
        DisconnectCause::IdleTimeout,
        "ReadWriteTimeout class should map to IdleTimeout disconnect cause"
    );
}

/// backend_write_timeout fires when the backend's socket send buffer stops
/// draining (we're writing, they're not reading). Attributed to
/// `ClientToBackend` (c2b direction writes to backend) on the write side.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_backend_write_timeout_fires_on_stuck_backend() {
    let client = NeverWriteStream;
    let backend = NeverWriteStream;

    let start = std::time::Instant::now();
    let result = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        None,
        None,
        None,
        Some(Duration::from_millis(1500)),
        8 * 1024,
    )
    .await;
    let elapsed = start.elapsed();

    assert!(
        elapsed < Duration::from_secs(4),
        "backend_write_timeout must fire within timeout + watchdog tick; elapsed = {:?}",
        elapsed
    );

    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("backend_write_timeout must produce first_failure");
    assert_eq!(
        *dir,
        Direction::ClientToBackend,
        "c2b direction writes to backend — write timeout should be attributed there"
    );
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Write));
    assert!(
        msg.contains("backend write inactivity"),
        "failure message should reflect inactivity, got: {}",
        msg
    );
}

/// When backend timeouts are enabled but no traffic flows, the read timeout
/// (applied to the b2c direction) fires before the write timeout — because
/// the c2b direction needs bytes from the client to attempt a backend write.
/// With a silent client+backend, only b2c's backend read watermark goes stale.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_backend_read_timeout_only_applies_to_backend_side() {
    let client = NeverReadStream;
    let backend = NeverReadStream;

    let result = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        None,
        None,
        Some(Duration::from_millis(1500)),
        Some(Duration::from_secs(60)),
        8 * 1024,
    )
    .await;

    let (dir, class, side, _) = result.first_failure.as_ref().unwrap();
    assert_eq!(*dir, Direction::BackendToClient);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Read));
}

/// Setting backend_read_timeout to 0 (Duration::ZERO) disables the
/// per-direction inactivity check. With both read and idle timeouts
/// disabled, the session stays open until explicitly terminated.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_backend_timeout_zero_disables_check() {
    let client = NeverReadStream;
    let backend = NeverReadStream;

    let result = tokio::time::timeout(
        Duration::from_secs(3),
        bidirectional_copy_for_test_with_timeouts(
            client,
            backend,
            None,
            None,
            Some(Duration::ZERO),
            Some(Duration::ZERO),
            8 * 1024,
        ),
    )
    .await;

    assert!(
        result.is_err(),
        "with timeout=0 (disabled), copy should not terminate on its own"
    );
}

/// A slow-but-progressing writer keeps the write watermark fresh, so the
/// write inactivity timeout should NOT fire even though individual writes
/// are slow.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_slow_progressing_write_does_not_fire_timeout() {
    let (client, mut client_peer) = tokio::io::duplex(64 * 1024);
    let (backend, mut backend_peer) = tokio::io::duplex(256);

    // Client sends data continuously.
    tokio::spawn(async move {
        let data = vec![0xABu8; 128];
        loop {
            if client_peer.write_all(&data).await.is_err() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    });

    // Backend drains slowly — reads small chunks with delays.
    tokio::spawn(async move {
        let mut buf = [0u8; 32];
        loop {
            match backend_peer.read(&mut buf).await {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    tokio::time::sleep(Duration::from_millis(200)).await;
                }
            }
        }
    });

    let result = tokio::time::timeout(
        Duration::from_secs(5),
        bidirectional_copy_for_test_with_timeouts(
            client,
            backend,
            None,
            None,
            None,
            Some(Duration::from_millis(1500)),
            8 * 1024,
        ),
    )
    .await;

    assert!(
        result.is_err(),
        "slow-but-progressing write should keep watermark fresh; copy should not terminate"
    );
}

// ── Graceful shutdown reclassification (write-after-opposite-EOF race) ───────
//
// Regression coverage for the TLS close_notify → FIN tail race that was
// producing 1 spurious error per payload size at 70 KB / 500 KB in the
// CI benchmark. The bidirectional relay's drain phase used to classify
// any `BrokenPipe` / `ConnectionReset` on the write side as a transport
// failure, even when the opposite half had already completed cleanly.
// These tests lock in the reclassification: write-after-EOF races on
// the remaining direction become `DisconnectCause::GracefulShutdown`
// (first_failure = None), and genuine errors are still flagged.

/// Outcome for a single `poll_write` call in `ScriptedStream`.
#[derive(Clone, Debug)]
enum WriteOutcome {
    /// Accept the entire buffer (`Ok(buf.len())`).
    Accept,
    /// Return `Ok(0)` — tokio's `write_all` translates this into
    /// `io::ErrorKind::WriteZero` after retrying.
    Zero,
    /// Return `Err(io::Error::new(kind, msg))`.
    Fail(io::ErrorKind, &'static str),
}
/// Flexible stream fixture for bidirectional-copy reclassification tests.
///
/// `reads` is a script of chunks returned in order; once exhausted, every
/// subsequent `poll_read` returns EOF. `writes` is a per-call outcome
/// script; once exhausted, every subsequent `poll_write` falls back to
/// `write_default`. Both directions are independent (an `AsyncRead` and an
/// `AsyncWrite` impl on the same stream — the bidirectional copy splits
/// the stream into halves via `tokio::io::split`).
///
/// This single fixture replaces ad-hoc stream structs in tests that need
/// to flow bytes successfully *before* triggering the close-race write
/// error — required for the `both_directions_transferred` admission gate
/// in the production reclassification logic.
struct ScriptedStream {
    reads: VecDeque<Vec<u8>>,
    writes: VecDeque<WriteOutcome>,
    write_default: WriteOutcome,
}

impl ScriptedStream {
    fn new(reads: Vec<Vec<u8>>, writes: Vec<WriteOutcome>, write_default: WriteOutcome) -> Self {
        Self {
            reads: reads.into(),
            writes: writes.into(),
            write_default,
        }
    }
}

impl AsyncRead for ScriptedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        match self.reads.pop_front() {
            None => Poll::Ready(Ok(())),
            Some(mut chunk) => {
                let n = buf.remaining().min(chunk.len());
                buf.put_slice(&chunk[..n]);
                if n < chunk.len() {
                    chunk.drain(..n);
                    self.reads.push_front(chunk);
                }
                Poll::Ready(Ok(()))
            }
        }
    }
}

impl AsyncWrite for ScriptedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let outcome = self
            .writes
            .pop_front()
            .unwrap_or_else(|| self.write_default.clone());
        match outcome {
            WriteOutcome::Accept => Poll::Ready(Ok(buf.len())),
            WriteOutcome::Zero => Poll::Ready(Ok(0)),
            WriteOutcome::Fail(kind, msg) => Poll::Ready(Err(io::Error::new(kind, msg))),
        }
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Helper: build the canonical "bench close-race" client/backend pair.
///
/// * Client transfers `request` bytes c2b, then EOFs its read side.
/// * Backend transfers `response_chunks` to b2c, then EOFs its read side.
/// * One write call on the *failing_side* succeeds (so the relevant
///   counter advances past zero), then a second write fails with
///   `failure_kind` — emulating the TLS close_notify → FIN tail race
///   firing AFTER both directions have already delivered bytes.
fn close_race_pair(
    request: &[u8],
    response_chunks: &[&[u8]],
    failing_side: FailingSide,
    failure: WriteOutcome,
) -> (ScriptedStream, ScriptedStream) {
    let response_chunks: Vec<Vec<u8>> = response_chunks.iter().map(|c| c.to_vec()).collect();
    match failing_side {
        // Client write fails on the second call → b2c (which writes to
        // client) errors after delivering the first response chunk.
        FailingSide::Client => {
            let client = ScriptedStream::new(
                vec![request.to_vec()],
                vec![WriteOutcome::Accept, failure],
                WriteOutcome::Accept,
            );
            let backend = ScriptedStream::new(response_chunks, vec![], WriteOutcome::Accept);
            (client, backend)
        }
        // Backend write fails on the second call → c2b (which writes to
        // backend) errors after delivering the first request chunk.
        FailingSide::Backend => {
            let client = ScriptedStream::new(
                vec![request.to_vec(), b"second-chunk".to_vec()],
                vec![],
                WriteOutcome::Accept,
            );
            let backend = ScriptedStream::new(
                response_chunks,
                vec![WriteOutcome::Accept, failure],
                WriteOutcome::Accept,
            );
            (client, backend)
        }
    }
}

#[derive(Clone, Copy)]
enum FailingSide {
    Client,
    Backend,
}

/// Regression: when one half of the bidirectional copy finishes with a
/// clean `Ok(0)` EOF and the remaining half subsequently hits `BrokenPipe`
/// on its write side (the classic TLS close_notify → FIN tail race), the
/// connection has shut down gracefully from the proxy's perspective. The
/// relay must report `first_failure = None` so operators see
/// `DisconnectCause::GracefulShutdown` instead of a spurious BackendError.
///
/// Setup mirrors the bench scenario the PR was written for: both
/// directions transfer real bytes (request c2b, first response chunk b2c)
/// *before* the close-race tail fires. The
/// `both_directions_transferred` admission gate is satisfied, so the
/// reclassification is allowed to proceed.
#[tokio::test]
async fn test_bidirectional_copy_reclassifies_write_after_eof_as_graceful() {
    let (client, backend) = close_race_pair(
        b"REQUEST",
        &[b"RESP-CHUNK-1", b"RESP-CHUNK-2"],
        FailingSide::Client,
        WriteOutcome::Fail(io::ErrorKind::BrokenPipe, "simulated write-after-close"),
    );

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    assert!(
        result.first_failure.is_none(),
        "write-after-EOF-on-opposite-half must reclassify as graceful, got {:?}",
        result.first_failure
    );
    assert!(
        result.bytes_client_to_backend > 0 && result.bytes_backend_to_client > 0,
        "both directions must have transferred bytes for the close-race admission gate to allow reclassification"
    );
}

/// Same reclassification, but triggered by `ConnectionReset` on the write
/// side instead of `BrokenPipe`. Both errnos map to the same benign
/// post-EOF tail race (Linux emits ECONNRESET when the peer has sent an
/// RST after close_notify, macOS/BSD tend to emit EPIPE).
#[tokio::test]
async fn test_bidirectional_copy_reclassifies_connection_reset_after_eof_as_graceful() {
    let (client, backend) = close_race_pair(
        b"REQUEST",
        &[b"RESP-CHUNK-1", b"RESP-CHUNK-2"],
        FailingSide::Client,
        WriteOutcome::Fail(
            io::ErrorKind::ConnectionReset,
            "simulated peer reset during close",
        ),
    );

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    assert!(
        result.first_failure.is_none(),
        "write-side ConnectionReset after opposite EOF must reclassify as graceful, got {:?}",
        result.first_failure
    );
}

/// Negative control: if the first half errors BEFORE any EOF, the
/// reclassification MUST NOT fire — a read error from the client is a
/// genuine transport failure. This prevents the graceful-shutdown branch
/// from masking real errors.
#[tokio::test]
async fn test_bidirectional_copy_does_not_reclassify_when_first_half_errors() {
    let client = ResetOnReadStream;
    let (backend, _peer) = tokio::io::duplex(1024);

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    let (dir, class, side, _msg) = result
        .first_failure
        .as_ref()
        .expect("client read error must still surface first_failure, not be masked");
    assert_eq!(
        *dir,
        Direction::ClientToBackend,
        "direction must still be attributed to the erroring half"
    );
    assert_eq!(
        *class,
        ErrorClass::ConnectionReset,
        "genuine read-side ConnectionReset must keep its classification"
    );
    assert_eq!(
        *side,
        Some(StreamIoSide::Read),
        "read-side failures must never be reclassified as graceful"
    );
}

/// Negative control: a read-side failure on the opposite half AFTER the
/// first half EOF'd must NOT be reclassified as graceful. This is the
/// "backend RST-after-FIN misbehaviour" case — the backend is actively
/// misbehaving and operators must see the error on their dashboards.
#[tokio::test]
async fn test_bidirectional_copy_does_not_reclassify_read_side_error_after_eof() {
    // c2b side: client EOFs immediately on read. Writes from c2b go to
    // backend and succeed so the EOF path (shutdown backend) runs cleanly.
    struct ClientEofReaderOkWriter;
    impl AsyncRead for ClientEofReaderOkWriter {
        fn poll_read(
            self: Pin<&mut Self>,
            _cx: &mut Context<'_>,
            _buf: &mut ReadBuf<'_>,
        ) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    impl AsyncWrite for ClientEofReaderOkWriter {
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

    // Backend stream: read fails with ConnectionReset (backend RST after
    // our FIN) — this is NOT graceful, it's a misbehaving backend.
    let client = ClientEofReaderOkWriter;
    let backend = ResetOnReadStream;

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    let (dir, class, side, _msg) = result
        .first_failure
        .as_ref()
        .expect("backend read-side ConnectionReset must NOT be reclassified as graceful");
    assert_eq!(*dir, Direction::BackendToClient);
    assert_eq!(*class, ErrorClass::ConnectionReset);
    assert_eq!(
        *side,
        Some(StreamIoSide::Read),
        "read-side errors are genuine transport failures regardless of opposite-half EOF state"
    );
}

/// Verify the reclassification preserves accurate per-direction byte
/// counters. The successful first-chunk write in each direction must be
/// reflected; the failed second-chunk write in b2c must NOT bump the
/// counter (per `copy_one_direction`'s post-write `fetch_add` which only
/// runs after a successful write).
#[tokio::test]
async fn test_bidirectional_copy_graceful_reclassification_preserves_byte_counts() {
    let request: &[u8] = b"REQUEST-7B";
    let response_chunks: [&[u8]; 2] = [b"RESP-CHUNK-1", b"RESP-CHUNK-2"];
    let (client, backend) = close_race_pair(
        request,
        &response_chunks,
        FailingSide::Client,
        WriteOutcome::Fail(io::ErrorKind::BrokenPipe, "simulated write-after-close"),
    );

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    assert!(
        result.first_failure.is_none(),
        "expected graceful reclassification, got {:?}",
        result.first_failure
    );
    assert_eq!(
        result.bytes_client_to_backend,
        request.len() as u64,
        "c2b counter should reflect the single successful request write"
    );
    // First response chunk's write to client succeeded; second chunk's
    // write hit the BrokenPipe BEFORE the counter increment. The metric
    // must reflect only the successfully-delivered first chunk — this
    // lock-in catches any "count partial/failed writes" regression that
    // could inflate `bytes_backend_to_client`.
    assert_eq!(
        result.bytes_backend_to_client,
        response_chunks[0].len() as u64,
        "b2c counter should reflect only the first chunk; the failed second-write is not credited"
    );
}

// ── Phase 1 grace-window reclassification (raw-kind precision) ──────────────
//
// The drain-path tests above exercise `drain_half_close_copy`, which sees
// the raw `io::ErrorKind` directly. These tests target the *other* half
// of the fix: the Phase 1 grace-window paths (lines ~2174 / ~2221 of
// `bidirectional_copy`). Those paths fire when one direction errors first,
// then the opposite direction completes `Ok(())` within the 100 ms grace
// window. Phase 2 must use the **precise raw `io::ErrorKind`** captured at
// Phase 1 time (`phase1_benign_write_candidate`) — never the post-classified
// `ErrorClass`, which collapses two distinct errnos into one bucket
// (`BrokenPipe` and `ConnectionAborted` both map to `ConnectionClosed`)
// and drops `WriteZero` into `RequestError` entirely.

/// Regression: a Phase 1 c2b `WriteZero` followed by an opposite-half
/// `Ok(())` EOF in the grace window MUST reclassify as graceful shutdown.
///
/// Why this matters: `WriteZero` post-classifies to `ErrorClass::RequestError`
/// (no match in `classify_boxed_error`'s `io::ErrorKind` arms). A previous
/// version of the Phase 2 reclassification used a post-classification helper
/// keyed on `ErrorClass::ConnectionClosed | ConnectionReset`, which silently
/// dropped `WriteZero` cases on the floor — the very benign-write-after-close
/// pattern produced by `copy_one_direction`'s own write loop when a TLS
/// peer's receive side has gone away mid-flush.
///
/// Setup flows bytes through both directions before the WriteZero error:
/// - c2b: client returns two request chunks; backend accepts the first
///   write, then returns `Ok(0)` on the second → tokio `write_all` emits
///   `WriteZero`. c2b transferred the first chunk successfully, so
///   `c2b_bytes > 0`.
/// - b2c: backend returns one response chunk then EOF; client accepts.
///   b2c delivers the chunk, then sees EOF → `Ok(())`. `b2c_bytes > 0`.
///
/// Trace:
/// 1. Phase 1 (biased) polls c2b first. c2b transfers the first chunk
///    (c2b_bytes += N), then on the second write-iteration hits `Ok(0)`
///    → `write_all` emits `WriteZero`. c2b errors with `(Write, WriteZero)`;
///    `phase1_benign_write_candidate` captured as `true` from the raw kind.
/// 2. Phase 2 enters the b2c grace window. b2c transfers the response
///    chunk (b2c_bytes += M), then read returns EOF → `Ok(())`.
/// 3. Phase 2 reclassifies: `phase1_benign_write_candidate && both_directions_transferred`
///    → `first_failure = None` (graceful shutdown).
#[tokio::test]
async fn test_phase1_grace_window_reclassifies_write_zero_as_graceful() {
    let (client, backend) = close_race_pair(
        b"REQUEST",
        &[b"RESP-CHUNK-1"],
        FailingSide::Backend,
        WriteOutcome::Zero,
    );

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    assert!(
        result.first_failure.is_none(),
        "WriteZero on Phase 1 c2b followed by clean b2c EOF (with bytes flowed both ways) must reclassify as graceful, got {:?}",
        result.first_failure
    );
    assert!(
        result.bytes_client_to_backend > 0 && result.bytes_backend_to_client > 0,
        "scenario requires both directions to have transferred bytes for the close-race admission gate"
    );
}

/// Regression (negative): a Phase 1 c2b `ConnectionAborted` followed by an
/// opposite-half `Ok(())` EOF in the grace window MUST NOT be reclassified
/// as graceful — `ConnectionAborted` is intentionally outside the benign
/// admission set even though it shares `ErrorClass::ConnectionClosed` with
/// the benign `BrokenPipe`.
///
/// Why this matters: a previous version of the Phase 2 reclassification
/// used a post-classification helper that admitted any
/// `ErrorClass::ConnectionClosed` Write-side failure. That over-admitted
/// `ConnectionAborted` (kernel-aborted connection, e.g., keepalive
/// failure) as if it were the benign TLS close-race tail. Operators would
/// then lose visibility into a real connection-abort signal. The fix
/// captures the precise raw `io::ErrorKind` at Phase 1 time so the Phase 2
/// grace window can honor the same exclusion list as
/// `is_post_eof_benign_write_error`.
///
/// Setup mirrors the WriteZero positive case (bytes flow in both
/// directions) so this test specifically validates the **raw-kind**
/// exclusion rather than tripping the orthogonal `both_directions_transferred`
/// gate. With both bytes counters > 0, the only reason the reclassification
/// is denied is the precise raw-kind check.
#[tokio::test]
async fn test_phase1_grace_window_does_not_reclassify_connection_aborted() {
    let (client, backend) = close_race_pair(
        b"REQUEST",
        &[b"RESP-CHUNK-1"],
        FailingSide::Backend,
        WriteOutcome::Fail(
            io::ErrorKind::ConnectionAborted,
            "simulated kernel connection abort",
        ),
    );

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    let (dir, class, side, _msg) = result.first_failure.as_ref().expect(
        "ConnectionAborted on Phase 1 c2b must NOT be reclassified as graceful — \
         it is outside the precise benign-write admission set even though it \
         shares ErrorClass::ConnectionClosed with the benign BrokenPipe",
    );
    assert_eq!(
        *dir,
        Direction::ClientToBackend,
        "direction must be attributed to the c2b half that errored"
    );
    assert_eq!(
        *class,
        ErrorClass::ConnectionClosed,
        "ConnectionAborted post-classifies to ConnectionClosed (per classify_boxed_error)"
    );
    assert_eq!(
        *side,
        Some(StreamIoSide::Write),
        "the failure was on the write side of c2b"
    );
    assert!(
        result.bytes_client_to_backend > 0 && result.bytes_backend_to_client > 0,
        "both directions transferred bytes — exclusion must be due to the raw-kind check, not the bytes gate"
    );
}

// ── Asymmetric truncation: bytes-flow gate denies reclassification ──────────
//
// The close-race reclassification is gated on **both** directions having
// transferred bytes (`both_directions_transferred` in tcp_proxy.rs).
// Without this gate, two genuine failure shapes would be silently
// re-labelled as `GracefulShutdown`:
//
//  1. The backend dies before responding — c2b transferred upload bytes
//     (c2b > 0), b2c never delivered any response (b2c == 0). c2b's next
//     write to the dead backend hits BrokenPipe, b2c sees FIN as EOF.
//  2. A client connects and immediately half-closes its write side without
//     sending anything (port scanner, premature abort). c2b sees EOF
//     instantly (c2b == 0); when backend pushes data into b2c, the write
//     to the closed client peer fails (b2c == 0).
//
// Both shapes look identical to the close-race tail at the
// raw-`io::ErrorKind` layer — the only signal that differentiates them
// is "did the relay carry a real transaction?", which the byte counters
// answer.

/// Asymmetric truncation #1: backend dies in the middle of a client
/// upload. c2b transferred request bytes successfully before hitting the
/// failing write; b2c never got a response chunk through. Even though the
/// raw kind is benign (BrokenPipe) and the opposite half completed
/// `Ok(())` cleanly, the reclassification MUST be denied because
/// `b2c_bytes == 0` — operators need to see this as a backend failure,
/// not graceful shutdown.
#[tokio::test]
async fn test_phase1_grace_window_denies_reclassification_when_b2c_transferred_no_bytes() {
    // c2b: client returns two chunks; backend accepts the first write,
    // then fails the second with BrokenPipe (backend died mid-upload).
    // b2c: backend read returns EOF immediately (no response delivered).
    let client = ScriptedStream::new(
        vec![b"REQ-CHUNK-1".to_vec(), b"REQ-CHUNK-2".to_vec()],
        vec![],
        WriteOutcome::Accept,
    );
    let backend = ScriptedStream::new(
        vec![],
        vec![
            WriteOutcome::Accept,
            WriteOutcome::Fail(
                io::ErrorKind::BrokenPipe,
                "simulated backend died mid-upload",
            ),
        ],
        WriteOutcome::Accept,
    );

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    let (dir, _class, side, _msg) = result.first_failure.as_ref().expect(
        "Asymmetric truncation (backend died before responding, b2c_bytes == 0) must NOT be \
         reclassified as graceful — operators need to see the backend failure",
    );
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*side, Some(StreamIoSide::Write));
    assert!(
        result.bytes_client_to_backend > 0,
        "c2b should have transferred at least the first request chunk before the backend died"
    );
    assert_eq!(
        result.bytes_backend_to_client, 0,
        "b2c should have transferred no bytes — backend FIN'd before responding"
    );
}

/// Asymmetric truncation #2: client connects and immediately half-closes
/// its write side without sending anything (port scanner / premature
/// abort). When the backend pushes data into b2c, the write to the
/// already-closed client peer fails. Even though the raw kind is benign
/// (BrokenPipe) and Phase 1 ended with c2b clean EOF, the drain-path
/// reclassification MUST be denied because both `c2b_bytes == 0` AND
/// `b2c_bytes == 0` — there's no evidence a real transaction took place.
#[tokio::test]
async fn test_drain_path_denies_reclassification_when_no_bytes_transferred() {
    // c2b: client read returns EOF immediately (Phase 1 c2b clean EOF;
    // no bytes carried). Client write fails with BrokenPipe so the b2c
    // drain path produces a benign-write error.
    let client = ScriptedStream::new(
        vec![],
        vec![],
        WriteOutcome::Fail(
            io::ErrorKind::BrokenPipe,
            "simulated client closed before backend pushed",
        ),
    );
    // b2c: backend returns one response chunk so the drain has something
    // to attempt to write into the closed client; the failed write is
    // what triggers the reclassification check.
    let backend = ScriptedStream::new(
        vec![b"UNSOLICITED-RESPONSE".to_vec()],
        vec![],
        WriteOutcome::Accept,
    );

    let result =
        bidirectional_copy_for_test(client, backend, TEST_IDLE_TIMEOUT, None, 8 * 1024).await;

    let (dir, _class, side, _msg) = result.first_failure.as_ref().expect(
        "Drain path with no bytes transferred either direction must NOT be reclassified \
         as graceful — there's no evidence of a real transaction",
    );
    assert_eq!(*dir, Direction::BackendToClient);
    assert_eq!(*side, Some(StreamIoSide::Write));
    assert_eq!(
        result.bytes_client_to_backend, 0,
        "client never sent any bytes (immediate EOF)"
    );
    assert_eq!(
        result.bytes_backend_to_client, 0,
        "b2c write failed before counter increment"
    );
}
