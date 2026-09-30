//! Flush progress for the shared relay copy loop
//! ([issue #5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588),
//! section 3; `docs/benchmark_audit_2026_09_17.md`).
//!
//! `src/proxy/tcp_proxy.rs::poll_copy_direction` used to accept bytes into the
//! writer, return to polling the reader, and park there without flushing. That
//! is only safe for a writer that hands everything straight to the transport.
//! A buffering writer keeps the bytes: `tokio::io::BufWriter` copies them into
//! its own buffer, and `tokio-rustls`' `poll_write` returns `Ok(n)` for
//! plaintext whose ciphertext it could not push (`common::Stream::poll_write`'s
//! `(n, would_block)` arm). For a request/response protocol the peer that owes
//! the relay its next read is then waiting on bytes nothing will send — the
//! WSS/large-payload timeout shape the audit was chasing. Tokio's own
//! `CopyBuffer::poll_copy` flushes when the read side is pending for exactly
//! this reason.
//!
//! Every test here drives the PRODUCTION relay through `_test_support`, not a
//! re-typed copy of the loop:
//!
//! * `bidirectional_copy_for_test_with_timeouts` — userspace TCP/TLS and
//!   WebSocket tunnel mode (`bidirectional_copy_for_relay`);
//! * `bidirectional_copy_for_fenced_relay_for_test` — the fenced entry point
//!   the HBONE HTTP/2 CONNECT byte tunnel enters, under the mesh admission
//!   fence's revocation bound. The tunnel's own H2 leg cannot be the buffering
//!   writer (`H2ConnectTunnel::poll_flush` is a compile-time no-op); the
//!   direction a buffering writer stalls on HBONE is backend→client, through
//!   the inbound mTLS `TlsStream`;
//! * `bidirectional_copy_with_authorization_for_test` — the authorization
//!   lifetime bound.
//!
//! The relay flushes only what it handed to a writer itself, so the two writes
//! that run just before it starts are covered as well, through their production
//! helpers: the TCP+TLS inspected-prefix forward
//! (`tcp_forward_prefix_under_trust_fence_for_test`) and the WebSocket
//! tunnel-mode forward of backend bytes recovered with the `101`
//! (`forward_ws_tunnel_residual_for_test`).
//!
//! The structural sibling inventory lives in `shared_invariant_parity_tests.rs`
//! (`every_tunnelled_relay_path_shares_one_flushing_byte_pump` and
//! `every_pre_relay_write_flushes_before_the_relay_starts`).
use rustls::pki_types::pem::PemObject;

use rustls::pki_types::{CertificateDer, PrivateKeyDer};
use std::io;
use std::pin::Pin;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};
use std::time::Duration;

use ferrum_edge::_test_support::{
    StreamCopyResult, StreamIoSide, bidirectional_copy_for_fenced_relay_for_test,
    bidirectional_copy_for_test_with_timeouts, bidirectional_copy_with_authorization_for_test,
    forward_ws_tunnel_residual_for_test, tcp_forward_prefix_under_trust_fence_for_test,
};
use ferrum_edge::plugins::Direction;
use ferrum_edge::retry::{ErrorClass, TLS_CLOSE_WITHOUT_NOTIFY};
use tokio::io::{
    AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufWriter, DuplexStream, ReadBuf,
};

/// Long enough that no assertion below can pass because a relay bound fired
/// instead of the flush.
const RELAY_IDLE_TIMEOUT: Option<Duration> = Some(Duration::from_secs(300));
const RELAY_HALF_CLOSE_CAP: Option<Duration> = Some(Duration::from_secs(300));

/// How long a delivery may take before the relay is considered deadlocked. The
/// unfixed loop never delivers at all, so this only has to exceed scheduling
/// noise.
const DELIVERY_WINDOW: Duration = Duration::from_secs(5);

/// The authorization bound is an absolute `Instant` armed before the relay is
/// spawned, so the delivery asserted under it has to land inside it and there
/// is no signal to sequence on — the deadline cannot be shortened once set. The
/// remedy is margin: six times the 500 ms this started at, which still bounds
/// the test at three seconds but leaves the whole spawn/poll/write/flush
/// sequence far more room than a saturated runner needs.
const AUTHORIZATION_LIFETIME: Duration = Duration::from_secs(3);

const RELAY_BUFFER: usize = 8 * 1024;
const PEER_BUFFER: usize = 64 * 1024;

const REQUEST: &[u8] = b"GET /relay HTTP/1.1\r\nHost: flush-progress\r\n\r\n";
const RESPONSE: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok";

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

/// Transparent `AsyncRead`/`AsyncWrite` wrapper that counts `poll_flush` calls.
///
/// Wrapping a real `BufWriter` rather than re-implementing one keeps the
/// buffering semantics authentic while making the relay's flush cadence
/// observable: the relay must owe at most one flush per accepted batch, never
/// one per byte.
struct FlushCounting<S> {
    inner: S,
    flushes: Arc<AtomicUsize>,
}

impl<S> FlushCounting<S> {
    fn new(inner: S, flushes: Arc<AtomicUsize>) -> Self {
        Self { inner, flushes }
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for FlushCounting<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for FlushCounting<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.inner).poll_write(cx, buf)
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.flushes.fetch_add(1, Ordering::SeqCst);
        Pin::new(&mut self.inner).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

/// A writer that accepts every byte and never lets go of one: `poll_flush`
/// stays `Pending` forever. Models a TLS writer whose transport has stopped
/// draining, so the relay owes a flush it cannot complete.
///
/// `accepted` is the observable signal a test sequences on. "The relay has
/// handed the payload to the stalled writer" is a state, not an elapsed
/// duration; waiting on a sleep only approximates it and can miss entirely on a
/// saturated runner, which is exactly the hosted-CI condition this repository
/// keeps hitting.
struct AcceptsButNeverFlushes {
    accepted: Arc<AtomicUsize>,
    /// `Pending` from `poll_shutdown` as well, so a wedged writer's half-close
    /// never resolves either. `false` keeps the ordinary
    /// "flush stalls, shutdown still works" shape.
    wedge_shutdown: bool,
}

impl AcceptsButNeverFlushes {
    /// A writer whose flush never completes. Returns the writer and the
    /// accepted-byte counter to sequence on.
    fn new() -> (Self, Arc<AtomicUsize>) {
        Self::with_wedged_shutdown(false)
    }

    /// The same writer, whose `poll_shutdown` never completes either — a
    /// backend that took the bytes and whose transport then stopped moving
    /// altogether, so the half-close it implies can never be performed.
    fn with_wedged_shutdown(wedge_shutdown: bool) -> (Self, Arc<AtomicUsize>) {
        let accepted = Arc::new(AtomicUsize::new(0));
        let writer = Self {
            accepted: Arc::clone(&accepted),
            wedge_shutdown,
        };
        (writer, accepted)
    }
}

impl AsyncRead for AcceptsButNeverFlushes {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for AcceptsButNeverFlushes {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.accepted.fetch_add(buf.len(), Ordering::SeqCst);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Pending
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if self.wedge_shutdown {
            return Poll::Pending;
        }
        Poll::Ready(Ok(()))
    }
}

/// A writer that accepts every byte, flushes, and then fails its half-close
/// with `kind`. `poll_shutdown` implies a flush attempt, not a completed one:
/// when it fails, the bytes this direction already credited never left.
///
/// Its read half reports EOF rather than `Pending`, so the opposite direction
/// finishes on its own instead of parking for the relay's (deliberately long)
/// idle timeout.
struct AcceptsThenFailsShutdown {
    kind: io::ErrorKind,
    accepted: Arc<AtomicUsize>,
}

impl AcceptsThenFailsShutdown {
    fn new(kind: io::ErrorKind) -> (Self, Arc<AtomicUsize>) {
        let accepted = Arc::new(AtomicUsize::new(0));
        let writer = Self {
            kind,
            accepted: Arc::clone(&accepted),
        };
        (writer, accepted)
    }
}

impl AsyncRead for AcceptsThenFailsShutdown {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AcceptsThenFailsShutdown {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.accepted.fetch_add(buf.len(), Ordering::SeqCst);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::new(self.kind, SHUTDOWN_FAILURE_TEXT)))
    }
}

const H2_SHUTDOWN_FAILURE_TEXT: &str = "simulated h2 close reason during half-close";

/// Hyper's own wrapper between the `io::Error` and the `h2::Error`.
///
/// `H2Upgraded::poll_shutdown` reports a close reason as
/// `io::Error::new(ErrorKind::Other, hyper::Error)`, and it is hyper's
/// `Error::source()` that exposes the `h2::Error` underneath. `hyper::Error`
/// cannot be constructed outside hyper, so this stands in for it — and it keeps
/// the production chain's NESTING, where the reason sits one `source()` hop
/// below the error the `io::Error` wraps directly.
#[derive(Debug)]
struct H2CloseCause(h2::Error);

impl std::fmt::Display for H2CloseCause {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{H2_SHUTDOWN_FAILURE_TEXT}: {}", self.0)
    }
}

impl std::error::Error for H2CloseCause {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.0)
    }
}

/// A writer that accepts every byte and then fails its half-close the way the
/// HBONE inbound byte tunnel's client leg does.
///
/// `hbone_proxy.rs` hands the fenced relay `TokioIo::new(upgraded)` — hyper's
/// `H2Upgraded` — whose `poll_shutdown` funnels EVERY h2 close reason through
/// `ErrorKind::Other`, including the `RST_STREAM(NO_ERROR)` a client sends when
/// it is simply discarding a stream it is done with. None of the socket errnos
/// the benign half-close set started from can come out of that writer, so the
/// reason has to be what decides.
///
/// Its read half reports EOF rather than `Pending`, so the opposite direction
/// finishes on its own instead of parking for the relay's (deliberately long)
/// idle timeout.
struct AcceptsThenFailsShutdownWithH2 {
    reason: h2::Reason,
    accepted: Arc<AtomicUsize>,
}

impl AcceptsThenFailsShutdownWithH2 {
    fn new(reason: h2::Reason) -> (Self, Arc<AtomicUsize>) {
        let accepted = Arc::new(AtomicUsize::new(0));
        let writer = Self {
            reason,
            accepted: Arc::clone(&accepted),
        };
        (writer, accepted)
    }
}

impl AsyncRead for AcceptsThenFailsShutdownWithH2 {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for AcceptsThenFailsShutdownWithH2 {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.accepted.fetch_add(buf.len(), Ordering::SeqCst);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other(H2CloseCause(h2::Error::from(
            self.reason,
        )))))
    }
}

/// Wait, bounded, until a fixture counter reaches `expected`.
///
/// The relay has to have polled before a test can act on "the writer is holding
/// the payload" or "the flush already completed". Those are states, and this
/// observes them; a sleep long enough to usually cover them is what fails on a
/// saturated runner.
async fn wait_until_at_least(counter: &AtomicUsize, expected: usize, what: &str) {
    let poll_until = async {
        while counter.load(Ordering::SeqCst) < expected {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    let observed = tokio::time::timeout(DELIVERY_WINDOW, poll_until).await;
    assert!(
        observed.is_ok(),
        "the relay must reach {expected} {what}, observed {}",
        counter.load(Ordering::SeqCst)
    );
}

const FLUSH_FAILURE_TEXT: &str = "simulated transport abort during flush";
const SHUTDOWN_FAILURE_TEXT: &str = "simulated transport abort during half-close";

/// A writer that accepts every byte and then fails the flush. The failure is
/// raised by the flush, not by a write, so it must still be attributed to the
/// write side of the direction that owed it.
struct AcceptsThenFailsFlush;

impl AsyncRead for AcceptsThenFailsFlush {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for AcceptsThenFailsFlush {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let failure = io::Error::new(io::ErrorKind::ConnectionAborted, FLUSH_FAILURE_TEXT);
        Poll::Ready(Err(failure))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// A duplex leg whose write half is buffered — the minimal reproduction of the
/// defect, and the shape the audit's extracted-function fixture used.
fn buffered_leg(capacity: usize) -> (BufWriter<DuplexStream>, DuplexStream) {
    let (near, far) = tokio::io::duplex(capacity);
    (BufWriter::with_capacity(capacity, near), far)
}

// ---------------------------------------------------------------------------
// The defect: bytes accepted by a buffering writer while the reader is pending
// ---------------------------------------------------------------------------

/// Regression for the audit's finding. The relay accepts the whole request into
/// a buffering backend writer and then parks on a client that is still open and
/// simply has nothing more to say. Before the fix the request sat in the
/// writer's buffer and the backend never saw a byte.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buffered_backend_writer_is_flushed_while_the_client_reader_is_pending() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (backend, mut backend_peer) = buffered_leg(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; REQUEST.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut seen))
        .await
        .expect("the relay must flush a buffering writer while its reader is pending")
        .expect("backend read");
    assert_eq!(seen, REQUEST, "the backend must see the request verbatim");

    // Only now let both peers go, so the delivery above cannot be credited to
    // the half-close flush inside `poll_shutdown`.
    drop(client_peer);
    drop(backend_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish once both peers close")
        .expect("relay task");
    assert!(
        result.first_failure.is_none(),
        "a flushed relay that both peers closed cleanly must report no failure, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
}

/// The same defect in the other direction: the backend answers and the client
/// leg is the buffering writer. Fixing one direction and leaving the other is
/// the sibling shape `.claude/rules/testing.md` calls out.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_buffered_client_writer_is_flushed_while_the_backend_reader_is_pending() {
    let (client, mut client_peer) = buffered_leg(PEER_BUFFER);
    let (backend, mut backend_peer) = tokio::io::duplex(PEER_BUFFER);

    backend_peer.write_all(RESPONSE).await.expect("response");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; RESPONSE.len()];
    tokio::time::timeout(DELIVERY_WINDOW, client_peer.read_exact(&mut seen))
        .await
        .expect("the backend→client direction must flush its buffering writer too")
        .expect("client read");
    assert_eq!(seen, RESPONSE, "the client must see the response verbatim");

    drop(client_peer);
    drop(backend_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish once both peers close")
        .expect("relay task");
    assert_eq!(result.bytes_backend_to_client, RESPONSE.len() as u64);
}

/// The fenced entry point — `bidirectional_copy_for_fenced_relay`, which the
/// HBONE HTTP/2 CONNECT byte tunnel enters — runs the same copy loop. Exercise
/// it the same way, so the sibling the audit named is covered behaviorally and
/// not only structurally.
///
/// This proves the SHARED PUMP, not an H2 byte tunnel: the buffering writer is
/// a `BufWriter`. On HBONE itself the H2 leg can never be the writer that holds
/// bytes — `H2ConnectTunnel::poll_flush` (`src/proxy/hbone_pool.rs`) is a
/// compile-time `Poll::Ready(Ok(()))` because the h2 driver flushes on its own.
/// The direction that a buffering writer can stall there is backend→client on
/// the inbound fenced relay, where the bytes reach the peer through the inbound
/// mTLS `TlsStream`; `a_rustls_writer_holding_ciphertext_is_flushed_while_the_reader_is_pending`
/// is the rustls-backpressure coverage for that writer.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_fenced_relay_entry_point_shares_the_flushing_pump() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (backend, mut backend_peer) = buffered_leg(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_fenced_relay_for_test(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
        None,
    ));

    let mut seen = vec![0u8; REQUEST.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut seen))
        .await
        .expect("the fenced HBONE relay must flush a buffering writer as well")
        .expect("tunnel read");
    assert_eq!(seen, REQUEST);

    drop(client_peer);
    drop(backend_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the fenced relay must finish once both peers close")
        .expect("relay task");
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
}

/// Real rustls backpressure, which is what tracker #5588 section 3 asks for.
///
/// The TLS transport window is deliberately smaller than one encrypted record
/// of the relayed payload, so `tokio-rustls` accepts the whole plaintext and
/// keeps the ciphertext it could not push. The far peer holds a partial record
/// it cannot decrypt, which is precisely the state in which the unfixed relay
/// parked on a still-open client and neither side ever moved again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rustls_writer_holding_ciphertext_is_flushed_while_the_reader_is_pending() {
    let (tls_backend, mut tls_peer) = tls_session(RUSTLS_TRANSPORT_WINDOW).await;

    let payload = vec![0x5au8; RUSTLS_PAYLOAD_LEN];
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer.write_all(&payload).await.expect("payload");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        tls_backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; RUSTLS_PAYLOAD_LEN];
    tokio::time::timeout(DELIVERY_WINDOW, tls_peer.read_exact(&mut seen))
        .await
        .expect("rustls kept the ciphertext; the relay must flush it, not park")
        .expect("TLS peer read");
    assert_eq!(seen, payload, "the TLS peer must see the payload verbatim");

    // Close both legs so the relay can complete; the TLS peer's transport going
    // away is what ends the backend→client half.
    drop(tls_peer);
    drop(client_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish once both legs close")
        .expect("relay task");
    assert_eq!(result.bytes_client_to_backend, RUSTLS_PAYLOAD_LEN as u64);
}

/// Smaller than the ~8 KiB record [`RUSTLS_PAYLOAD_LEN`] produces, so the first
/// `write_io` fills the transport and rustls retains the remainder.
const RUSTLS_TRANSPORT_WINDOW: usize = 4 * 1024;
const RUSTLS_PAYLOAD_LEN: usize = 8 * 1024;

/// A completed TLS session over an in-memory transport that buffers `window`
/// bytes per direction, as `(client, server)`. A window smaller than one
/// encrypted record is what makes `tokio-rustls` accept plaintext and return
/// `Ok(n)` while keeping ciphertext it could not push.
async fn tls_session(
    window: usize,
) -> (
    tokio_rustls::client::TlsStream<DuplexStream>,
    tokio_rustls::server::TlsStream<DuplexStream>,
) {
    let (server_config, client_config) = test_tls_configs();
    let (client_io, server_io) = tokio::io::duplex(window);

    let acceptor = tokio_rustls::TlsAcceptor::from(server_config);
    let server_handshake = tokio::spawn(async move {
        let accepted = acceptor.accept(server_io).await;
        accepted.expect("server handshake")
    });
    let connector = tokio_rustls::TlsConnector::from(client_config);
    let host = "localhost".to_string();
    let name = rustls::pki_types::ServerName::try_from(host).expect("server name");
    let connect = connector.connect(name, client_io);
    let client = connect.await.expect("client handshake");
    let server = server_handshake.await.expect("server handshake task");
    (client, server)
}

fn test_tls_configs() -> (Arc<rustls::ServerConfig>, Arc<rustls::ClientConfig>) {
    let ecdsa = &rcgen::PKCS_ECDSA_P256_SHA256;
    let key = rcgen::KeyPair::generate_for(ecdsa).expect("leaf key");
    let params = rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("params");
    let cert = params.self_signed(&key).expect("self-signed leaf");

    let certs = CertificateDer::pem_slice_iter(cert.pem().as_bytes())
        .collect::<Result<Vec<_>, _>>()
        .expect("parse test leaf certificate");
    let private_key =
        PrivateKeyDer::from_pem_slice(key.serialize_pem().as_bytes()).expect("parse test leaf key");

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let server = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .with_no_client_auth()
        .with_single_cert(certs, private_key)
        .expect("test TLS server config");
    let client = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .expect("test TLS protocol versions")
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(ferrum_edge::tls::NoVerifier))
        .with_no_client_auth();

    (Arc::new(server), Arc::new(client))
}

// ---------------------------------------------------------------------------
// Cost: one flush per accepted batch, never one per byte
// ---------------------------------------------------------------------------

/// The flush is owed once per batch the writer accepted, and the debt is
/// cleared when it completes. An unbuffered writer's `poll_flush` is a no-op,
/// so this is also what keeps the plain-TCP hot path syscall-free.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn one_accepted_batch_owes_exactly_one_flush() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (buffered, mut backend_peer) = buffered_leg(PEER_BUFFER);
    let backend = FlushCounting::new(buffered, Arc::clone(&flushes));

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut first = vec![0u8; REQUEST.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut first))
        .await
        .expect("the buffered request must be flushed")
        .expect("backend read");
    assert_eq!(
        flushes.load(Ordering::SeqCst),
        1,
        "one accepted batch must owe exactly one flush, not one per byte"
    );

    // A second batch: the writer accepts again, so the relay owes one more
    // flush and no more than one. Reading the batch back proves that flush
    // already completed, so the count cannot still be racing upward.
    client_peer.write_all(RESPONSE).await.expect("second batch");
    let mut second = vec![0u8; RESPONSE.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut second))
        .await
        .expect("the second buffered batch must be flushed")
        .expect("backend read");
    assert_eq!(
        flushes.load(Ordering::SeqCst),
        2,
        "a completed flush clears the debt; only a new batch re-owes one"
    );

    drop(client_peer);
    drop(backend_peer);
    let _ = tokio::time::timeout(DELIVERY_WINDOW, relay).await;
}

// ---------------------------------------------------------------------------
// Preserved: half-close in both directions, and byte attribution
// ---------------------------------------------------------------------------

/// A client that half-closes its write side must still get its buffered
/// request delivered — `poll_shutdown` implies a flush — and the backend's
/// reply must still reach the client through the Phase 2 half-close drain.
/// Both per-direction counters must be exact.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn half_close_delivers_buffered_bytes_in_both_directions_with_exact_counters() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (backend, mut backend_peer) = buffered_leg(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");
    client_peer.shutdown().await.expect("client half-close");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let backend_side = tokio::spawn(async move {
        let mut received = Vec::new();
        backend_peer
            .read_to_end(&mut received)
            .await
            .expect("backend read up to the relay half-close");
        backend_peer.write_all(RESPONSE).await.expect("response");
        backend_peer.shutdown().await.expect("backend half-close");
        received
    });

    let mut delivered = Vec::new();
    tokio::time::timeout(DELIVERY_WINDOW, client_peer.read_to_end(&mut delivered))
        .await
        .expect("the half-close drain must deliver the backend response")
        .expect("client read");
    let received = tokio::time::timeout(DELIVERY_WINDOW, backend_side)
        .await
        .expect("the backend fixture must finish")
        .expect("backend task");

    assert_eq!(
        received, REQUEST,
        "the half-closing client's buffered request must arrive intact"
    );
    assert_eq!(
        delivered, RESPONSE,
        "the backend reply must arrive intact through the half-close drain"
    );

    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish after both half-closes")
        .expect("relay task");
    assert!(
        result.first_failure.is_none(),
        "an orderly half-close in both directions must report no failure, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
    assert_eq!(result.bytes_backend_to_client, RESPONSE.len() as u64);
}

// ---------------------------------------------------------------------------
// Preserved: deadlines, cancellation, and error attribution
// ---------------------------------------------------------------------------

/// `backend_write_timeout` must still bound a writer that took the bytes and
/// cannot let go of them. The relay's own buffer is empty at that point, so the
/// write-stall watermark has to stay armed across the in-flight flush rather
/// than going inert the moment the writer said `Ok`.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_writer_that_never_completes_its_flush_still_trips_the_write_timeout() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let (backend, _accepted) = AcceptsButNeverFlushes::new();
    let relay = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        None,
        None,
        None,
        Some(Duration::from_millis(1500)),
        RELAY_BUFFER,
    );
    let result = tokio::time::timeout(Duration::from_secs(10), relay)
        .await
        .expect("the write deadline must fire while the writer holds the bytes");

    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a stalled flush must surface the backend write inactivity timeout");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Write));
    assert!(
        msg.contains("backend write inactivity"),
        "failure message must name the write inactivity deadline, got: {msg}"
    );
    assert_eq!(
        result.bytes_client_to_backend,
        REQUEST.len() as u64,
        "bytes the writer already accepted stay credited, matching the splice path"
    );
    drop(client_peer);
}

/// The half-close is the other place a writer can sit holding bytes it
/// accepted, and it is the one the first round of this fix left unbounded.
/// `poll_shutdown` implies a flush *attempt*, not a completed one, so the
/// write-stall deadline has to survive `begin_half_close` and go inert only
/// when the shutdown resolves.
///
/// The configuration is the one that makes it load-bearing: idle timeout and
/// half-close cap both disabled — a documented long-lived-TCP setting — leave
/// `backend_write_timeout_ms` as the only timer that still describes this
/// direction. A non-zero write timeout also keeps the relay on the
/// direction-tracking path rather than tokio's all-bounds-disabled fast path.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_wedged_half_close_still_trips_the_write_timeout_with_no_other_bound() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");
    // EOF on the client leg is what drives this direction into the half-close;
    // the bytes written before it stay readable, then the reader sees EOF.
    client_peer.shutdown().await.expect("client half-close");

    let (backend, accepted) = AcceptsButNeverFlushes::with_wedged_shutdown(true);
    // The third and fourth arguments are the idle timeout and the half-close
    // cap: `tcp_idle_timeout_seconds: 0` and `tcp_half_close_max_wait_seconds:
    // 0`. Only `backend_write_timeout` is left.
    let relay = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        None,
        None,
        None,
        Some(Duration::from_millis(1500)),
        RELAY_BUFFER,
    );
    let result = tokio::time::timeout(Duration::from_secs(10), relay)
        .await
        .expect("the write deadline must bound a half-close that cannot complete");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        REQUEST.len(),
        "the writer must have taken the request before the half-close wedged"
    );
    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a wedged half-close must surface the backend write inactivity timeout");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Write));
    assert!(
        msg.contains("backend write inactivity"),
        "failure message must name the write inactivity deadline, got: {msg}"
    );
    assert_eq!(
        result.bytes_client_to_backend,
        REQUEST.len() as u64,
        "bytes the writer already accepted stay credited, matching the splice path"
    );
    drop(client_peer);
}

/// A `poll_shutdown` that fails did not perform the flush it implies: the bytes
/// this direction already credited never left the writer. Reporting the
/// direction as a clean completion would hide that tail.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_half_close_whose_shutdown_fails_is_reported_as_a_write_failure() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");
    client_peer.shutdown().await.expect("client half-close");

    let (backend, accepted) = AcceptsThenFailsShutdown::new(io::ErrorKind::ConnectionAborted);
    let relay = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    );
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("a failing half-close must end the relay rather than park it");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        REQUEST.len(),
        "the writer must have taken the request before failing its half-close"
    );
    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("an accepted-but-undelivered tail is not a clean completion");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ConnectionClosed);
    assert_eq!(
        *side,
        Some(StreamIoSide::Write),
        "the half-close belongs to the writer, so the failure is write-side"
    );
    assert!(
        msg.contains(SHUTDOWN_FAILURE_TEXT),
        "the transport's own message must survive classification, got: {msg}"
    );
    assert_eq!(
        result.bytes_client_to_backend,
        REQUEST.len() as u64,
        "bytes accepted before the failing half-close stay credited"
    );
    drop(client_peer);
}

/// The propagation is scoped to what the finding is about: a tail the writer
/// accepted and never delivered. A direction that owes no flush — its writer
/// already flushed everything it took — truncates nothing when its half-close
/// fails, and stays a clean completion. Without that scope, every teardown on a
/// connection that carried its bytes successfully would become an error.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_half_close_with_nothing_outstanding_stays_a_clean_completion() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let (failing, accepted) = AcceptsThenFailsShutdown::new(io::ErrorKind::ConnectionAborted);
    let backend = FlushCounting::new(failing, Arc::clone(&flushes));
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    // A completed flush is what clears the debt, so half-close the client only
    // once one has been observed: the relay then reaches `poll_shutdown` owing
    // nothing, which is the state under test.
    wait_until_at_least(&accepted, REQUEST.len(), "accepted bytes").await;
    wait_until_at_least(&flushes, 1, "completed flushes").await;
    client_peer.shutdown().await.expect("client half-close");

    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish once the half-close resolves")
        .expect("relay task");
    assert!(
        result.first_failure.is_none(),
        "a half-close that truncates nothing must stay graceful, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
    drop(client_peer);
}

/// The counterpart bound: a benign write-after-close errno on the half-close is
/// the tail of the peer's own `close_notify`/FIN dance, and stays a clean
/// completion exactly as it did before this arm propagated anything. Widening
/// the propagation to cover these would turn ordinary teardown into
/// `total_errors`, which is what `is_post_eof_benign_write_error` exists to
/// prevent.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_benign_write_after_close_half_close_stays_a_clean_completion() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");
    client_peer.shutdown().await.expect("client half-close");

    let (backend, accepted) = AcceptsThenFailsShutdown::new(io::ErrorKind::BrokenPipe);
    let relay = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    );
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("a benign half-close failure must still end the relay promptly");

    assert_eq!(accepted.load(Ordering::SeqCst), REQUEST.len());
    assert!(
        result.first_failure.is_none(),
        "a benign write-after-close half-close must stay graceful, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
    drop(client_peer);
}

/// The HBONE exposure: the inbound byte tunnel's client leg cannot raise any of
/// the socket errnos, so an ordinary abort-after-done arrives as
/// `ErrorKind::Other`.
///
/// The shape is the production one. The loopback app answers and closes, so
/// backend→client accepts the response and reaches EOF in the same poll batch
/// still owing its flush; the client, whose own upload already ended, discards
/// the stream with `RST_STREAM(NO_ERROR)`. Treating that as a write-side failure
/// would turn routine teardown into a `record_hbone_relay_failure`, an `HBONE
/// tunnel relay failed` warning, and a `body_completed = false` transaction
/// summary, so the close REASON — not the errno — decides.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_h2_no_error_close_reason_on_the_half_close_stays_a_clean_completion() {
    let (backend, mut backend_peer) = tokio::io::duplex(PEER_BUFFER);
    backend_peer
        .write_all(RESPONSE)
        .await
        .expect("backend response");
    // EOF on the backend leg is what drives backend→client into the half-close.
    backend_peer.shutdown().await.expect("backend half-close");

    let (client, accepted) = AcceptsThenFailsShutdownWithH2::new(h2::Reason::NO_ERROR);
    let relay = bidirectional_copy_for_fenced_relay_for_test(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
        None,
    );
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("an h2 NO_ERROR half-close must end the relay promptly");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        RESPONSE.len(),
        "the tunnel leg must have taken the response before its half-close"
    );
    assert!(
        result.first_failure.is_none(),
        "an h2 close reason of NO_ERROR is graceful teardown, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_backend_to_client, RESPONSE.len() as u64);
    drop(backend_peer);
}

/// The counterpart bound: every OTHER h2 close reason is a real write-side
/// failure, exactly as a non-benign errno is. Admitting `ErrorKind::Other`
/// itself would swallow all of them, and the accepted-but-undelivered tail this
/// arm exists to report would go back to being a clean completion.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_non_benign_h2_close_reason_on_the_half_close_is_reported_as_a_write_failure() {
    let (backend, mut backend_peer) = tokio::io::duplex(PEER_BUFFER);
    backend_peer
        .write_all(RESPONSE)
        .await
        .expect("backend response");
    backend_peer.shutdown().await.expect("backend half-close");

    let (client, accepted) = AcceptsThenFailsShutdownWithH2::new(h2::Reason::INTERNAL_ERROR);
    let relay = bidirectional_copy_for_fenced_relay_for_test(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
        None,
    );
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("a failing half-close must end the relay rather than park it");

    assert_eq!(
        accepted.load(Ordering::SeqCst),
        RESPONSE.len(),
        "the tunnel leg must have taken the response before failing its half-close"
    );
    let (dir, _class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("an accepted-but-undelivered tail is not a clean completion");
    assert_eq!(*dir, Direction::BackendToClient);
    assert_eq!(
        *side,
        Some(StreamIoSide::Write),
        "the half-close belongs to the writer, so the failure is write-side"
    );
    assert!(
        msg.contains(H2_SHUTDOWN_FAILURE_TEXT),
        "the transport's own message must survive classification, got: {msg}"
    );
    assert_eq!(
        result.bytes_backend_to_client,
        RESPONSE.len() as u64,
        "bytes accepted before the failing half-close stay credited"
    );
    drop(backend_peer);
}

/// A failure raised by the flush belongs to the write side of the direction
/// that owed it, not to the reader it was about to park on.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_failing_flush_is_attributed_to_the_write_side() {
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = bidirectional_copy_for_test_with_timeouts(
        client,
        AcceptsThenFailsFlush,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    );
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("a failing flush must end the relay rather than park it");

    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a failing flush must surface as a relay failure");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ConnectionClosed);
    assert_eq!(
        *side,
        Some(StreamIoSide::Write),
        "the flush belongs to the writer, so the failure is write-side"
    );
    assert!(
        msg.contains(FLUSH_FAILURE_TEXT),
        "the transport's own message must survive classification, got: {msg}"
    );
    assert_eq!(
        result.bytes_client_to_backend,
        REQUEST.len() as u64,
        "bytes the writer accepted before failing its flush stay credited"
    );
    drop(client_peer);
}

/// The mesh admission fence revokes live tunnels through this relay. A writer
/// that is holding bytes it will never flush must not be able to keep a revoked
/// tunnel alive: the revocation bound is raced ahead of both copy halves.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn admission_revocation_still_cuts_a_relay_whose_writer_holds_bytes() {
    let token = tokio_util::sync::CancellationToken::new();
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let (backend, accepted) = AcceptsButNeverFlushes::new();
    let relay = tokio::spawn(bidirectional_copy_for_fenced_relay_for_test(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
        Some(token.clone()),
    ));

    // The revocation has to interrupt a direction that is parked mid-flush, so
    // wait for the writer to have actually taken the request rather than for a
    // duration that usually covers it.
    wait_until_at_least(&accepted, REQUEST.len(), "accepted bytes").await;
    token.cancel();

    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("revocation must end the relay even with a flush outstanding")
        .expect("relay task");

    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a revoked tunnel must surface the fence's fixed failure");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ConnectionClosed);
    assert_eq!(*side, Some(StreamIoSide::Read));
    assert!(
        msg.contains("mesh admission revoked"),
        "the fence's compiled-in message must survive, got: {msg}"
    );
    assert_eq!(
        result.bytes_client_to_backend,
        REQUEST.len() as u64,
        "bytes accepted before revocation stay credited"
    );
    drop(client_peer);
}

/// The authorization lifetime bound is the other top-level cut. Flushing while
/// the reader is pending must not delay it, and the bytes the writer already
/// took must still be delivered and counted.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_authorization_deadline_still_fires_with_a_buffering_writer() {
    let expired = Arc::new(AtomicBool::new(false));
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    let (backend, mut backend_peer) = buffered_leg(PEER_BUFFER);

    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_with_authorization_for_test(
        client,
        backend,
        tokio::time::Instant::now() + AUTHORIZATION_LIFETIME,
        Arc::clone(&expired),
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; REQUEST.len()];
    tokio::time::timeout(DELIVERY_WINDOW, backend_peer.read_exact(&mut seen))
        .await
        .expect("an authorization-bounded relay must still flush what it accepted")
        .expect("backend read");
    assert_eq!(seen, REQUEST);

    let result = tokio::time::timeout(AUTHORIZATION_LIFETIME + DELIVERY_WINDOW, relay)
        .await
        .expect("the authorization deadline must end the relay")
        .expect("relay task");

    assert!(
        expired.load(Ordering::Acquire),
        "the authorization-expiry flag must latch"
    );
    let (dir, class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("expiry must surface a typed failure");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*class, ErrorClass::ReadWriteTimeout);
    assert_eq!(*side, Some(StreamIoSide::Read));
    assert!(
        msg.contains("authorization lifetime reached"),
        "failure message must be the fixed authorization lifetime text: {msg}"
    );
    assert_eq!(result.bytes_client_to_backend, REQUEST.len() as u64);
    drop(client_peer);
}

// ---------------------------------------------------------------------------
// No busy loop: a pending flush parks on the writer's waker
// ---------------------------------------------------------------------------

/// How long the relay is watched while its flush is pending. Far below the
/// relay watchdog's first tick (five seconds for the 300 s bounds above), so a
/// well-behaved relay polls the flush zero more times in this window.
const SPIN_OBSERVATION_WINDOW: Duration = Duration::from_millis(250);

/// Extra `poll_flush` calls tolerated during [`SPIN_OBSERVATION_WINDOW`]. A
/// relay that re-polls a pending flush instead of parking produces thousands;
/// this only absorbs a stray wake-up.
const SPURIOUS_FLUSH_POLL_ALLOWANCE: usize = 2;

/// Shared state of a [`GatedFlushWriter`], observed and released by the test.
#[derive(Default)]
struct FlushGate {
    open: AtomicBool,
    flush_polls: AtomicUsize,
    parked: Mutex<Option<Waker>>,
    held: Mutex<Vec<u8>>,
    delivered: Mutex<Vec<u8>>,
}

impl FlushGate {
    /// Let the flush complete, then wake the task parked on it — the way a
    /// transport reports write readiness. Nothing else wakes the relay.
    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        let parked = self.parked.lock().expect("flush gate waker").take();
        if let Some(waker) = parked {
            waker.wake();
        }
    }

    fn delivered(&self) -> Vec<u8> {
        self.delivered.lock().expect("flush gate delivery").clone()
    }
}

/// A buffering writer whose flush stays `Pending` until the test opens its
/// gate. A pending flush registers the waker it was polled with, exactly as a
/// real transport registers write interest, and a completed flush moves what
/// the writer held to `delivered`. The read half never produces anything: a
/// backend that is waiting for the request.
struct GatedFlushWriter(Arc<FlushGate>);

impl AsyncRead for GatedFlushWriter {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Pending
    }
}

impl AsyncWrite for GatedFlushWriter {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let mut held = self.0.held.lock().expect("flush gate buffer");
        held.extend_from_slice(buf);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let gate = &self.0;
        gate.flush_polls.fetch_add(1, Ordering::SeqCst);
        if !gate.open.load(Ordering::SeqCst) {
            *gate.parked.lock().expect("flush gate waker") = Some(cx.waker().clone());
            // Re-check after publishing the waker, so an `open()` that ran
            // between the first check and the store is not lost.
            if !gate.open.load(Ordering::SeqCst) {
                return Poll::Pending;
            }
        }
        let held = std::mem::take(&mut *gate.held.lock().expect("flush gate buffer"));
        let mut delivered = gate.delivered.lock().expect("flush gate delivery");
        delivered.extend_from_slice(&held);
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Flush progress must not turn into a busy loop. A writer whose flush is
/// `Pending` has registered the task's waker with whatever will drain it, so
/// the relay has to park on that rather than re-poll the flush until it
/// happens to succeed. It then has to resume on that waker alone: the client
/// sends nothing further and the backend never answers.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_flush_parks_on_the_writer_waker_instead_of_spinning() {
    let gate = Arc::new(FlushGate::default());
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer
        .write_all(REQUEST)
        .await
        .expect("client request");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        GatedFlushWriter(Arc::clone(&gate)),
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    wait_until_at_least(&gate.flush_polls, 1, "flush polls").await;
    let parked_at = gate.flush_polls.load(Ordering::SeqCst);
    tokio::time::sleep(SPIN_OBSERVATION_WINDOW).await;
    let polled_while_parked = gate.flush_polls.load(Ordering::SeqCst) - parked_at;
    assert!(
        polled_while_parked <= SPURIOUS_FLUSH_POLL_ALLOWANCE,
        "a pending flush must park the relay, not spin on it: {polled_while_parked} more \
         flush polls in {SPIN_OBSERVATION_WINDOW:?}"
    );
    assert!(
        gate.delivered().is_empty(),
        "nothing may reach the peer while the flush is still pending"
    );

    gate.open();
    let delivered = async {
        while gate.delivered().len() < REQUEST.len() {
            tokio::time::sleep(Duration::from_millis(2)).await;
        }
    };
    tokio::time::timeout(DELIVERY_WINDOW, delivered)
        .await
        .expect("the flush's own waker must resume the relay without further input");
    assert_eq!(
        gate.delivered(),
        REQUEST,
        "the flushed bytes must be the request, verbatim"
    );

    // The backend never answers, so the backend→client half would wait for
    // the 300 s idle bound; this test is about the flush, not the teardown.
    relay.abort();
    drop(client_peer);
}

// ---------------------------------------------------------------------------
// Real rustls backpressure: the reply direction and the half-close
// ---------------------------------------------------------------------------

/// The reply direction of a TLS-terminated frontend — WSS in tunnel mode and
/// TCP+TLS — where the relay's writer is the frontend's `tokio-rustls` SERVER
/// stream. The transport window is again smaller than one record, so rustls
/// accepts the backend's reply and keeps ciphertext the client cannot decrypt
/// yet, while the relay's reader is a backend waiting for the client's next
/// message.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rustls_frontend_writer_holding_ciphertext_is_flushed_toward_the_client() {
    let (mut tls_client, tls_frontend) = tls_session(RUSTLS_TRANSPORT_WINDOW).await;

    let reply = vec![0xa5u8; RUSTLS_PAYLOAD_LEN];
    let (backend, mut backend_peer) = tokio::io::duplex(PEER_BUFFER);
    backend_peer.write_all(&reply).await.expect("reply");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        tls_frontend,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut seen = vec![0u8; RUSTLS_PAYLOAD_LEN];
    tokio::time::timeout(DELIVERY_WINDOW, tls_client.read_exact(&mut seen))
        .await
        .expect("rustls kept the reply's ciphertext; the relay must flush it, not park")
        .expect("TLS client read");
    assert_eq!(seen, reply, "the TLS client must see the reply verbatim");

    drop(tls_client);
    drop(backend_peer);
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish once both legs close")
        .expect("relay task");
    assert_eq!(result.bytes_backend_to_client, RUSTLS_PAYLOAD_LEN as u64);
}

/// A client that sends its payload and half-closes while `tokio-rustls` still
/// holds part of the ciphertext. The half-close has to push that ciphertext
/// out ahead of `close_notify`, so the TLS peer reads the whole payload and
/// then a clean end of stream rather than a truncation — and the relay reports
/// an orderly completion with exact counters.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rustls_half_close_delivers_retained_ciphertext_before_close_notify() {
    let (tls_backend, mut tls_peer) = tls_session(RUSTLS_TRANSPORT_WINDOW).await;

    let payload = vec![0x3cu8; RUSTLS_PAYLOAD_LEN];
    let (client, mut client_peer) = tokio::io::duplex(PEER_BUFFER);
    client_peer.write_all(&payload).await.expect("payload");
    client_peer.shutdown().await.expect("client half-close");

    let relay = tokio::spawn(bidirectional_copy_for_test_with_timeouts(
        client,
        tls_backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        RELAY_BUFFER,
    ));

    let mut received = Vec::new();
    tokio::time::timeout(DELIVERY_WINDOW, tls_peer.read_to_end(&mut received))
        .await
        .expect("the half-close must deliver the retained ciphertext")
        .expect("the TLS peer must end on close_notify, not on a truncated record");
    assert_eq!(
        received, payload,
        "every byte must arrive before close_notify"
    );

    // The peer answers the half-close with its own close_notify, which ends the
    // backend→client half through the Phase 2 drain.
    tls_peer.shutdown().await.expect("TLS peer close_notify");
    let result = tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the relay must finish after both half-closes")
        .expect("relay task");
    assert!(
        result.first_failure.is_none(),
        "an orderly TLS half-close must report no failure, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, RUSTLS_PAYLOAD_LEN as u64);
    assert_eq!(result.bytes_backend_to_client, 0);
    drop(client_peer);
}

// ---------------------------------------------------------------------------
// Writes that run before the relay starts
// ---------------------------------------------------------------------------
//
// The relay owes a flush only for bytes it handed to a writer itself, so a
// write that runs just before it starts has to flush on its own. Two do:
// the TCP+TLS inspected-prefix forward, and the WebSocket tunnel-mode forward
// of backend bytes recovered at the frame-codec boundary. The third, the
// outbound PROXY v2 header, goes to a raw `TcpStream` and already flushes.
// `shared_invariant_parity_tests.rs`
// (`every_pre_relay_write_flushes_before_the_relay_starts`) pins that the
// production paths use these helpers.

/// The decrypted opening bytes first-bytes inspection consumed are the
/// client's request. Written into a TLS backend leg whose transport is
/// backpressured, they must still leave the rustls writer before the forward
/// returns — otherwise the relay starts owing nothing, parks on a client that
/// is waiting for the answer, and the backend never sees the request.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_inspected_prefix_is_flushed_through_rustls_before_the_relay_starts() {
    let (mut tls_backend, mut tls_peer) = tls_session(RUSTLS_TRANSPORT_WINDOW).await;
    let prefix = vec![0x47u8; RUSTLS_PAYLOAD_LEN];

    let forward = tokio::spawn(async move {
        let outcome =
            tcp_forward_prefix_under_trust_fence_for_test(&mut tls_backend, &prefix, None).await;
        // Hand the writer back so it is not dropped before the peer has read.
        (outcome.is_ok(), tls_backend)
    });

    let mut seen = vec![0u8; RUSTLS_PAYLOAD_LEN];
    tokio::time::timeout(DELIVERY_WINDOW, tls_peer.read_exact(&mut seen))
        .await
        .expect("the forwarded prefix must not stay in the rustls writer")
        .expect("TLS peer read");
    assert_eq!(seen, vec![0x47u8; RUSTLS_PAYLOAD_LEN]);

    let (forwarded, _tls_backend) = tokio::time::timeout(DELIVERY_WINDOW, forward)
        .await
        .expect("the prefix forward must complete once the peer drains it")
        .expect("forward task");
    assert!(forwarded, "a live, unfenced backend forwards its prefix");
}

/// WebSocket tunnel mode forwards the backend bytes that arrived with the
/// `101` — a server-first message — to the client before the raw relay starts.
/// Written into the WSS frontend's rustls writer under backpressure, they must
/// still reach the client: the relay starts owing nothing, and the client and
/// backend may each be waiting for the other.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn ws_tunnel_residual_bytes_are_flushed_through_rustls_before_the_relay_starts() {
    let (mut tls_client, mut tls_frontend) = tls_session(RUSTLS_TRANSPORT_WINDOW).await;
    let residual = vec![0x81u8; RUSTLS_PAYLOAD_LEN];

    let forward = tokio::spawn(async move {
        let mut offset = 0usize;
        let outcome =
            forward_ws_tunnel_residual_for_test(&mut tls_frontend, &residual, &mut offset).await;
        // Hand the writer back so it is not dropped before the client has read.
        (outcome, offset, tls_frontend)
    });

    let mut seen = vec![0u8; RUSTLS_PAYLOAD_LEN];
    tokio::time::timeout(DELIVERY_WINDOW, tls_client.read_exact(&mut seen))
        .await
        .expect("the recovered backend bytes must not stay in the rustls writer")
        .expect("TLS client read");
    assert_eq!(seen, vec![0x81u8; RUSTLS_PAYLOAD_LEN]);

    let (outcome, offset, _tls_frontend) = tokio::time::timeout(DELIVERY_WINDOW, forward)
        .await
        .expect("the residual forward must complete once the client drains it")
        .expect("forward task");
    outcome.expect("residual forward");
    assert_eq!(
        offset, RUSTLS_PAYLOAD_LEN,
        "every residual byte the writer accepted is reported"
    );
}

/// No residual, no write and no flush: a tunnel whose backend sent nothing
/// with its `101` keeps its previous behaviour exactly.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_ws_tunnel_residual_writes_and_flushes_nothing() {
    let flushes = Arc::new(AtomicUsize::new(0));
    let (buffered, _client_peer) = buffered_leg(PEER_BUFFER);
    let mut client = FlushCounting::new(buffered, Arc::clone(&flushes));

    let mut offset = 0usize;
    forward_ws_tunnel_residual_for_test(&mut client, &[], &mut offset)
        .await
        .expect("an empty residual forward");

    assert_eq!(offset, 0);
    assert_eq!(
        flushes.load(Ordering::SeqCst),
        0,
        "an empty residual must not add a flush"
    );
}

/// A transport whose reads hand out scripted chunks back to back (each one
/// immediately ready), then EOF, and whose writes accept everything while
/// recording each write's size.
struct ScriptedChunks {
    chunks: std::collections::VecDeque<Vec<u8>>,
    writes: Arc<Mutex<Vec<usize>>>,
}

impl AsyncRead for ScriptedChunks {
    fn poll_read(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if let Some(mut chunk) = self.chunks.pop_front() {
            let n = chunk.len().min(buf.remaining());
            buf.put_slice(&chunk[..n]);
            if n < chunk.len() {
                self.chunks.push_front(chunk.split_off(n));
            }
        }
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for ScriptedChunks {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        self.writes.lock().unwrap().push(buf.len());
        Poll::Ready(Ok(buf.len()))
    }
    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

/// Relay `client_reads` (each chunk immediately ready, then EOF) to a backend
/// through a relay with a `buf_size` buffer, and return the size of every
/// write the backend saw. The relay must end cleanly with every byte counted.
async fn relay_backend_write_sizes(buf_size: usize, client_reads: Vec<usize>) -> Vec<usize> {
    let total: usize = client_reads.iter().sum();
    let backend_writes = Arc::new(Mutex::new(Vec::new()));
    let client = ScriptedChunks {
        chunks: client_reads
            .into_iter()
            .map(|len| vec![b'x'; len])
            .collect(),
        writes: Arc::new(Mutex::new(Vec::new())),
    };
    let backend = ScriptedChunks {
        chunks: Default::default(),
        writes: Arc::clone(&backend_writes),
    };
    // An idle timeout routes through the direction-tracking relay loop (the
    // production path); with every timeout off the relay takes tokio's
    // `copy_bidirectional` fast path instead.
    let result = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        None,
        None,
        None,
        buf_size,
    )
    .await;
    assert!(
        result.first_failure.is_none(),
        "a scripted relay that ends in clean EOF must report no failure, got {:?}",
        result.first_failure
    );
    assert_eq!(result.bytes_client_to_backend, total as u64);
    assert_eq!(result.bytes_backend_to_client, 0);
    backend_writes.lock().unwrap().clone()
}

/// One maximum TLS record's plaintext: the read size that starts a top-up.
const TLS_RECORD: usize = 16 * 1024;

/// Issue #5588: a userspace TLS reader hands the relay one 16 KiB record per
/// read. While more is ready, the relay tops its buffer up and writes the
/// batch once instead of once per record.
#[tokio::test]
async fn full_record_reads_are_batched_into_one_write() {
    let writes = relay_backend_write_sizes(64 * 1024, vec![16 * 1024, 16 * 1024, 5_000]).await;
    assert_eq!(writes, vec![2 * 16 * 1024 + 5_000]);
}

/// A short read ends the batch at once: no speculative extra read.
#[tokio::test]
async fn a_short_read_is_written_without_topping_up() {
    let writes = relay_backend_write_sizes(64 * 1024, vec![1_000, 2_000]).await;
    assert_eq!(writes, vec![1_000, 2_000]);
}

/// One byte under a full record is a short read: it is written on its own.
#[tokio::test]
async fn a_read_one_byte_under_a_full_record_does_not_top_up() {
    let writes = relay_backend_write_sizes(64 * 1024, vec![TLS_RECORD - 1, TLS_RECORD]).await;
    assert_eq!(writes, vec![TLS_RECORD - 1, TLS_RECORD]);
}

/// A batch stops when the buffer is full: the default adaptive 64 KiB buffer
/// takes four records (three extra reads), and the fifth starts a new batch.
#[tokio::test]
async fn a_full_buffer_ends_the_batch() {
    let writes = relay_backend_write_sizes(64 * 1024, vec![TLS_RECORD; 5]).await;
    assert_eq!(writes, vec![65_536, 16_384]);
}

/// The round cap binds only on a buffer larger than 144 KiB: a batch is the
/// first read plus at most `RELAY_TOP_UP_MAX_ROUNDS` (8) extra reads.
#[tokio::test]
async fn the_round_cap_ends_the_batch_on_a_large_buffer() {
    let writes = relay_backend_write_sizes(256 * 1024, vec![TLS_RECORD; 12]).await;
    assert_eq!(writes, vec![147_456, 49_152]);
}

/// One step of a [`ScriptedReader`] read script.
enum ReadStep {
    /// Hand out this many bytes, immediately ready.
    Data(usize),
    /// Fail the read with this error.
    Fail(io::Error),
    /// Stay `Pending` until the gate opens, keeping the waker so that opening
    /// it wakes the relay.
    Wait(Arc<ReadGate>),
}

/// The gate a [`ReadStep::Wait`] parks on.
#[derive(Default)]
struct ReadGate {
    open: AtomicBool,
    waker: Mutex<Option<Waker>>,
}

impl ReadGate {
    fn open(&self) {
        self.open.store(true, Ordering::SeqCst);
        if let Some(waker) = self.waker.lock().unwrap().take() {
            waker.wake();
        }
    }
}

/// A client leg whose reads follow a script of [`ReadStep`]s and then report
/// EOF, counting every `poll_read` so a test can prove the relay stopped
/// asking. Its write half accepts everything; the backend→client direction
/// (whose backend reports EOF at once) only half-closes it.
struct ScriptedReader {
    steps: std::collections::VecDeque<ReadStep>,
    polls: Arc<AtomicUsize>,
    /// Fail every poll after the first EOF (see [`Self::erroring_after_eof`]).
    error_after_eof: bool,
    eof_seen: bool,
}

const POLLED_AFTER_EOF_TEXT: &str = "simulated wrapper error on a poll past EOF";

impl ScriptedReader {
    fn new(steps: Vec<ReadStep>) -> (Self, Arc<AtomicUsize>) {
        Self::build(steps, false)
    }

    /// The same reader, failing every poll after its first EOF with
    /// `ConnectionAborted` — the way `AdmittedStream` or
    /// `AuthorizationDeadlineStream` can answer a poll past EOF.
    fn erroring_after_eof(steps: Vec<ReadStep>) -> (Self, Arc<AtomicUsize>) {
        Self::build(steps, true)
    }

    fn build(steps: Vec<ReadStep>, error_after_eof: bool) -> (Self, Arc<AtomicUsize>) {
        let polls = Arc::new(AtomicUsize::new(0));
        let reader = Self {
            steps: steps.into(),
            polls: Arc::clone(&polls),
            error_after_eof,
            eof_seen: false,
        };
        (reader, polls)
    }
}

impl AsyncRead for ScriptedReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        self.polls.fetch_add(1, Ordering::SeqCst);
        if self.eof_seen && self.error_after_eof {
            let e = io::Error::new(io::ErrorKind::ConnectionAborted, POLLED_AFTER_EOF_TEXT);
            return Poll::Ready(Err(e));
        }
        loop {
            match self.steps.pop_front() {
                None => {
                    self.eof_seen = true;
                    return Poll::Ready(Ok(()));
                }
                Some(ReadStep::Data(len)) => {
                    let n = len.min(buf.remaining());
                    buf.put_slice(&vec![b'x'; n]);
                    if n < len {
                        self.steps.push_front(ReadStep::Data(len - n));
                    }
                    return Poll::Ready(Ok(()));
                }
                Some(ReadStep::Fail(e)) => return Poll::Ready(Err(e)),
                Some(ReadStep::Wait(gate)) => {
                    let mut waker = gate.waker.lock().unwrap();
                    if gate.open.load(Ordering::SeqCst) {
                        continue;
                    }
                    *waker = Some(cx.waker().clone());
                    drop(waker);
                    self.steps.push_front(ReadStep::Wait(gate));
                    return Poll::Pending;
                }
            }
        }
    }
}

impl AsyncWrite for ScriptedReader {
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

const CLIENT_READ_FAILURE_TEXT: &str = "simulated client reset mid-batch";
const BACKEND_WRITE_FAILURE_TEXT: &str = "simulated backend abort on write";

/// What a [`RecordingBackend`] saw.
#[derive(Clone, Default)]
struct BackendLog {
    writes: Arc<Mutex<Vec<usize>>>,
    written: Arc<AtomicUsize>,
    shut_down: Arc<AtomicBool>,
}

/// A backend leg that records each write's size and its half-close, and
/// reports EOF on read. With `fail_writes` set, every write fails instead.
struct RecordingBackend {
    log: BackendLog,
    fail_writes: Option<io::ErrorKind>,
}

impl RecordingBackend {
    fn new(fail_writes: Option<io::ErrorKind>) -> (Self, BackendLog) {
        let log = BackendLog::default();
        let backend = Self {
            log: log.clone(),
            fail_writes,
        };
        (backend, log)
    }
}

impl AsyncRead for RecordingBackend {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

impl AsyncWrite for RecordingBackend {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(kind) = self.fail_writes {
            return Poll::Ready(Err(io::Error::new(kind, BACKEND_WRITE_FAILURE_TEXT)));
        }
        self.log.writes.lock().unwrap().push(buf.len());
        self.log.written.fetch_add(buf.len(), Ordering::SeqCst);
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.log.shut_down.store(true, Ordering::SeqCst);
        Poll::Ready(Ok(()))
    }
}

/// Run the direction-tracking relay (an idle timeout keeps it off tokio's
/// `copy_bidirectional` fast path) with the default adaptive 64 KiB buffer.
async fn run_relay(client: ScriptedReader, backend: RecordingBackend) -> StreamCopyResult {
    let relay = bidirectional_copy_for_test_with_timeouts(
        client,
        backend,
        RELAY_IDLE_TIMEOUT,
        RELAY_HALF_CLOSE_CAP,
        None,
        None,
        64 * 1024,
    );
    tokio::time::timeout(DELIVERY_WINDOW, relay)
        .await
        .expect("the scripted relay must finish on its own")
}

/// A top-up read that returns `Pending` ends the batch without holding it: the
/// record already read is written at once, not kept until more arrives.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_pending_mid_top_up_still_writes_the_batch() {
    let gate = Arc::new(ReadGate::default());
    let (client, _polls) = ScriptedReader::new(vec![
        ReadStep::Data(TLS_RECORD),
        ReadStep::Wait(Arc::clone(&gate)),
        ReadStep::Data(1_000),
    ]);
    let (backend, log) = RecordingBackend::new(None);
    let relay = tokio::spawn(run_relay(client, backend));

    // More data arrives only once the first record reached the backend, so it
    // cannot be what completed that write.
    wait_until_at_least(&log.written, TLS_RECORD, "backend bytes").await;
    gate.open();

    let result = relay.await.expect("relay task");
    assert!(
        result.first_failure.is_none(),
        "a batch cut short by `Pending` is not a failure, got {:?}",
        result.first_failure
    );
    assert_eq!(*log.writes.lock().unwrap(), vec![TLS_RECORD, 1_000]);
    assert_eq!(result.bytes_client_to_backend, (TLS_RECORD + 1_000) as u64);
    assert!(
        log.shut_down.load(Ordering::SeqCst),
        "the backend must be half-closed"
    );
}

/// A read error met while topping up waits until the batch is written, then
/// ends the direction as a read-side failure — once, from the relay's own
/// state rather than by asking the reader again.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_read_error_mid_top_up_is_reported_after_the_batch() {
    let reset = io::Error::new(io::ErrorKind::ConnectionReset, CLIENT_READ_FAILURE_TEXT);
    let script = vec![ReadStep::Data(TLS_RECORD), ReadStep::Fail(reset)];
    let (client, polls) = ScriptedReader::new(script);
    let (backend, log) = RecordingBackend::new(None);
    let result = run_relay(client, backend).await;

    assert_eq!(
        *log.writes.lock().unwrap(),
        vec![TLS_RECORD],
        "the record read before the error must be written first"
    );
    assert_eq!(result.bytes_client_to_backend, TLS_RECORD as u64);
    let (dir, _class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a client read error is a relay failure");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(
        *side,
        Some(StreamIoSide::Read),
        "the error came from the reader"
    );
    assert_eq!(
        msg.matches(CLIENT_READ_FAILURE_TEXT).count(),
        1,
        "the reader's own message must be reported once, got: {msg}"
    );
    assert_eq!(
        polls.load(Ordering::SeqCst),
        2,
        "the deferred error is reported without polling the reader again"
    );
}

/// The deferred error may be userspace rustls' missing-`close_notify` EOF. It
/// takes the same clean half-close a first-read one does: no failure, and the
/// backend is shut down after the batch.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_close_without_notify_mid_top_up_half_closes_cleanly() {
    let close = io::Error::new(
        io::ErrorKind::UnexpectedEof,
        format!("peer closed connection {TLS_CLOSE_WITHOUT_NOTIFY}"),
    );
    let script = vec![ReadStep::Data(TLS_RECORD), ReadStep::Fail(close)];
    let (client, polls) = ScriptedReader::new(script);
    let (backend, log) = RecordingBackend::new(None);
    let result = run_relay(client, backend).await;

    assert!(
        result.first_failure.is_none(),
        "a close without close_notify is clean EOF, got {:?}",
        result.first_failure
    );
    assert_eq!(*log.writes.lock().unwrap(), vec![TLS_RECORD]);
    assert_eq!(result.bytes_client_to_backend, TLS_RECORD as u64);
    assert!(
        log.shut_down.load(Ordering::SeqCst),
        "the backend must be half-closed"
    );
    assert_eq!(polls.load(Ordering::SeqCst), 2);
}

/// EOF met while topping up is remembered: the batch is written, the backend
/// is half-closed, and the reader is never polled past its EOF. Wrappers such
/// as the admission, trust-fence, HBONE tunnel and authorization-deadline
/// streams may answer a second poll with an error, which would turn this clean
/// EOF into a read-side failure — so this reader does exactly that.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn eof_mid_top_up_half_closes_after_the_batch() {
    let (client, polls) = ScriptedReader::erroring_after_eof(vec![ReadStep::Data(TLS_RECORD)]);
    let (backend, log) = RecordingBackend::new(None);
    let result = run_relay(client, backend).await;

    assert!(
        result.first_failure.is_none(),
        "EOF mid-batch is a clean end, not an error from polling past it, got {:?}",
        result.first_failure
    );
    assert_eq!(
        *log.writes.lock().unwrap(),
        vec![TLS_RECORD],
        "one write, then EOF"
    );
    assert_eq!(result.bytes_client_to_backend, TLS_RECORD as u64);
    assert!(
        log.shut_down.load(Ordering::SeqCst),
        "the backend must be half-closed"
    );
    assert_eq!(
        polls.load(Ordering::SeqCst),
        2,
        "the reader must not be polled again after the top-up saw EOF"
    );
}

/// When writing the batch fails, the write error ends the direction and the
/// deferred read error is dropped — the order the relay had before batching,
/// when the failing read was never reached.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_write_failure_after_a_deferred_read_error_reports_the_write() {
    let reset = io::Error::new(io::ErrorKind::ConnectionReset, CLIENT_READ_FAILURE_TEXT);
    let script = vec![ReadStep::Data(TLS_RECORD), ReadStep::Fail(reset)];
    let (client, polls) = ScriptedReader::new(script);
    let (backend, log) = RecordingBackend::new(Some(io::ErrorKind::ConnectionAborted));
    let result = run_relay(client, backend).await;

    let (dir, _class, side, msg) = result
        .first_failure
        .as_ref()
        .expect("a failed backend write is a relay failure");
    assert_eq!(*dir, Direction::ClientToBackend);
    assert_eq!(*side, Some(StreamIoSide::Write));
    assert!(
        msg.contains(BACKEND_WRITE_FAILURE_TEXT),
        "the write error must be the one reported, got: {msg}"
    );
    assert!(
        !msg.contains(CLIENT_READ_FAILURE_TEXT),
        "the deferred read error must not replace the write error, got: {msg}"
    );
    assert!(log.writes.lock().unwrap().is_empty());
    assert_eq!(result.bytes_client_to_backend, 0);
    assert_eq!(polls.load(Ordering::SeqCst), 2);
}
