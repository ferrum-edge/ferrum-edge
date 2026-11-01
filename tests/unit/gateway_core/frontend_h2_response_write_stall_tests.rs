//! Frontend HTTP/2 response flow-control stall bound (hyper patch 008).
//!
//! An HTTP/2 client can keep its connection alive, reading its socket and
//! answering PINGs, while it never sends `WINDOW_UPDATE`. The gateway's
//! response pipe then parks on send capacity with an idle transport, so the
//! socket-level `ClientWriteStallIo` bound never sees a blocked write, and
//! `backend_read_timeout_ms` never runs because nothing polls the backend
//! body. Before hyper patch 008 that held the response body, and the backend
//! connection behind it, for as long as the client kept the connection.
//!
//! These tests drive the production accept loop over h2c and TLS ALPN `h2`
//! with an h2 client that never releases receive capacity, against a backend
//! that streams forever and reports when the gateway lets go of it.

use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;

use super::frontend_h2_admission_tests::{ProxyHarness, frontend_tls_pair, tls_connect};

const HEADER_READ_TIMEOUT_SECONDS: u64 = 30;
/// The bound under test, `FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS`.
const STALL_SECONDS: u64 = 1;
/// Generous ceiling for the reset and the backend release on a loaded runner.
const RELEASE_GRACE: Duration = Duration::from_secs(15);
/// How long the disabled control must keep the stream open.
const DISABLED_HOLD: Duration = Duration::from_secs(4);

/// HTTP/1.1 backend that answers every request with an endless chunked body
/// and publishes the time from the response head until the gateway closed the
/// connection (its write failed).
async fn start_endless_backend() -> (
    u16,
    watch::Receiver<Option<Duration>>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind endless backend");
    let port = listener.local_addr().expect("backend addr").port();
    let (released_tx, released_rx) = watch::channel(None);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                break;
            };
            let released_tx = released_tx.clone();
            tokio::spawn(async move {
                if let Some(elapsed) = serve_endless(stream).await {
                    let _ = released_tx.send(Some(elapsed));
                }
            });
        }
    });
    (port, released_rx, handle)
}

async fn serve_endless(mut stream: TcpStream) -> Option<Duration> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    let started = Instant::now();
    let response_head = b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\
                          Transfer-Encoding: chunked\r\n\r\n";
    if stream.write_all(response_head).await.is_err() {
        return Some(started.elapsed());
    }
    let payload = vec![b'x'; 16 * 1024];
    let mut chunk = format!("{:x}\r\n", payload.len()).into_bytes();
    chunk.extend_from_slice(&payload);
    chunk.extend_from_slice(b"\r\n");
    loop {
        if stream.write_all(&chunk).await.is_err() {
            return Some(started.elapsed());
        }
        // A steady producer: the backend-facing read timeout must stay quiet.
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// Opens one stream for the endless response with the RFC 9113 default
/// windows. The client keeps reading its socket; it only ever withholds
/// `WINDOW_UPDATE`.
async fn open_stream<S>(io: S, authority: &str) -> (h2::RecvStream, tokio::task::JoinHandle<()>)
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(65_535)
        .initial_connection_window_size(65_535)
        .handshake::<_, Bytes>(io)
        .await
        .expect("HTTP/2 handshake with the frontend");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = http::Request::get(format!("{authority}/slow/stream"))
        .body(())
        .expect("request");
    let mut send_request = send_request.ready().await.expect("stream slot");
    let (response, _) = send_request
        .send_request(request, true)
        .expect("send request");
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("response head in time")
        .expect("response head");
    assert_eq!(response.status(), http::StatusCode::OK);
    (response.into_body(), driver)
}

/// Reads DATA without releasing capacity. Returns the bytes received and the
/// reset that ended the stream, or `None` if it was still open after `within`.
async fn drain_withholding_window(
    body: &mut h2::RecvStream,
    within: Duration,
) -> (usize, Option<h2::Reason>) {
    let mut received = 0;
    let ended = tokio::time::timeout(within, async {
        loop {
            match body.data().await {
                Some(Ok(data)) => received += data.len(),
                Some(Err(err)) => return err.reason(),
                None => return None,
            }
        }
    })
    .await;
    match ended {
        Ok(reason) => (received, Some(reason.unwrap_or(h2::Reason::NO_ERROR))),
        Err(_) => (received, None),
    }
}

async fn wait_for_release(
    released: &mut watch::Receiver<Option<Duration>>,
    within: Duration,
) -> Option<Duration> {
    tokio::time::timeout(within, async {
        loop {
            if let Some(elapsed) = *released.borrow_and_update() {
                return elapsed;
            }
            if released.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    })
    .await
    .ok()
}

async fn assert_stalled_stream_is_reset<S>(
    io: S,
    authority: &str,
    released: &mut watch::Receiver<Option<Duration>>,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    // Taken before the request: the gateway may start timing the stall
    // before `open_stream` returns, so a later start could undercount it.
    let started = Instant::now();
    let (mut body, driver) = open_stream(io, authority).await;
    let (received, reset) = drain_withholding_window(&mut body, RELEASE_GRACE).await;
    assert_eq!(
        reset,
        Some(h2::Reason::CANCEL),
        "a client that never sends WINDOW_UPDATE must have its stream reset \
         (received {received} bytes)"
    );
    assert_eq!(received, 65_535, "the client's whole window is used first");
    assert!(
        started.elapsed() >= Duration::from_secs(STALL_SECONDS),
        "reset before a whole bound: {:?}",
        started.elapsed()
    );
    let released = wait_for_release(released, RELEASE_GRACE).await;
    assert!(
        released.is_some(),
        "the backend connection outlived the stream reset"
    );
    driver.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn h2c_stream_whose_client_never_opens_its_window_is_reset() {
    let (backend_port, mut released, backend) = start_endless_backend().await;
    let harness =
        ProxyHarness::start_with_env(HEADER_READ_TIMEOUT_SECONDS, None, backend_port, |env| {
            env.http_client_write_timeout_seconds = STALL_SECONDS
        })
        .await;

    let stream = harness.connect().await;
    let authority = format!("http://{}", harness.addr);
    assert_stalled_stream_is_reset(stream, &authority, &mut released).await;

    harness.shutdown().await;
    backend.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tls_h2_stream_whose_client_never_opens_its_window_is_reset() {
    let (backend_port, mut released, backend) = start_endless_backend().await;
    let (tls, ca_pem) = frontend_tls_pair();
    let harness = ProxyHarness::start_with_env(
        HEADER_READ_TIMEOUT_SECONDS,
        Some(tls),
        backend_port,
        |env| env.http_client_write_timeout_seconds = STALL_SECONDS,
    )
    .await;

    let stream = tls_connect(harness.addr, &ca_pem, b"h2").await;
    assert_eq!(
        stream.get_ref().1.alpn_protocol(),
        Some(b"h2".as_slice()),
        "frontend HTTPS must negotiate HTTP/2 via ALPN"
    );
    assert_stalled_stream_is_reset(stream, "https://localhost", &mut released).await;

    harness.shutdown().await;
    backend.abort();
}

/// `0` disables the bound: the same stall keeps the stream and the backend.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn zero_bound_keeps_a_stream_whose_client_never_opens_its_window() {
    let (backend_port, mut released, backend) = start_endless_backend().await;
    let harness =
        ProxyHarness::start_with_env(HEADER_READ_TIMEOUT_SECONDS, None, backend_port, |env| {
            env.http_client_write_timeout_seconds = 0
        })
        .await;

    let stream = harness.connect().await;
    let (mut body, driver) = open_stream(stream, &format!("http://{}", harness.addr)).await;
    let (received, reset) = drain_withholding_window(&mut body, DISABLED_HOLD).await;
    assert_eq!(reset, None, "with the bound disabled the stream stays open");
    assert_eq!(received, 65_535);
    assert!(
        wait_for_release(&mut released, Duration::from_millis(100))
            .await
            .is_none(),
        "with the bound disabled the backend connection stays open"
    );

    driver.abort();
    harness.shutdown().await;
    backend.abort();
}

/// The frontend wiring reads hyper-util patch 002's forward, which exists
/// only behind its `ferrum-h2-response-write-timeout` feature; binding the
/// method here makes losing the feature fail the gateway's test build too.
#[test]
fn vendored_hyper_util_forwards_the_response_write_timeout() {
    let mut builder =
        hyper_util::server::conn::auto::Builder::new(hyper_util::rt::TokioExecutor::new());
    builder
        .http2()
        .response_write_timeout(Some(Duration::from_secs(1)));
}
