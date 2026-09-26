//! Committed streaming responses that overrun the response size limit.
//!
//! An unknown-length backend body under `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`
//! streams through the size-limited adapter chain after its status and headers
//! are committed. When the whole over-limit body is ready at once (a small
//! backend response read in one segment), the limit trips in the same hyper
//! write pass that queued the response head. The client must still see the
//! committed status and the bytes accepted within the limit, then a truncated
//! body — never a connection close before any status line.
//!
//! The same contract holds for a backend error that arrives with the first
//! bytes on the unlimited streaming bodies (reqwest, direct HTTP/2 and gRPC,
//! native HTTP/3), and for the size-limit error of the plugin-inspected
//! streaming body.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use bytes::Bytes;
use http_body::Body;
use http_body_util::{BodyExt, Empty};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::{TokioExecutor, TokioIo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ferrum_edge::_test_support::{
    inspected_streaming_body_from_ready_chunks_then_limit_error,
    size_limited_streaming_body_from_ready_chunks,
    unlimited_streaming_body_from_ready_chunks_then_error,
    unlimited_streaming_body_pending_once_then_error,
};
use ferrum_edge::proxy::body::ProxyBody;

const LIMIT: usize = 8;
const BACKEND_RESET: &str = "backend reset";
/// A non-zero idle read timeout, far longer than any test runs.
const IDLE_READ_TIMEOUT_MS: u64 = 30_000;
/// Every unlimited streaming body builder the test seam can name.
const UNLIMITED_ADAPTERS: [&str; 6] = [
    "direct",
    "coalescing",
    "h2_direct",
    "h2_coalescing",
    "h3_direct",
    "h3_coalescing",
];

/// Two ready chunks: the first fits the limit exactly, the second overruns it.
fn over_limit_body() -> ProxyBody {
    size_limited_streaming_body_from_ready_chunks(
        vec![
            Bytes::from_static(b"abcdefgh"),
            Bytes::from_static(b"ijklmnop"),
        ],
        LIMIT,
    )
}

/// One ready chunk followed at once by a backend reset on the unlimited
/// streaming body named by `adapter` (reqwest, direct H2/gRPC, or native H3),
/// with the idle read timeout off.
fn backend_reset_body(adapter: &str) -> ProxyBody {
    let chunks = vec![Bytes::from_static(b"abcdefgh")];
    unlimited_streaming_body_from_ready_chunks_then_error(adapter, chunks, 0)
}

fn direct_backend_reset_body() -> ProxyBody {
    backend_reset_body("direct")
}

fn coalescing_backend_reset_body() -> ProxyBody {
    backend_reset_body("coalescing")
}

fn h2_direct_backend_reset_body() -> ProxyBody {
    backend_reset_body("h2_direct")
}

fn h2_coalescing_backend_reset_body() -> ProxyBody {
    backend_reset_body("h2_coalescing")
}

fn h3_direct_backend_reset_body() -> ProxyBody {
    backend_reset_body("h3_direct")
}

fn h3_coalescing_backend_reset_body() -> ProxyBody {
    backend_reset_body("h3_coalescing")
}

/// The plugin-inspected streaming body after its task queued the released
/// bytes and then the size-limit error.
fn inspected_over_limit_body() -> ProxyBody {
    let chunks = vec![Bytes::from_static(b"abcdefgh")];
    inspected_streaming_body_from_ready_chunks_then_limit_error(chunks)
}

#[derive(Default)]
struct WakeCounter(AtomicUsize);

impl Wake for WakeCounter {
    fn wake(self: Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }

    fn wake_by_ref(self: &Arc<Self>) {
        self.0.fetch_add(1, Ordering::SeqCst);
    }
}

/// Polls `body` to its terminal error: the accepted bytes, then one `Pending`
/// with exactly one self-wake, then an error containing `expected_error`.
/// Returns the error message.
fn assert_error_yields_once_after_the_accepted_bytes(
    mut body: ProxyBody,
    expected_error: &str,
) -> String {
    let wakes = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);

    let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
        panic!("expected the accepted bytes before the terminal error");
    };
    assert_eq!(
        frame.data_ref().map(|data| &data[..]),
        Some(&b"abcdefgh"[..])
    );

    // The body has failed, but the frontend still holds the committed head
    // and the accepted bytes. The error waits one scheduler turn so they flush.
    assert!(
        Pin::new(&mut body).poll_frame(&mut cx).is_pending(),
        "the terminal error must not reach the frontend in the pass that took the data"
    );
    assert_eq!(
        wakes.0.load(Ordering::SeqCst),
        1,
        "the deferred error must wake its own task"
    );
    assert!(
        !body.is_end_stream(),
        "a body holding its terminal error has not ended"
    );

    let Poll::Ready(Some(Err(error))) = Pin::new(&mut body).poll_frame(&mut cx) else {
        panic!("expected the terminal error after the yield");
    };
    let message = error.to_string();
    assert!(
        message.contains(expected_error),
        "unexpected error: {message}"
    );
    message
}

#[test]
fn over_limit_error_yields_once_after_the_accepted_bytes() {
    assert_error_yields_once_after_the_accepted_bytes(
        over_limit_body(),
        "response body exceeds maximum size",
    );
}

#[test]
fn direct_body_backend_reset_yields_once_after_the_accepted_bytes() {
    assert_error_yields_once_after_the_accepted_bytes(direct_backend_reset_body(), BACKEND_RESET);
}

#[test]
fn coalescing_body_backend_reset_yields_once_after_the_accepted_bytes() {
    assert_error_yields_once_after_the_accepted_bytes(
        coalescing_backend_reset_body(),
        BACKEND_RESET,
    );
}

#[test]
fn h2_direct_body_backend_reset_yields_once_after_the_accepted_bytes() {
    assert_error_yields_once_after_the_accepted_bytes(
        h2_direct_backend_reset_body(),
        BACKEND_RESET,
    );
}

#[test]
fn h2_coalescing_body_backend_reset_yields_once_after_the_accepted_bytes() {
    assert_error_yields_once_after_the_accepted_bytes(
        h2_coalescing_backend_reset_body(),
        BACKEND_RESET,
    );
}

#[tokio::test]
async fn h3_direct_body_backend_reset_yields_once_after_the_accepted_bytes() {
    assert_error_yields_once_after_the_accepted_bytes(
        h3_direct_backend_reset_body(),
        BACKEND_RESET,
    );
}

#[tokio::test]
async fn h3_coalescing_body_backend_reset_yields_once_after_the_accepted_bytes() {
    // The H3 coalescer arms its flush timer on the first buffered chunk, so
    // this body needs a runtime.
    assert_error_yields_once_after_the_accepted_bytes(
        h3_coalescing_backend_reset_body(),
        BACKEND_RESET,
    );
}

#[tokio::test]
async fn h2_body_backend_reset_yields_once_under_a_client_grpc_deadline() {
    // The absolute gRPC deadline replaces the idle read timeout. The hold
    // wraps it, so a backend error inside the deadline is still held once.
    for adapter in ["h2_direct_grpc_deadline", "h2_coalescing_grpc_deadline"] {
        let chunks = vec![Bytes::from_static(b"abcdefgh")];
        let body = unlimited_streaming_body_from_ready_chunks_then_error(
            adapter,
            chunks,
            IDLE_READ_TIMEOUT_MS,
        );
        let message = assert_error_yields_once_after_the_accepted_bytes(body, BACKEND_RESET);
        assert!(
            !message.contains("deadline"),
            "{adapter}: the held backend error must not turn into a deadline: {message}"
        );
    }
}

#[tokio::test]
async fn backend_reset_yields_once_through_the_idle_read_timeout() {
    // The hold wraps the idle read timeout, so the backend error passes
    // through the timeout before it is held, and the next poll hands it out.
    for adapter in UNLIMITED_ADAPTERS {
        let chunks = vec![Bytes::from_static(b"abcdefgh")];
        let body = unlimited_streaming_body_from_ready_chunks_then_error(
            adapter,
            chunks,
            IDLE_READ_TIMEOUT_MS,
        );
        let message = assert_error_yields_once_after_the_accepted_bytes(body, BACKEND_RESET);
        assert!(
            !message.contains("read timeout"),
            "{adapter}: the held backend error must not turn into a timeout: {message}"
        );
    }
}

#[tokio::test(start_paused = true)]
async fn held_backend_error_survives_an_idle_deadline_that_expires_on_the_held_turn() {
    // The backend stalls for the whole idle read timeout, then fails. The
    // error reaches the body on the same poll on which the idle deadline has
    // expired. The error was read first, so it must win: the failure is the
    // backend's, not a timeout.
    for adapter in UNLIMITED_ADAPTERS {
        let mut body =
            unlimited_streaming_body_pending_once_then_error(adapter, IDLE_READ_TIMEOUT_MS);
        let wakes = Arc::new(WakeCounter::default());
        let waker = Waker::from(Arc::clone(&wakes));
        let mut cx = Context::from_waker(&waker);

        assert!(
            Pin::new(&mut body).poll_frame(&mut cx).is_pending(),
            "{adapter}: the stalled backend read must be pending"
        );
        tokio::time::advance(Duration::from_millis(IDLE_READ_TIMEOUT_MS + 1)).await;

        assert!(
            Pin::new(&mut body).poll_frame(&mut cx).is_pending(),
            "{adapter}: the backend error must be held for one turn"
        );
        let Poll::Ready(Some(Err(error))) = Pin::new(&mut body).poll_frame(&mut cx) else {
            panic!("{adapter}: expected the held backend error");
        };
        let message = error.to_string();
        assert!(
            message.contains(BACKEND_RESET) && !message.contains("read timeout"),
            "{adapter}: the held backend error must not turn into a timeout: {message}"
        );
    }
}

#[tokio::test]
async fn inspected_body_over_limit_error_yields_once_after_the_released_bytes() {
    assert_error_yields_once_after_the_accepted_bytes(
        inspected_over_limit_body(),
        "response body exceeds maximum size",
    );
}

/// Serves one response whose body is `make_body()` over a real hyper HTTP/1.1
/// connection and returns every byte the raw client read before the close.
async fn serve_once_over_http1(make_body: fn() -> ProxyBody) -> String {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind frontend");
    let addr = listener.local_addr().expect("frontend addr");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let service = service_fn(move |_req: Request<Incoming>| async move {
            Ok::<_, std::convert::Infallible>(Response::new(make_body()))
        });
        // The connection ends with the body error by design.
        let _ = hyper::server::conn::http1::Builder::new()
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let mut client = TcpStream::connect(addr).await.expect("connect");
    client
        .write_all(b"GET / HTTP/1.1\r\nHost: test\r\n\r\n")
        .await
        .expect("write request");
    let mut raw = Vec::new();
    tokio::time::timeout(Duration::from_secs(5), client.read_to_end(&mut raw))
        .await
        .expect("frontend closes the connection")
        .expect("read response");
    server.await.expect("frontend task");
    String::from_utf8_lossy(&raw).into_owned()
}

/// The client saw the committed status and the accepted chunk, then a
/// truncated body.
fn assert_committed_head_then_truncated_body(response: &str) {
    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "the committed status must reach the client: {response:?}"
    );
    assert!(
        response.contains("\r\n8\r\nabcdefgh\r\n"),
        "the accepted chunk must reach the client: {response:?}"
    );
    assert!(
        !response.ends_with("0\r\n\r\n"),
        "a failed body must not end with a clean last-chunk: {response:?}"
    );
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_the_over_limit_abort() {
    let response = serve_once_over_http1(over_limit_body).await;
    assert_committed_head_then_truncated_body(&response);
    assert!(
        !response.contains("ijklmnop"),
        "no byte past the limit may reach the client: {response:?}"
    );
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_a_direct_body_backend_reset() {
    let response = serve_once_over_http1(direct_backend_reset_body).await;
    assert_committed_head_then_truncated_body(&response);
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_a_coalescing_body_backend_reset() {
    let response = serve_once_over_http1(coalescing_backend_reset_body).await;
    assert_committed_head_then_truncated_body(&response);
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_an_h2_direct_body_backend_reset() {
    let response = serve_once_over_http1(h2_direct_backend_reset_body).await;
    assert_committed_head_then_truncated_body(&response);
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_an_h2_coalescing_body_backend_reset() {
    let response = serve_once_over_http1(h2_coalescing_backend_reset_body).await;
    assert_committed_head_then_truncated_body(&response);
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_an_h3_direct_body_backend_reset() {
    let response = serve_once_over_http1(h3_direct_backend_reset_body).await;
    assert_committed_head_then_truncated_body(&response);
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_an_h3_coalescing_body_backend_reset() {
    let response = serve_once_over_http1(h3_coalescing_backend_reset_body).await;
    assert_committed_head_then_truncated_body(&response);
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_the_inspected_body_over_limit_abort() {
    let response = serve_once_over_http1(inspected_over_limit_body).await;
    assert_committed_head_then_truncated_body(&response);
}

/// Serves one response whose body is `make_body()` over a real hyper HTTP/2
/// connection and returns the status the client saw and its body result.
///
/// On the test's current-thread runtime the FIFO run queue polls h2's
/// connection task, woken when the stream queued its HEADERS and DATA, before
/// the stream task that the held error woke. The connection task therefore
/// writes the HEADERS frame before the stream reset, deterministically.
async fn serve_once_over_http2(make_body: fn() -> ProxyBody) -> (u16, Result<Bytes, String>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind frontend");
    let addr = listener.local_addr().expect("frontend addr");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let service = service_fn(move |_req: Request<Incoming>| async move {
            Ok::<_, std::convert::Infallible>(Response::new(make_body()))
        });
        // The stream ends with the body error by design.
        let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service)
            .await;
    });

    let stream = TcpStream::connect(addr).await.expect("connect");
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("h2 handshake");
    let client_conn = tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .uri("http://test/")
        .body(Empty::<Bytes>::new())
        .expect("build request");
    let response = tokio::time::timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .expect("response headers in time")
        .expect("the committed status must reach the client before the stream reset");
    let status = response.status().as_u16();
    let body = tokio::time::timeout(Duration::from_secs(5), response.into_body().collect())
        .await
        .expect("the body ends in time")
        .map(|collected| collected.to_bytes())
        .map_err(|err| err.to_string());

    drop(sender);
    client_conn.abort();
    server.abort();
    (status, body)
}

#[tokio::test(flavor = "current_thread")]
async fn http2_client_sees_the_committed_status_before_the_over_limit_reset() {
    let (status, body) = serve_once_over_http2(over_limit_body).await;
    assert_eq!(status, 200, "the committed status must reach the client");
    assert!(
        body.is_err(),
        "the over-limit body must end with the stream reset: {body:?}"
    );
}

#[tokio::test(flavor = "current_thread")]
async fn http2_client_sees_the_committed_status_before_an_h2_or_h3_backend_reset() {
    let bodies: [(&str, fn() -> ProxyBody); 4] = [
        ("h2_direct", h2_direct_backend_reset_body),
        ("h2_coalescing", h2_coalescing_backend_reset_body),
        ("h3_direct", h3_direct_backend_reset_body),
        ("h3_coalescing", h3_coalescing_backend_reset_body),
    ];
    for (adapter, make_body) in bodies {
        let (status, body) = serve_once_over_http2(make_body).await;
        assert_eq!(status, 200, "{adapter}: committed status lost");
        assert!(
            body.is_err(),
            "{adapter}: the failed body must end with the stream reset: {body:?}"
        );
    }
}
