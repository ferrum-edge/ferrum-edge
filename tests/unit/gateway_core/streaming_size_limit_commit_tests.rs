//! Committed streaming responses that overrun the response size limit.
//!
//! An unknown-length backend body under `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`
//! streams through the size-limited adapter chain after its status and headers
//! are committed. When the whole over-limit body is ready at once (a small
//! backend response read in one segment), the limit trips in the same hyper
//! write pass that queued the response head. The client must still see the
//! committed status and the bytes accepted within the limit, then a truncated
//! body — never a connection close before any status line.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll, Wake, Waker};
use std::time::Duration;

use bytes::Bytes;
use http_body::Body;
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper::{Request, Response};
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use ferrum_edge::_test_support::size_limited_streaming_body_from_ready_chunks;
use ferrum_edge::proxy::body::ProxyBody;

const LIMIT: usize = 8;

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

#[test]
fn over_limit_error_yields_once_after_the_accepted_bytes() {
    let mut body = over_limit_body();
    let wakes = Arc::new(WakeCounter::default());
    let waker = Waker::from(Arc::clone(&wakes));
    let mut cx = Context::from_waker(&waker);

    let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut body).poll_frame(&mut cx) else {
        panic!("expected the accepted bytes before the limit error");
    };
    assert_eq!(
        frame.data_ref().map(|data| &data[..]),
        Some(&b"abcdefgh"[..])
    );

    // The limit has tripped, but the frontend still holds the committed head
    // and the accepted bytes. The error waits one scheduler turn so they flush.
    assert!(
        Pin::new(&mut body).poll_frame(&mut cx).is_pending(),
        "the over-limit error must not reach the frontend in the pass that took the data"
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
        panic!("expected the size-limit error after the yield");
    };
    let message = error.to_string();
    assert!(
        message.contains("response body exceeds maximum size"),
        "unexpected error: {message}"
    );
}

#[tokio::test]
async fn http1_client_sees_the_committed_status_before_the_over_limit_abort() {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind frontend");
    let addr = listener.local_addr().expect("frontend addr");
    let server = tokio::spawn(async move {
        let (stream, _) = listener.accept().await.expect("accept");
        let service = service_fn(|_req: Request<Incoming>| async {
            Ok::<_, std::convert::Infallible>(Response::new(over_limit_body()))
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
    let response = String::from_utf8_lossy(&raw);

    assert!(
        response.starts_with("HTTP/1.1 200 OK\r\n"),
        "the committed status must reach the client: {response:?}"
    );
    assert!(
        response.contains("\r\n8\r\nabcdefgh\r\n"),
        "the chunk accepted within the limit must reach the client: {response:?}"
    );
    assert!(
        !response.contains("ijklmnop"),
        "no byte past the limit may reach the client: {response:?}"
    );
    assert!(
        !response.ends_with("0\r\n\r\n"),
        "an over-limit body must not end with a clean last-chunk: {response:?}"
    );
    server.await.expect("frontend task");
}
