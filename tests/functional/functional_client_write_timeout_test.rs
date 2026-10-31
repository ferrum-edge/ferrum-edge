//! Functional coverage for the downstream write-stall bound
//! (`FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS`).
//!
//! A client that requests an endless, unauthenticated streaming response and
//! then stops reading its socket used to hold the gateway connection, the
//! response body, and the backend connection behind it indefinitely: the
//! backend-facing `backend_read_timeout_ms` deliberately ignores time spent
//! waiting on the client, and hyper stops polling the body while the client
//! socket is full. These tests drive that exact slow-read shape on HTTP/1.1
//! and HTTP/2 (h2c prior knowledge) and observe, from the BACKEND, whether
//! the gateway ever lets go of the upstream connection.
//!
//! Run with:
//!
//! ```bash
//! cargo build --bin ferrum-edge && \
//!   cargo test --test functional_tests functional_client_write_timeout -- --ignored --nocapture
//! ```

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::task::{Context, Poll};
use std::time::{Duration, Instant};

use bytes::Bytes;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::watch;
use tokio::task::JoinHandle;

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::port_registry::TestSocket;

/// Generous bound for "the gateway released the backend": the stall window
/// (2s) plus the time to fill the loopback socket buffers, with headroom for a
/// loaded CI runner.
const RELEASE_GRACE: Duration = Duration::from_secs(20);

/// How long the disabled control must keep the backend connection alive.
const DISABLED_HOLD: Duration = Duration::from_secs(6);

/// Backend that answers every request with an endless chunked stream and
/// reports, per connection, when its own write first failed (the gateway let
/// go of the upstream connection).
struct EndlessBackend {
    port: u16,
    released: watch::Receiver<Option<Duration>>,
    task: JoinHandle<()>,
}

impl Drop for EndlessBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

async fn spawn_endless_backend() -> EndlessBackend {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind endless backend");
    let port = listener.local_addr().expect("backend addr").port();
    let (tx, rx) = watch::channel(None);
    let tx = Arc::new(tx);
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let tx = Arc::clone(&tx);
            tokio::spawn(async move {
                let elapsed = serve_endless(stream).await;
                if let Some(elapsed) = elapsed {
                    let _ = tx.send(Some(elapsed));
                }
            });
        }
    });
    EndlessBackend {
        port,
        released: rx,
        task,
    }
}

/// Serves one endless chunked response. Returns how long after the response
/// head the gateway closed the connection, or `None` if the request never
/// arrived (a capability probe, for example).
async fn serve_endless(mut stream: TcpStream) -> Option<Duration> {
    let mut head = Vec::with_capacity(1024);
    let mut buf = [0u8; 1024];
    while !head.windows(4).any(|w| w == b"\r\n\r\n") {
        match stream.read(&mut buf).await {
            Ok(0) | Err(_) => return None,
            Ok(n) => head.extend_from_slice(&buf[..n]),
        }
    }
    if !head.starts_with(b"GET /stream/") {
        let _ = stream
            .write_all(b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\n\r\n")
            .await;
        return None;
    }
    let started = Instant::now();
    if stream
        .write_all(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\n\
              Transfer-Encoding: chunked\r\n\r\n",
        )
        .await
        .is_err()
    {
        return Some(started.elapsed());
    }
    let payload = vec![b'x'; 32 * 1024];
    let mut chunk = format!("{:x}\r\n", payload.len()).into_bytes();
    chunk.extend_from_slice(&payload);
    chunk.extend_from_slice(b"\r\n");
    loop {
        if stream.write_all(&chunk).await.is_err() {
            return Some(started.elapsed());
        }
        // Keep producing at a steady rate: a backend that never stalls is what
        // keeps `backend_read_timeout_ms` from ending the exchange.
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn stall_gateway_builder(backend_port: u16, timeout_seconds: &str) -> TestGatewayBuilder {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "client-write-timeout",
            "listen_path": "/stream",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            // The backend never stalls, so the backend-facing bounds stay
            // quiet; the client-side bound is the only thing that can end it.
            "backend_read_timeout_ms": 2000,
            "backend_write_timeout_ms": 2000
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    });
    TestGateway::builder()
        .mode_file(serde_yaml::to_string(&config).expect("serialize config"))
        .log_level("info")
        .capture_output()
        .env("FERRUM_HTTP_CLIENT_WRITE_TIMEOUT_SECONDS", timeout_seconds)
}

async fn spawn_gateway(backend_port: u16, timeout_seconds: &str) -> TestGateway {
    let mut gateway = stall_gateway_builder(backend_port, timeout_seconds)
        .spawn()
        .await
        .expect("start client-write-timeout gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");
    gateway
}

/// Opens an HTTP/1.1 request for the endless stream and never reads a byte.
async fn non_reading_h1_client(proxy_port: u16) -> TcpStream {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to proxy");
    // Best effort: a small receive buffer makes the gateway's write park
    // sooner. The assertions hold either way.
    let _ = socket2::SockRef::from(&stream).set_recv_buffer_size(8 * 1024);
    let mut stream = stream;
    stream
        .write_all(b"GET /stream/events HTTP/1.1\r\nHost: example.com\r\n\r\n")
        .await
        .expect("write request");
    stream
}

async fn wait_for_release(backend: &mut EndlessBackend, within: Duration) -> Option<Duration> {
    let waited = tokio::time::timeout(within, async {
        loop {
            if let Some(elapsed) = *backend.released.borrow_and_update() {
                return elapsed;
            }
            if backend.released.changed().await.is_err() {
                std::future::pending::<()>().await;
            }
        }
    })
    .await;
    waited.ok()
}

async fn assert_stall_logged(gateway: &TestGateway) {
    let output = gateway
        .wait_for_captured_output(
            |out| out.contains("client_write_stall"),
            Duration::from_secs(5),
        )
        .await
        .unwrap_or_default();
    assert!(
        output.contains("client_write_stall"),
        "the stall close must be logged with error_kind=client_write_stall; logs:\n{}",
        gateway.read_combined_captured_output().unwrap_or_default()
    );
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_client_write_timeout_releases_backend_of_non_reading_h1_client() {
    let mut backend = spawn_endless_backend().await;
    let mut gateway = spawn_gateway(backend.port, "2").await;

    let _client = non_reading_h1_client(gateway.proxy_port).await;

    let released = wait_for_release(&mut backend, RELEASE_GRACE).await;
    let logs = gateway.read_combined_captured_output().unwrap_or_default();
    let released = released.unwrap_or_else(|| {
        panic!(
            "a client that never reads held the backend connection for {RELEASE_GRACE:?}; \
             logs:\n{logs}"
        )
    });
    assert!(
        released >= Duration::from_secs(2),
        "the bound fired before a whole stall window: {released:?}"
    );

    assert_stall_logged(&gateway).await;

    gateway.shutdown();
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_client_write_timeout_zero_keeps_non_reading_h1_client() {
    let mut backend = spawn_endless_backend().await;
    let mut gateway = spawn_gateway(backend.port, "0").await;

    let _client = non_reading_h1_client(gateway.proxy_port).await;

    assert!(
        wait_for_release(&mut backend, DISABLED_HOLD)
            .await
            .is_none(),
        "with the bound disabled the stalled exchange must stay open"
    );

    gateway.shutdown();
}

/// Client transport that stops reading once `stop` is set, while still
/// accepting writes. This is an HTTP/2 client whose application stopped
/// draining its socket.
struct StopReading<T> {
    inner: T,
    stop: Arc<AtomicBool>,
}

impl<T: AsyncRead + Unpin> AsyncRead for StopReading<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        if self.stop.load(Ordering::SeqCst) {
            // Never wake: this client is gone from the reader's point of view.
            return Poll::Pending;
        }
        Pin::new(&mut self.get_mut().inner).poll_read(cx, buf)
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for StopReading<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().inner).poll_write(cx, buf)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().inner).poll_shutdown(cx)
    }
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn functional_client_write_timeout_releases_backend_of_non_reading_h2_client() {
    let mut backend = spawn_endless_backend().await;
    let mut gateway = spawn_gateway(backend.port, "2").await;

    let tcp = TcpStream::connect(("127.0.0.1", gateway.proxy_port))
        .await
        .expect("connect to proxy");
    let _ = socket2::SockRef::from(&tcp).set_recv_buffer_size(8 * 1024);
    let stop = Arc::new(AtomicBool::new(false));
    let io = StopReading {
        inner: tcp,
        stop: Arc::clone(&stop),
    };
    // Large windows so HTTP/2 flow control never parks the gateway first: the
    // only thing that stops the response is the client's socket.
    let (send_request, connection) = h2::client::Builder::new()
        .initial_window_size(64 * 1024 * 1024)
        .initial_connection_window_size(64 * 1024 * 1024)
        .handshake::<_, Bytes>(io)
        .await
        .expect("h2c handshake with the gateway");
    let driver = tokio::spawn(async move {
        let _ = connection.await;
    });

    let request = http::Request::builder()
        .method("GET")
        .uri(format!(
            "http://127.0.0.1:{}/stream/events",
            gateway.proxy_port
        ))
        .body(())
        .expect("build h2 request");
    let mut send_request = send_request.ready().await.expect("h2 stream slot");
    let (response, _send_body) = send_request
        .send_request(request, true)
        .expect("send h2 request");
    let response = tokio::time::timeout(Duration::from_secs(10), response)
        .await
        .expect("response head")
        .expect("response head");
    assert_eq!(response.status().as_u16(), 200);
    // Keep the body (dropping it would reset the stream) and stop reading.
    let _body = response.into_body();
    stop.store(true, Ordering::SeqCst);

    let released = wait_for_release(&mut backend, RELEASE_GRACE).await;
    let logs = gateway.read_combined_captured_output().unwrap_or_default();
    assert!(
        released.is_some(),
        "an HTTP/2 client that stopped reading its socket held the backend connection for \
         {RELEASE_GRACE:?}; logs:\n{logs}"
    );
    assert_stall_logged(&gateway).await;

    driver.abort();
    gateway.shutdown();
}
