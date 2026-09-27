//! Functional tests for `websocket_permessage_deflate` (issue #5769).
//!
//! The backend is a raw RFC 6455 server that negotiates RFC 7692
//! `permessage-deflate` whenever it is offered, then sends an RSV1-flagged
//! compressed message and echoes client frames byte-for-byte (RSV1 included).
//! Clients speak raw frame bytes on HTTP/1.1 Upgrade, HTTP/2 Extended CONNECT,
//! and HTTP/3 Extended CONNECT, so the assertions see the reserved bits the
//! gateway's frame parser would otherwise reject:
//!
//! - a `strip` (default) proxy never forwards the offer, answers without an
//!   extension, and relays plain frames;
//! - a `passthrough` proxy forwards only the `permessage-deflate` offer
//!   element, returns only the backend's `permessage-deflate` answer element,
//!   and relays compressed frames unchanged in both directions;
//! - file-mode startup refuses `passthrough` next to a frame-parsing plugin.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::{Http3Client, WebSocketOptions};

use bytes::Bytes;
use http_body_util::Empty;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::{Duration, Instant};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::mpsc;
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;

const IO_TIMEOUT: Duration = Duration::from_secs(15);
const MAX_HEAD_BYTES: usize = 16 * 1024;

/// The client's offer: one `permessage-deflate` element plus a legacy
/// extension the gateway must drop.
const CLIENT_OFFER: &str = "permessage-deflate; client_max_window_bits, x-webkit-deflate-frame";
/// What a passthrough proxy may forward of [`CLIENT_OFFER`].
const FORWARDED_OFFER: &str = "permessage-deflate; client_max_window_bits";
/// The backend's answer, including a token it was never offered.
const BACKEND_ANSWER: &str = "permessage-deflate; server_no_context_takeover, x-backend-private";
/// What a passthrough proxy may return of [`BACKEND_ANSWER`].
const FORWARDED_ANSWER: &str = "permessage-deflate; server_no_context_takeover";

/// RFC 7692 §7.2.3.1: "Hello" compressed with an empty sliding window.
const DEFLATED_HELLO: [u8; 7] = [0xf2, 0x48, 0xcd, 0xc9, 0xc9, 0x07, 0x00];
const CLIENT_MASK: [u8; 4] = [0x37, 0xfa, 0x21, 0x3d];

/// Unmasked frame: FIN | RSV1 | Text carrying [`DEFLATED_HELLO`].
fn deflated_server_frame() -> Vec<u8> {
    let mut frame = vec![0xc1, DEFLATED_HELLO.len() as u8];
    frame.extend_from_slice(&DEFLATED_HELLO);
    frame
}

/// Masked client frame: FIN | RSV1 | Text carrying [`DEFLATED_HELLO`].
fn deflated_client_frame() -> Vec<u8> {
    let mut frame = vec![0xc1, 0x80 | DEFLATED_HELLO.len() as u8];
    frame.extend_from_slice(&CLIENT_MASK);
    for (index, byte) in DEFLATED_HELLO.iter().enumerate() {
        frame.push(byte ^ CLIENT_MASK[index % 4]);
    }
    frame
}

/// Unmasked uncompressed frame: FIN | Text "Hello".
fn plain_server_frame() -> Vec<u8> {
    let mut frame = vec![0x81, 5];
    frame.extend_from_slice(b"Hello");
    frame
}

fn header_values<'a>(head: &'a str, name: &str) -> Vec<&'a str> {
    head.split("\r\n")
        .skip(1)
        .filter_map(|line| line.split_once(':'))
        .filter(|(field, _)| field.trim().eq_ignore_ascii_case(name))
        .map(|(_, value)| value.trim())
        .collect()
}

/// Read an HTTP/1.1 head, returning it with any bytes read past its end.
async fn read_head<S: AsyncRead + Unpin>(stream: &mut S) -> std::io::Result<(String, Vec<u8>)> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    loop {
        if let Some(end) = buf.windows(4).position(|window| window == b"\r\n\r\n") {
            let rest = buf.split_off(end + 4);
            return Ok((String::from_utf8_lossy(&buf).into_owned(), rest));
        }
        if buf.len() > MAX_HEAD_BYTES {
            return Err(std::io::Error::other("head too large"));
        }
        let read = stream.read(&mut chunk).await?;
        if read == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        buf.extend_from_slice(&chunk[..read]);
    }
}

/// Read `len` bytes, consuming `pending` (bytes already read past a head) first.
async fn try_read_exact_after<S: AsyncRead + Unpin>(
    stream: &mut S,
    pending: &mut Vec<u8>,
    len: usize,
) -> std::io::Result<Vec<u8>> {
    let take = pending.len().min(len);
    let mut out: Vec<u8> = pending.drain(..take).collect();
    let mut rest = vec![0u8; len - take];
    timeout(IO_TIMEOUT, stream.read_exact(&mut rest))
        .await
        .map_err(|_| std::io::Error::from(std::io::ErrorKind::TimedOut))??;
    out.extend_from_slice(&rest);
    Ok(out)
}

async fn read_exact_after<S: AsyncRead + Unpin>(
    stream: &mut S,
    pending: &mut Vec<u8>,
    len: usize,
) -> Vec<u8> {
    try_read_exact_after(stream, pending, len)
        .await
        .expect("frame bytes arrive in time")
}

/// Echo one client frame back unmasked, preserving its first byte (FIN, RSV
/// bits, opcode). Only short frames are needed here.
async fn echo_one_frame(stream: &mut TcpStream, pending: &mut Vec<u8>) -> Option<()> {
    let header = try_read_exact_after(stream, pending, 2).await.ok()?;
    let len = usize::from(header[1] & 0x7f);
    if len > 125 {
        return None;
    }
    let mask = if header[1] & 0x80 != 0 {
        Some(try_read_exact_after(stream, pending, 4).await.ok()?)
    } else {
        None
    };
    let mut payload = try_read_exact_after(stream, pending, len).await.ok()?;
    if let Some(mask) = mask {
        for (index, byte) in payload.iter_mut().enumerate() {
            *byte ^= mask[index % 4];
        }
    }
    let mut frame = vec![header[0], len as u8];
    frame.extend_from_slice(&payload);
    stream.write_all(&frame).await.ok()
}

async fn serve_backend_connection(
    mut stream: TcpStream,
    offers: mpsc::UnboundedSender<Option<String>>,
) {
    let Ok(Ok((head, mut pending))) = timeout(IO_TIMEOUT, read_head(&mut stream)).await else {
        return;
    };
    // The gateway's capability probe opens with the h2c preface; only real
    // WebSocket upgrades are answered.
    if !head.starts_with("GET ") {
        return;
    }
    let Some(key) = header_values(&head, "sec-websocket-key").first().copied() else {
        return;
    };
    let offer = header_values(&head, "sec-websocket-extensions").join(", ");
    let offered = !offer.is_empty();
    let negotiate = offer.to_ascii_lowercase().contains("permessage-deflate");
    let _ = offers.send(offered.then_some(offer));

    let mut response = format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\
         Sec-WebSocket-Accept: {}\r\n",
        derive_accept_key(key.as_bytes())
    );
    if negotiate {
        response.push_str(&format!("Sec-WebSocket-Extensions: {BACKEND_ANSWER}\r\n"));
    }
    response.push_str("\r\n");
    let first_frame = if negotiate {
        deflated_server_frame()
    } else {
        plain_server_frame()
    };
    if stream.write_all(response.as_bytes()).await.is_err() {
        return;
    }
    if stream.write_all(&first_frame).await.is_err() {
        return;
    }
    while echo_one_frame(&mut stream, &mut pending).await.is_some() {}
}

struct DeflateBackend {
    port: u16,
    offers: mpsc::UnboundedReceiver<Option<String>>,
    task: tokio::task::JoinHandle<()>,
}

impl DeflateBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .expect("bind deflate backend");
        let port = listener.local_addr().expect("backend addr").port();
        let (tx, offers) = mpsc::unbounded_channel();
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                tokio::spawn(serve_backend_connection(stream, tx.clone()));
            }
        });
        Self { port, offers, task }
    }

    /// The `Sec-WebSocket-Extensions` value the next backend handshake saw.
    async fn next_offer(&mut self) -> Option<String> {
        timeout(IO_TIMEOUT, self.offers.recv())
            .await
            .expect("backend handshake observed in time")
            .expect("backend channel open")
    }
}

impl Drop for DeflateBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "ws-deflate-passthrough"
    listen_path: "/deflate"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    websocket_permessage_deflate: passthrough
  - id: "ws-deflate-strip"
    listen_path: "/strip"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false

consumers: []
plugin_configs: []
"#
    )
}

async fn start_gateway(backend_port: u16) -> TestGateway {
    let gateway = TestGateway::builder()
        .mode_file(build_config(backend_port))
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");
    gateway
}

/// Assert the negotiated relay carries compressed frames unchanged both ways.
async fn assert_deflate_relay<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    pending: &mut Vec<u8>,
) {
    let first = read_exact_after(stream, pending, deflated_server_frame().len()).await;
    assert_eq!(
        first,
        deflated_server_frame(),
        "the backend's RSV1 frame must reach the client unchanged"
    );
    stream
        .write_all(&deflated_client_frame())
        .await
        .expect("send compressed client frame");
    let echo = read_exact_after(stream, pending, deflated_server_frame().len()).await;
    assert_eq!(
        echo,
        deflated_server_frame(),
        "the client's RSV1 frame must reach the backend unchanged"
    );
}

async fn h1_upgrade(proxy_port: u16, path: &str) -> (TcpStream, String, Vec<u8>) {
    let mut stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect gateway");
    let request = format!(
        "GET {path} HTTP/1.1\r\nHost: 127.0.0.1:{proxy_port}\r\nUpgrade: websocket\r\n\
         Connection: Upgrade\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
         Sec-WebSocket-Version: 13\r\nSec-WebSocket-Extensions: {CLIENT_OFFER}\r\n\r\n"
    );
    stream
        .write_all(request.as_bytes())
        .await
        .expect("send upgrade");
    let (head, pending) = timeout(IO_TIMEOUT, read_head(&mut stream))
        .await
        .expect("upgrade response in time")
        .expect("read upgrade response");
    (stream, head, pending)
}

async fn h2_extended_connect(
    proxy_port: u16,
    path: &str,
) -> (http::StatusCode, http::HeaderMap, TokioIo<hyper::upgrade::Upgraded>) {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h2 gateway");
    let _ = stream.set_nodelay(true);
    let (mut sender, conn) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("h2 handshake");
    tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = http::Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_2)
        .uri(format!("http://127.0.0.1:{proxy_port}{path}"))
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header(http::header::SEC_WEBSOCKET_EXTENSIONS, CLIENT_OFFER)
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build H2 Extended CONNECT");
    let response = timeout(IO_TIMEOUT, sender.send_request(request))
        .await
        .expect("H2 CONNECT response in time")
        .expect("send H2 CONNECT");
    let status = response.status();
    let headers = response.headers().clone();
    let upgraded = hyper::upgrade::on(response)
        .await
        .expect("H2 Extended CONNECT upgrade");
    (status, headers, TokioIo::new(upgraded))
}

fn extension_answer(headers: &http::HeaderMap) -> Vec<String> {
    headers
        .get_all(http::header::SEC_WEBSOCKET_EXTENSIONS)
        .iter()
        .map(|value| value.to_str().expect("ASCII answer").to_string())
        .collect()
}

#[ignore]
#[tokio::test]
async fn functional_ws_deflate_http1_strip_and_passthrough() {
    let mut backend = DeflateBackend::start().await;
    let gateway = start_gateway(backend.port).await;
    let port = gateway.proxy_port;

    let (mut stream, head, mut pending) = h1_upgrade(port, "/strip").await;
    assert!(head.starts_with("HTTP/1.1 101"), "strip upgrade: {head}");
    assert!(
        header_values(&head, "sec-websocket-extensions").is_empty(),
        "a strip proxy must not answer with an extension: {head}"
    );
    assert_eq!(backend.next_offer().await, None, "strip must drop the offer");
    let first = read_exact_after(&mut stream, &mut pending, plain_server_frame().len()).await;
    assert_eq!(first, plain_server_frame());
    drop(stream);

    let (mut stream, head, mut pending) = h1_upgrade(port, "/deflate").await;
    assert!(head.starts_with("HTTP/1.1 101"), "passthrough upgrade: {head}");
    assert_eq!(
        header_values(&head, "sec-websocket-extensions"),
        vec![FORWARDED_ANSWER]
    );
    assert_eq!(backend.next_offer().await.as_deref(), Some(FORWARDED_OFFER));
    assert_deflate_relay(&mut stream, &mut pending).await;
}

#[ignore]
#[tokio::test]
async fn functional_ws_deflate_h2_extended_connect_strip_and_passthrough() {
    let mut backend = DeflateBackend::start().await;
    let gateway = start_gateway(backend.port).await;
    let port = gateway.proxy_port;

    let (status, headers, mut io) = h2_extended_connect(port, "/strip").await;
    assert_eq!(status, http::StatusCode::OK);
    assert!(extension_answer(&headers).is_empty());
    assert_eq!(backend.next_offer().await, None, "strip must drop the offer");
    let first = read_exact_after(&mut io, &mut Vec::new(), plain_server_frame().len()).await;
    assert_eq!(first, plain_server_frame());
    drop(io);

    let (status, headers, mut io) = h2_extended_connect(port, "/deflate").await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(extension_answer(&headers), vec![FORWARDED_ANSWER]);
    assert_eq!(backend.next_offer().await.as_deref(), Some(FORWARDED_OFFER));
    assert_deflate_relay(&mut io, &mut Vec::new()).await;
}

#[ignore]
#[tokio::test]
async fn functional_ws_deflate_http3_strip_and_passthrough() {
    let mut backend = DeflateBackend::start().await;
    let gateway = TestGateway::builder()
        .mode_file(build_config(backend.port))
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");
    let client = Http3Client::insecure().expect("H3 client");
    let options = WebSocketOptions {
        headers: vec![(
            "sec-websocket-extensions".to_string(),
            CLIENT_OFFER.to_string(),
        )],
        ..WebSocketOptions::default()
    };

    let strip_url = format!("https://localhost:{https_port}/strip");
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut strip = loop {
        match client.websocket(&strip_url, options.clone()).await {
            Ok(ws) => break ws,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("H3 WebSocket did not connect: {err}"),
        }
    };
    assert_eq!(strip.status, http::StatusCode::OK);
    assert!(extension_answer(&strip.headers).is_empty());
    assert_eq!(backend.next_offer().await, None, "strip must drop the offer");
    let first = strip
        .recv_raw_exact(plain_server_frame().len())
        .await
        .expect("strip first frame");
    assert_eq!(first, plain_server_frame());
    drop(strip);

    let deflate_url = format!("https://localhost:{https_port}/deflate");
    let mut deflate = client
        .websocket(&deflate_url, options)
        .await
        .expect("H3 passthrough WebSocket");
    assert_eq!(deflate.status, http::StatusCode::OK);
    assert_eq!(extension_answer(&deflate.headers), vec![FORWARDED_ANSWER]);
    assert_eq!(backend.next_offer().await.as_deref(), Some(FORWARDED_OFFER));
    let first = deflate
        .recv_raw_exact(deflated_server_frame().len())
        .await
        .expect("compressed server frame");
    assert_eq!(
        first,
        deflated_server_frame(),
        "the backend's RSV1 frame must reach the H3 client unchanged"
    );
    deflate
        .send_raw_bytes(deflated_client_frame())
        .await
        .expect("send compressed client frame");
    let echo = deflate
        .recv_raw_exact(deflated_server_frame().len())
        .await
        .expect("compressed echo");
    assert_eq!(
        echo,
        deflated_server_frame(),
        "the H3 client's RSV1 frame must reach the backend unchanged"
    );
}

#[ignore]
#[tokio::test]
async fn functional_ws_deflate_passthrough_refused_with_frame_plugin() {
    let config = r#"version: "1"
proxies:
  - id: "ws-deflate-passthrough"
    listen_path: "/deflate"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 9
    websocket_permessage_deflate: passthrough

consumers: []
plugin_configs:
  - id: "global-ws-rate"
    plugin_name: "ws_rate_limiting"
    config:
      frames_per_second: 100
    scope: global
    enabled: true
"#;
    let failure = TestGateway::builder()
        .mode_file(config)
        .spawn_expect_failure(Duration::from_secs(30))
        .await
        .expect("passthrough next to a frame plugin must refuse startup");
    let output = failure.combined_output();
    assert!(
        output.contains("websocket_permessage_deflate: passthrough"),
        "startup refusal must name the field: {output}"
    );
}
