//! Functional tests for route-level WebSocket Origin admission.
//!
//! `allowed_ws_origins` is a protocol gate, not a plugin setting. These tests
//! exercise real H1 Upgrade, H2 Extended CONNECT, and H3 Extended CONNECT
//! requests to ensure disallowed origins are rejected before backend dispatch.

use crate::common::TestGateway;
use crate::scaffolding::{Http3Client, WebSocketOptions};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{HeaderMap, StatusCode};
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;

const ALLOWED_ORIGIN: &str = "https://allowed.example";
const DENIED_ORIGIN: &str = "https://evil.example";

async fn start_counting_ws_backend(listener: TcpListener, handshakes: Arc<AtomicUsize>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let handshakes = Arc::clone(&handshakes);
        tokio::spawn(async move {
            let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws_stream) => ws_stream,
                Err(_) => return,
            };
            handshakes.fetch_add(1, Ordering::SeqCst);

            let (mut sink, mut source) = ws_stream.split();
            while let Some(Ok(msg)) = source.next().await {
                match msg {
                    Message::Text(text) => {
                        let _ = sink
                            .send(Message::Text(format!("Echo: {text}").into()))
                            .await;
                    }
                    Message::Binary(data) => {
                        let _ = sink
                            .send(Message::Text(
                                format!("Echo binary: {} bytes", data.len()).into(),
                            ))
                            .await;
                    }
                    Message::Ping(data) => {
                        let _ = sink.send(Message::Pong(data)).await;
                    }
                    Message::Close(_) => break,
                    _ => {}
                }
            }
        });
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"version: "1"
proxies:
  - id: "ws-origin"
    listen_path: "/ws-origin"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: false
    allowed_ws_origins:
      - "{ALLOWED_ORIGIN}"
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
    )
}

struct CountingWsBackend {
    port: u16,
    handshakes: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl CountingWsBackend {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ws backend");
        let port = listener.local_addr().expect("backend addr").port();
        let handshakes = Arc::new(AtomicUsize::new(0));
        let task = tokio::spawn(start_counting_ws_backend(listener, Arc::clone(&handshakes)));
        sleep(Duration::from_millis(100)).await;

        Self {
            port,
            handshakes,
            task,
        }
    }

    fn handshakes(&self) -> usize {
        self.handshakes.load(Ordering::SeqCst)
    }
}

impl Drop for CountingWsBackend {
    fn drop(&mut self) {
        self.task.abort();
    }
}

struct WsOriginHarness {
    gateway: TestGateway,
    backend: CountingWsBackend,
}

impl WsOriginHarness {
    async fn new() -> Self {
        let backend = CountingWsBackend::start().await;
        let gateway = TestGateway::builder()
            .mode_file(build_config(backend.port))
            .log_level("warn")
            .spawn()
            .await
            .expect("start gateway");
        gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .expect("proxy port ready");

        Self { gateway, backend }
    }

    fn ws_url(&self) -> String {
        format!("ws://127.0.0.1:{}/ws-origin", self.gateway.proxy_port)
    }

    fn handshakes(&self) -> usize {
        self.backend.handshakes()
    }
}

fn request_with_origin(url: &str, origin: Option<&str>) -> http::Request<()> {
    let mut request = url.into_client_request().expect("valid websocket request");
    if let Some(origin) = origin {
        request
            .headers_mut()
            .insert(http::header::ORIGIN, origin.parse().expect("origin header"));
    }
    request
}

async fn assert_h1_ws_rejected(url: &str, origin: Option<&str>) {
    let err = match tokio_tungstenite::connect_async(request_with_origin(url, origin)).await {
        Ok(_) => panic!("WebSocket handshake should have been rejected"),
        Err(err) => err,
    };

    match err {
        WsError::Http(response) => {
            assert_eq!(response.status(), StatusCode::FORBIDDEN);
        }
        other => panic!("expected HTTP 403 handshake rejection, got {other:?}"),
    }
}

async fn send_h2_extended_connect(proxy_port: u16, origin: &str) -> (http::response::Parts, Bytes) {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h2 gateway");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);

    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let mut request = Request::builder()
        .method(http::Method::CONNECT)
        .version(http::Version::HTTP_2)
        .uri(format!("http://127.0.0.1:{proxy_port}/ws-origin"))
        .header(http::header::ORIGIN, origin)
        .header("sec-websocket-version", "13")
        .body(Full::new(Bytes::new()))
        .expect("build H2 extended CONNECT");
    request
        .extensions_mut()
        .insert(hyper::ext::Protocol::from_static("websocket"));

    let response = sender
        .send_request(request)
        .await
        .expect("send H2 extended CONNECT");
    let (parts, body) = response.into_parts();
    let bytes = body.collect().await.expect("collect h2 body").to_bytes();

    drop(sender);
    conn_task.abort();
    (parts, bytes)
}

fn h3_options(origin: &str) -> WebSocketOptions {
    WebSocketOptions {
        headers: vec![(
            http::header::ORIGIN.as_str().to_string(),
            origin.to_string(),
        )],
        ..WebSocketOptions::default()
    }
}

fn assert_forbidden_body(body: &str) {
    assert!(
        body.contains("WebSocket Origin not allowed"),
        "unexpected forbidden body: {body}"
    );
}

fn assert_forbidden_headers(headers: &HeaderMap) {
    assert!(
        headers.get(http::header::UPGRADE).is_none(),
        "403 rejection must not include Upgrade"
    );
    assert!(
        headers.get("sec-websocket-accept").is_none(),
        "403 rejection must not include Sec-WebSocket-Accept"
    );
}

#[ignore]
#[tokio::test]
async fn functional_ws_origin_http1_enforces_allowlist_before_backend() {
    let h = WsOriginHarness::new().await;
    let url = h.ws_url();

    let (mut ws, response) =
        tokio_tungstenite::connect_async(request_with_origin(&url, Some(ALLOWED_ORIGIN)))
            .await
            .expect("allowed H1 WebSocket");
    assert_eq!(response.status(), StatusCode::SWITCHING_PROTOCOLS);
    ws.send(Message::Text("allowed".into()))
        .await
        .expect("send text");
    assert_eq!(
        ws.next().await.expect("reply").expect("reply ok"),
        Message::Text("Echo: allowed".into())
    );
    ws.send(Message::Close(None)).await.expect("close");
    assert_eq!(h.handshakes(), 1, "allowed H1 handshake reaches backend");

    assert_h1_ws_rejected(&url, Some(DENIED_ORIGIN)).await;
    assert_eq!(h.handshakes(), 1, "denied H1 origin must not reach backend");

    assert_h1_ws_rejected(&url, None).await;
    assert_eq!(
        h.handshakes(),
        1,
        "missing H1 origin must not reach backend when allowlist is non-empty"
    );
}

#[ignore]
#[tokio::test]
async fn functional_ws_origin_h2_extended_connect_rejects_before_backend() {
    let h = WsOriginHarness::new().await;

    let (parts, body) = send_h2_extended_connect(h.gateway.proxy_port, DENIED_ORIGIN).await;
    assert_eq!(parts.status, StatusCode::FORBIDDEN);
    assert_forbidden_headers(&parts.headers);
    assert_forbidden_body(&String::from_utf8_lossy(&body));
    assert_eq!(
        h.handshakes(),
        0,
        "denied H2 Extended CONNECT origin must not reach backend"
    );
}

#[ignore]
#[tokio::test]
async fn functional_ws_origin_http3_enforces_allowlist_before_backend() {
    let backend = CountingWsBackend::start().await;
    let https_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("reserve https port");
    let https_port = https_listener.local_addr().expect("https addr").port();
    drop(https_listener);

    let _gateway = TestGateway::builder()
        .mode_file(build_config(backend.port))
        .log_level("warn")
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start h3 gateway");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/ws-origin");
    let deadline = Instant::now() + Duration::from_secs(10);

    let mut allowed = loop {
        match client.websocket(&url, h3_options(ALLOWED_ORIGIN)).await {
            Ok(ws) => break ws,
            Err(err) if Instant::now() < deadline => {
                let _ = err;
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => panic!("H3 allowed WebSocket did not connect: {err}"),
        }
    };
    assert_eq!(allowed.status, StatusCode::OK);
    allowed.send_text("h3 allowed").await.expect("send text");
    assert_eq!(allowed.recv_text().await.expect("echo"), "Echo: h3 allowed");
    allowed.send_close().await.expect("close");
    assert_eq!(backend.handshakes(), 1, "allowed H3 WS reaches backend");

    let mut denied = client
        .websocket(&url, h3_options(DENIED_ORIGIN))
        .await
        .expect("H3 denied response");
    assert_eq!(denied.status, StatusCode::FORBIDDEN);
    assert_forbidden_headers(&denied.headers);
    let denied_body = denied.recv_body_text().await.expect("denied body");
    assert_forbidden_body(&denied_body);
    assert_eq!(
        backend.handshakes(),
        1,
        "denied H3 origin must not reach backend"
    );
}
