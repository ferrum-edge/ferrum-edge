//! Functional coverage for WebSocket connection admission.
//!
//! `FERRUM_WEBSOCKET_MAX_CONNECTIONS` is the process-wide budget.
//! `FERRUM_WEBSOCKET_MAX_CONNECTIONS_PER_IP` is the per-source session bound,
//! keyed on the trusted-proxy-resolved client IP.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{Http3Client, WebSocketOptions};

use bytes::Bytes;
use futures_util::{SinkExt, StreamExt};
use http::{Method, StatusCode, Version};
use http_body_util::Empty;
use hyper::client::conn::http2;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::{Duration, Instant};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tokio_tungstenite::tungstenite::protocol::Message;

const SOURCE_A: &str = "198.51.100.1";
const SOURCE_B: &str = "198.51.100.2";

#[ignore]
#[tokio::test]
async fn functional_websocket_connection_limit_rejects_second_h1_upgrade() {
    let (backend_port, backend_task) = spawn_ws_backend().await;
    let mut gateway = ws_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start WebSocket limit gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let url = format!("ws://127.0.0.1:{}/ws", gateway.proxy_port);
    let (mut first, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("first H1 websocket");
    first
        .send(Message::Text("first".into()))
        .await
        .expect("send first websocket message");
    assert_eq!(
        first
            .next()
            .await
            .expect("first websocket reply")
            .expect("reply"),
        Message::Text("Echo: first".into())
    );

    let err = match tokio_tungstenite::connect_async(&url).await {
        Ok(_) => panic!("second H1 websocket should be rejected while the first is open"),
        Err(err) => err,
    };
    match err {
        WsError::Http(response) => {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        other => panic!("expected HTTP 503 handshake rejection, got {other:?}"),
    }

    first.close(None).await.expect("close first websocket");
    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_websocket_connection_limit_rejects_second_h3_connect() {
    let (backend_port, backend_task) = spawn_ws_backend().await;
    let mut gateway = ws_limit_gateway_builder(backend_port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start H3 WebSocket limit gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/ws");
    let mut first = retry_h3_websocket(&client, &url)
        .await
        .expect("first H3 websocket");
    assert_eq!(first.status, StatusCode::OK);
    first.send_text("first").await.expect("send first text");
    assert_eq!(first.recv_text().await.expect("first echo"), "Echo: first");

    let mut second = retry_h3_websocket(&client, &url)
        .await
        .expect("second H3 rejection response");
    assert_eq!(second.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        second
            .recv_body_text()
            .await
            .expect("H3 rejection body")
            .contains("WebSocket connection limit exceeded")
    );

    first.send_close().await.expect("close first H3 websocket");
    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_websocket_per_ip_limit_rejects_same_source_h1() {
    let (backend_port, backend_task) = spawn_ws_backend().await;
    let mut gateway = ws_per_ip_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start per-IP WebSocket gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let url = format!("ws://127.0.0.1:{}/ws", gateway.proxy_port);
    let (mut first, _) = tokio_tungstenite::connect_async(h1_ws_request(&url, SOURCE_A))
        .await
        .expect("first source-A websocket");
    first
        .send(Message::Text("a1".into()))
        .await
        .expect("send source-A message");
    assert_eq!(
        first.next().await.expect("source-A reply").expect("reply"),
        Message::Text("Echo: a1".into())
    );

    let err = match tokio_tungstenite::connect_async(h1_ws_request(&url, SOURCE_A)).await {
        Ok(_) => panic!("second source-A websocket should be rejected"),
        Err(err) => err,
    };
    match err {
        WsError::Http(response) => {
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        }
        other => panic!("expected HTTP 503 handshake rejection, got {other:?}"),
    }

    let (mut other, _) = tokio_tungstenite::connect_async(h1_ws_request(&url, SOURCE_B))
        .await
        .expect("source-B websocket should still be admitted");
    other
        .send(Message::Text("b1".into()))
        .await
        .expect("send source-B message");
    assert_eq!(
        other.next().await.expect("source-B reply").expect("reply"),
        Message::Text("Echo: b1".into())
    );

    first.close(None).await.expect("close source-A websocket");
    other.close(None).await.expect("close source-B websocket");
    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_websocket_per_ip_limit_releases_on_h1_disconnect() {
    let (backend_port, backend_task) = spawn_ws_backend().await;
    let mut gateway = ws_per_ip_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start per-IP WebSocket gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let url = format!("ws://127.0.0.1:{}/ws", gateway.proxy_port);
    let (mut first, _) = tokio_tungstenite::connect_async(h1_ws_request(&url, SOURCE_A))
        .await
        .expect("first source-A websocket");
    first.close(None).await.expect("close source-A websocket");
    drop(first);

    wait_for_h1_reconnect(&url, SOURCE_A).await;

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_websocket_per_ip_limit_rejects_h2_multiplexed() {
    let (backend_port, backend_task) = spawn_ws_backend().await;
    let mut gateway = ws_per_ip_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start per-IP WebSocket gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let port = gateway.proxy_port;
    let (mut sender, conn_task) = h2_handshake(port).await;

    let first_response = sender
        .send_request(h2_ws_request(port, SOURCE_A))
        .await
        .expect("send first H2 CONNECT");
    assert_eq!(first_response.status(), StatusCode::OK);
    let first_upgrade = hyper::upgrade::on(first_response)
        .await
        .expect("first H2 Extended CONNECT upgrade");
    let mut first = tokio_tungstenite::WebSocketStream::from_raw_socket(
        TokioIo::new(first_upgrade),
        tokio_tungstenite::tungstenite::protocol::Role::Client,
        None,
    )
    .await;
    first
        .send(Message::Text("a1".into()))
        .await
        .expect("send first H2 websocket message");
    assert_eq!(
        first.next().await.expect("first H2 reply").expect("reply"),
        Message::Text("Echo: a1".into())
    );

    let second_response = sender
        .send_request(h2_ws_request(port, SOURCE_A))
        .await
        .expect("send second H2 CONNECT on the same connection");
    assert_eq!(second_response.status(), StatusCode::SERVICE_UNAVAILABLE);

    let (mut other_sender, other_conn_task) = h2_handshake(port).await;
    let other_response = other_sender
        .send_request(h2_ws_request(port, SOURCE_B))
        .await
        .expect("send source-B H2 CONNECT");
    assert_eq!(other_response.status(), StatusCode::OK);

    first.close(None).await.expect("close first H2 websocket");
    drop(first);
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;
    let _ = tokio::time::timeout(Duration::from_secs(2), other_conn_task).await;
    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_websocket_per_ip_limit_rejects_h3_multiplexed() {
    let (backend_port, backend_task) = spawn_ws_backend().await;
    let mut gateway = ws_per_ip_gateway_builder(backend_port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env_ephemeral_port("FERRUM_PROXY_HTTPS_PORT")
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start H3 per-IP WebSocket gateway");
    let https_port = gateway
        .env_port("FERRUM_PROXY_HTTPS_PORT")
        .expect("harness-allocated HTTPS port");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/ws");
    let mut conn = retry_h3_connection(&client, &url).await;
    let mut first = conn
        .websocket(&url, xff_options(SOURCE_A))
        .await
        .expect("first H3 websocket on shared connection");
    assert_eq!(first.status, StatusCode::OK);
    first.send_text("a1").await.expect("send first H3 text");
    assert_eq!(first.recv_text().await.expect("first H3 echo"), "Echo: a1");

    let mut second = conn
        .websocket(&url, xff_options(SOURCE_A))
        .await
        .expect("second H3 CONNECT on the same QUIC connection");
    assert_eq!(second.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(
        second
            .recv_body_text()
            .await
            .expect("H3 rejection body")
            .contains("WebSocket connection limit exceeded")
    );

    let mut other_conn = retry_h3_connection(&client, &url).await;
    let mut other = other_conn
        .websocket(&url, xff_options(SOURCE_B))
        .await
        .expect("source-B H3 websocket");
    assert_eq!(other.status, StatusCode::OK);

    first.send_close().await.expect("close first H3 websocket");
    other
        .send_close()
        .await
        .expect("close source-B H3 websocket");
    gateway.shutdown();
    backend_task.abort();
}

fn ws_limit_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(ws_limit_config(backend_port))
        .log_level("warn")
        .env("FERRUM_WEBSOCKET_MAX_CONNECTIONS", "1")
}

fn ws_per_ip_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(ws_limit_config(backend_port))
        .log_level("warn")
        .env("FERRUM_WEBSOCKET_MAX_CONNECTIONS", "20000")
        .env("FERRUM_WEBSOCKET_MAX_CONNECTIONS_PER_IP", "1")
        .env("FERRUM_TRUSTED_PROXIES", "127.0.0.0/8")
}

fn ws_limit_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "ws-limit",
            "listen_path": "/ws",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    });
    serde_yaml::to_string(&config).expect("serialize WebSocket limit config")
}

fn h1_ws_request(url: &str, xff: &str) -> http::Request<()> {
    let mut request = url.into_client_request().expect("valid websocket request");
    request
        .headers_mut()
        .insert("X-Forwarded-For", xff.parse().expect("xff header"));
    request
}

fn xff_options(xff: &str) -> WebSocketOptions {
    WebSocketOptions {
        headers: vec![("x-forwarded-for".into(), xff.into())],
        ..Default::default()
    }
}

fn h2_ws_request(port: u16, xff: &str) -> http::Request<Empty<Bytes>> {
    http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://127.0.0.1:{port}/ws"))
        .version(Version::HTTP_2)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .header("x-forwarded-for", xff)
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build H2 WebSocket CONNECT request")
}

async fn h2_handshake(port: u16) -> (http2::SendRequest<Empty<Bytes>>, JoinHandle<()>) {
    let stream = TcpStream::connect(("127.0.0.1", port))
        .await
        .expect("connect H2 gateway");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (sender, conn) = http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("H2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    (sender, conn_task)
}

async fn wait_for_h1_reconnect(url: &str, xff: &str) {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match tokio_tungstenite::connect_async(h1_ws_request(url, xff)).await {
            Ok((mut ws, _)) => {
                let _ = ws.close(None).await;
                return;
            }
            Err(_) if Instant::now() < deadline => {
                sleep(Duration::from_millis(50)).await;
            }
            Err(err) => {
                panic!("per-source WebSocket slot was not released after disconnect: {err}")
            }
        }
    }
}

async fn spawn_ws_backend() -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind WebSocket backend");
    let port = listener.local_addr().expect("backend addr").port();
    let task = tokio::spawn(run_ws_backend(listener));
    (port, task)
}

#[allow(clippy::collapsible_match)]
async fn run_ws_backend(listener: TcpListener) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(_) => return,
            };
            let (mut sink, mut source) = ws_stream.split();
            while let Some(Ok(msg)) = source.next().await {
                match msg {
                    Message::Text(text) => {
                        let echo = format!("Echo: {text}");
                        if sink.send(Message::Text(echo.into())).await.is_err() {
                            break;
                        }
                    }
                    Message::Binary(data) => {
                        if sink.send(Message::Binary(data)).await.is_err() {
                            break;
                        }
                    }
                    Message::Ping(data) => {
                        if sink.send(Message::Pong(data)).await.is_err() {
                            break;
                        }
                    }
                    Message::Close(close) => {
                        let _ = sink.send(Message::Close(close)).await;
                        break;
                    }
                    _ => {}
                }
            }
        });
    }
}

async fn retry_h3_websocket(
    client: &Http3Client,
    url: &str,
) -> Result<crate::scaffolding::clients::Http3WebSocket, Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = None;
    loop {
        match client.websocket(url, WebSocketOptions::default()).await {
            Ok(ws) => return Ok(ws),
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                return Err(format!(
                    "H3 websocket did not complete; last startup error={last_err:?}; final error={err}"
                )
                .into());
            }
        }
    }
}

async fn retry_h3_connection(
    client: &Http3Client,
    url: &str,
) -> crate::scaffolding::clients::Http3Connection {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = None;
    loop {
        match client.connect(url).await {
            Ok(conn) => return conn,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!(
                    "H3 connection did not complete; last startup error={last_err:?}; final error={err}"
                );
            }
        }
    }
}
