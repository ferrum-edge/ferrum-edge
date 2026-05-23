//! Functional coverage for the global WebSocket connection limit.
//!
//! `FERRUM_WEBSOCKET_MAX_CONNECTIONS` should reject new upgrade attempts while
//! existing upgraded WebSocket tunnels are still open.

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{Http3Client, WebSocketOptions};
use crate::scaffolding::reserve_colocated_tcp_udp;

use futures_util::{SinkExt, StreamExt};
use http::StatusCode;
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::Error as WsError;
use tokio_tungstenite::tungstenite::protocol::Message;

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
    let https_port = reserve_https_port().await;
    let mut gateway = ws_limit_gateway_builder(backend_port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start H3 WebSocket limit gateway");

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

fn ws_limit_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(ws_limit_config(backend_port))
        .log_level("warn")
        .env("FERRUM_WEBSOCKET_MAX_CONNECTIONS", "1")
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

async fn spawn_ws_backend() -> (u16, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
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

async fn reserve_https_port() -> u16 {
    let (tcp, udp) = reserve_colocated_tcp_udp()
        .await
        .expect("reserve colocated https port");
    let port = tcp.port;
    assert_eq!(port, udp.port);
    drop(tcp);
    drop(udp);
    port
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
