//! Functional coverage for the global WebSocket frame-size limit.
//!
//! Plugin tests cover `ws_message_size_limiting`; this module exercises the
//! protocol parser limit wired from `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES`.

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::{Http3Client, WebSocketOptions};
use crate::scaffolding::reserve_colocated_tcp_udp;

use futures_util::{SinkExt, StreamExt};
use http::StatusCode;
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::{Duration, Instant};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::protocol::Message;

const MAX_FRAME_BYTES: &str = "16";

#[ignore]
#[tokio::test]
async fn functional_websocket_frame_limit_h1_rejects_oversized_client_frame() {
    let (backend_port, backend_messages, backend_task) = spawn_counting_ws_backend().await;
    let mut gateway = frame_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start WebSocket frame-limit gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let url = format!("ws://127.0.0.1:{}/ws", gateway.proxy_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("H1 websocket connect");

    ws.send(Message::Text("ok".into()))
        .await
        .expect("send small frame");
    assert_eq!(
        ws.next().await.expect("small reply").expect("small reply"),
        Message::Text("Echo: ok".into())
    );
    assert_backend_messages(&backend_messages, 1).await;

    ws.send(Message::Text("x".repeat(17).into()))
        .await
        .expect("send oversized frame");
    assert_no_text_echo(ws.next().await).await;
    assert_backend_messages(&backend_messages, 1).await;

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_websocket_frame_limit_h3_rejects_oversized_client_frame() {
    let (backend_port, backend_messages, backend_task) = spawn_counting_ws_backend().await;
    let https_port = reserve_https_port().await;
    let mut gateway = frame_limit_gateway_builder(backend_port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start H3 WebSocket frame-limit gateway");

    let client = Http3Client::insecure().expect("h3 client");
    let url = format!("https://localhost:{https_port}/ws");
    let mut ws = retry_h3_websocket(&client, &url).await;
    assert_eq!(ws.status, StatusCode::OK);

    ws.send_text("ok").await.expect("send small H3 frame");
    assert_eq!(ws.recv_text().await.expect("small H3 echo"), "Echo: ok");
    assert_backend_messages(&backend_messages, 1).await;

    ws.send_text(&"x".repeat(17))
        .await
        .expect("send oversized H3 frame");
    let oversized_read = tokio::time::timeout(Duration::from_secs(2), ws.recv_text()).await;
    if let Ok(Ok(text)) = oversized_read {
        panic!("oversized H3 frame was echoed: {text}");
    }
    assert_backend_messages(&backend_messages, 1).await;

    gateway.shutdown();
    backend_task.abort();
}

fn frame_limit_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(frame_limit_config(backend_port))
        .log_level("warn")
        .env("FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES", MAX_FRAME_BYTES)
        .env("FERRUM_WEBSOCKET_TUNNEL_MODE", "false")
}

fn frame_limit_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "ws-frame-limit",
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
    serde_yaml::to_string(&config).expect("serialize WebSocket frame-limit config")
}

async fn spawn_counting_ws_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind WebSocket backend");
    let port = listener.local_addr().expect("backend addr").port();
    let messages = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn(run_counting_ws_backend(listener, Arc::clone(&messages)));
    (port, messages, task)
}

#[allow(clippy::collapsible_match)]
async fn run_counting_ws_backend(listener: TcpListener, messages: Arc<AtomicUsize>) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let messages = Arc::clone(&messages);
        tokio::spawn(async move {
            let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                Ok(ws) => ws,
                Err(_) => return,
            };
            let (mut sink, mut source) = ws_stream.split();
            while let Some(Ok(msg)) = source.next().await {
                match msg {
                    Message::Text(text) => {
                        messages.fetch_add(1, Ordering::SeqCst);
                        let echo = format!("Echo: {text}");
                        if sink.send(Message::Text(echo.into())).await.is_err() {
                            break;
                        }
                    }
                    Message::Binary(data) => {
                        messages.fetch_add(1, Ordering::SeqCst);
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
) -> crate::scaffolding::clients::Http3WebSocket {
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut last_err = None;
    loop {
        match client.websocket(url, WebSocketOptions::default()).await {
            Ok(ws) => return ws,
            Err(err) if Instant::now() < deadline => {
                last_err = Some(err.to_string());
                sleep(Duration::from_millis(100)).await;
            }
            Err(err) => {
                panic!(
                    "H3 websocket did not complete; last startup error={last_err:?}; final error={err}"
                );
            }
        }
    }
}

async fn assert_no_text_echo(next: Option<Result<Message, tokio_tungstenite::tungstenite::Error>>) {
    match next {
        Some(Ok(Message::Text(text))) => panic!("oversized frame was echoed: {text}"),
        Some(Ok(Message::Binary(data))) => panic!("oversized frame returned binary: {data:?}"),
        _ => {}
    }
}

async fn assert_backend_messages(messages: &AtomicUsize, expected: usize) {
    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        messages.load(Ordering::SeqCst),
        expected,
        "unexpected backend WebSocket message count"
    );
}
