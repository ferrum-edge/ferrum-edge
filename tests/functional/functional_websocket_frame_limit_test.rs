//! Functional coverage for global and plugin WebSocket frame-size limits.
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
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::protocol::frame::Frame;
use tokio_tungstenite::tungstenite::protocol::frame::coding::{CloseCode, Data, OpCode};
use tokio_tungstenite::tungstenite::protocol::{CloseFrame, Message};

const MAX_FRAME_BYTES: &str = "16";

#[ignore]
#[tokio::test]
async fn functional_ws_message_size_limit_h1_preserves_close_and_rejects_oversized_frame() {
    let (backend_port, backend_messages, mut backend_closes, backend_task) =
        spawn_counting_ws_backend().await;
    let mut gateway = plugin_frame_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start H1 plugin frame-limit gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let url = format!("ws://127.0.0.1:{}/ws", gateway.proxy_port);
    let (mut graceful_ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("H1 graceful-close websocket connect");
    let graceful_reason = "graceful close exceeds sixteen bytes";
    graceful_ws
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: graceful_reason.into(),
        })))
        .await
        .expect("send H1 graceful Close above application frame ceiling");
    let graceful_echo = tokio::time::timeout(Duration::from_secs(2), graceful_ws.next())
        .await
        .expect("H1 graceful Close echo timed out")
        .expect("H1 graceful stream ended before Close echo")
        .expect("read H1 graceful Close echo");
    assert_graceful_close_message(graceful_echo, graceful_reason);
    assert_backend_close(&mut backend_closes, CloseCode::Normal, graceful_reason).await;

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

/// Global `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` overflow (no size plugin) must
/// still emit RFC 6455 Close 1009 to both peers rather than an abrupt 1006.
#[ignore]
#[tokio::test]
async fn functional_websocket_global_frame_limit_sends_1009_to_both_peers() {
    let (backend_port, backend_messages, mut backend_closes, backend_task) =
        spawn_counting_ws_backend().await;
    let mut gateway = frame_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start H1 global frame-limit gateway");
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
        .expect("send oversized global-cap frame");
    let client_close = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(Some(close)))) => break close,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(Message::Close(None))) => {
                    panic!("global frame-cap overflow closed with 1005/no status")
                }
                other => panic!("unexpected reply before global 1009 Close: {other:?}"),
            }
        }
    })
    .await
    .expect("client close timed out");
    assert_eq!(client_close.code, CloseCode::Size);
    assert!(
        client_close.reason.is_empty(),
        "global fallback reason must stay bounded/non-secret, got {:?}",
        client_close.reason
    );
    assert_backend_close(&mut backend_closes, CloseCode::Size, "").await;
    assert_backend_messages(&backend_messages, 1).await;

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_websocket_frame_limit_h3_rejects_oversized_client_frame() {
    let (backend_port, backend_messages, _backend_closes, backend_task) =
        spawn_counting_ws_backend().await;
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

#[ignore]
#[tokio::test]
async fn functional_ws_message_size_limit_h2_sends_1009_to_both_peers() {
    use bytes::Bytes;
    use http::{Method, Version};
    use http_body_util::Empty;
    use hyper::client::conn::http2;
    use hyper_util::rt::{TokioExecutor, TokioIo};
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::protocol::Role;

    let (backend_port, mut backend_closes, backend_task) = spawn_recording_close_ws_backend().await;
    let mut gateway = plugin_frame_limit_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start H2 plugin frame-limit gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let stream = tokio::net::TcpStream::connect(("127.0.0.1", gateway.proxy_port))
        .await
        .expect("connect H2 gateway");
    let (mut sender, conn) = http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .expect("H2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });
    let request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://127.0.0.1:{}/ws", gateway.proxy_port))
        .version(Version::HTTP_2)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build H2 WebSocket request");
    let response = sender
        .send_request(request)
        .await
        .expect("send H2 WebSocket request");
    assert_eq!(response.status(), StatusCode::OK);
    let upgraded = hyper::upgrade::on(response)
        .await
        .expect("upgrade H2 CONNECT");
    let mut ws = WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;

    let graceful_request = http::Request::builder()
        .method(Method::CONNECT)
        .uri(format!("http://127.0.0.1:{}/ws", gateway.proxy_port))
        .version(Version::HTTP_2)
        .header(http::header::SEC_WEBSOCKET_VERSION, "13")
        .extension(hyper::ext::Protocol::from_static("websocket"))
        .body(Empty::<Bytes>::new())
        .expect("build graceful H2 WebSocket request");
    let graceful_response = sender
        .send_request(graceful_request)
        .await
        .expect("send graceful H2 WebSocket request");
    assert_eq!(graceful_response.status(), StatusCode::OK);
    let graceful_upgraded = hyper::upgrade::on(graceful_response)
        .await
        .expect("upgrade graceful H2 CONNECT");
    let mut graceful_ws =
        WebSocketStream::from_raw_socket(TokioIo::new(graceful_upgraded), Role::Client, None).await;
    let graceful_reason = "graceful close exceeds sixteen bytes";
    graceful_ws
        .send(Message::Close(Some(CloseFrame {
            code: CloseCode::Normal,
            reason: graceful_reason.into(),
        })))
        .await
        .expect("send H2 graceful Close above plugin frame ceiling");
    let graceful_echo = tokio::time::timeout(Duration::from_secs(2), graceful_ws.next())
        .await
        .expect("H2 graceful Close echo timed out")
        .expect("H2 graceful stream ended before Close echo")
        .expect("read H2 graceful Close echo");
    assert_graceful_close_message(graceful_echo, graceful_reason);
    assert_backend_close(&mut backend_closes, CloseCode::Normal, graceful_reason).await;

    ws.send(Message::Frame(Frame::message(
        vec![1u8; 16],
        OpCode::Data(Data::Binary),
        false,
    )))
    .await
    .expect("send first H2 fragment");
    ws.send(Message::Ping(vec![1].into()))
        .await
        .expect("send interleaved H2 ping");
    ws.send(Message::Frame(Frame::message(
        vec![2u8; 16],
        OpCode::Data(Data::Continue),
        true,
    )))
    .await
    .expect("send final H2 continuation");
    let valid = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Text(text))) if text == "binary:32" => break text,
                Some(Ok(Message::Pong(_))) => continue,
                other => panic!("unexpected H2 fragmented reply: {other:?}"),
            }
        }
    })
    .await
    .expect("H2 fragmented reply timed out");
    assert_eq!(valid.as_str(), "binary:32");

    ws.send(Message::Text("backend-frag".into()))
        .await
        .expect("request fragmented H2 backend response");
    let backend_valid = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Binary(bytes))) => break bytes,
                Some(Ok(Message::Ping(_))) | Some(Ok(Message::Pong(_))) => continue,
                other => panic!("unexpected fragmented H2 backend reply: {other:?}"),
            }
        }
    })
    .await
    .expect("fragmented H2 backend reply timed out");
    assert_eq!(backend_valid.len(), 32);

    // Control frames remain independently bounded. This Ping is valid under
    // RFC 6455's 125-byte control-frame cap but exceeds the plugin's 16-byte
    // actual-frame policy.
    ws.send(Message::Ping(vec![9u8; 17].into()))
        .await
        .expect("send oversized H2 control frame");
    let h2_close = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(Some(close)))) => break close,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                other => panic!("unexpected H2 reply before policy close: {other:?}"),
            }
        }
    })
    .await
    .expect("H2 close timed out");
    assert_eq!(h2_close.code, CloseCode::Size);
    assert_eq!(h2_close.reason.as_str(), "plugin frame limit");
    assert_backend_close(&mut backend_closes, CloseCode::Size, "plugin frame limit").await;

    drop(ws);
    let _ = tokio::time::timeout(Duration::from_secs(2), conn_task).await;
    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_ws_message_size_limit_h3_sends_1009_to_both_peers() {
    use crate::scaffolding::H3WebSocketFrame;

    let (backend_port, mut backend_closes, backend_task) = spawn_recording_close_ws_backend().await;
    let https_port = reserve_https_port().await;
    let mut gateway = plugin_frame_limit_gateway_builder(backend_port)
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .spawn()
        .await
        .expect("start H3 plugin frame-limit gateway");

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/ws");
    let mut graceful_ws = retry_h3_websocket(&client, &url).await;
    let graceful_reason = "graceful close exceeds sixteen bytes";
    let mut graceful_payload = Vec::from(u16::from(CloseCode::Normal).to_be_bytes());
    graceful_payload.extend_from_slice(graceful_reason.as_bytes());
    graceful_ws
        .send_fragment(0x8, &graceful_payload, true)
        .await
        .expect("send H3 graceful Close above plugin frame ceiling");
    let graceful_echo = tokio::time::timeout(Duration::from_secs(2), graceful_ws.recv_frame())
        .await
        .expect("H3 graceful Close echo timed out")
        .expect("read H3 graceful Close echo");
    let graceful_echo_payload = match graceful_echo {
        H3WebSocketFrame::Close(payload) => payload,
        other => panic!("expected H3 graceful Close echo, got {other:?}"),
    };
    assert_close_payload(&graceful_echo_payload, CloseCode::Normal, graceful_reason);
    assert_backend_close(&mut backend_closes, CloseCode::Normal, graceful_reason).await;

    let mut ws = retry_h3_websocket(&client, &url).await;
    ws.send_fragment(0x2, &[1u8; 16], false)
        .await
        .expect("send first H3 fragment");
    ws.send_fragment(0x9, &[7], true)
        .await
        .expect("send interleaved H3 ping");
    ws.send_fragment(0x0, &[2u8; 16], true)
        .await
        .expect("send final H3 continuation");
    let valid = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.recv_frame().await.expect("read H3 fragmented reply") {
                H3WebSocketFrame::Text(text) if text == "binary:32" => break text,
                H3WebSocketFrame::Pong(_) => continue,
                other => panic!("unexpected H3 fragmented reply: {other:?}"),
            }
        }
    })
    .await
    .expect("H3 fragmented reply timed out");
    assert_eq!(valid, "binary:32");

    ws.send_text("backend-frag")
        .await
        .expect("request fragmented H3 backend response");
    let backend_valid = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.recv_frame().await.expect("read H3 backend fragments") {
                H3WebSocketFrame::Binary(bytes) => break bytes,
                H3WebSocketFrame::Ping(_) | H3WebSocketFrame::Pong(_) => continue,
                other => panic!("unexpected fragmented H3 backend reply: {other:?}"),
            }
        }
    })
    .await
    .expect("fragmented H3 backend reply timed out");
    assert_eq!(backend_valid.len(), 32);
    // RFC 9220 keeps RFC 6455's 125-byte control payload cap. Exercise the
    // stricter per-proxy parser ceiling on an otherwise-valid H3 Ping.
    ws.send_fragment(0x9, &[9u8; 17], true)
        .await
        .expect("send oversized H3 control frame");
    let close = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.recv_frame().await.expect("read H3 close") {
                close @ H3WebSocketFrame::Close(_) => break close,
                H3WebSocketFrame::Ping(_) | H3WebSocketFrame::Pong(_) => continue,
                other => panic!("unexpected H3 reply before policy close: {other:?}"),
            }
        }
    })
    .await
    .expect("H3 close timed out");
    let payload = match close {
        H3WebSocketFrame::Close(payload) => payload,
        other => panic!("expected H3 Close, got {other:?}"),
    };
    assert_close_payload(&payload, CloseCode::Size, "plugin frame limit");
    assert_backend_close(&mut backend_closes, CloseCode::Size, "plugin frame limit").await;

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

fn plugin_frame_limit_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(plugin_frame_limit_config(backend_port))
        .log_level("warn")
        .env("FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES", "1048576")
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

fn plugin_frame_limit_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "ws-frame-limit",
            "listen_path": "/ws",
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "plugins": [{"plugin_config_id": "ws-size-limit"}]
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "ws-size-limit",
            "plugin_name": "ws_message_size_limiting",
            "scope": "proxy",
            "proxy_id": "ws-frame-limit",
            "enabled": true,
            "priority_override": 101,
            "config": {
                "max_frame_bytes": 16,
                "max_message_bytes": 64,
                "close_reason": "plugin frame limit"
            }
        }]
    });
    serde_yaml::to_string(&config).expect("serialize plugin WebSocket frame-limit config")
}

async fn spawn_recording_close_ws_backend() -> (
    u16,
    mpsc::UnboundedReceiver<(CloseCode, String)>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recording WebSocket backend");
    let port = listener.local_addr().expect("backend addr").port();
    let (close_tx, close_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let close_tx = close_tx.clone();
            tokio::spawn(async move {
                let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                    return;
                };
                while let Some(Ok(message)) = ws.next().await {
                    match message {
                        Message::Text(text) if text == "backend-frag" => {
                            if ws
                                .send(Message::Frame(Frame::message(
                                    vec![3u8; 16],
                                    OpCode::Data(Data::Binary),
                                    false,
                                )))
                                .await
                                .is_err()
                            {
                                break;
                            }
                            if ws.send(Message::Ping(vec![4].into())).await.is_err() {
                                break;
                            }
                            if ws
                                .send(Message::Frame(Frame::message(
                                    vec![5u8; 16],
                                    OpCode::Data(Data::Continue),
                                    true,
                                )))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Message::Text(text) => {
                            if ws.send(Message::Text(text)).await.is_err() {
                                break;
                            }
                        }
                        Message::Binary(bytes) => {
                            if ws
                                .send(Message::Text(format!("binary:{}", bytes.len()).into()))
                                .await
                                .is_err()
                            {
                                break;
                            }
                        }
                        Message::Close(Some(close)) => {
                            let _ = close_tx.send((close.code, close.reason.to_string()));
                            let _ = ws.send(Message::Close(Some(close))).await;
                            break;
                        }
                        Message::Close(None) => break,
                        _ => {}
                    }
                }
            });
        }
    });
    (port, close_rx, task)
}

fn assert_graceful_close_message(message: Message, expected_reason: &str) {
    let Message::Close(Some(close)) = message else {
        panic!("expected detailed graceful Close echo, got {message:?}");
    };
    assert_eq!(close.code, CloseCode::Normal);
    assert_eq!(close.reason.as_str(), expected_reason);
}

fn assert_close_payload(payload: &[u8], expected_code: CloseCode, expected_reason: &str) {
    assert!(payload.len() >= 2, "close payload omitted status code");
    assert_eq!(
        u16::from_be_bytes([payload[0], payload[1]]),
        u16::from(expected_code)
    );
    assert_eq!(
        std::str::from_utf8(&payload[2..]).expect("UTF-8 close reason"),
        expected_reason
    );
}

async fn assert_backend_close(
    backend_closes: &mut mpsc::UnboundedReceiver<(CloseCode, String)>,
    expected_code: CloseCode,
    expected_reason: &str,
) {
    let (code, reason) = tokio::time::timeout(Duration::from_secs(2), backend_closes.recv())
        .await
        .expect("backend close timed out")
        .expect("backend close channel ended");
    assert_eq!(code, expected_code);
    assert_eq!(reason, expected_reason);
}

async fn spawn_counting_ws_backend() -> (
    u16,
    Arc<AtomicUsize>,
    mpsc::UnboundedReceiver<(CloseCode, String)>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind WebSocket backend");
    let port = listener.local_addr().expect("backend addr").port();
    let messages = Arc::new(AtomicUsize::new(0));
    let (close_tx, close_rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(run_counting_ws_backend(
        listener,
        Arc::clone(&messages),
        close_tx,
    ));
    (port, messages, close_rx, task)
}

#[allow(clippy::collapsible_match)]
async fn run_counting_ws_backend(
    listener: TcpListener,
    messages: Arc<AtomicUsize>,
    close_tx: mpsc::UnboundedSender<(CloseCode, String)>,
) {
    loop {
        let Ok((stream, _)) = listener.accept().await else {
            continue;
        };
        let messages = Arc::clone(&messages);
        let close_tx = close_tx.clone();
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
                    Message::Close(Some(close)) => {
                        let _ = close_tx.send((close.code, close.reason.to_string()));
                        let _ = sink.send(Message::Close(Some(close))).await;
                        break;
                    }
                    Message::Close(None) => {
                        let _ = sink.send(Message::Close(None)).await;
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
