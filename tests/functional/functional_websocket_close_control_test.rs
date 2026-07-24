//! Functional regressions for WebSocket close/control-frame correctness.
//!
//! - Local Ping auto-answer (no double Pong when the backend is silent)
//! - Global frame-size overflow emits Close 1009 to both peers
//! - Idle-timeout teardown emits Close 1001 to both peers

use crate::common::{TestGateway, TestGatewayBuilder};
use futures_util::{SinkExt, StreamExt};
use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};
use std::time::Duration;
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::protocol::frame::coding::CloseCode;
use tokio_tungstenite::tungstenite::protocol::Message;

const GLOBAL_MAX_FRAME_BYTES: &str = "16";

#[ignore]
#[tokio::test]
async fn functional_ws_ping_answered_locally_exactly_once_when_backend_silent() {
    let (backend_port, backend_pings, backend_task) = spawn_silent_ping_ws_backend().await;
    let mut gateway = close_control_gateway_builder(backend_port)
        .spawn()
        .await
        .expect("start Ping close-control gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let url = format!("ws://127.0.0.1:{}/ws", gateway.proxy_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("websocket connect");

    ws.send(Message::Ping(b"probe".to_vec().into()))
        .await
        .expect("send Ping");

    let pong = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Pong(payload))) => break payload,
                Some(Ok(Message::Ping(_))) => continue,
                other => panic!("expected local Pong, got {other:?}"),
            }
        }
    })
    .await
    .expect("local Pong timed out");
    assert_eq!(&pong[..], b"probe");

    // Documented gateway behavior: framer auto-answers; Ping is not relayed, so
    // a silent backend cannot produce a second Pong.
    let second = tokio::time::timeout(Duration::from_millis(400), ws.next()).await;
    if let Ok(Some(Ok(Message::Pong(_)))) = second {
        panic!("received a second Pong; Ping must not be forwarded to the backend");
    }

    sleep(Duration::from_millis(100)).await;
    assert_eq!(
        backend_pings.load(Ordering::SeqCst),
        0,
        "backend must not observe the client Ping when the gateway answers locally"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_ws_global_frame_limit_sends_1009_to_both_peers() {
    let (backend_port, mut backend_closes, backend_task) =
        spawn_recording_close_ws_backend().await;
    let mut gateway = close_control_gateway_builder(backend_port)
        .env("FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES", GLOBAL_MAX_FRAME_BYTES)
        .spawn()
        .await
        .expect("start global frame-limit gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let url = format!("ws://127.0.0.1:{}/ws", gateway.proxy_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("websocket connect");

    ws.send(Message::Text("ok".into()))
        .await
        .expect("send small frame");
    assert_eq!(
        ws.next().await.expect("small reply").expect("small reply"),
        Message::Text("Echo: ok".into())
    );

    ws.send(Message::Text("x".repeat(17).into()))
        .await
        .expect("send oversized frame");
    let close = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(Some(frame)))) => break frame,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                other => panic!("expected Close 1009, got {other:?}"),
            }
        }
    })
    .await
    .expect("client Close 1009 timed out");
    assert_eq!(close.code, CloseCode::Size);
    assert_eq!(u16::from(close.code), 1009);

    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_closes.recv())
            .await
            .expect("backend close timed out")
            .expect("backend close channel ended");
    assert_eq!(backend_code, CloseCode::Size);
    assert!(
        backend_reason.is_empty(),
        "global overflow Close reason must be empty, got {backend_reason:?}"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_ws_idle_timeout_sends_1001_to_both_peers() {
    let (backend_port, mut backend_closes, backend_task) =
        spawn_recording_close_ws_backend().await;
    let mut gateway = close_control_gateway_builder(backend_port)
        .env("FERRUM_WEBSOCKET_IDLE_TIMEOUT_SECONDS", "1")
        .spawn()
        .await
        .expect("start idle-timeout gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let url = format!("ws://127.0.0.1:{}/ws", gateway.proxy_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("websocket connect");

    ws.send(Message::Text("warmup".into()))
        .await
        .expect("send warmup");
    assert_eq!(
        ws.next().await.expect("warmup reply").expect("warmup reply"),
        Message::Text("Echo: warmup".into())
    );

    let client_close = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match ws.next().await {
                Some(Ok(Message::Close(Some(frame)))) => break frame,
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => continue,
                Some(Ok(other)) => panic!("unexpected frame before idle Close: {other:?}"),
                Some(Err(err)) => panic!("client stream error before idle Close: {err}"),
                None => panic!("client stream ended without idle Close"),
            }
        }
    })
    .await
    .expect("client idle Close timed out");
    assert_eq!(client_close.code, CloseCode::Away);
    assert_eq!(u16::from(client_close.code), 1001);
    assert_eq!(client_close.reason.as_str(), "idle timeout");

    let (backend_code, backend_reason) =
        tokio::time::timeout(Duration::from_secs(2), backend_closes.recv())
            .await
            .expect("backend idle close timed out")
            .expect("backend close channel ended");
    assert_eq!(backend_code, CloseCode::Away);
    assert_eq!(backend_reason, "idle timeout");

    gateway.shutdown();
    backend_task.abort();
}

fn close_control_gateway_builder(backend_port: u16) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(close_control_config(backend_port))
        .log_level("warn")
        .env("FERRUM_WEBSOCKET_TUNNEL_MODE", "false")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
}

fn close_control_config(backend_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "ws-close-control",
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
    serde_yaml::to_string(&config).expect("serialize close-control WebSocket config")
}

async fn spawn_silent_ping_ws_backend() -> (u16, Arc<AtomicUsize>, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind silent Ping backend");
    let port = listener.local_addr().expect("backend addr").port();
    let pings = Arc::new(AtomicUsize::new(0));
    let task = tokio::spawn({
        let pings = Arc::clone(&pings);
        async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    continue;
                };
                let pings = Arc::clone(&pings);
                tokio::spawn(async move {
                    let Ok(mut ws) = tokio_tungstenite::accept_async(stream).await else {
                        return;
                    };
                    while let Some(Ok(message)) = ws.next().await {
                        match message {
                            Message::Ping(_) => {
                                pings.fetch_add(1, Ordering::SeqCst);
                                // Deliberately do not answer — proves the
                                // client's Pong came from the gateway.
                            }
                            Message::Text(text) => {
                                let _ = ws.send(Message::Text(format!("Echo: {text}").into())).await;
                            }
                            Message::Close(close) => {
                                let _ = ws.send(Message::Close(close)).await;
                                break;
                            }
                            _ => {}
                        }
                    }
                });
            }
        }
    });
    (port, pings, task)
}

async fn spawn_recording_close_ws_backend() -> (
    u16,
    mpsc::UnboundedReceiver<(CloseCode, String)>,
    JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind recording close backend");
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
                        Message::Text(text) => {
                            if ws
                                .send(Message::Text(format!("Echo: {text}").into()))
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
                        Message::Close(None) => {
                            let _ = close_tx.send((CloseCode::Status, String::new()));
                            break;
                        }
                        _ => {}
                    }
                }
            });
        }
    });
    (port, close_rx, task)
}
