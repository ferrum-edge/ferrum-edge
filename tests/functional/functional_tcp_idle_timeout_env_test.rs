//! Functional coverage for the global TCP stream idle-timeout env.
//!
//! `functional_tcp_proxy_test` covers per-proxy `tcp_idle_timeout_seconds`.
//! These tests cover the global `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` fallback and
//! the documented `0` disables behavior.

use crate::common::{TestGateway, TestGatewayBuilder};
use crate::scaffolding::reserve_port;

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinHandle;
use tokio::time::sleep;

#[ignore]
#[tokio::test]
async fn functional_tcp_idle_timeout_env_closes_idle_stream_connection() {
    let (gateway, stream_port, backend_task) = spawn_tcp_gateway_with_idle_timeout("1").await;

    let mut stream = connect_stream_port(stream_port).await;
    assert_tcp_echo(&mut stream, b"before-idle").await;

    sleep(Duration::from_secs(2)).await;

    let mut buf = [0u8; 16];
    let read = tokio::time::timeout(Duration::from_secs(3), stream.read(&mut buf)).await;
    match read {
        Ok(Ok(0)) | Ok(Err(_)) => {}
        Ok(Ok(n)) => panic!("idle stream stayed open and yielded {n} bytes"),
        Err(_) => panic!("idle stream was not closed by global timeout"),
    }

    drop(gateway);
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_tcp_idle_timeout_env_zero_keeps_idle_stream_connection_open() {
    let (gateway, stream_port, backend_task) = spawn_tcp_gateway_with_idle_timeout("0").await;

    let mut stream = connect_stream_port(stream_port).await;
    assert_tcp_echo(&mut stream, b"before-idle").await;

    sleep(Duration::from_secs(2)).await;
    assert_tcp_echo(&mut stream, b"after-idle").await;

    drop(gateway);
    backend_task.abort();
}

async fn spawn_tcp_gateway_with_idle_timeout(
    timeout_seconds: &str,
) -> (crate::common::TestGateway, u16, JoinHandle<()>) {
    const MAX_ATTEMPTS: u32 = 5;
    let mut last_err = None;
    for _ in 0..MAX_ATTEMPTS {
        let backend_reservation = reserve_port().await.expect("backend port");
        let backend_port = backend_reservation.port;
        let backend_task = start_tcp_echo_server_on(backend_reservation.into_listener()).await;

        let stream_reservation = reserve_port().await.expect("stream port");
        let stream_port = stream_reservation.drop_and_take_port();

        match tcp_gateway_builder(backend_port, stream_port, timeout_seconds)
            .spawn()
            .await
        {
            Ok(gateway) => {
                if wait_for_stream_port(stream_port, Duration::from_secs(5))
                    .await
                    .is_ok()
                {
                    return (gateway, stream_port, backend_task);
                }
                last_err = Some("stream listener did not become ready".to_string());
                backend_task.abort();
                drop(gateway);
            }
            Err(err) => {
                last_err = Some(err.to_string());
                backend_task.abort();
            }
        }
        sleep(Duration::from_millis(200)).await;
    }
    panic!("failed to start TCP idle-timeout gateway after {MAX_ATTEMPTS} attempts: {last_err:?}");
}

fn tcp_gateway_builder(
    backend_port: u16,
    stream_port: u16,
    timeout_seconds: &str,
) -> TestGatewayBuilder {
    TestGateway::builder()
        .mode_file(tcp_idle_timeout_config(backend_port, stream_port))
        .log_level("warn")
        .env("FERRUM_TCP_IDLE_TIMEOUT_SECONDS", timeout_seconds)
}

fn tcp_idle_timeout_config(backend_port: u16, stream_port: u16) -> String {
    let config = serde_json::json!({
        "version": "1",
        "proxies": [{
            "id": "tcp-idle-env",
            "listen_port": stream_port,
            "backend_scheme": "tcp",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "response_body_mode": "stream"
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": []
    });
    serde_yaml::to_string(&config).expect("serialize TCP idle-timeout config")
}

async fn start_tcp_echo_server_on(listener: TcpListener) -> JoinHandle<()> {
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 4096];
                loop {
                    match stream.read(&mut buf).await {
                        Ok(0) => break,
                        Ok(n) => {
                            if stream.write_all(&buf[..n]).await.is_err() {
                                break;
                            }
                        }
                        Err(_) => break,
                    }
                }
            });
        }
    })
}

async fn wait_for_stream_port(
    port: u16,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(err) if Instant::now() >= deadline => return Err(err.into()),
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }
}

async fn connect_stream_port(port: u16) -> TcpStream {
    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => return stream,
            Err(err) if Instant::now() >= deadline => {
                panic!("stream port {port} did not accept connections: {err}")
            }
            Err(_) => sleep(Duration::from_millis(25)).await,
        }
    }
}

async fn assert_tcp_echo(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.expect("write tcp payload");
    let mut buf = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut buf))
        .await
        .expect("tcp echo read timed out")
        .expect("tcp echo read error");
    assert_eq!(buf, payload, "TCP echo should match payload");
}
