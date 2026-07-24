//! Functional tests for gateway-level WebSocket limits.
//!
//! These are distinct from the `ws_message_size_limiting` plugin tests: they
//! exercise the global `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` runtime setting
//! applied by the proxy's WebSocket frame parser.

use futures_util::{SinkExt, StreamExt};
use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::{sleep, timeout};
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Message;

async fn free_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind port 0");
    listener.local_addr().unwrap().port()
}

async fn start_ws_echo_server(port: u16) -> tokio::task::JoinHandle<()> {
    let handle = tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("bind WS echo server");

        loop {
            let Ok((stream, _addr)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                    Ok(s) => s,
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
                            let echo = format!("Echo binary: {} bytes", data.len());
                            if sink.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    });
    sleep(Duration::from_millis(200)).await;
    handle
}

#[derive(Clone, Copy)]
enum RawBackendFirstFrameShape {
    CoalescedComplete,
    EmptyResidual,
    CoalescedPrefix,
}

async fn start_raw_ws_first_frame_backend(
    port: u16,
    shape: RawBackendFirstFrameShape,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .expect("bind raw WS backend");
        let (mut stream, key) = loop {
            let Ok((mut stream, _addr)) = listener.accept().await else {
                return;
            };
            let request = read_headers(&mut stream)
                .await
                .expect("backend reads gateway handshake");
            let Some(key) = header_value(&request, "sec-websocket-key") else {
                continue;
            };
            break (stream, key);
        };
        let response = format!(
            "HTTP/1.1 101 Switching Protocols\r\n\
             Upgrade: websocket\r\n\
             Connection: Upgrade\r\n\
             Sec-WebSocket-Accept: {}\r\n\
             \r\n",
            derive_accept_key(key.as_bytes())
        );
        let frame = first_backend_frame();
        match shape {
            RawBackendFirstFrameShape::CoalescedComplete => {
                let mut bytes = response.into_bytes();
                bytes.extend_from_slice(&frame);
                stream
                    .write_all(&bytes)
                    .await
                    .expect("backend writes 101 + full frame");
            }
            RawBackendFirstFrameShape::EmptyResidual => {
                stream
                    .write_all(response.as_bytes())
                    .await
                    .expect("backend writes 101");
                sleep(Duration::from_millis(75)).await;
                stream
                    .write_all(&frame)
                    .await
                    .expect("backend writes frame after 101");
            }
            RawBackendFirstFrameShape::CoalescedPrefix => {
                let mut bytes = response.into_bytes();
                bytes.extend_from_slice(&frame[..3]);
                stream
                    .write_all(&bytes)
                    .await
                    .expect("backend writes 101 + frame prefix");
                sleep(Duration::from_millis(75)).await;
                stream
                    .write_all(&frame[3..])
                    .await
                    .expect("backend writes frame suffix");
            }
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), stream.read_u8()).await;
    })
}

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn write_ws_config(config_path: &std::path::Path, backend_port: u16) {
    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-global-limit-proxy"
    listen_path: "/ws-echo"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: true
    pool_enable_http2: false
consumers: []
plugin_configs: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 0
"#
    );

    let mut file = std::fs::File::create(config_path).expect("create config file");
    file.write_all(config.as_bytes()).expect("write config");
}

fn first_backend_frame() -> Vec<u8> {
    vec![0x82, 0x03, 0x01, 0x02, 0x03]
}

async fn read_headers(stream: &mut TcpStream) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 512];
    loop {
        if find_header_end(&buf).is_some() {
            return Ok(buf);
        }
        let n = timeout(Duration::from_secs(5), stream.read(&mut chunk)).await??;
        if n == 0 {
            return Err("connection closed before headers completed".into());
        }
        buf.extend_from_slice(&chunk[..n]);
        if buf.len() > 8192 {
            return Err("headers exceeded test limit".into());
        }
    }
}

fn find_header_end(bytes: &[u8]) -> Option<usize> {
    bytes
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|pos| pos + 4)
}

fn header_value(headers: &[u8], name: &str) -> Option<String> {
    let text = std::str::from_utf8(headers).ok()?;
    text.lines().find_map(|line| {
        let (raw_name, raw_value) = line.split_once(':')?;
        raw_name
            .trim()
            .eq_ignore_ascii_case(name)
            .then(|| raw_value.trim().to_string())
    })
}

async fn raw_ws_client_first_backend_frame(
    gateway_port: u16,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut stream = TcpStream::connect(format!("127.0.0.1:{gateway_port}")).await?;
    let request = "GET /ws-echo HTTP/1.1\r\n\
                   Host: localhost\r\n\
                   Upgrade: websocket\r\n\
                   Connection: Upgrade\r\n\
                   Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\
                   Sec-WebSocket-Version: 13\r\n\
                   \r\n";
    stream.write_all(request.as_bytes()).await?;
    let response = read_headers(&mut stream).await?;
    let header_end = find_header_end(&response).ok_or("gateway response headers incomplete")?;
    let response_text = std::str::from_utf8(&response[..header_end])?;
    assert!(
        response_text.starts_with("HTTP/1.1 101"),
        "gateway response was not a WebSocket 101: {response_text:?}"
    );
    let mut frame = vec![0u8; first_backend_frame().len()];
    let tail = &response[header_end..];
    let copied = tail.len().min(frame.len());
    frame[..copied].copy_from_slice(&tail[..copied]);
    if copied < frame.len() {
        timeout(
            Duration::from_secs(5),
            stream.read_exact(&mut frame[copied..]),
        )
        .await??;
    }
    Ok(frame)
}

async fn wait_for_gateway(gateway_port: u16) -> Result<(), Box<dyn std::error::Error>> {
    let deadline = std::time::Instant::now() + Duration::from_secs(15);
    let addr = format!("127.0.0.1:{gateway_port}");

    loop {
        if std::time::Instant::now() >= deadline {
            return Err("gateway did not start within 15 seconds".into());
        }
        match TcpStream::connect(&addr).await {
            Ok(mut stream) => {
                let _ = stream.shutdown().await;
                return Ok(());
            }
            Err(_) => sleep(Duration::from_millis(300)).await,
        }
    }
}

async fn start_gateway_with_retry(
    config_path: &str,
    extra_env: &[(&str, &str)],
) -> (std::process::Child, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let gateway_port = free_port().await;
        let admin_port = free_port().await;
        let mut cmd = std::process::Command::new(gateway_binary_path());
        cmd.env("FERRUM_MODE", "file")
            .env("FERRUM_FILE_CONFIG_PATH", config_path)
            .env("FERRUM_PROXY_HTTP_PORT", gateway_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("RUST_LOG", "ferrum_edge=warn")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        for (name, value) in extra_env {
            cmd.env(name, value);
        }

        match cmd.spawn() {
            Ok(mut child) => match wait_for_gateway(gateway_port).await {
                Ok(()) => return (child, gateway_port),
                Err(e) => {
                    last_err = e.to_string();
                    let _ = child.kill();
                    let _ = child.wait();
                }
            },
            Err(e) => {
                last_err = e.to_string();
            }
        }

        eprintln!(
            "Gateway startup attempt {attempt}/{MAX_ATTEMPTS} failed (proxy port {gateway_port}): {last_err}"
        );
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("gateway did not start after {MAX_ATTEMPTS} attempts: {last_err}");
}

/// Global frame-size env config should be enforced on parsed H1 WebSocket
/// frames when tunnel mode is disabled.
#[ignore]
#[tokio::test]
async fn test_websocket_global_frame_size_limit_rejects_oversized_frame() {
    crate::common::ensure_gateway_built().expect("build gateway");

    let backend_port = free_port().await;
    let echo_handle = start_ws_echo_server(backend_port).await;

    let temp_dir = TempDir::new().expect("create temp dir");
    let config_path = temp_dir.path().join("config.yaml");
    write_ws_config(&config_path, backend_port);

    let (mut gateway, gateway_port) = start_gateway_with_retry(
        config_path.to_str().unwrap(),
        &[
            ("FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES", "32"),
            ("FERRUM_WEBSOCKET_TUNNEL_MODE", "false"),
        ],
    )
    .await;

    let url = format!("ws://127.0.0.1:{gateway_port}/ws-echo");
    let (mut ws, response) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("connect WebSocket through gateway");
    assert_eq!(
        response.status(),
        http::StatusCode::SWITCHING_PROTOCOLS,
        "handshake should succeed before frame-size enforcement"
    );

    ws.send(Message::Text("small frame".into()))
        .await
        .expect("send small frame");
    let small_reply = timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("small echo timed out")
        .expect("small echo stream ended")
        .expect("small echo errored");
    assert_eq!(small_reply, Message::Text("Echo: small frame".into()));

    ws.send(Message::Text("x".repeat(64).into()))
        .await
        .expect("send oversized frame");
    let oversized_result = timeout(Duration::from_secs(5), ws.next())
        .await
        .expect("oversized frame did not close or error");
    match oversized_result {
        None => {}
        Some(Err(_)) => {}
        Some(Ok(Message::Close(_))) => {}
        Some(Ok(Message::Text(text))) => {
            panic!("oversized frame was echoed instead of rejected: {text}");
        }
        Some(Ok(other)) => {
            panic!("oversized frame produced unexpected message: {other:?}");
        }
    }

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
}

#[ignore]
#[tokio::test]
async fn test_websocket_tunnel_preserves_backend_frame_coalesced_with_101() {
    crate::common::ensure_gateway_built().expect("build gateway");

    for shape in [
        RawBackendFirstFrameShape::CoalescedComplete,
        RawBackendFirstFrameShape::EmptyResidual,
        RawBackendFirstFrameShape::CoalescedPrefix,
    ] {
        let backend_port = free_port().await;
        let backend = start_raw_ws_first_frame_backend(backend_port, shape).await;

        let temp_dir = TempDir::new().expect("create temp dir");
        let config_path = temp_dir.path().join("config.yaml");
        write_ws_config(&config_path, backend_port);

        let (mut gateway, gateway_port) = start_gateway_with_retry(
            config_path.to_str().unwrap(),
            &[("FERRUM_WEBSOCKET_TUNNEL_MODE", "true")],
        )
        .await;

        let frame = raw_ws_client_first_backend_frame(gateway_port)
            .await
            .expect("client receives backend frame");
        assert_eq!(frame, first_backend_frame());

        let _ = gateway.kill();
        let _ = gateway.wait();
        backend.abort();
    }
}
