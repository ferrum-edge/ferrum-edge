//! Functional tests for configured request header size limits.
//!
//! These spawn a real file-mode gateway and exercise the live H1/H2 protocol
//! frontends with mutated limit env vars:
//!
//! - `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES`
//! - `FERRUM_MAX_HEADER_SIZE_BYTES`
//!
//! Run with: `cargo test --test functional_tests header_size_limit -- --ignored --nocapture`

use crate::common::{TestGateway, spawn_http_echo};

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;

struct RawResponse {
    status_code: u16,
    body: String,
}

fn build_config(backend_port: u16) -> String {
    format!(
        "version: \"1\"\nproxies:\n\
         \x20 - id: \"header-size-http\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_scheme: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {backend_port}\n\
         \x20   strip_listen_path: false\n\
         \x20   plugins: []\n\
         consumers: []\n\
         plugin_configs: []\n",
    )
}

async fn start_gateway(extra_env: &[(&str, &str)]) -> (TestGateway, crate::common::EchoServer) {
    let echo = spawn_http_echo().await.expect("start echo backend");
    let mut builder = TestGateway::builder()
        .mode_file(build_config(echo.port))
        .log_level("warn")
        .capture_output();
    for (key, value) in extra_env {
        builder = builder.env(*key, *value);
    }
    let gateway = builder.spawn().await.expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port ready");
    (gateway, echo)
}

async fn send_raw_h1(proxy_port: u16, raw: &[u8]) -> RawResponse {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to gateway");
    let _ = stream.set_nodelay(true);
    let (read_half, mut write_half) = stream.into_split();
    write_half.write_all(raw).await.expect("send raw request");
    write_half.flush().await.expect("flush raw request");

    let mut reader = BufReader::new(read_half);
    let mut status_line = Vec::new();
    let _ = tokio::time::timeout(
        Duration::from_secs(5),
        reader.read_until(b'\n', &mut status_line),
    )
    .await;
    let status_text = String::from_utf8_lossy(&status_line);
    let status_code = status_text
        .split_whitespace()
        .nth(1)
        .and_then(|s| s.parse::<u16>().ok())
        .unwrap_or(0);

    let mut content_length: Option<usize> = None;
    loop {
        let mut line = Vec::new();
        let read_result =
            tokio::time::timeout(Duration::from_secs(2), reader.read_until(b'\n', &mut line)).await;
        let n = match read_result {
            Ok(Ok(n)) => n,
            _ => 0,
        };
        if n == 0 {
            break;
        }
        let line = String::from_utf8_lossy(&line);
        let trimmed = line.trim_end_matches(['\r', '\n']);
        if trimmed.is_empty() {
            break;
        }
        if let Some((key, value)) = trimmed.split_once(':')
            && key.eq_ignore_ascii_case("content-length")
        {
            content_length = value.trim().parse().ok();
        }
    }

    let body = if let Some(len) = content_length {
        let mut buf = vec![0u8; len];
        let _ = tokio::time::timeout(Duration::from_secs(2), reader.read_exact(&mut buf)).await;
        String::from_utf8_lossy(&buf).into_owned()
    } else {
        let mut buf = Vec::new();
        let _ = tokio::time::timeout(Duration::from_secs(2), reader.read_to_end(&mut buf)).await;
        String::from_utf8_lossy(&buf).into_owned()
    };

    RawResponse { status_code, body }
}

async fn send_h2_with_header(proxy_port: u16, name: &str, value: &str) -> RawResponse {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to gateway");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let req = Request::builder()
        .method("GET")
        .uri("http://example.com/")
        .header(name, value)
        .body(Full::new(Bytes::new()))
        .expect("build h2 request");
    let resp = sender.send_request(req).await.expect("send h2 request");
    let status_code = resp.status().as_u16();
    let body = resp
        .into_body()
        .collect()
        .await
        .map(|b| String::from_utf8_lossy(&b.to_bytes()).into_owned())
        .unwrap_or_default();

    drop(sender);
    conn_task.abort();
    RawResponse { status_code, body }
}

#[ignore]
#[tokio::test]
async fn functional_header_size_limit_h1_single_header_env_rejects_large_header() {
    let (mut gateway, _echo) = start_gateway(&[
        ("FERRUM_MAX_HEADER_SIZE_BYTES", "4096"),
        ("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "64"),
    ])
    .await;

    let huge = "a".repeat(96);
    let req = format!("GET / HTTP/1.1\r\nHost: example.com\r\nX-Huge: {huge}\r\n\r\n");
    let resp = send_raw_h1(gateway.proxy_port, req.as_bytes()).await;

    assert_eq!(resp.status_code, 431, "body={}", resp.body);
    assert!(
        resp.body.contains("x-huge") && resp.body.contains("exceeds maximum size of 64 bytes"),
        "unexpected body: {}",
        resp.body
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_header_size_limit_h2_single_header_env_rejects_large_header() {
    let (mut gateway, _echo) = start_gateway(&[
        ("FERRUM_MAX_HEADER_SIZE_BYTES", "4096"),
        ("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "64"),
    ])
    .await;

    let huge = "a".repeat(96);
    let resp = send_h2_with_header(gateway.proxy_port, "x-huge", &huge).await;

    assert_eq!(resp.status_code, 431, "body={}", resp.body);
    assert!(
        resp.body.contains("x-huge") && resp.body.contains("exceeds maximum size of 64 bytes"),
        "unexpected body: {}",
        resp.body
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_header_size_limit_h1_total_header_env_rejects_aggregate_headers() {
    let (mut gateway, _echo) = start_gateway(&[
        ("FERRUM_MAX_HEADER_SIZE_BYTES", "512"),
        ("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "4096"),
    ])
    .await;

    let mut req = String::from("GET / HTTP/1.1\r\nHost: example.com\r\n");
    for i in 0..8 {
        req.push_str(&format!("X-Fill-{i}: {}\r\n", "b".repeat(72)));
    }
    req.push_str("\r\n");

    let resp = send_raw_h1(gateway.proxy_port, req.as_bytes()).await;

    assert_eq!(resp.status_code, 431, "body={}", resp.body);
    if !resp.body.is_empty() {
        assert!(
            resp.body
                .contains("Total request headers exceed maximum size")
                || resp.body.contains("headers"),
            "unexpected body: {}",
            resp.body
        );
    }

    gateway.shutdown();
}
