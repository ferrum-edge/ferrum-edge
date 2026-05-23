//! Functional tests for configured URL length and query-parameter limits.
//!
//! These spawn a real file-mode gateway and exercise the live H1/H2 frontends
//! with mutated env vars:
//!
//! - `FERRUM_MAX_URL_LENGTH_BYTES`
//! - `FERRUM_MAX_QUERY_PARAMS`
//!
//! Run with: `cargo test --test functional_tests functional_url_query_limit -- --ignored --nocapture`

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
         \x20 - id: \"url-query-http\"\n\
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

async fn send_raw_h1(proxy_port: u16, target: &str) -> RawResponse {
    let raw = format!("GET {target} HTTP/1.1\r\nHost: example.com\r\n\r\n");
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect to gateway");
    let _ = stream.set_nodelay(true);
    let (read_half, mut write_half) = stream.into_split();
    write_half
        .write_all(raw.as_bytes())
        .await
        .expect("send raw request");
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

async fn send_h2(proxy_port: u16, target: &str) -> RawResponse {
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
        .uri(format!("http://example.com{target}"))
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
async fn functional_url_query_limit_h1_url_length_env_rejects_long_target() {
    let (mut gateway, _echo) = start_gateway(&[("FERRUM_MAX_URL_LENGTH_BYTES", "32")]).await;

    let target = format!("/{}", "a".repeat(48));
    let resp = send_raw_h1(gateway.proxy_port, &target).await;

    assert_eq!(resp.status_code, 414, "body={}", resp.body);
    assert!(
        resp.body.contains("Request URL length") && resp.body.contains("maximum of 32 bytes"),
        "unexpected body: {}",
        resp.body
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_url_query_limit_h2_url_length_env_rejects_long_target() {
    let (mut gateway, _echo) = start_gateway(&[("FERRUM_MAX_URL_LENGTH_BYTES", "32")]).await;

    let target = format!("/{}", "a".repeat(48));
    let resp = send_h2(gateway.proxy_port, &target).await;

    assert_eq!(resp.status_code, 414, "body={}", resp.body);
    assert!(
        resp.body.contains("Request URL length") && resp.body.contains("maximum of 32 bytes"),
        "unexpected body: {}",
        resp.body
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_url_query_limit_h1_query_param_env_rejects_excess_params() {
    let (mut gateway, _echo) = start_gateway(&[("FERRUM_MAX_QUERY_PARAMS", "2")]).await;

    let resp = send_raw_h1(gateway.proxy_port, "/?a=1&b=2&c=3").await;

    assert_eq!(resp.status_code, 400, "body={}", resp.body);
    assert!(
        resp.body
            .contains("Query parameter count (3) exceeds maximum of 2"),
        "unexpected body: {}",
        resp.body
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_url_query_limit_h2_query_param_env_rejects_excess_params() {
    let (mut gateway, _echo) = start_gateway(&[("FERRUM_MAX_QUERY_PARAMS", "2")]).await;

    let resp = send_h2(gateway.proxy_port, "/?a=1&b=2&c=3").await;

    assert_eq!(resp.status_code, 400, "body={}", resp.body);
    assert!(
        resp.body
            .contains("Query parameter count (3) exceeds maximum of 2"),
        "unexpected body: {}",
        resp.body
    );

    gateway.shutdown();
}

#[ignore]
#[tokio::test]
async fn functional_url_query_limit_h1_query_param_zero_disables_count_limit() {
    let (mut gateway, _echo) = start_gateway(&[("FERRUM_MAX_QUERY_PARAMS", "0")]).await;

    let target = "/?a=1&b=2&c=3&d=4&e=5";
    let resp = send_raw_h1(gateway.proxy_port, target).await;

    assert_eq!(resp.status_code, 200, "body={}", resp.body);
    assert!(
        resp.body.contains(target),
        "backend should receive the high-query-count target when the count limit is disabled; body={}",
        resp.body
    );

    gateway.shutdown();
}
