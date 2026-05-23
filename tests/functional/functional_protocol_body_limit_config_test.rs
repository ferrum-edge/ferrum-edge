//! Functional tests for protocol body-size limit configuration.
//!
//! Run: `cargo test --test functional_tests -- --ignored functional_body_limit --nocapture`

use crate::common::TestGateway;

use serde_json::Value;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

const DEFAULT_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;
const ABOVE_DEFAULT_BODY_LIMIT_BYTES: usize = DEFAULT_BODY_LIMIT_BYTES + 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

fn build_config(backend_port: u16) -> String {
    format!(
        "version: \"1\"\nproxies:\n\
         \x20 - id: \"body-limit-http\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_scheme: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {backend_port}\n\
         \x20   strip_listen_path: false\n\
         consumers: []\n\
         plugin_configs: []\n",
    )
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
}

fn parse_content_length(headers: &str) -> usize {
    headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then(|| value.trim().parse::<usize>().ok())
                .flatten()
        })
        .unwrap_or(0)
}

async fn read_request_body_len(stream: &mut TcpStream) -> Option<(usize, usize)> {
    let mut buffered = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];
    let header_end = loop {
        let read = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            return None;
        }
        buffered.extend_from_slice(&chunk[..read]);
        if let Some(pos) = find_header_end(&buffered) {
            break pos + 4;
        }
        if buffered.len() > 64 * 1024 {
            return None;
        }
    };

    let header_text = String::from_utf8_lossy(&buffered[..header_end]);
    let content_length = parse_content_length(&header_text);
    let mut received = buffered
        .len()
        .saturating_sub(header_end)
        .min(content_length);

    while received < content_length {
        let read = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if read == 0 {
            break;
        }
        received += read.min(content_length - received);
    }

    Some((content_length, received))
}

async fn start_request_body_echo_server_on(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let Some((content_length, received)) = read_request_body_len(&mut stream).await else {
                return;
            };
            let body = format!(
                r#"{{"content_length":{content_length},"received_body_bytes":{received}}}"#
            );
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {len}\r\n\
                 Content-Type: application/json\r\n\
                 X-Body-Zero: request\r\n\
                 \r\n\
                 {body}",
                len = body.len(),
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

async fn start_large_response_server_on(listener: TcpListener, body_len: usize) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buffered = Vec::with_capacity(1024);
            let mut chunk = [0u8; 1024];
            loop {
                let read = tokio::time::timeout(IO_TIMEOUT, stream.read(&mut chunk)).await;
                let Ok(Ok(read)) = read else {
                    return;
                };
                if read == 0 {
                    return;
                }
                buffered.extend_from_slice(&chunk[..read]);
                if find_header_end(&buffered).is_some() {
                    break;
                }
            }

            let headers = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {body_len}\r\n\
                 Content-Type: application/octet-stream\r\n\
                 X-Body-Zero: response\r\n\
                 \r\n"
            );
            if stream.write_all(headers.as_bytes()).await.is_err() {
                return;
            }

            let chunk = vec![b'x'; 16 * 1024];
            let mut remaining = body_len;
            while remaining > 0 {
                let n = remaining.min(chunk.len());
                if stream.write_all(&chunk[..n]).await.is_err() {
                    return;
                }
                remaining -= n;
            }
            let _ = stream.shutdown().await;
        });
    }
}

async fn spawn_gateway(
    backend: impl std::future::Future<Output = ()> + Send + 'static,
    backend_port: u16,
    env_key: &str,
) -> (TestGateway, tokio::task::JoinHandle<()>) {
    let backend_task = tokio::spawn(backend);
    sleep(Duration::from_millis(150)).await;

    let gateway = TestGateway::builder()
        .mode_file(build_config(backend_port))
        .log_level("warn")
        .capture_output()
        .env(env_key, "0")
        .spawn()
        .await
        .expect("start gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .expect("proxy port did not become ready");

    (gateway, backend_task)
}

#[ignore]
#[tokio::test]
async fn functional_body_limit_h1_request_body_zero_allows_above_default_body() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let (mut gateway, backend_task) = spawn_gateway(
        start_request_body_echo_server_on(backend_listener),
        backend_port,
        "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES",
    )
    .await;

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("reqwest client");
    let expected_len = ABOVE_DEFAULT_BODY_LIMIT_BYTES;
    let response = client
        .post(format!("http://127.0.0.1:{}/upload", gateway.proxy_port))
        .body(vec![b'a'; expected_len])
        .send()
        .await
        .expect("request through gateway");

    assert_eq!(response.status().as_u16(), 200);
    let body: Value = response.json().await.expect("json response");
    assert_eq!(body["content_length"].as_u64(), Some(expected_len as u64));
    assert_eq!(
        body["received_body_bytes"].as_u64(),
        Some(expected_len as u64),
        "backend should receive the full request body when request limit is disabled"
    );

    gateway.shutdown();
    backend_task.abort();
}

#[ignore]
#[tokio::test]
async fn functional_body_limit_h1_response_body_zero_allows_above_default_body() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let expected_len = ABOVE_DEFAULT_BODY_LIMIT_BYTES;
    let (mut gateway, backend_task) = spawn_gateway(
        start_large_response_server_on(backend_listener, expected_len),
        backend_port,
        "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES",
    )
    .await;

    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(60))
        .build()
        .expect("reqwest client");
    let response = client
        .get(format!("http://127.0.0.1:{}/large", gateway.proxy_port))
        .send()
        .await
        .expect("request through gateway");

    assert_eq!(response.status().as_u16(), 200);
    assert_eq!(
        response
            .headers()
            .get("x-body-zero")
            .and_then(|v| v.to_str().ok()),
        Some("response")
    );
    let body = response.bytes().await.expect("response body");
    assert_eq!(
        body.len(),
        expected_len,
        "client should receive the full response body when response limit is disabled"
    );

    gateway.shutdown();
    backend_task.abort();
}
