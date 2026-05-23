//! Functional HTTP/3 coverage for protocol body-size limit configuration.
//!
//! Run: `cargo test --test functional_tests -- --ignored functional_body_limit_h3 --nocapture`

use crate::common::TestGateway;
use crate::scaffolding::clients::{GetOptions, Http3Client};

use std::time::{Duration, Instant};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

const DEFAULT_BODY_LIMIT_BYTES: usize = 10 * 1024 * 1024;
const ABOVE_DEFAULT_BODY_LIMIT_BYTES: usize = DEFAULT_BODY_LIMIT_BYTES + 1024;
const IO_TIMEOUT: Duration = Duration::from_secs(30);

fn build_config(backend_port: u16) -> String {
    format!(
        "version: \"1\"\nproxies:\n\
         \x20 - id: \"body-limit-h3\"\n\
         \x20   listen_path: \"/\"\n\
         \x20   backend_scheme: http\n\
         \x20   backend_host: \"127.0.0.1\"\n\
         \x20   backend_port: {backend_port}\n\
         \x20   strip_listen_path: false\n\
         \x20   backend_connect_timeout_ms: 60000\n\
         \x20   backend_read_timeout_ms: 60000\n\
         \x20   backend_write_timeout_ms: 60000\n\
         consumers: []\n\
         plugin_configs: []\n",
    )
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|window| window == b"\r\n\r\n")
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
                 X-Body-Zero: response-h3\r\n\
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

async fn spawn_h3_gateway(
    backend: impl std::future::Future<Output = ()> + Send + 'static,
    backend_port: u16,
    env_key: &str,
) -> (TestGateway, tokio::task::JoinHandle<()>, u16) {
    let backend_task = tokio::spawn(backend);
    sleep(Duration::from_millis(150)).await;

    let https_reservation = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let https_port = https_reservation.local_addr().unwrap().port();
    drop(https_reservation);

    let gateway = TestGateway::builder()
        .mode_file(build_config(backend_port))
        .log_level("warn")
        .capture_output()
        .env("FERRUM_ENABLE_HTTP3", "true")
        .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
        .env("FERRUM_FRONTEND_TLS_CERT_PATH", "tests/certs/server.crt")
        .env("FERRUM_FRONTEND_TLS_KEY_PATH", "tests/certs/server.key")
        .env(env_key, "0")
        .spawn()
        .await
        .expect("start gateway");

    (gateway, backend_task, https_port)
}

#[ignore]
#[tokio::test]
async fn functional_body_limit_h3_response_body_zero_allows_above_default_body() {
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let expected_len = ABOVE_DEFAULT_BODY_LIMIT_BYTES;
    let (mut gateway, backend_task, https_port) = spawn_h3_gateway(
        start_large_response_server_on(backend_listener, expected_len),
        backend_port,
        "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES",
    )
    .await;

    let client = Http3Client::insecure().expect("H3 client");
    let url = format!("https://localhost:{https_port}/large");
    let options = GetOptions::default().header("x-body-zero", "response-h3");
    let mut last_err = None;
    let response = {
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            match client.get_with_options(&url, options.clone()).await {
                Ok(response) => break response,
                Err(err) if Instant::now() < deadline => {
                    last_err = Some(err.to_string());
                    sleep(Duration::from_millis(100)).await;
                }
                Err(err) => {
                    panic!(
                        "H3 large GET did not complete with response limit disabled; last startup error={last_err:?}; final error={err}"
                    );
                }
            }
        }
    };

    assert_eq!(
        response.status.as_u16(),
        200,
        "body={}",
        response.body_text()
    );
    assert_eq!(
        response
            .headers
            .get("x-body-zero")
            .and_then(|v| v.to_str().ok()),
        Some("response-h3")
    );
    assert_eq!(
        response.body_bytes.len(),
        expected_len,
        "client should receive the full H3 response body when response limit is disabled"
    );

    gateway.shutdown();
    backend_task.abort();
}
