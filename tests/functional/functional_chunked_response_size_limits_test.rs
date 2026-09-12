//! Functional tests for response-size limits on unknown-length backend bodies.
//!
//! These cover backend responses without `Content-Length`, where the gateway
//! must enforce `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` while streaming or while
//! buffering due to `response_body_mode: buffer`.

use crate::common::TestGateway;

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::error::Error;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

const STARTUP_ATTEMPTS: u32 = 3;

/// Issue #4784: the origin, request transformer, and response transformer must
/// retain distinct attribution while enforcing their directional size ceilings.
#[tokio::test]
#[ignore]
async fn transformer_response_size_policy_status_logging_and_attribution() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut request = Vec::new();
                while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                    let mut chunk = [0u8; 2048];
                    let len = stream.read(&mut chunk).await.unwrap();
                    if len == 0 {
                        return;
                    }
                    request.extend_from_slice(&chunk[..len]);
                }
                let request = String::from_utf8_lossy(&request);
                let body = if request.starts_with("GET /backend") {
                    "x".repeat(129)
                } else {
                    "{}".to_string()
                };
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len(),
                );
                stream.write_all(response.as_bytes()).await.unwrap();
            });
        }
    });
    let mut proxies = Vec::new();
    let mut plugin_configs = vec![serde_json::json!({
        "id": "logs",
        "plugin_name": "stdout_logging",
        "scope": "global",
        "enabled": true,
        "config": {}
    })];
    for (route, transformer, payload_bytes) in [
        ("backend", None, 0),
        ("request", Some("request_transformer"), 115),
        ("response", Some("response_transformer"), 115),
        ("boundary", Some("response_transformer"), 114),
    ] {
        // File-mode proxies only run the plugin configs they attach; a
        // `proxy_id` on the config alone does not bind it to the route.
        let mut attached = vec![serde_json::json!({
            "plugin_config_id": format!("{route}-limit")
        })];
        if transformer.is_some() {
            attached.push(serde_json::json!({
                "plugin_config_id": format!("{route}-transform")
            }));
        }
        proxies.push(serde_json::json!({
            "id": route,
            "listen_path": format!("/{route}"),
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": false,
            "pool_enable_http2": false,
            "plugins": attached
        }));
        plugin_configs.push(serde_json::json!({
            "id": format!("{route}-limit"),
            "proxy_id": route,
            "plugin_name": if route == "request" {
                "request_size_limiting"
            } else {
                "response_size_limiting"
            },
            "scope": "proxy",
            "enabled": true,
            "config": {"max_bytes": 128}
        }));
        if let Some(transformer) = transformer {
            plugin_configs.push(serde_json::json!({
                "id": format!("{route}-transform"),
                "proxy_id": route,
                "plugin_name": transformer,
                "scope": "proxy",
                "enabled": true,
                "config": {"rules": [{
                    "operation": "add",
                    "target": "body",
                    "key": "padding",
                    "value": "x".repeat(payload_bytes)
                }]}
            }));
        }
    }
    let config = serde_json::json!({
        "version": "1",
        "proxies": proxies,
        "plugin_configs": plugin_configs,
        "consumers": []
    });
    let mut gateway = TestGateway::builder()
        .mode_file(serde_yaml::to_string(&config).unwrap())
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .capture_output()
        .spawn()
        .await
        .unwrap();
    gateway
        .wait_for_proxy_port(Duration::from_secs(10))
        .await
        .unwrap();
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(10))
        .build()
        .unwrap();
    for (route, expected_status, expected_header) in [
        ("backend", 502, Some("backend_error")),
        ("request", 413, None),
        ("response", 502, Some("overload")),
        ("boundary", 200, None),
    ] {
        let url = format!("http://127.0.0.1:{}/{route}", gateway.proxy_port);
        let response = if route == "request" {
            client
                .post(url)
                .header("content-type", "application/json")
                .body("{}")
        } else {
            client.get(url)
        }
        .send()
        .await
        .unwrap();
        assert_eq!(response.status().as_u16(), expected_status, "{route}");
        assert_eq!(
            response
                .headers()
                .get("x-gateway-error")
                .map(|v| v.to_str().unwrap()),
            expected_header,
            "{route}",
        );
        let body = response.text().await.unwrap();
        if route == "response" {
            assert_eq!(body, r#"{"error":"Response body too large","limit":128}"#);
        } else if route == "boundary" {
            assert_eq!(body.len(), 128);
        }
    }
    // Access logs use the nonblocking writer; wait a bounded interval for flush.
    let mut logs = String::new();
    for _ in 0..20 {
        logs = gateway.read_combined_captured_output().unwrap();
        if logs.contains("\"proxy_id\":\"boundary\"") {
            break;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    for (route, class) in [
        ("backend", Some("response_body_too_large")),
        ("request", None),
        ("response", Some("dispatch_policy_rejected")),
        ("boundary", None),
    ] {
        let row = logs
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .find(|row| row["proxy_id"] == route)
            .unwrap_or_else(|| panic!("missing {route} transaction: {logs}"));
        if let Some(class) = class {
            assert_eq!(row["error_class"], class, "{route}: {logs}");
        }
    }
    let warning = logs
        .lines()
        .find(|line| line.contains("output exceeds response size policy"))
        .unwrap_or_else(|| panic!("missing transformer warning: {logs}"));
    assert!(warning.contains("WARN"), "{warning}");
    assert!(warning.contains("response_transformer"), "{warning}");
    assert!(warning.contains("produced_bytes_at_least"), "{warning}");
    assert!(warning.contains("129"), "{warning}");
    assert!(warning.contains("128"), "{warning}");
    assert!(
        logs.lines()
            .any(|line| line.contains("WARN") && line.contains("Backend response body")),
        "{logs}"
    );
    assert_eq!(
        logs.lines()
            .filter(|line| line.contains("output exceeds response size policy"))
            .count(),
        1,
        "{logs}",
    );
    gateway.shutdown();
    backend_task.abort();
}

struct ChunkedHarness {
    _gateway: TestGateway,
    backend_task: tokio::task::JoinHandle<()>,
    proxy_port: u16,
}

impl ChunkedHarness {
    async fn new(response_body_mode: Option<&str>, max_response_bytes: &str) -> Self {
        let mut last_error = None;
        for attempt in 1..=STARTUP_ATTEMPTS {
            match Self::try_new(response_body_mode, max_response_bytes).await {
                Ok(harness) => return harness,
                Err(error) => {
                    eprintln!(
                        "chunked response harness startup attempt {attempt}/{STARTUP_ATTEMPTS} \
                         failed: {error}"
                    );
                    last_error = Some(error);
                    if attempt < STARTUP_ATTEMPTS {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }

        panic!(
            "chunked response harness failed after {STARTUP_ATTEMPTS} attempts: {}",
            last_error
                .map(|error| error.to_string())
                .unwrap_or_else(|| "no startup error recorded".to_string())
        );
    }

    async fn try_new(
        response_body_mode: Option<&str>,
        max_response_bytes: &str,
    ) -> Result<Self, Box<dyn Error + Send + Sync>> {
        let backend_listener = TcpListener::bind("127.0.0.1:0").await?;
        let backend_port = backend_listener.local_addr()?.port();

        let gateway = TestGateway::builder()
            .mode_file(build_config(backend_port, response_body_mode))
            .log_level("warn")
            .env("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", max_response_bytes)
            .capture_output()
            // Retry the complete harness below so every attempt receives a
            // fresh backend listener as well as fresh gateway ports/config.
            .max_attempts(1)
            .spawn()
            .await?;
        if let Err(error) = gateway.wait_for_proxy_port(Duration::from_secs(10)).await {
            let logs = gateway.read_combined_captured_output().unwrap_or_default();
            let diagnostics = if logs.is_empty() {
                String::new()
            } else {
                format!("\n--- captured gateway output ---\n{logs}")
            };
            return Err(format!("{error}{diagnostics}").into());
        }

        let backend_task = tokio::spawn(run_chunked_backend(backend_listener));

        Ok(Self {
            proxy_port: gateway.proxy_port,
            _gateway: gateway,
            backend_task,
        })
    }
}

impl Drop for ChunkedHarness {
    fn drop(&mut self) {
        self.backend_task.abort();
    }
}

fn build_config(backend_port: u16, response_body_mode: Option<&str>) -> String {
    let response_body_mode = response_body_mode
        .map(|mode| format!("    response_body_mode: {mode}\n"))
        .unwrap_or_default();
    format!(
        r#"
version: "1"
proxies:
  - id: "chunked-response-size-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
{response_body_mode}
consumers: []
plugin_configs: []
"#
    )
}

async fn run_chunked_backend(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buf = [0u8; 1024];
            let _ = stream.read(&mut buf).await;
            let response = b"HTTP/1.1 200 OK\r\n\
                Transfer-Encoding: chunked\r\n\
                Content-Type: text/plain\r\n\
                Connection: close\r\n\
                \r\n\
                8\r\nabcdefgh\r\n\
                8\r\nijklmnop\r\n\
                0\r\n\r\n";
            let _ = stream.write_all(response).await;
            let _ = stream.shutdown().await;
        });
    }
}

/// Returns `(Some(status), body_result)` when response headers were received
/// before the proxy reset the H2 stream, and `(None, Err(reset_error))` when
/// the proxy reset the stream during the request-send phase (an equally valid
/// "body reset" outcome — see the caller's assertion). The send-phase reset
/// happens when the proxy's chunked-response size limit fires before any
/// response bytes can be flushed to the client.
async fn send_h2_get(proxy_port: u16) -> (Option<u16>, Result<String, String>) {
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect h2");
    let _ = stream.set_nodelay(true);
    let io = TokioIo::new(stream);
    let (mut sender, conn) = hyper::client::conn::http2::handshake(TokioExecutor::new(), io)
        .await
        .expect("h2 handshake");
    let conn_task = tokio::spawn(async move {
        let _ = conn.await;
    });

    let request = Request::builder()
        .method("GET")
        .uri("http://example.com/chunked")
        .header("host", "example.com")
        .body(Full::new(Bytes::new()))
        .expect("build h2 request");
    let result = match sender.send_request(request).await {
        Ok(response) => {
            let status = response.status().as_u16();
            let body = response
                .into_body()
                .collect()
                .await
                .map(|collected| String::from_utf8_lossy(&collected.to_bytes()).into_owned())
                .map_err(|err| err.to_string());
            (Some(status), body)
        }
        Err(err) => (None, Err(err.to_string())),
    };

    drop(sender);
    conn_task.abort();

    result
}

#[ignore]
#[tokio::test]
async fn functional_chunked_response_size_limit_http1_streaming_body_errors_after_limit() {
    let harness = ChunkedHarness::new(None, "8").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .get(format!("http://127.0.0.1:{}/chunked", harness.proxy_port))
        .send()
        .await
        .expect("send h1 request");

    assert_eq!(response.status().as_u16(), 200);
    let body = response.bytes().await;
    assert!(
        body.is_err(),
        "streaming unknown-length response over the limit must fail the body read"
    );
}

#[ignore]
#[tokio::test]
async fn functional_chunked_response_size_limit_http2_streaming_body_resets_after_limit() {
    let harness = ChunkedHarness::new(None, "8").await;

    let (status, body) = send_h2_get(harness.proxy_port).await;

    // The proxy must abort the H2 response when the streaming chunked body
    // exceeds the limit. Two equivalent outcomes are accepted:
    //   * Headers arrive (status 200), then the body collect errors when the
    //     proxy resets the stream mid-body.
    //   * The proxy resets the stream before any headers can be flushed —
    //     `send_request` surfaces the RST_STREAM directly. This is a hyper
    //     scheduling race observed on the GitHub-hosted runner; semantically
    //     it is the same "body reset" outcome.
    assert!(
        body.is_err(),
        "H2 downstream body should reset when unknown-length backend body exceeds limit"
    );
    if let Some(s) = status {
        assert_eq!(s, 200, "if headers arrived, the proxy must report 200");
    }
}

#[ignore]
#[tokio::test]
async fn functional_chunked_response_size_limit_buffer_mode_returns_502() {
    let harness = ChunkedHarness::new(Some("buffer"), "8").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .get(format!("http://127.0.0.1:{}/chunked", harness.proxy_port))
        .send()
        .await
        .expect("send h1 request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 502, "body={body}");
    assert!(
        body.contains("Backend response body exceeds maximum size"),
        "unexpected body: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_chunked_response_size_limit_zero_streams_full_body() {
    let harness = ChunkedHarness::new(None, "0").await;
    let client = reqwest::Client::builder()
        .http1_only()
        .timeout(Duration::from_secs(5))
        .build()
        .expect("http1 client");

    let response = client
        .get(format!("http://127.0.0.1:{}/chunked", harness.proxy_port))
        .send()
        .await
        .expect("send h1 request");
    let status = response.status().as_u16();
    let body = response.text().await.expect("read body");

    assert_eq!(status, 200, "body={body}");
    assert_eq!(body, "abcdefghijklmnop");
}
