//! Functional coverage for `transaction_debugger` bounded body capture (#3316).
//!
//! Runs the real gateway in file mode with `FERRUM_LOG_LEVEL=debug`, captures
//! its stdout, and asserts that the debug target carries a bounded, redacted
//! request/response sample for small textual bodies while every excluded shape
//! (oversized, encoded, unknown-length, binary/non-textual) is reported as an
//! explicit omission and still proxied normally.

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;
use crate::scaffolding::clients::Http2Client;

use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;

/// Backend that answers every request with the same small JSON document.
/// The document carries a credential-shaped field so the response-side
/// redaction is observable end to end.
async fn run_json_backend(listener: TcpListener) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            // Read at least the request head; the exact body is irrelevant to
            // the canned response.
            let _ = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf)).await;
            let body = r#"{"result":"ok","access_token":"resp-secret-value"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Length: {}\r\n\
                 Content-Type: application/json\r\n\
                 Connection: close\r\n\
                 \r\n\
                 {body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn build_config(backend_port: u16) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "debug-body-proxy"
    listen_path: "/"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: false
    plugins:
      - plugin_config_id: "debug-body-capture"

consumers: []
plugin_configs:
  - id: "debug-body-capture"
    plugin_name: "transaction_debugger"
    scope: proxy
    proxy_id: "debug-body-proxy"
    enabled: true
    config:
      log_request_body: true
      log_response_body: true
      max_request_body_bytes: 256
      max_response_body_bytes: 256
"#
    )
}

struct DebugBodyHarness {
    gateway: TestGateway,
    _backend_task: tokio::task::JoinHandle<()>,
    proxy_port: u16,
}

impl DebugBodyHarness {
    async fn new() -> Self {
        let mut last_error = None;
        for attempt in 1..=3 {
            match Self::try_new().await {
                Ok(harness) => return harness,
                Err(error) => {
                    eprintln!("debug body harness attempt {attempt}/3 failed: {error}");
                    last_error = Some(error);
                }
            }
        }
        panic!(
            "debug body harness did not start after 3 fresh-port attempts: {}",
            last_error.unwrap_or_else(|| "no startup error recorded".to_string())
        );
    }

    async fn try_new() -> Result<Self, String> {
        let backend_listener = TcpListener::bind_test("127.0.0.1:0")
            .await
            .map_err(|error| format!("bind backend: {error}"))?;
        let backend_port = backend_listener
            .local_addr()
            .map_err(|error| format!("backend addr: {error}"))?
            .port();

        let gateway = TestGateway::builder()
            .mode_file(build_config(backend_port))
            .log_level("debug")
            .capture_output()
            .spawn()
            .await
            .map_err(|error| format!("start gateway: {error}"))?;
        let proxy_port = gateway.proxy_port;
        let backend_task = tokio::spawn(run_json_backend(backend_listener));
        let harness = Self {
            gateway,
            _backend_task: backend_task,
            proxy_port,
        };
        harness
            .gateway
            .wait_for_proxy_port(Duration::from_secs(10))
            .await
            .map_err(|error| format!("proxy port ready: {error}"))?;
        Ok(harness)
    }

    /// Poll the captured gateway output until `predicate` matches. The gateway
    /// logs through an async non-blocking sink, so a record it has already
    /// emitted may not have reached the capture file yet; polling can only turn
    /// a flush race into a hit, never a hit into a miss.
    async fn wait_for_logs<F>(&self, predicate: F) -> String
    where
        F: Fn(&str) -> bool,
    {
        self.gateway
            .wait_for_captured_output(predicate, Duration::from_secs(10))
            .await
            .unwrap_or_else(|error| format!("<failed to read output: {error}>"))
    }
}

#[ignore]
#[tokio::test]
async fn functional_transaction_debugger_captures_bounded_redacted_bodies_h1_h2() {
    let harness = DebugBodyHarness::new().await;
    let base = format!("http://127.0.0.1:{}", harness.proxy_port);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("build h1 client");

    // 1. Small JSON request: captured, with the credential field redacted.
    let response = client
        .post(format!("{base}/small"))
        .header("content-type", "application/json")
        .body(r#"{"user":"alice","password":"req-secret-value"}"#)
        .send()
        .await
        .expect("small json request");
    assert_eq!(response.status(), 200);
    let _ = response.bytes().await;

    // 2. Oversized request body: never captured, still proxied normally.
    let oversized = format!(r#"{{"pad":"{}"}}"#, "x".repeat(1024));
    let response = client
        .post(format!("{base}/oversized"))
        .header("content-type", "application/json")
        .body(oversized)
        .send()
        .await
        .expect("oversized request");
    assert_eq!(response.status(), 200);
    let _ = response.bytes().await;

    // 3. Non-textual request body: excluded by content type.
    let response = client
        .post(format!("{base}/binary"))
        .header("content-type", "application/octet-stream")
        .body(vec![0x00u8, 0xff, 0xfe, 0x01])
        .send()
        .await
        .expect("binary request");
    assert_eq!(response.status(), 200);
    let _ = response.bytes().await;

    // 4. H2 (prior knowledge) parity: the same capture runs on the H2 path.
    let h2 = Http2Client::h2c_prior_knowledge().expect("build h2c client");
    let response = h2
        .as_reqwest()
        .post(format!("{base}/h2"))
        .header("content-type", "application/json")
        .body(r#"{"user":"bob","api_key":"h2-secret-value"}"#)
        .send()
        .await
        .expect("h2 json request");
    assert_eq!(response.status(), 200);
    assert_eq!(response.version(), reqwest::Version::HTTP_2);
    let _ = response.bytes().await;

    // The gateway logs JSON through a non-blocking writer, so assertions match
    // serialized fields (`"direction":"request"`), and the snapshot is polled
    // rather than slept on: a line already emitted may not have reached the
    // capture file yet.
    let logs = harness
        .wait_for_logs(|output| {
            output.contains(r#""reason":"content_type_excluded""#) && output.contains("bob")
        })
        .await;

    assert!(
        logs.contains("Bounded body capture"),
        "no body capture record emitted:\n{logs}"
    );
    // Request and response samples both appear, with credentials redacted.
    assert!(logs.contains(r#""capture":"captured""#), "logs:\n{logs}");
    assert!(logs.contains(r#""direction":"request""#), "logs:\n{logs}");
    assert!(logs.contains(r#""direction":"response""#), "logs:\n{logs}");
    assert!(logs.contains(r#""body_kind":"json""#), "logs:\n{logs}");
    assert!(logs.contains("alice"), "logs:\n{logs}");
    assert!(
        !logs.contains("req-secret-value"),
        "request credential leaked into debug output:\n{logs}"
    );
    assert!(
        !logs.contains("resp-secret-value"),
        "response credential leaked into debug output:\n{logs}"
    );
    assert!(
        !logs.contains("h2-secret-value"),
        "h2 request credential leaked into debug output:\n{logs}"
    );
    assert!(logs.contains("bob"), "h2 capture missing:\n{logs}");

    // Excluded shapes are explicit omissions, not silent gaps.
    assert!(
        logs.contains(r#""reason":"over_capture_limit""#),
        "oversized body omission missing:\n{logs}"
    );
    assert!(
        logs.contains(r#""reason":"content_type_excluded""#),
        "non-textual body omission missing:\n{logs}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_transaction_debugger_leaves_unknown_length_requests_streaming() {
    let harness = DebugBodyHarness::new().await;
    let base = format!("http://127.0.0.1:{}", harness.proxy_port);
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(20))
        .build()
        .expect("build h1 client");

    // A chunked request has no Content-Length, so the capture screen must
    // decline it and the request must still be proxied unchanged.
    let chunk = bytes::Bytes::from_static(br#"{"user":"carol"}"#);
    let stream = futures_util::stream::iter(vec![Ok::<_, std::io::Error>(chunk)]);
    let response = client
        .post(format!("{base}/chunked"))
        .header("content-type", "application/json")
        .body(reqwest::Body::wrap_stream(stream))
        .send()
        .await
        .expect("chunked request");
    assert_eq!(response.status(), 200);
    let _ = response.bytes().await;

    let unknown_length = r#""reason":"unknown_length""#;
    let logs = harness
        .wait_for_logs(|output| output.contains(unknown_length))
        .await;
    assert!(
        logs.contains(unknown_length),
        "chunked request must report an unknown_length omission:\n{logs}"
    );
    assert!(
        !logs.contains("carol"),
        "an unknown-length body must never be captured:\n{logs}"
    );
}
