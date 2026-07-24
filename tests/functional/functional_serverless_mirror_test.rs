//! Functional Tests for Serverless Function and Request Mirror Plugins (E2E)
//!
//! Tests:
//! - Serverless function plugin in "terminate" mode (bypasses backend, returns function response)
//! - Request mirror plugin (fire-and-forget copy to a secondary destination)
//!
//! All tests use file mode with ephemeral ports and mock HTTP servers.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_serverless_mirror

use bytes::Bytes;
use http_body_util::{BodyExt, Full};
use hyper::Request;
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::io::Write;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::sleep;

// ============================================================================
// Mock Server Helpers
// ============================================================================

/// Start a simple HTTP backend that returns a distinctive JSON body.
async fn start_backend_server(port: u16) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind backend server");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let body = r#"{"source":"backend"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Start a mock serverless function endpoint that returns a custom response.
async fn start_function_server(port: u16, invocations: Arc<AtomicUsize>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind function server");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let invocations = Arc::clone(&invocations);
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let n = stream.read(&mut buf).await.unwrap_or(0);
                invocations.fetch_add(1, Ordering::SeqCst);

                let request = String::from_utf8_lossy(&buf[..n]);
                let is_governed_partial_response =
                    request.contains(r#""path":"/fn/range-governed""#);
                let is_governed_delta_response = request.contains(r#""path":"/fn/delta-governed""#);
                let is_partial_response = request.contains(r#""path":"/fn/range""#);
                let is_delta_response = request.contains(r#""path":"/fn/delta""#);
                let response = if is_governed_partial_response {
                    let body =
                        r#"{"choices":[{"message":{"content":"contact secret@example.com"}}]}"#;
                    format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Type: application/json\r\nContent-Range: bytes 0-66/100\r\nAccept-Ranges: bytes\r\nETag: \"partial-sensitive-v1\"\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else if is_governed_delta_response {
                    let body = r#"{"choices":[{"message":{"tool_calls":[{"type":"function","function":{"name":"filesystem.write","arguments":"{\"token\":\"sk-SECRET123\"}"}}]}}]}"#;
                    format!(
                        "HTTP/1.1 226 IM Used\r\nContent-Length: {}\r\nContent-Type: application/json\r\nIM: diffe\r\nDelta-Base: \"delta-sensitive-v1\"\r\nETag: \"delta-sensitive-v2\"\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else if is_partial_response {
                    let body = r#"{"source":"serverless-function","message":"partial"}"#;
                    format!(
                        "HTTP/1.1 206 Partial Content\r\nContent-Length: {}\r\nContent-Type: application/json\r\nContent-Range: bytes 0-51/100\r\nAccept-Ranges: bytes\r\nETag: \"partial-v1\"\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else if is_delta_response {
                    let body = r#"{"source":"serverless-function","message":"delta"}"#;
                    format!(
                        "HTTP/1.1 226 IM Used\r\nContent-Length: {}\r\nContent-Type: application/json\r\nIM: diffe\r\nDelta-Base: \"delta-v1\"\r\nETag: \"delta-v2\"\r\nConnection: close\r\n\r\n{}",
                        body.len(),
                        body
                    )
                } else {
                    let body =
                        r#"{"source":"serverless-function","message":"hello from function"}"#;
                    format!(
                        "HTTP/1.1 429 Too Many Requests\r\nContent-Length: {}\r\nContent-Type: application/json\r\nRetry-After: 30\r\nWWW-Authenticate: Bearer realm=function\r\nTraceparent: 00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01\r\nX-RateLimit-Remaining: 0\r\nETag: \"function-v1\"\r\nLast-Modified: Wed, 01 Jan 2025 00:00:00 GMT\r\nDigest: sha-256=stale\r\nContent-Digest: sha-256=:stale:\r\nRepr-Digest: sha-256=:stale:\r\nContent-MD5: stale-md5\r\nContent-Range: bytes 0-63/64\r\nAccept-Ranges: bytes\r\nSignature-Input: sig1=(\"content-digest\")\r\nSignature: sig1=:stale:\r\nContent-Disposition: attachment; filename=decision.json\r\nSet-Cookie: first=1; Path=/\r\nSet-Cookie: second=2; Path=/\r\nConnection: close, x-function-internal\r\nX-Function-Internal: strip-me\r\nX-Amz-Request-Id: provider-control\r\n\r\n{}",
                        body.len(),
                        body
                    )
                };
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Start a mock mirror server that sets a flag when it receives a request.
async fn start_mirror_server(port: u16, called: Arc<AtomicBool>) {
    let listener = TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind mirror server");

    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            let called = called.clone();
            tokio::spawn(async move {
                let mut buf = vec![0u8; 8192];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                // Mark that the mirror received a request
                called.store(true, Ordering::SeqCst);

                let body = r#"{"source":"mirror"}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: application/json\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

// ============================================================================
// Gateway Helpers
// ============================================================================

/// Detect the gateway binary path (debug preferred, fallback to release).
fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

/// Start the gateway in file mode with the given config and ports.
fn start_gateway(config_path: &str, proxy_port: u16, admin_port: u16) -> std::process::Child {
    let binary_path = gateway_binary_path();

    std::process::Command::new(binary_path)
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "debug")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

/// Wait for the gateway admin health endpoint to respond.
/// Returns true if healthy, false if timed out.
async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);

    for _ in 0..60 {
        if let Ok(resp) = client.get(&health_url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

/// Allocate an ephemeral port by binding to port 0 and returning the assigned port.
async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

/// Start the gateway with retry logic for port allocation races.
/// Allocates fresh gateway/admin ports each attempt.
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let mut child = start_gateway(config_path, proxy_port, admin_port);

        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (proxy_port={}, admin_port={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        let _ = child.kill();
        let _ = child.wait();

        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("Gateway did not start after {} attempts", MAX_ATTEMPTS);
}

// ============================================================================
// Functional Tests
// ============================================================================

/// Test serverless_function plugin in terminate mode.
///
/// The gateway should call the mock function URL and return its response
/// directly to the client, bypassing the backend entirely.
#[ignore]
#[tokio::test]
async fn test_serverless_function_terminate_mode() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let backend_port = ephemeral_port().await;
    let function_port = ephemeral_port().await;

    let config_content = format!(
        r#"
version: "1"
proxies:
  - id: "serverless-proxy"
    listen_path: "/fn"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "dedup-1"
      - plugin_config_id: "serverless-1"
      - plugin_config_id: "response-transformer-1"
      - plugin_config_id: "tool-governor-1"
      - plugin_config_id: "response-guard-1"
consumers: []
plugin_configs:
  - id: "dedup-1"
    proxy_id: "serverless-proxy"
    plugin_name: "request_deduplication"
    scope: "proxy"
    enabled: true
    config:
      applicable_methods: ["GET", "HEAD"]
  - id: "serverless-1"
    proxy_id: "serverless-proxy"
    plugin_name: "serverless_function"
    scope: "proxy"
    enabled: true
    config:
      provider: "gcp_cloud_functions"
      mode: "terminate"
      function_url: "http://127.0.0.1:{function_port}/function"
      timeout_ms: 5000
  - id: "response-transformer-1"
    proxy_id: "serverless-proxy"
    plugin_name: "response_transformer"
    scope: "proxy"
    enabled: true
    config:
      rules:
        - operation: "update"
          target: "body"
          key: "source"
          value: "gateway-rewritten"
  - id: "tool-governor-1"
    proxy_id: "serverless-proxy"
    plugin_name: "ai_tool_governor"
    scope: "proxy"
    enabled: true
    config:
      tools:
        filesystem.write:
          action: "redact_args"
          blocked_arg_patterns:
            - name: "secret"
              regex: "sk-[A-Za-z0-9]+"
  - id: "response-guard-1"
    proxy_id: "serverless-proxy"
    plugin_name: "ai_response_guard"
    scope: "proxy"
    enabled: true
    config:
      pii_patterns: ["email"]
      action: "redact"
upstreams: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 5
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    // Start both backend and function servers
    let _backend = tokio::spawn(start_backend_server(backend_port));
    let function_invocations = Arc::new(AtomicUsize::new(0));
    let _function = tokio::spawn(start_function_server(
        function_port,
        Arc::clone(&function_invocations),
    ));
    sleep(Duration::from_millis(300)).await;

    // Start gateway with retry
    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send request through the gateway
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/fn/test", proxy_port))
        .header("idempotency-key", "h1-terminal-key")
        .send()
        .await
        .expect("Request failed");

    assert_eq!(
        resp.status().as_u16(),
        429,
        "Expected 429 from serverless function, got {}",
        resp.status()
    );
    assert_eq!(
        resp.headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("30")
    );
    for invalidated in [
        "etag",
        "last-modified",
        "digest",
        "content-digest",
        "repr-digest",
        "content-md5",
        "content-range",
        "accept-ranges",
        "signature-input",
        "signature",
    ] {
        assert!(
            !resp.headers().contains_key(invalidated),
            "rewritten response retained stale {invalidated}"
        );
    }
    assert_eq!(
        resp.headers()
            .get("content-disposition")
            .and_then(|value| value.to_str().ok()),
        Some("attachment; filename=decision.json")
    );
    assert_eq!(resp.headers().get_all("set-cookie").iter().count(), 2);
    assert!(resp.headers().contains_key("www-authenticate"));
    assert!(resp.headers().contains_key("traceparent"));
    assert!(resp.headers().contains_key("x-ratelimit-remaining"));
    assert!(!resp.headers().contains_key("connection"));
    assert!(!resp.headers().contains_key("x-function-internal"));
    assert!(!resp.headers().contains_key("x-amz-request-id"));

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("gateway-rewritten"),
        "Response should be the transformed serverless body. Got: {}",
        body
    );
    assert!(
        !body.contains(r#""source":"backend"#),
        "Response should NOT come from the backend. Got: {}",
        body
    );
    assert_eq!(function_invocations.load(Ordering::SeqCst), 1);

    let replay = client
        .get(format!("http://127.0.0.1:{}/fn/test", proxy_port))
        .header("idempotency-key", "h1-terminal-key")
        .send()
        .await
        .expect("H1 replay request failed");
    assert_eq!(replay.status().as_u16(), 429);
    assert_eq!(
        replay
            .headers()
            .get("x-idempotent-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    for sanitized in [
        "retry-after",
        "www-authenticate",
        "traceparent",
        "x-ratelimit-remaining",
    ] {
        assert!(
            !replay.headers().contains_key(sanitized),
            "dedup replay retained per-request {sanitized}"
        );
    }
    assert_eq!(replay.headers().get_all("set-cookie").iter().count(), 0);
    assert!(replay.text().await.unwrap().contains("gateway-rewritten"));
    assert_eq!(function_invocations.load(Ordering::SeqCst), 1);

    // Exercise the same terminate contract over an H2 frontend connection.
    let stream = TcpStream::connect(("127.0.0.1", proxy_port))
        .await
        .expect("connect H2 frontend");
    let (mut sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .expect("H2 handshake");
    let connection_task = tokio::spawn(async move {
        let _ = connection.await;
    });
    let request = Request::builder()
        .method("GET")
        .uri("http://example.com/fn/h2")
        .header("host", "example.com")
        .header("idempotency-key", "h2-terminal-key")
        .body(Full::new(Bytes::new()))
        .expect("build H2 request");
    let response = sender.send_request(request).await.expect("H2 request");
    assert_eq!(response.status().as_u16(), 429);
    assert_eq!(
        response
            .headers()
            .get("retry-after")
            .and_then(|value| value.to_str().ok()),
        Some("30")
    );
    assert!(!response.headers().contains_key("etag"));
    assert!(!response.headers().contains_key("content-digest"));
    assert_eq!(response.headers().get_all("set-cookie").iter().count(), 2);
    assert!(!response.headers().contains_key("x-function-internal"));
    let h2_body = response
        .into_body()
        .collect()
        .await
        .expect("collect H2 response")
        .to_bytes();
    assert!(String::from_utf8_lossy(&h2_body).contains("gateway-rewritten"));
    assert_eq!(function_invocations.load(Ordering::SeqCst), 2);

    let replay_request = Request::builder()
        .method("GET")
        .uri("http://example.com/fn/h2")
        .header("host", "example.com")
        .header("idempotency-key", "h2-terminal-key")
        .body(Full::new(Bytes::new()))
        .expect("build H2 replay request");
    let replay_response = sender
        .send_request(replay_request)
        .await
        .expect("H2 replay request");
    assert_eq!(replay_response.status().as_u16(), 429);
    assert_eq!(
        replay_response
            .headers()
            .get("x-idempotent-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    let replay_body = replay_response
        .into_body()
        .collect()
        .await
        .expect("collect H2 replay response")
        .to_bytes();
    assert!(String::from_utf8_lossy(&replay_body).contains("gateway-rewritten"));
    assert_eq!(function_invocations.load(Ordering::SeqCst), 2);
    connection_task.abort();

    let head = client
        .head(format!("http://127.0.0.1:{}/fn/head", proxy_port))
        .header("idempotency-key", "head-terminal-key")
        .send()
        .await
        .expect("HEAD request failed");
    assert_eq!(head.status().as_u16(), 429);
    assert!(head.bytes().await.unwrap().is_empty());
    assert_eq!(function_invocations.load(Ordering::SeqCst), 3);

    let head_replay = client
        .head(format!("http://127.0.0.1:{}/fn/head", proxy_port))
        .header("idempotency-key", "head-terminal-key")
        .send()
        .await
        .expect("HEAD replay request failed");
    assert_eq!(head_replay.status().as_u16(), 429);
    assert_eq!(
        head_replay
            .headers()
            .get("x-idempotent-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true")
    );
    assert!(head_replay.bytes().await.unwrap().is_empty());
    assert_eq!(function_invocations.load(Ordering::SeqCst), 3);

    let partial = client
        .get(format!("http://127.0.0.1:{}/fn/range", proxy_port))
        .send()
        .await
        .expect("partial response request failed");
    // This proxy configures a `response_transformer` body rule over JSON, so the
    // shared representation gate claims every JSON response here — including this
    // `206`. The gateway cannot fetch the remaining ranges, so it cannot prove the
    // configured rule applied to the complete resource: the fragment is rejected
    // rather than forwarded with the rule silently unapplied. Forwarding it is the
    // bypass GHSA-62h9-7rm5-7vqm describes, and the fragment's own range/validator
    // metadata must not survive onto the replacement response.
    assert_eq!(partial.status().as_u16(), 502);
    assert!(!partial.headers().contains_key("content-range"));
    assert!(!partial.headers().contains_key("etag"));
    let partial_body = partial.text().await.unwrap();
    assert!(
        !partial_body.contains("serverless-function"),
        "the uninspectable fragment body must not reach the client: {partial_body}"
    );
    assert_eq!(function_invocations.load(Ordering::SeqCst), 4);

    let delta = client
        .get(format!("http://127.0.0.1:{}/fn/delta", proxy_port))
        .send()
        .await
        .expect("delta response request failed");
    // Same contract for a `226` delta: the gateway does not apply the delta, so it
    // cannot produce the complete resource the configured rule was written for.
    assert_eq!(delta.status().as_u16(), 502);
    assert!(!delta.headers().contains_key("im"));
    assert!(!delta.headers().contains_key("delta-base"));
    assert!(!delta.headers().contains_key("etag"));
    let delta_body = delta.text().await.unwrap();
    assert!(
        !delta_body.contains("serverless-function"),
        "the uninspectable delta body must not reach the client: {delta_body}"
    );
    assert_eq!(function_invocations.load(Ordering::SeqCst), 5);

    let governed_partial = client
        .get(format!("http://127.0.0.1:{}/fn/range-governed", proxy_port))
        .send()
        .await
        .expect("governed partial response request failed");
    assert_eq!(governed_partial.status().as_u16(), 502);
    assert!(!governed_partial.headers().contains_key("content-range"));
    assert!(!governed_partial.headers().contains_key("etag"));
    let governed_partial_body = governed_partial.text().await.unwrap();
    assert!(!governed_partial_body.contains("secret@example.com"));
    assert_eq!(function_invocations.load(Ordering::SeqCst), 6);

    let governed_delta = client
        .get(format!("http://127.0.0.1:{}/fn/delta-governed", proxy_port))
        .send()
        .await
        .expect("governed delta response request failed");
    assert_eq!(governed_delta.status().as_u16(), 502);
    assert!(!governed_delta.headers().contains_key("im"));
    assert!(!governed_delta.headers().contains_key("delta-base"));
    let governed_delta_body = governed_delta.text().await.unwrap();
    assert!(!governed_delta_body.contains("sk-SECRET123"));
    assert_eq!(function_invocations.load(Ordering::SeqCst), 7);

    // Unprotected fragment pass-through (a `206`/`226` no configured body policy
    // claims) is proven in `tests/unit/gateway_core/response_representation_tests.rs`
    // rather than here: every plugin on this proxy is a governing one, and
    // `ai_response_guard` independently fails closed on a non-JSON body, so this
    // proxy cannot express an unclaimed response.

    let _ = gw.kill();
    let _ = gw.wait();
}

/// Test request_mirror plugin sends a copy of the request to the mirror server.
///
/// The primary backend should respond normally, and the mirror server should
/// also receive the request (verified via a shared AtomicBool flag).
#[ignore]
#[tokio::test]
async fn test_request_mirror_sends_copy() {
    let temp_dir = TempDir::new().expect("Failed to create temp dir");
    let config_path = temp_dir.path().join("config.yaml");

    let backend_port = ephemeral_port().await;
    let mirror_port = ephemeral_port().await;

    let config_content = format!(
        r#"
version: "1"
proxies:
  - id: "mirror-proxy"
    listen_path: "/api"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port: ''}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "mirror-1"
consumers: []
plugin_configs:
  - id: "mirror-1"
    proxy_id: "mirror-proxy"
    plugin_name: "request_mirror"
    scope: "proxy"
    enabled: true
    config:
      mirror_host: "127.0.0.1"
      mirror_port: {mirror_port: ''}
      mirror_protocol: "http"
      percentage: 100.0
upstreams: []
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 1
"#
    );

    let mut f = std::fs::File::create(&config_path).unwrap();
    f.write_all(config_content.as_bytes()).unwrap();
    drop(f);

    // Shared flag to verify the mirror received the request
    let mirror_called = Arc::new(AtomicBool::new(false));

    // Start backend and mirror servers
    let _backend = tokio::spawn(start_backend_server(backend_port));
    let _mirror = tokio::spawn(start_mirror_server(mirror_port, mirror_called.clone()));
    sleep(Duration::from_millis(300)).await;

    // Start gateway with retry
    let (mut gw, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    // Send request through the gateway
    let client = reqwest::Client::new();
    let resp = client
        .get(format!("http://127.0.0.1:{}/api/test", proxy_port))
        .send()
        .await
        .expect("Request failed");

    // Primary backend should respond normally
    assert_eq!(
        resp.status().as_u16(),
        200,
        "Expected 200 from primary backend, got {}",
        resp.status()
    );

    let body = resp.text().await.unwrap();
    assert!(
        body.contains("backend"),
        "Response should come from the primary backend. Got: {}",
        body
    );

    // Give the fire-and-forget mirror request time to complete
    sleep(Duration::from_millis(500)).await;

    // Verify the mirror server received the request
    assert!(
        mirror_called.load(Ordering::SeqCst),
        "Mirror server should have received a copy of the request"
    );

    let _ = gw.kill();
    let _ = gw.wait();
}
