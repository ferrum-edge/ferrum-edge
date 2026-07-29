//! Functional Tests for `ai_semantic_firewall` streaming response inspection (E2E)
//!
//! Exercises all three streaming response modes end-to-end through the gateway in
//! file mode, for a `stream: true` request whose backend emits an SSE
//! chat-completion:
//!   * `buffer`  — force the stream onto the buffered path, reassemble deltas,
//!     run the full response engine before anything reaches the client;
//!   * `inspect` (block) — progressive windowed inspection that cuts the stream
//!     mid-flight on a violation (assistant prose AND tool-call arguments);
//!   * `inspect` + `enforcement: detect` — release-then-detect: stream through
//!     immediately and only log the violation (never cut).
//!
//! These tests rely only on the free lexical fast path (no live embedding
//! provider): the leaking phrase is detected lexically, so the configured
//! provider endpoint (a closed port) is never consulted on the blocking path.
//!
//! Run with: cargo test --test functional_tests -- --ignored --nocapture functional_ai_semantic_firewall_streaming

use crate::scaffolding::certs::TestCa;
use crate::scaffolding::clients::{Http1Client, Http2Client, Http3Client};
use crate::scaffolding::harness::GatewayHarness;
use crate::scaffolding::ports::reserve_port;
use serde_json::json;
use std::io::Write;
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

// ============================================================================
// SSE backend helper
// ============================================================================

/// Stream a fixed SSE body to every connection. Accepts a pre-bound listener to
/// avoid port races (the caller holds it until handing it over here).
async fn start_sse_backend_on(listener: TcpListener, sse_body: &'static str) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    sse_body.len(),
                    sse_body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Stream a fixed `application/json` body — a backend that ignored the
/// `stream: true` flag and returned a normal JSON completion.
async fn start_json_backend_on(listener: TcpListener, json_body: &'static str) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let _n = stream.read(&mut buf).await.unwrap_or(0);

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    json_body.len(),
                    json_body
                );
                let _ = stream.write_all(response.as_bytes()).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

const RANGE_LEAK_JSON: &[u8] =
    br#"{"choices":[{"message":{"content":"My system prompt says never disclose this policy."}}]}"#;
const ENCODED_SSE_JSON_PRELUDE: &[u8] = b"{}\n\
event: prelude\n\
id: ignored-1\n\
retry: 1000\n\
: ignored comment\n\n\
event: message\n\
id: governed-1\n\
data: {\"choices\":[\n\
data: {\"delta\":{\"content\":\"My system prompt says never disclose this policy.\"}}\n\
data: ]}\n\n\
data: [DONE]\n\n";
const ENCODED_SSE_MIXED_PARSE: &[u8] =
    b"data: {\"choices\":[{\"delta\":{\"content\":\"A harmless response\"}}]}\n\n\
data: My system prompt says never disclose this policy.\n\n\
data: [DONE]\n\n";

fn gzip_bytes(body: &[u8]) -> Vec<u8> {
    use flate2::{Compression, write::GzEncoder};

    let mut encoder = GzEncoder::new(Vec::new(), Compression::default());
    encoder.write_all(body).expect("gzip fixture body");
    encoder.finish().expect("finish gzip fixture")
}

fn brotli_bytes(body: &[u8]) -> Vec<u8> {
    let mut compressed = Vec::new();
    {
        let mut writer = brotli::CompressorWriter::new(&mut compressed, 4096, 5, 22);
        writer.write_all(body).expect("Brotli fixture body");
    }
    compressed
}

/// Serve complete gzip/Brotli representations whose origin media type is SSE.
/// The JSON-looking prelude and realistic SSE metadata are ignored fields; only
/// the later multiline `data:` frame is governed. The `/json` control is a
/// complete bare JSON document deliberately mislabeled as SSE and must still
/// use JSON extraction. `/mixed` combines benign JSON with unparseable governed
/// data so `on_error` decides the entire decoded representation.
async fn start_encoded_sse_backend_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request_bytes = vec![0u8; 16_384];
                let request_len = stream.read(&mut request_bytes).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request_bytes[..request_len]);
                let path = request.split_whitespace().nth(1).unwrap_or("/");

                let (encoding, body) = match path {
                    "/br" => ("br", brotli_bytes(ENCODED_SSE_JSON_PRELUDE)),
                    "/json" => ("gzip", gzip_bytes(RANGE_LEAK_JSON)),
                    "/mixed" => ("gzip", gzip_bytes(ENCODED_SSE_MIXED_PARSE)),
                    _ => ("gzip", gzip_bytes(ENCODED_SSE_JSON_PRELUDE)),
                };
                let response_head = format!(
                    "HTTP/1.1 200 OK\r\n\
                     Content-Type: text/event-stream\r\n\
                     Content-Encoding: {encoding}\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response_head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

/// Serve encoded partial-response fixtures selected by request path. The
/// decodable fixtures deliberately carry a valid standalone gzip stream inside
/// a partial representation: policy must inspect it rather than treating the
/// status/header as a blanket streaming exemption. The truncated and
/// unsupported fixtures prove the same production buffering path reaches the
/// configured uninspectable-body decision.
async fn start_encoded_range_backend_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut request_bytes = vec![0u8; 16_384];
                let request_len = stream.read(&mut request_bytes).await.unwrap_or(0);
                let request = String::from_utf8_lossy(&request_bytes[..request_len]);
                let path = request.split_whitespace().nth(1).unwrap_or("/");

                let (status, encoding, body) = match path {
                    "/truncated" => {
                        let complete = gzip_bytes(RANGE_LEAK_JSON);
                        (206, "gzip", complete[1..complete.len() - 1].to_vec())
                    }
                    "/unsupported" => (206, "zstd", b"unsupported fragment".to_vec()),
                    "/identity" => (206, "identity", RANGE_LEAK_JSON.to_vec()),
                    "/content-range-only" => (200, "gzip", gzip_bytes(RANGE_LEAK_JSON)),
                    _ => (206, "gzip", gzip_bytes(RANGE_LEAK_JSON)),
                };
                let range_start = 128usize;
                let range_end = range_start + body.len().saturating_sub(1);
                let range_total = range_end + 129;
                let reason = if status == 206 {
                    "Partial Content"
                } else {
                    "OK"
                };
                let response_head = format!(
                    "HTTP/1.1 {status} {reason}\r\n\
                     Content-Type: application/json\r\n\
                     Content-Encoding: {encoding}\r\n\
                     Content-Range: bytes {range_start}-{range_end}/{range_total}\r\n\
                     Content-Length: {}\r\n\
                     Connection: close\r\n\r\n",
                    body.len()
                );
                let _ = stream.write_all(response_head.as_bytes()).await;
                let _ = stream.write_all(&body).await;
                let _ = stream.shutdown().await;
            });
        }
    }
}

fn encoded_response_config(backend_port: u16, listen_path: &str, on_error: &str) -> String {
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "asf-range-proxy",
            "listen_path": listen_path,
            "backend_scheme": "http",
            "backend_host": "127.0.0.1",
            "backend_port": backend_port,
            "strip_listen_path": true,
            "plugins": [{"plugin_config_id": "asf-range"}],
        }],
        "consumers": [],
        "upstreams": [],
        "plugin_configs": [{
            "id": "asf-range",
            "proxy_id": "asf-range-proxy",
            "plugin_name": "ai_semantic_firewall",
            "scope": "proxy",
            "enabled": true,
            "config": {
                "inspect": {"request": false, "response": true},
                "on_error": on_error,
                "provider": {
                    "type": "openai_compatible_embeddings",
                    "endpoint": "http://127.0.0.1:9/v1/embeddings",
                    "model": "test-embedding-model",
                    "request_timeout_ms": 500,
                },
                "builtins": {"response_leakage": true},
            },
        }],
    });
    serde_yaml::to_string(&config).expect("serialize encoded-response config")
}

async fn start_encoded_response_h3_gateway(config: String) -> (GatewayHarness, TempDir, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    let mut last_error = None;
    for attempt in 1..=MAX_ATTEMPTS {
        let reservation = reserve_port().await.expect("reserve H3 frontend port");
        let https_port = reservation.port;
        drop(reservation);

        let tls_dir = TempDir::new().expect("frontend TLS temp dir");
        let ca = TestCa::new(&format!("asf-encoded-h3-{attempt}")).expect("frontend test CA");
        let (cert, key) = ca.valid().expect("frontend leaf certificate");
        let cert_path = tls_dir.path().join("gateway.cert.pem");
        let key_path = tls_dir.path().join("gateway.key.pem");
        std::fs::write(&cert_path, cert).expect("write frontend certificate");
        std::fs::write(&key_path, key).expect("write frontend key");

        let result = GatewayHarness::builder()
            .file_config(config.clone())
            .pool_warmup_enabled(false)
            .max_attempts(1)
            .env("FERRUM_ENABLE_HTTP3", "true")
            .env("FERRUM_PROXY_HTTPS_PORT", https_port.to_string())
            .env(
                "FERRUM_FRONTEND_TLS_CERT_PATH",
                cert_path.to_string_lossy().into_owned(),
            )
            .env(
                "FERRUM_FRONTEND_TLS_KEY_PATH",
                key_path.to_string_lossy().into_owned(),
            )
            .spawn()
            .await;
        match result {
            Ok(harness) => return (harness, tls_dir, https_port),
            Err(error) => {
                last_error = Some(error.to_string());
                if attempt < MAX_ATTEMPTS {
                    sleep(Duration::from_secs(1)).await;
                }
            }
        }
    }
    panic!(
        "encoded-range H3 gateway failed after {MAX_ATTEMPTS} attempts: {}",
        last_error.unwrap_or_else(|| "no startup error recorded".to_string())
    );
}

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

fn start_gateway(config_path: &str, proxy_port: u16, admin_port: u16) -> std::process::Child {
    std::process::Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_LOG_LEVEL", "debug")
        // No backend-hit assertions here, but disable warmup so the startup
        // HEAD probe doesn't race the single-shot SSE backend.
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("Failed to start gateway binary")
}

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

/// Start the gateway with retry on port-binding failures, allocating fresh
/// ephemeral ports each attempt to survive the bind-drop-rebind race.
async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    const MAX_ATTEMPTS: u32 = 3;
    for attempt in 1..=MAX_ATTEMPTS {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);

        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        let mut child = start_gateway(config_path, proxy_port, admin_port);

        if wait_for_gateway(admin_port).await {
            return (child, proxy_port, admin_port);
        }

        eprintln!(
            "Gateway startup attempt {}/{} failed (ports: proxy={}, admin={})",
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

/// File-mode config: a single proxy with `ai_semantic_firewall` in `buffer`
/// streaming mode, response-only inspection, lexical `response_leakage`.
fn buffer_mode_config(backend_port: u16) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "asf-proxy"
    listen_path: "/ai"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "asf-1"

consumers: []

plugin_configs:
  - id: "asf-1"
    proxy_id: "asf-proxy"
    plugin_name: "ai_semantic_firewall"
    scope: "proxy"
    enabled: true
    config:
      inspect:
        request: false
        response: true
      streaming_response: "buffer"
      on_error: "warn"
      provider:
        type: "openai_compatible_embeddings"
        endpoint: "http://127.0.0.1:9/v1/embeddings"
        model: "test-embedding-model"
        request_timeout_ms: 500
      builtins:
        prompt_injection: false
        jailbreak: false
        system_prompt_exfiltration: false
        data_exfiltration: false
        indirect_prompt_injection: false
        tool_abuse: false
        response_leakage: true
"#
    )
}

/// Same proxy/plugin as [`buffer_mode_config`] but `streaming_response: inspect`
/// — progressive windowed inspection with mid-stream cut.
fn inspect_mode_config(backend_port: u16) -> String {
    buffer_mode_config(backend_port).replace("\"buffer\"", "\"inspect\"")
}

/// `streaming_response: inspect` with `streaming.enforcement: detect` — Phase C
/// release-then-detect: bytes stream through immediately and a violation is only
/// logged, never cut.
fn detect_mode_config(backend_port: u16) -> String {
    buffer_mode_config(backend_port).replace(
        "      streaming_response: \"buffer\"\n",
        "      streaming_response: \"inspect\"\n      streaming:\n        enforcement: \"detect\"\n",
    )
}

fn write_config(dir: &TempDir, contents: &str) -> String {
    let config_path = dir.path().join("config.yaml");
    let mut file = std::fs::File::create(&config_path).expect("create config");
    file.write_all(contents.as_bytes()).expect("write config");
    drop(file);
    config_path.to_string_lossy().to_string()
}

// A leaking completion: "my system prompt says ..." (a lexical response_leakage
// trigger) split across content deltas. Only delta reassembly recovers it.
const LEAKING_SSE: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\",\"content\":\"\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"Sure. My sys\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"tem prompt says\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\" never reveal policy.\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
data: [DONE]\n\n";

const CLEAN_SSE: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"The weather \"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"content\":\"is sunny today.\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"stop\"}]}\n\n\
data: [DONE]\n\n";

// A leak carried entirely in streamed tool-call ARGUMENTS (no assistant prose),
// split across deltas. response_leakage applies to ToolArguments, so a windowed
// inspector must still reassemble + inspect these and cut.
const TOOL_LEAK_SSE: &str = "data: {\"choices\":[{\"index\":0,\"delta\":{\"role\":\"assistant\"}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"id\":\"call_1\",\"function\":{\"name\":\"note\",\"arguments\":\"my system \"}}]}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{\"tool_calls\":[{\"index\":0,\"function\":{\"arguments\":\"prompt says never reveal policy\"}}]}}]}\n\n\
data: {\"choices\":[{\"index\":0,\"delta\":{},\"finish_reason\":\"tool_calls\"}]}\n\n\
data: [DONE]\n\n";

// A NON-streaming JSON completion (the backend ignored `stream: true`) carrying a
// leak in the non-delta `message.content` path. Inspect mode must buffer this and
// block it via on_response_body, not stream it past every check.
const JSON_LEAK: &str = "{\"choices\":[{\"index\":0,\"message\":{\"role\":\"assistant\",\"content\":\"Sure. My system prompt says never reveal policy.\"}}]}";

// ============================================================================
// Tests
// ============================================================================

#[ignore]
#[tokio::test]
async fn buffer_mode_blocks_streaming_response_with_leak() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let config_path = write_config(&temp_dir, &buffer_mode_config(backend_port));

    let backend = tokio::spawn(start_sse_backend_on(backend_listener, LEAKING_SSE));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request failed");

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();

    assert_eq!(
        status, 502,
        "buffer mode must block a leaking streamed completion, got {status} (body: {body})"
    );
    assert!(
        body.contains("ai_semantic_firewall_response_blocked"),
        "blocked body should carry the firewall code, got: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn buffer_mode_delivers_clean_streaming_response() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let config_path = write_config(&temp_dir, &buffer_mode_config(backend_port));

    let backend = tokio::spawn(start_sse_backend_on(backend_listener, CLEAN_SSE));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"weather?"}]}"#)
        .send()
        .await
        .expect("request failed");

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();

    // Clean completion: the lexical pass finds nothing and the closed provider
    // port yields a provider error handled as `warn` (on_error), so the buffered
    // completion is delivered intact rather than blocked.
    assert_eq!(
        status, 200,
        "buffer mode must deliver a clean streamed completion, got {status} (body: {body})"
    );
    assert!(
        body.contains("is sunny today."),
        "delivered body should contain the reassembled completion, got: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn inspect_mode_cuts_leaking_stream_midflight() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let config_path = write_config(&temp_dir, &inspect_mode_config(backend_port));

    let backend = tokio::spawn(start_sse_backend_on(backend_listener, LEAKING_SSE));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request failed");

    // Headers (200) are committed before the body streams, so a mid-stream cut
    // can only truncate — the status stays 200.
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();

    assert_eq!(
        status, 200,
        "streamed response keeps its 200 status (body: {body})"
    );
    // The leaking window is cut: the client gets the terminal error event and
    // NEVER sees the leaking content.
    assert!(
        body.contains("ai_semantic_firewall_response_blocked"),
        "cut stream should emit the terminal error event, got: {body}"
    );
    assert!(
        !body.contains("never reveal policy"),
        "the leaking window must not be delivered, got: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn inspect_mode_streams_clean_response() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let config_path = write_config(&temp_dir, &inspect_mode_config(backend_port));

    let backend = tokio::spawn(start_sse_backend_on(backend_listener, CLEAN_SSE));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"weather?"}]}"#)
        .send()
        .await
        .expect("request failed");

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();

    assert_eq!(
        status, 200,
        "clean stream is delivered, got {status} (body: {body})"
    );
    assert!(
        body.contains("is sunny today."),
        "clean windows should be released to the client, got: {body}"
    );
    assert!(
        !body.contains("ai_semantic_firewall_response_blocked"),
        "a clean stream must not emit the cut error event, got: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn inspect_mode_cuts_leaking_tool_call_stream() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let config_path = write_config(&temp_dir, &inspect_mode_config(backend_port));

    let backend = tokio::spawn(start_sse_backend_on(backend_listener, TOOL_LEAK_SSE));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request failed");

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();

    assert_eq!(status, 200, "streamed response keeps its 200 status");
    // The leak lives only in tool-call arguments, yet the windowed inspector
    // reassembles + inspects them and cuts the stream.
    assert!(
        body.contains("ai_semantic_firewall_response_blocked"),
        "a leaking tool-call stream must be cut, got: {body}"
    );
    assert!(
        !body.contains("never reveal policy"),
        "the leaking tool arguments must not be delivered, got: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn inspect_detect_mode_forwards_leak_without_cutting() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let config_path = write_config(&temp_dir, &detect_mode_config(backend_port));

    let backend = tokio::spawn(start_sse_backend_on(backend_listener, LEAKING_SSE));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request failed");

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();

    // detect mode is release-then-detect: it never cuts, so the (leaking) stream
    // is delivered in full and only logged. This is the deliberate contrast with
    // block mode's `inspect_mode_cuts_leaking_stream_midflight`.
    assert_eq!(status, 200, "detect mode delivers the stream, got {status}");
    assert!(
        body.contains("never reveal policy"),
        "detect mode forwards the content (no cut), got: {body}"
    );
    assert!(
        !body.contains("ai_semantic_firewall_response_blocked"),
        "detect mode must NOT emit the cut error event, got: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn inspect_mode_buffers_and_blocks_non_sse_json_leak() {
    // A backend that ignored stream:true and returned a JSON completion: inspect
    // mode must BUFFER it (the windowed inspector only handles SSE) and block the
    // leak via on_response_body — not stream it past every check uninspected.
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let config_path = write_config(&temp_dir, &inspect_mode_config(backend_port));

    let backend = tokio::spawn(start_json_backend_on(backend_listener, JSON_LEAK));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request failed");

    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();

    // Buffered + inspected → blocked with a proper status (not a truncated 200),
    // and the leak never reaches the client. Codex round-6: this is the scenario
    // where the response was previously streamed past on_response_body.
    assert_ne!(
        status, 200,
        "a buffered JSON leak must be blocked, got 200: {body}"
    );
    assert!(
        body.contains("ai_semantic_firewall_response_blocked"),
        "a non-SSE JSON leak must be blocked by on_response_body, got: {body}"
    );
    assert!(
        !body.contains("never reveal policy"),
        "the leaking JSON content must not be delivered, got: {body}"
    );
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_partial_responses_are_buffered_and_enforced_over_h1_and_h2() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind encoded-range backend");
    let backend_port = backend_listener
        .local_addr()
        .expect("encoded-range backend address")
        .port();
    let backend = tokio::spawn(start_encoded_range_backend_on(backend_listener));
    let harness = GatewayHarness::builder()
        .file_config(encoded_response_config(backend_port, "/range", "reject"))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn encoded-range gateway");

    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    for (path, expected_code) in [
        ("decodable", "ai_semantic_firewall_response_blocked"),
        ("truncated", "ai_semantic_firewall_response_uninspectable"),
        ("unsupported", "ai_semantic_firewall_response_uninspectable"),
        ("identity", "ai_semantic_firewall_response_blocked"),
    ] {
        let response = h1
            .get(&harness.proxy_url(&format!("/range/{path}")))
            .await
            .unwrap_or_else(|error| panic!("HTTP/1.1 {path} request failed: {error}"));
        let body = response.body_text();
        assert_eq!(
            response.status.as_u16(),
            502,
            "HTTP/1.1 {path} range escaped buffered enforcement: {body}"
        );
        assert!(
            body.contains(expected_code),
            "HTTP/1.1 {path} returned the wrong firewall decision: {body}"
        );
    }

    // This backend returns 200 plus Content-Range, proving the header alone
    // keeps the response on the same buffered final-hook path. Http2Client
    // requires prior-knowledge H2 and asserts the response version internally.
    let h2 = Http2Client::h2c_prior_knowledge().expect("HTTP/2 client");
    let response = h2
        .get(&harness.proxy_url("/range/content-range-only"))
        .await
        .expect("HTTP/2 Content-Range request");
    let body = String::from_utf8_lossy(&response.body_bytes);
    assert_eq!(
        response.status.as_u16(),
        502,
        "HTTP/2 Content-Range response escaped buffered enforcement: {body}"
    );
    assert!(
        body.contains("ai_semantic_firewall_response_blocked"),
        "HTTP/2 Content-Range response returned the wrong firewall decision: {body}"
    );

    backend.abort();
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn encoded_partial_response_is_buffered_and_enforced_over_h3() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind encoded-range backend");
    let backend_port = backend_listener
        .local_addr()
        .expect("encoded-range backend address")
        .port();
    let backend = tokio::spawn(start_encoded_range_backend_on(backend_listener));
    let (harness, _tls_dir, https_port) = start_encoded_response_h3_gateway(
        encoded_response_config(backend_port, "/range", "reject"),
    )
    .await;

    let client = Http3Client::insecure().expect("HTTP/3 client");
    let response = client
        .get(&format!("https://127.0.0.1:{https_port}/range/decodable"))
        .await
        .expect("HTTP/3 encoded partial request");
    let body = String::from_utf8_lossy(&response.body_bytes);
    assert_eq!(
        response.status.as_u16(),
        502,
        "HTTP/3 encoded partial escaped buffered enforcement: {body}"
    );
    assert!(
        body.contains("ai_semantic_firewall_response_blocked"),
        "HTTP/3 encoded partial returned the wrong firewall decision: {body}"
    );
    assert_eq!(
        response.body_error, None,
        "HTTP/3 firewall rejection should complete cleanly"
    );

    drop(harness);
    backend.abort();
}

#[ignore]
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn decoded_sse_json_preludes_are_inspected_over_h1_h2_and_h3() {
    let backend_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind encoded-SSE backend");
    let backend_port = backend_listener
        .local_addr()
        .expect("encoded-SSE backend address")
        .port();
    let backend = tokio::spawn(start_encoded_sse_backend_on(backend_listener));
    let config = encoded_response_config(backend_port, "/sse", "allow");
    let harness = GatewayHarness::builder()
        .file_config(config.clone())
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn encoded-SSE gateway");

    let h1 = Http1Client::insecure().expect("HTTP/1.1 client");
    for path in ["gzip", "br", "json"] {
        let response = h1
            .get(&harness.proxy_url(&format!("/sse/{path}")))
            .await
            .unwrap_or_else(|error| panic!("HTTP/1.1 encoded-SSE {path} failed: {error}"));
        let body = response.body_text();
        assert_eq!(
            response.status.as_u16(),
            502,
            "HTTP/1.1 encoded-SSE {path} escaped inspection: {body}"
        );
        assert!(
            body.contains("ai_semantic_firewall_response_blocked"),
            "HTTP/1.1 encoded-SSE {path} used the wrong decision: {body}"
        );
    }

    let h2 = Http2Client::h2c_prior_knowledge().expect("HTTP/2 client");
    for path in ["gzip", "br", "json"] {
        let response = h2
            .get(&harness.proxy_url(&format!("/sse/{path}")))
            .await
            .unwrap_or_else(|error| panic!("HTTP/2 encoded-SSE {path} failed: {error}"));
        let body = String::from_utf8_lossy(&response.body_bytes);
        assert_eq!(
            response.status.as_u16(),
            502,
            "HTTP/2 encoded-SSE {path} escaped inspection: {body}"
        );
        assert!(
            body.contains("ai_semantic_firewall_response_blocked"),
            "HTTP/2 encoded-SSE {path} used the wrong decision: {body}"
        );
    }

    let response = h1
        .get(&harness.proxy_url("/sse/mixed"))
        .await
        .expect("HTTP/1.1 mixed decoded-SSE allow request");
    assert_eq!(
        response.status.as_u16(),
        200,
        "on_error=allow must deliver a partially unparseable decoded SSE body"
    );
    drop(harness);

    let (h3_harness, _tls_dir, https_port) = start_encoded_response_h3_gateway(config).await;
    let h3 = Http3Client::insecure().expect("HTTP/3 client");
    for path in ["gzip", "br", "json"] {
        let response = h3
            .get(&format!("https://127.0.0.1:{https_port}/sse/{path}"))
            .await
            .unwrap_or_else(|error| panic!("HTTP/3 encoded-SSE {path} failed: {error}"));
        let body = String::from_utf8_lossy(&response.body_bytes);
        assert_eq!(
            response.status.as_u16(),
            502,
            "HTTP/3 encoded-SSE {path} escaped inspection: {body}"
        );
        assert!(
            body.contains("ai_semantic_firewall_response_blocked"),
            "HTTP/3 encoded-SSE {path} used the wrong decision: {body}"
        );
        assert_eq!(
            response.body_error, None,
            "HTTP/3 encoded-SSE rejection should complete cleanly"
        );
    }

    drop(h3_harness);

    let reject_harness = GatewayHarness::builder()
        .file_config(encoded_response_config(backend_port, "/sse", "reject"))
        .pool_warmup_enabled(false)
        .spawn()
        .await
        .expect("spawn reject-mode encoded-SSE gateway");
    let response = h1
        .get(&reject_harness.proxy_url("/sse/mixed"))
        .await
        .expect("HTTP/1.1 mixed decoded-SSE reject request");
    let body = response.body_text();
    assert_eq!(
        response.status.as_u16(),
        502,
        "partially unparseable decoded SSE escaped reject-mode enforcement: {body}"
    );
    assert!(
        body.contains("ai_semantic_firewall_response_uninspectable"),
        "mixed decoded SSE used the wrong reject-mode decision: {body}"
    );
    assert!(
        !body.contains("My system prompt says never disclose this policy"),
        "unparseable sensitive SSE data leaked through the reject response: {body}"
    );

    drop(reject_harness);
    backend.abort();
}

// ============================================================================
// streaming.max_hold_ms — live slow-backend hold deadline (issue #3303)
// ============================================================================

/// An embeddings endpoint that accepts the TCP connection, reads the request,
/// and then never answers. This is the "deliberately slow semantic backend" the
/// hold deadline exists for: `provider.request_timeout_ms` is set far higher
/// than `streaming.max_hold_ms` in these tests, so only the hold deadline can
/// resolve the window.
async fn start_stalled_embeddings_backend_on(listener: TcpListener) {
    loop {
        if let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buf = vec![0u8; 16384];
                let _n = stream.read(&mut buf).await.unwrap_or(0);
                // Hold the connection open without replying. The gateway must
                // stop waiting on its own.
                sleep(Duration::from_secs(120)).await;
                drop(stream);
            });
        }
    }
}

/// `streaming_response: inspect` with a short absolute hold deadline against a
/// stalled embeddings provider. `on_hold_timeout` selects fail-closed/fail-open.
fn hold_timeout_config(backend_port: u16, embeddings_port: u16, on_hold_timeout: &str) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "asf-proxy"
    listen_path: "/ai"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "asf-1"

consumers: []

plugin_configs:
  - id: "asf-1"
    proxy_id: "asf-proxy"
    plugin_name: "ai_semantic_firewall"
    scope: "proxy"
    enabled: true
    config:
      inspect:
        request: false
        response: true
      streaming_response: "inspect"
      on_error: "reject"
      streaming:
        max_hold_ms: 300
        on_hold_timeout: "{on_hold_timeout}"
      provider:
        type: "openai_compatible_embeddings"
        endpoint: "http://127.0.0.1:{embeddings_port}/v1/embeddings"
        model: "test-embedding-model"
        request_timeout_ms: 15000
      builtins:
        prompt_injection: false
        jailbreak: false
        system_prompt_exfiltration: false
        data_exfiltration: false
        indirect_prompt_injection: false
        tool_abuse: false
        response_leakage: true
"#
    )
}

#[ignore]
#[tokio::test]
async fn inspect_mode_cuts_stream_when_hold_deadline_expires() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let embeddings_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let embeddings_port = embeddings_listener.local_addr().unwrap().port();
    let config_path = write_config(
        &temp_dir,
        &hold_timeout_config(backend_port, embeddings_port, "cut"),
    );

    // CLEAN_SSE never matches lexically, so the firewall must consult the
    // (stalled) semantic provider — the window is genuinely held awaiting a
    // verdict that never arrives.
    let backend = tokio::spawn(start_sse_backend_on(backend_listener, CLEAN_SSE));
    let embeddings = tokio::spawn(start_stalled_embeddings_backend_on(embeddings_listener));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let started = std::time::Instant::now();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request failed");
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    let elapsed = started.elapsed();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();
    embeddings.abort();

    assert_eq!(
        status, 200,
        "headers are committed before the body streams (body: {body})"
    );
    assert!(
        elapsed < Duration::from_secs(10),
        "hold deadline must bind before provider.request_timeout_ms (15s), took {elapsed:?}"
    );
    assert!(
        body.contains("ai_semantic_firewall_response_blocked"),
        "an expired hold under on_hold_timeout=cut emits the terminal error event, got: {body}"
    );
    assert!(
        !body.contains("sunny today"),
        "the un-inspected held window must never reach the client, got: {body}"
    );
}

#[ignore]
#[tokio::test]
async fn inspect_mode_forwards_held_window_when_configured_to_fail_open() {
    let temp_dir = TempDir::new().expect("temp dir");
    let backend_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let embeddings_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let embeddings_port = embeddings_listener.local_addr().unwrap().port();
    let config_path = write_config(
        &temp_dir,
        &hold_timeout_config(backend_port, embeddings_port, "forward"),
    );

    let backend = tokio::spawn(start_sse_backend_on(backend_listener, CLEAN_SSE));
    let embeddings = tokio::spawn(start_stalled_embeddings_backend_on(embeddings_listener));
    let (mut gateway, proxy_port, _admin_port) = start_gateway_with_retry(&config_path).await;

    let client = reqwest::Client::new();
    let started = std::time::Instant::now();
    let response = client
        .post(format!(
            "http://127.0.0.1:{}/ai/v1/chat/completions",
            proxy_port
        ))
        .header("content-type", "application/json")
        .body(r#"{"stream":true,"messages":[{"role":"user","content":"hello"}]}"#)
        .send()
        .await
        .expect("request failed");
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    let elapsed = started.elapsed();

    let _ = gateway.kill();
    let _ = gateway.wait();
    backend.abort();
    embeddings.abort();

    assert_eq!(status, 200);
    assert!(
        elapsed < Duration::from_secs(10),
        "hold deadline must bind before provider.request_timeout_ms (15s), took {elapsed:?}"
    );
    assert!(
        body.contains("sunny today"),
        "an explicit fail-open policy releases the held window, got: {body}"
    );
    assert!(
        !body.contains("ai_semantic_firewall_response_blocked"),
        "fail-open must not cut, got: {body}"
    );
}
