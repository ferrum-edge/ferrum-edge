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
