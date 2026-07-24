//! Functional coverage for `ai_stream_router` Anthropic streaming normalization.
//!
//! Run with: cargo build --bin ferrum-edge && cargo test --test functional_tests \
//!   functional_ai_stream_router -- --ignored --nocapture

use std::io::Write;
use std::sync::{Arc, Mutex};
use std::time::Duration;
use tempfile::TempDir;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::time::sleep;

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
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_LOG_LEVEL", "warn")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .expect("start ferrum-edge")
}

async fn wait_for_gateway(admin_port: u16) -> bool {
    let client = reqwest::Client::new();
    let health_url = format!("http://127.0.0.1:{admin_port}/health");
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

async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    for attempt in 1..=3 {
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
        let _ = child.kill();
        let _ = child.wait();
        if attempt < 3 {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!("gateway failed to start");
}

const ANTHROPIC_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_fn\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":2,\"output_tokens\":1}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"hello-fn\"}}\n\n",
    "event: message_delta\n",
    "data: {\"type\":\"message_delta\",\"delta\":{\"stop_reason\":\"end_turn\"},\"usage\":{\"output_tokens\":1}}\n\n",
    "event: message_stop\n",
    "data: {\"type\":\"message_stop\"}\n\n",
);

const ANTHROPIC_PARTIAL_SSE: &str = concat!(
    "event: message_start\n",
    "data: {\"type\":\"message_start\",\"message\":{\"id\":\"msg_cut\",\"type\":\"message\",\"role\":\"assistant\",\"model\":\"claude-3-5-sonnet\",\"content\":[],\"usage\":{\"input_tokens\":1,\"output_tokens\":1}}}\n\n",
    "event: content_block_delta\n",
    "data: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"text_delta\",\"text\":\"truncated\"}}\n\n",
);

#[derive(Default, Clone)]
struct CapturedRequest {
    raw: String,
}

async fn anthropic_provider(
    listener: TcpListener,
    body: &'static str,
    capture: Arc<Mutex<Option<CapturedRequest>>>,
) {
    loop {
        let Ok((mut stream, _)) = listener.accept().await else {
            continue;
        };
        let capture = Arc::clone(&capture);
        tokio::spawn(async move {
            let mut buf = vec![0u8; 65536];
            let n = stream.read(&mut buf).await.unwrap_or(0);
            let raw = String::from_utf8_lossy(&buf[..n]).into_owned();
            *capture.lock().unwrap() = Some(CapturedRequest { raw });
            let response = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                body.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.shutdown().await;
        });
    }
}

fn write_config(dir: &TempDir, provider_port: u16) -> std::path::PathBuf {
    let path = dir.path().join("config.yaml");
    let yaml = format!(
        r#"
version: "1"
proxies:
  - id: "stream-router"
    listen_path: "/v1/chat/completions"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {provider_port: ''}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "asr"
consumers: []
plugin_configs:
  - id: "asr"
    proxy_id: "stream-router"
    plugin_name: "ai_stream_router"
    scope: "proxy"
    enabled: true
    config:
      normalize_response_stream: true
      providers:
        - name: anthropic
          provider_type: anthropic
          endpoint: "http://127.0.0.1:{provider_port}/v1/messages"
          api_key: "sk-ant-test"
          model_patterns: ["claude-*"]
          allow_plaintext: true
          priority: 1
expected_resource_counts:
  proxies: 1
  consumers: 0
  upstreams: 0
  plugin_configs: 1
"#
    );
    let mut file = std::fs::File::create(&path).unwrap();
    file.write_all(yaml.as_bytes()).unwrap();
    path
}

#[ignore]
#[tokio::test]
async fn test_ai_stream_router_normalizes_anthropic_sse_and_requests_identity_encoding() {
    let provider_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_port = provider_listener.local_addr().unwrap().port();
    let capture = Arc::new(Mutex::new(None));
    let provider_task = tokio::spawn(anthropic_provider(
        provider_listener,
        ANTHROPIC_SSE,
        Arc::clone(&capture),
    ));

    let tmp = TempDir::new().unwrap();
    let config_path = write_config(&tmp, provider_port);
    let (mut child, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("accept-encoding", "gzip, br")
        .json(&serde_json::json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "messages": [
                {"role": "user", "content": "hi"},
                {
                    "role": "assistant",
                    "content": null,
                    "tool_calls": [{
                        "id": "call_1",
                        "type": "function",
                        "function": {"name": "lookup", "arguments": "{}"}
                    }]
                },
                {"role": "tool", "tool_call_id": "call_1", "content": "ok"}
            ]
        }))
        .send()
        .await
        .expect("client request");

    assert_eq!(resp.status(), 200);
    assert!(
        resp.headers()
            .get("content-encoding")
            .is_none_or(|v| v == "identity"),
        "normalized response must not retain a non-identity Content-Encoding"
    );
    let body = resp.text().await.unwrap();
    assert!(body.contains("chat.completion.chunk"));
    assert!(body.contains("hello-fn"));
    assert!(body.trim_end().ends_with("data: [DONE]"));
    assert!(!body.contains("content_block_delta"));

    let captured = capture
        .lock()
        .unwrap()
        .clone()
        .expect("provider saw request");
    assert!(
        captured
            .raw
            .to_ascii_lowercase()
            .contains("accept-encoding: identity"),
        "provider must receive only identity Accept-Encoding: {}",
        captured.raw
    );
    assert!(
        captured.raw.contains("tool_use") || captured.raw.contains("tool_result"),
        "provider must receive translated tool history: {}",
        captured.raw
    );

    let _ = child.kill();
    let _ = child.wait();
    provider_task.abort();
}

#[ignore]
#[tokio::test]
async fn test_ai_stream_router_premature_provider_eof_is_not_success() {
    let provider_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let provider_port = provider_listener.local_addr().unwrap().port();
    let capture = Arc::new(Mutex::new(None));
    let provider_task = tokio::spawn(anthropic_provider(
        provider_listener,
        ANTHROPIC_PARTIAL_SSE,
        Arc::clone(&capture),
    ));

    let tmp = TempDir::new().unwrap();
    let config_path = write_config(&tmp, provider_port);
    let (mut child, proxy_port, _admin_port) =
        start_gateway_with_retry(config_path.to_str().unwrap()).await;

    let client = reqwest::Client::new();
    let resp = client
        .post(format!("http://127.0.0.1:{proxy_port}/v1/chat/completions"))
        .header("content-type", "application/json")
        .json(&serde_json::json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .expect("client request");

    assert_eq!(resp.status(), 200);
    let body = resp.text().await.unwrap();
    assert!(body.contains("upstream_error"));
    assert!(body.contains("before message_stop") || body.contains("truncated"));
    assert_eq!(body.matches("data: [DONE]").count(), 1);

    let _ = child.kill();
    let _ = child.wait();
    provider_task.abort();
}
