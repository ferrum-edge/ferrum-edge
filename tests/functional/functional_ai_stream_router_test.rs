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

fn start_gateway(
    config_path: &str,
    proxy_port: u16,
    admin_port: u16,
    identity: &crate::common::SpawnedGatewayIdentity,
) -> std::process::Child {
    let mut cmd = std::process::Command::new(gateway_binary_path());
    cmd.arg("run");
    cmd.env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path)
        .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
        .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .env("FERRUM_LOG_LEVEL", "warn")
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null());
    identity.apply_to_command(&mut cmd);
    cmd.spawn().expect("start ferrum-edge")
}

async fn wait_for_owned_gateway(
    child: &mut std::process::Child,
    admin_port: u16,
    identity: &crate::common::SpawnedGatewayIdentity,
) -> bool {
    crate::common::wait_for_owned_gateway_identity(
        child,
        admin_port,
        identity,
        Duration::from_secs(15),
    )
    .await
    .is_ok()
}

async fn start_gateway_with_retry(config_path: &str) -> (std::process::Child, u16, u16) {
    for attempt in 1..=3 {
        let proxy_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_port = proxy_listener.local_addr().unwrap().port();
        drop(proxy_listener);
        let admin_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let admin_port = admin_listener.local_addr().unwrap().port();
        drop(admin_listener);

        let identity = crate::common::SpawnedGatewayIdentity::mint("ai-stream-router");
        let mut child = start_gateway(config_path, proxy_port, admin_port, &identity);
        if wait_for_owned_gateway(&mut child, admin_port, &identity).await {
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

/// Read a complete HTTP/1.1 request: headers, then exactly `Content-Length`
/// body bytes.
///
/// Returns whatever was read if the peer closes early or stalls, so a
/// malformed, truncated, or stalled request still surfaces in the assertion
/// message rather than hanging the test until the job timeout. The bound is
/// per-read and generous: the only writer here is the gateway on loopback.
async fn read_full_request(stream: &mut tokio::net::TcpStream) -> String {
    const READ_BOUND: Duration = Duration::from_secs(10);
    let mut raw: Vec<u8> = Vec::with_capacity(8192);
    let mut chunk = [0u8; 8192];

    let header_end = loop {
        if let Some(idx) = raw.windows(4).position(|w| w == b"\r\n\r\n") {
            break idx + 4;
        }
        match tokio::time::timeout(READ_BOUND, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => raw.extend_from_slice(&chunk[..n]),
            _ => return String::from_utf8_lossy(&raw).into_owned(),
        }
    };

    let content_length = String::from_utf8_lossy(&raw[..header_end])
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            if name.trim().eq_ignore_ascii_case("content-length") {
                value.trim().parse::<usize>().ok()
            } else {
                None
            }
        })
        .unwrap_or(0);

    while raw.len() < header_end + content_length {
        match tokio::time::timeout(READ_BOUND, stream.read(&mut chunk)).await {
            Ok(Ok(n)) if n > 0 => raw.extend_from_slice(&chunk[..n]),
            _ => break,
        }
    }

    String::from_utf8_lossy(&raw).into_owned()
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
            // Read the WHOLE request before capturing it. A single `read()` is
            // only guaranteed to return whatever one TCP segment carried, so a
            // request whose body lands in a later segment used to be captured
            // as headers-only — and the tool-history assertion below then failed
            // against a `raw` that legitimately contained no body at all.
            let raw = read_full_request(&mut stream).await;
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
    backend_port: {provider_port}
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

/// Live proxy datapath for issue #3301 layered residual `Content-Encoding`.
///
/// This is not a plugin-method unit/integration call: it starts the real
/// `ferrum-edge` binary ([`TestGateway`]) and a held ephemeral Anthropic
/// upstream that returns Anthropic SSE bytes encoded as `gzip, br`. The client
/// request traverses the actual proxy + `ai_stream_router` response path;
/// assertions require identity OpenAI SSE bytes, repaired representation
/// headers, and no encoded provider frames on the wire.
#[ignore]
#[tokio::test]
async fn test_ai_stream_router_live_gzip_br_chain_normalizes_through_real_proxy() {
    use crate::common::TestGateway;
    use flate2::Compression;
    use flate2::write::GzEncoder;

    // Hold the provider listener for the process lifetime (no bind-drop-rebind).
    let provider_listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind held anthropic provider listener");
    let provider_port = provider_listener
        .local_addr()
        .expect("provider addr")
        .port();

    let mut gzipped = GzEncoder::new(Vec::new(), Compression::default());
    gzipped
        .write_all(ANTHROPIC_SSE.as_bytes())
        .expect("gzip anthropic sse");
    let gzip_layer = gzipped.finish().expect("finish gzip layer");
    let mut layered = Vec::new();
    {
        let mut encoder = brotli::CompressorWriter::new(&mut layered, 4096, 5, 22);
        encoder
            .write_all(&gzip_layer)
            .expect("brotli over gzip layer");
    }
    let encoded_frame_sentinel = layered.clone();

    let provider_task = tokio::spawn(async move {
        // Accept until the real streaming POST arrives. Ignore any stray probes
        // without consuming the layered fixture on a non-POST connection.
        loop {
            let Ok((mut stream, _)) = provider_listener.accept().await else {
                return;
            };
            // TCP does not preserve HTTP header-write boundaries. Read through
            // the complete header block so a split after the request line (or
            // immediately before Accept-Encoding) cannot make this live test
            // diagnose a correct gateway request as missing the identity
            // negotiation. Keep the fixture bounded and deadline-controlled.
            const MAX_REQUEST_BYTES: usize = 64 * 1024;
            let mut request = Vec::with_capacity(4096);
            let mut chunk = [0u8; 4096];
            while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                if request.len() == MAX_REQUEST_BYTES {
                    return;
                }
                let read_len = chunk.len().min(MAX_REQUEST_BYTES - request.len());
                let n = match tokio::time::timeout(
                    Duration::from_secs(5),
                    stream.read(&mut chunk[..read_len]),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                    Ok(Ok(n)) => n,
                };
                request.extend_from_slice(&chunk[..n]);
            }
            let Some(header_end) = request
                .windows(4)
                .position(|window| window == b"\r\n\r\n")
                .map(|index| index + 4)
            else {
                return;
            };
            let header_text = String::from_utf8_lossy(&request[..header_end]);
            let content_length = header_text
                .lines()
                .filter_map(|line| line.split_once(':'))
                .find_map(|(name, value)| {
                    if name.eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            let Some(request_len) = header_end
                .checked_add(content_length)
                .filter(|length| *length <= MAX_REQUEST_BYTES)
            else {
                return;
            };
            // Drain the declared request body before responding. Dropping a
            // socket with unread upload bytes can reset the response on some
            // kernels and would turn this fixture into another transport race.
            while request.len() < request_len {
                let read_len = chunk.len().min(request_len - request.len());
                let n = match tokio::time::timeout(
                    Duration::from_secs(5),
                    stream.read(&mut chunk[..read_len]),
                )
                .await
                {
                    Ok(Ok(0)) | Ok(Err(_)) | Err(_) => return,
                    Ok(Ok(n)) => n,
                };
                request.extend_from_slice(&chunk[..n]);
            }
            let raw = String::from_utf8_lossy(&request).into_owned();
            if !raw.lines().next().unwrap_or("").starts_with("POST ") {
                let _ = stream
                    .write_all(
                        b"HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
                    )
                    .await;
                let _ = stream.shutdown().await;
                continue;
            }
            let response = format!(
                "HTTP/1.1 200 OK\r\n\
                 Content-Type: text/event-stream\r\n\
                 Content-Encoding: gzip, br\r\n\
                 Content-Length: {}\r\n\
                 ETag: \"encoded-provider\"\r\n\
                 Vary: Accept-Encoding, Origin\r\n\
                 Connection: close\r\n\
                 \r\n",
                layered.len()
            );
            let _ = stream.write_all(response.as_bytes()).await;
            let _ = stream.write_all(&layered).await;
            let _ = stream.shutdown().await;
            // Prove the gateway requested identity (claim path) even though the
            // upstream still chose a residual layered coding.
            assert!(
                raw.to_ascii_lowercase()
                    .contains("accept-encoding: identity"),
                "live provider must see identity Accept-Encoding: {raw}"
            );
            break;
        }
    });

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "stream-router-live-chain"
    listen_path: "/v1/chat/completions"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {provider_port}
    strip_listen_path: false
    pool_enable_http2: false
    plugins:
      - plugin_config_id: "asr-live-chain"

consumers: []

plugin_configs:
  - id: "asr-live-chain"
    proxy_id: "stream-router-live-chain"
    plugin_name: "ai_stream_router"
    scope: "proxy"
    enabled: true
    config:
      normalize_response_stream: true
      providers:
        - name: anthropic
          provider_type: anthropic
          endpoint: "http://127.0.0.1:{provider_port}/v1/messages"
          api_key: "sk-ant-live-chain"
          model_patterns: ["claude-*"]
          allow_plaintext: true
          priority: 1
"#
    );

    // TestGateway allocates held ephemeral proxy/admin ports, observes child
    // ownership + readiness with a bounded deadline, and tears down cleanly.
    let mut gateway = TestGateway::builder()
        .mode_file(config)
        .log_level("warn")
        .env("FERRUM_POOL_WARMUP_ENABLED", "false")
        .spawn()
        .await
        .expect("start live ai_stream_router encoding-chain gateway");
    gateway
        .wait_for_proxy_port(Duration::from_secs(5))
        .await
        .expect("proxy port ready");

    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .no_gzip()
        .build()
        .expect("client");
    let resp = client
        .post(gateway.proxy_url("/v1/chat/completions"))
        .header("content-type", "application/json")
        .header("accept-encoding", "gzip, br")
        .json(&serde_json::json!({
            "model": "claude-3-5-sonnet",
            "stream": true,
            "messages": [{"role": "user", "content": "hi"}]
        }))
        .send()
        .await
        .expect("live proxy request");

    assert_eq!(resp.status(), 200, "live chain decode must succeed");
    assert!(
        resp.headers()
            .get("content-encoding")
            .is_none_or(|v| v == "identity"),
        "client must see identity/absent Content-Encoding, got {:?}",
        resp.headers().get("content-encoding")
    );
    assert!(
        resp.headers().get("content-length").is_none(),
        "rewritten SSE must not retain the provider Content-Length"
    );
    assert!(
        resp.headers().get("etag").is_none(),
        "rewritten SSE must invalidate provider validators"
    );
    if let Some(vary) = resp.headers().get("vary") {
        let vary = vary.to_str().unwrap_or_default().to_ascii_lowercase();
        assert!(
            !vary.contains("accept-encoding"),
            "Accept-Encoding must be scrubbed from Vary: {vary}"
        );
    }

    let body_bytes = resp.bytes().await.expect("response body");
    assert!(
        encoded_frame_sentinel.len() >= 16,
        "fixture must be large enough for a sliding-window opaque-frame check"
    );
    assert!(
        body_bytes.windows(16).all(|window| {
            !encoded_frame_sentinel
                .windows(16)
                .any(|frame| frame == window)
        }),
        "no 16-byte window of the gzip,br payload may appear in the client body"
    );
    let body = String::from_utf8(body_bytes.to_vec()).expect("normalized body is utf-8");
    assert!(body.contains("chat.completion.chunk"), "{body}");
    assert!(body.contains("hello-fn"), "{body}");
    assert!(body.trim_end().ends_with("data: [DONE]"), "{body}");
    assert!(!body.contains("content_block_delta"), "{body}");
    assert!(!body.contains("upstream_error"), "{body}");

    tokio::time::timeout(Duration::from_secs(5), provider_task)
        .await
        .expect("provider task finished within deadline")
        .expect("provider task completed without panic");
    gateway.shutdown();
}
