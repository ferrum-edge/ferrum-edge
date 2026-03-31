//! Functional tests for centralized Redis rate limiting.
//!
//! Tests all three rate limiting plugins (`rate_limiting`, `ai_rate_limiter`,
//! `ws_rate_limiting`) with `sync_mode: "redis"` to verify centralized counters
//! work end-to-end through a real gateway binary.
//!
//! ## Requirements
//!
//! These tests require a Redis-compatible server running at `127.0.0.1:6379`.
//! If Redis is not available, tests are skipped gracefully (not failed).
//!
//! Start Redis locally:
//!   docker run --rm -p 6379:6379 redis:7-alpine
//!
//! Run these tests:
//!   cargo test --test functional_tests functional_redis_rate_limiting -- --ignored --nocapture
//!
//! Compatible with Redis, Valkey, DragonflyDB, KeyDB, or Garnet.

use chrono::Utc;
use futures_util::{SinkExt, StreamExt};
use jsonwebtoken::{EncodingKey, Header, encode};
use serde_json::json;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, SystemTime};
use tempfile::TempDir;
use tokio::time::sleep;
use tokio_tungstenite::tungstenite::protocol::Message;
use uuid::Uuid;

const REDIS_URL: &str = "redis://127.0.0.1:6379/15"; // Use DB 15 to avoid collisions

// ============================================================================
// Redis availability check
// ============================================================================

/// Check if Redis is reachable at the expected address.
/// Returns false if Redis is down — tests will be skipped.
async fn redis_is_available() -> bool {
    match tokio::net::TcpStream::connect("127.0.0.1:6379").await {
        Ok(_) => true,
        Err(_) => {
            eprintln!(
                "Redis not available at 127.0.0.1:6379 — skipping centralized rate limiting tests"
            );
            false
        }
    }
}

/// Flush the test Redis database (DB 15) to start clean.
async fn flush_redis_db() {
    let Ok(stream) = tokio::net::TcpStream::connect("127.0.0.1:6379").await else {
        return;
    };
    let (reader, mut writer) = tokio::io::split(stream);
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    // SELECT 15
    writer
        .write_all(b"*2\r\n$6\r\nSELECT\r\n$2\r\n15\r\n")
        .await
        .unwrap();
    let mut buf = [0u8; 64];
    let mut reader = reader;
    let _ = reader.read(&mut buf).await;

    // FLUSHDB
    writer.write_all(b"*1\r\n$7\r\nFLUSHDB\r\n").await.unwrap();
    let _ = reader.read(&mut buf).await;
}

// ============================================================================
// Test Harness (Database mode with Redis rate limiting)
// ============================================================================

struct RedisRateLimitHarness {
    _temp_dir: TempDir,
    gateway_process: Option<Child>,
    proxy_base_url: String,
    admin_base_url: String,
    jwt_secret: String,
    jwt_issuer: String,
}

impl RedisRateLimitHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let temp_dir = TempDir::new()?;
        let jwt_secret = "test-redis-rl-jwt-secret-12345".to_string();
        let jwt_issuer = "ferrum-edge-redis-rl-test".to_string();

        let admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let admin_port = admin_listener.local_addr()?.port();
        drop(admin_listener);

        let proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await?;
        let proxy_port = proxy_listener.local_addr()?.port();
        drop(proxy_listener);

        let db_url = format!(
            "sqlite:{}?mode=rwc",
            temp_dir.path().join("test_redis_rl.db").to_string_lossy()
        );

        // Start gateway (SQLite with ?mode=rwc auto-creates the database)
        let binary_path = gateway_binary_path();
        let gateway_process = Command::new(binary_path)
            .env("FERRUM_MODE", "database")
            .env("FERRUM_ADMIN_JWT_SECRET", &jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &jwt_issuer)
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", &db_url)
            .env("FERRUM_DB_POLL_INTERVAL", "2")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .env("FERRUM_LOG_LEVEL", "debug")
            .env("FERRUM_TRUSTED_PROXIES", "127.0.0.1")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?;

        let harness = Self {
            _temp_dir: temp_dir,
            gateway_process: Some(gateway_process),
            proxy_base_url: format!("http://127.0.0.1:{}", proxy_port),
            admin_base_url: format!("http://127.0.0.1:{}", admin_port),
            jwt_secret,
            jwt_issuer,
        };

        harness.wait_for_health().await?;
        Ok(harness)
    }

    async fn wait_for_health(&self) -> Result<(), Box<dyn std::error::Error>> {
        let health_url = format!("{}/health", self.admin_base_url);
        let deadline = SystemTime::now() + Duration::from_secs(30);
        loop {
            if SystemTime::now() >= deadline {
                return Err("Gateway did not start within 30 seconds".into());
            }
            match reqwest::get(&health_url).await {
                Ok(r) if r.status().is_success() => return Ok(()),
                _ => sleep(Duration::from_millis(500)).await,
            }
        }
    }

    async fn wait_for_poll(&self) {
        sleep(Duration::from_secs(3)).await;
    }

    fn generate_admin_token(&self) -> String {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "jti": Uuid::new_v4().to_string()
        });
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        encode(&header, &claims, &key).expect("Failed to encode admin JWT")
    }

    fn auth_header(&self) -> String {
        format!("Bearer {}", self.generate_admin_token())
    }

    async fn create_proxy(
        &self,
        client: &reqwest::Client,
        proxy: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = client
            .post(format!("{}/proxies", self.admin_base_url))
            .header("Authorization", self.auth_header())
            .json(proxy)
            .send()
            .await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(format!("Failed to create proxy: {}", body).into());
        }
        Ok(())
    }

    async fn create_plugin(
        &self,
        client: &reqwest::Client,
        plugin: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = client
            .post(format!("{}/plugins/config", self.admin_base_url))
            .header("Authorization", self.auth_header())
            .json(plugin)
            .send()
            .await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(format!("Failed to create plugin: {}", body).into());
        }
        Ok(())
    }

    async fn update_proxy(
        &self,
        client: &reqwest::Client,
        proxy_id: &str,
        proxy: &serde_json::Value,
    ) -> Result<(), Box<dyn std::error::Error>> {
        let resp = client
            .put(format!("{}/proxies/{}", self.admin_base_url, proxy_id))
            .header("Authorization", self.auth_header())
            .json(proxy)
            .send()
            .await?;
        if !resp.status().is_success() {
            let body = resp.text().await?;
            return Err(format!("Failed to update proxy: {}", body).into());
        }
        Ok(())
    }
}

impl Drop for RedisRateLimitHarness {
    fn drop(&mut self) {
        if let Some(mut child) = self.gateway_process.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

// ============================================================================
// Helpers
// ============================================================================

fn gateway_binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

async fn start_header_echo_backend(
    port: u16,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut request_line = String::new();
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
                let _ = buf_reader.read_line(&mut request_line).await;

                // Read all headers
                let mut headers = std::collections::HashMap::new();
                let mut content_length: usize = 0;
                loop {
                    let mut line = String::new();
                    let _ = buf_reader.read_line(&mut line).await;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((key, value)) = trimmed.split_once(':') {
                        let key_lower = key.trim().to_lowercase();
                        let val = value.trim().to_string();
                        if key_lower == "content-length" {
                            content_length = val.parse().unwrap_or(0);
                        }
                        headers.insert(key_lower, val);
                    }
                }

                // Read body if present
                let mut request_body = String::new();
                if content_length > 0 {
                    let mut body_buf = vec![0u8; content_length];
                    use tokio::io::AsyncReadExt;
                    let _ = buf_reader.read_exact(&mut body_buf).await;
                    request_body = String::from_utf8_lossy(&body_buf).to_string();
                }

                let body = json!({
                    "request_line": request_line.trim(),
                    "headers": headers,
                    "body": request_body,
                });
                let body_str = body.to_string();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_str.len(),
                    body_str
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(handle)
}

/// Start a mock LLM backend that returns OpenAI-compatible token usage responses.
async fn start_ai_backend(
    port: u16,
    total_tokens: u64,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let tokens = total_tokens;
            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut buf_reader = tokio::io::BufReader::new(reader);
                use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

                // Read request line + headers (discard)
                loop {
                    let mut line = String::new();
                    let _ = buf_reader.read_line(&mut line).await;
                    if line.trim().is_empty() {
                        break;
                    }
                }

                // Return OpenAI-format response with token usage
                let body = json!({
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello!"},
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": tokens / 2,
                        "completion_tokens": tokens / 2,
                        "total_tokens": tokens
                    }
                });
                let body_str = body.to_string();

                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body_str.len(),
                    body_str
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(handle)
}

/// Start a WebSocket echo server.
async fn start_ws_echo_server(port: u16) {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port))
        .await
        .expect("Failed to bind WS echo server");

    loop {
        if let Ok((stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let ws_stream = match tokio_tungstenite::accept_async(stream).await {
                    Ok(s) => s,
                    Err(_) => return,
                };
                let (mut sink, mut source) = ws_stream.split();
                while let Some(Ok(msg)) = source.next().await {
                    match msg {
                        Message::Text(text) => {
                            let echo = format!("Echo: {}", text);
                            if sink.send(Message::Text(echo)).await.is_err() {
                                break;
                            }
                        }
                        Message::Binary(data) => {
                            let echo = format!("Echo binary: {} bytes", data.len());
                            if sink.send(Message::Text(echo)).await.is_err() {
                                break;
                            }
                        }
                        Message::Ping(data) => {
                            if sink.send(Message::Pong(data)).await.is_err() {
                                break;
                            }
                        }
                        Message::Close(_) => break,
                        _ => {}
                    }
                }
            });
        }
    }
}

/// Set up a proxy with plugins via the admin API.
async fn setup_proxy_with_plugins(
    harness: &RedisRateLimitHarness,
    client: &reqwest::Client,
    proxy_id: &str,
    listen_path: &str,
    backend_port: u16,
    backend_protocol: &str,
    plugins: Vec<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    harness
        .create_proxy(
            client,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_protocol": backend_protocol,
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
            }),
        )
        .await?;

    let mut plugin_refs = Vec::new();
    for plugin in &plugins {
        harness.create_plugin(client, plugin).await?;
        plugin_refs.push(json!({"plugin_config_id": plugin["id"].as_str().unwrap()}));
    }

    harness
        .update_proxy(
            client,
            proxy_id,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_protocol": backend_protocol,
                "backend_host": "localhost",
                "backend_port": backend_port,
                "strip_listen_path": true,
                "plugins": plugin_refs,
            }),
        )
        .await?;

    Ok(())
}

// ============================================================================
// Test: rate_limiting plugin with Redis centralized mode
// ============================================================================

/// Verify that rate_limiting plugin enforces limits via Redis.
/// Uses a unique key prefix per test run to avoid cross-test interference.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_centralized() {
    if !redis_is_available().await {
        return;
    }
    flush_redis_db().await;

    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();
    let unique_prefix = format!("ferrum:test:rl:{}", Uuid::new_v4().simple());

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-redis-rl",
        "/redis-rl",
        backend_port,
        "http",
        vec![json!({
            "id": "plugin-redis-rl",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": "proxy-redis-rl",
            "enabled": true,
            "config": {
                "window_seconds": 60,
                "max_requests": 3,
                "expose_headers": true,
                "sync_mode": "redis",
                "redis_url": REDIS_URL,
                "redis_key_prefix": unique_prefix
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Send 3 requests — should all succeed
    for i in 1..=3 {
        let resp = client
            .get(format!("{}/redis-rl/test", harness.proxy_base_url))
            .send()
            .await
            .expect("Request failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "Request {} should succeed, got {}",
            i,
            resp.status()
        );
    }

    // 4th request should be rate limited (429)
    let resp = client
        .get(format!("{}/redis-rl/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        429,
        "4th request should be rate limited via Redis"
    );

    // Verify rate limit headers
    assert!(
        resp.headers().contains_key("x-ratelimit-limit")
            || resp.headers().contains_key("retry-after"),
        "Rate limit response should include rate limit headers"
    );

    println!("test_rate_limiting_redis_centralized PASSED");
}

// ============================================================================
// Test: rate_limiting Redis fallback to local when Redis URL is unreachable
// ============================================================================

/// Verify that when Redis is configured but unreachable (bad port), the plugin
/// gracefully falls back to local in-memory rate limiting.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_fallback_to_local() {
    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    // Use a Redis URL on an unreachable port
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-redis-fb",
        "/redis-fallback",
        backend_port,
        "http",
        vec![json!({
            "id": "plugin-redis-fb",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": "proxy-redis-fb",
            "enabled": true,
            "config": {
                "window_seconds": 60,
                "max_requests": 3,
                "expose_headers": true,
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:19999/0",
                "redis_key_prefix": "ferrum:test:fallback"
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // Even though Redis is unreachable, requests should still work via local fallback
    for i in 1..=3 {
        let resp = client
            .get(format!("{}/redis-fallback/test", harness.proxy_base_url))
            .send()
            .await
            .expect("Request failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "Request {} should succeed via local fallback, got {}",
            i,
            resp.status()
        );
    }

    // 4th request should still be rate limited (by local DashMap)
    let resp = client
        .get(format!("{}/redis-fallback/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        429,
        "4th request should be rate limited via local fallback"
    );

    println!("test_rate_limiting_redis_fallback_to_local PASSED");
}

// ============================================================================
// Test: ai_rate_limiter plugin with Redis centralized mode
// ============================================================================

/// Verify that ai_rate_limiter plugin enforces token budgets via Redis.
#[tokio::test]
#[ignore]
async fn test_ai_rate_limiter_redis_centralized() {
    if !redis_is_available().await {
        return;
    }
    flush_redis_db().await;

    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");

    // Start a mock AI backend that returns 500 tokens per response
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_ai_backend(backend_port, 500).await.unwrap();

    let client = reqwest::Client::new();
    let unique_prefix = format!("ferrum:test:ai:{}", Uuid::new_v4().simple());

    // Token limit = 1000, each response uses 500 tokens → 2 requests allowed
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-ai-redis",
        "/ai-redis",
        backend_port,
        "http",
        vec![json!({
            "id": "plugin-ai-redis",
            "plugin_name": "ai_rate_limiter",
            "scope": "proxy",
            "proxy_id": "proxy-ai-redis",
            "enabled": true,
            "config": {
                "token_limit": 1000,
                "window_seconds": 60,
                "limit_by": "ip",
                "expose_headers": true,
                "sync_mode": "redis",
                "redis_url": REDIS_URL,
                "redis_key_prefix": unique_prefix
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // First 2 requests should succeed (500 + 500 = 1000 tokens)
    for i in 1..=2 {
        let resp = client
            .post(format!(
                "{}/ai-redis/v1/chat/completions",
                harness.proxy_base_url
            ))
            .header("Content-Type", "application/json")
            .body(r#"{"model":"test","messages":[{"role":"user","content":"hi"}]}"#)
            .send()
            .await
            .expect("Request failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "AI request {} should succeed, got {}",
            i,
            resp.status()
        );
        // Read the body to ensure the response body plugin phase runs
        let _ = resp.text().await;
    }

    // 3rd request should be over the token budget (429)
    let resp = client
        .post(format!(
            "{}/ai-redis/v1/chat/completions",
            harness.proxy_base_url
        ))
        .header("Content-Type", "application/json")
        .body(r#"{"model":"test","messages":[{"role":"user","content":"hi"}]}"#)
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        429,
        "3rd AI request should be token-limited via Redis"
    );

    println!("test_ai_rate_limiter_redis_centralized PASSED");
}

// ============================================================================
// Test: ws_rate_limiting plugin with Redis centralized mode
// ============================================================================

/// Verify that ws_rate_limiting plugin enforces frame rate limits via Redis.
#[tokio::test]
#[ignore]
async fn test_ws_rate_limiting_redis_centralized() {
    if !redis_is_available().await {
        return;
    }
    flush_redis_db().await;

    let backend_port = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let gateway_port = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let unique_prefix = format!("ferrum:test:ws:{}", Uuid::new_v4().simple());

    let temp_dir = TempDir::new().unwrap();
    let config_path = temp_dir.path().join("config.yaml");
    let config = format!(
        r#"
proxies:
  - id: "ws-redis-proxy"
    listen_path: "/ws-redis"
    backend_protocol: ws
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ws-redis-rl"

consumers: []

plugin_configs:
  - id: "ws-redis-rl"
    plugin_name: "ws_rate_limiting"
    scope: "proxy"
    proxy_id: "ws-redis-proxy"
    enabled: true
    config:
      frames_per_second: 5
      burst_size: 20
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{unique_prefix}"
"#,
    );
    std::fs::write(&config_path, config).expect("Failed to write config");

    let mut gateway = Command::new(gateway_binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
        .env("FERRUM_PROXY_HTTP_PORT", gateway_port.to_string())
        .env("RUST_LOG", "ferrum_edge=debug")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start gateway");

    sleep(Duration::from_secs(3)).await;

    let url = format!("ws://127.0.0.1:{}/ws-redis", gateway_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Send messages within limit — should pass
    for i in 0..5 {
        let msg = format!("msg {}", i);
        ws.send(Message::Text(msg.clone())).await.unwrap();
        let reply = ws.next().await.unwrap().unwrap();
        assert_eq!(
            reply,
            Message::Text(format!("Echo: {}", msg)),
            "Message {} within limit should echo via Redis mode",
            i
        );
    }

    // Burst to exceed limit — should eventually close the connection
    let mut connection_closed = false;
    for i in 5..100 {
        let msg = format!("burst msg {}", i);
        match ws.send(Message::Text(msg)).await {
            Ok(_) => {
                match tokio::time::timeout(Duration::from_millis(500), ws.next()).await {
                    Ok(Some(Ok(Message::Close(_)))) => {
                        connection_closed = true;
                        println!("Connection closed at message {} (redis rate limited)", i);
                        break;
                    }
                    Ok(None) => {
                        connection_closed = true;
                        break;
                    }
                    Err(_) => {
                        connection_closed = true;
                        break;
                    }
                    Ok(Some(Ok(_))) => {} // Normal echo
                    Ok(Some(Err(_))) => {
                        connection_closed = true;
                        break;
                    }
                }
            }
            Err(_) => {
                connection_closed = true;
                break;
            }
        }
    }

    assert!(
        connection_closed,
        "Connection should have been closed by Redis-backed rate limiter"
    );

    let _ = gateway.kill();
    let _ = gateway.wait();
    echo_handle.abort();
    println!("test_ws_rate_limiting_redis_centralized PASSED");
}

// ============================================================================
// Test: Two gateway instances sharing rate limit state via Redis
// ============================================================================

/// The most important centralized rate limiting test: two gateway instances
/// share rate limit state through Redis. Requests spread across both
/// instances are correctly counted against a single shared limit.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_shared_across_instances() {
    if !redis_is_available().await {
        return;
    }
    flush_redis_db().await;

    // Start a shared backend
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let unique_prefix = format!("ferrum:test:shared:{}", Uuid::new_v4().simple());
    let temp_dir = TempDir::new().unwrap();

    // Helper to start a file-mode gateway with rate limiting
    let start_instance = |instance_num: u16, proxy_port: u16, prefix: String| {
        let config_path = temp_dir
            .path()
            .join(format!("config_{}.yaml", instance_num));
        let config = format!(
            r#"
proxies:
  - id: "shared-rl-proxy"
    listen_path: "/shared-rl"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "shared-rl-plugin"

consumers: []

plugin_configs:
  - id: "shared-rl-plugin"
    plugin_name: "rate_limiting"
    scope: "proxy"
    proxy_id: "shared-rl-proxy"
    enabled: true
    config:
      window_seconds: 60
      max_requests: 4
      expose_headers: true
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix}"
"#,
        );
        std::fs::write(&config_path, config).expect("Failed to write config");

        Command::new(gateway_binary_path())
            .env("FERRUM_MODE", "file")
            .env("FERRUM_FILE_CONFIG_PATH", config_path.to_str().unwrap())
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("RUST_LOG", "ferrum_edge=debug")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("Failed to start gateway instance")
    };

    // Allocate ports for two gateway instances
    let port1 = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };
    let port2 = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let mut gw1 = start_instance(1, port1, unique_prefix.clone());
    let mut gw2 = start_instance(2, port2, unique_prefix.clone());

    // Wait for both gateways to start and load config
    sleep(Duration::from_secs(5)).await;

    let client = reqwest::Client::new();

    // Verify both gateways are serving the route by hitting a non-existent path
    // (which returns 404 but proves the gateway is up and listening)
    for port in [port1, port2] {
        let deadline = SystemTime::now() + Duration::from_secs(10);
        loop {
            if SystemTime::now() >= deadline {
                panic!("Gateway on port {} did not start", port);
            }
            match client
                .get(format!(
                    "http://127.0.0.1:{}/health-probe-nonexistent",
                    port
                ))
                .send()
                .await
            {
                // Any response (including 404) means the gateway is up
                Ok(_) => break,
                _ => sleep(Duration::from_millis(500)).await,
            }
        }
    }

    // Flush Redis to start with clean counters (no warmup interference)
    flush_redis_db().await;
    sleep(Duration::from_millis(200)).await;

    // Send 2 requests to gateway 1 — should succeed
    for i in 1..=2 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/shared-rl/test", port1))
            .send()
            .await
            .expect("Request to GW1 failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "GW1 request {} should succeed",
            i
        );
    }

    // Send 2 requests to gateway 2 — should succeed (total: 4)
    for i in 1..=2 {
        let resp = client
            .get(format!("http://127.0.0.1:{}/shared-rl/test", port2))
            .send()
            .await
            .expect("Request to GW2 failed");
        assert_eq!(
            resp.status().as_u16(),
            200,
            "GW2 request {} should succeed",
            i
        );
    }

    // 5th request to either gateway should be rate limited (429)
    let resp = client
        .get(format!("http://127.0.0.1:{}/shared-rl/test", port1))
        .send()
        .await
        .expect("5th request failed");
    assert_eq!(
        resp.status().as_u16(),
        429,
        "5th request (to GW1) should be rate limited — shared Redis counter reached 4"
    );

    // Also verify GW2 is rate limited
    let resp = client
        .get(format!("http://127.0.0.1:{}/shared-rl/test", port2))
        .send()
        .await
        .expect("6th request failed");
    assert_eq!(
        resp.status().as_u16(),
        429,
        "6th request (to GW2) should also be rate limited — shared Redis counter"
    );

    let _ = gw1.kill();
    let _ = gw1.wait();
    let _ = gw2.kill();
    let _ = gw2.wait();
    println!("test_rate_limiting_redis_shared_across_instances PASSED");
}
