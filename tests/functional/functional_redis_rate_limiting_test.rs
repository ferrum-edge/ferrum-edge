//! Functional tests for centralized Redis rate limiting.
//!
//! Tests the Redis-backed rate limiting plugins end-to-end through a real gateway
//! binary. `rate_limiting` and `ai_rate_limiter` should share counters across
//! gateway instances; `ws_rate_limiting` uses Redis as an externalized per-
//! connection counter backend and has a separate cross-instance namespacing test.
//!
//! ## Requirements
//!
//! These tests require a Redis-compatible server running at `127.0.0.1:6379`.
//! If Redis is not available, tests are skipped gracefully (not failed).
//! Set `FERRUM_REDIS_REQUIRED=1` for CI gates that must fail instead of skip.
//!
//! Start Redis locally:
//!   docker run --rm -p 6379:6379 redis:7-alpine
//!
//! Run these tests:
//!   cargo test --test functional_tests functional_redis_rate_limiting -- --ignored --nocapture
//!
//! Compatible with Redis, Valkey, DragonflyDB, KeyDB, or Garnet.

use crate::common::TestGateway;

use futures_util::{SinkExt, StreamExt};
use serde_json::json;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use tokio::sync::Notify;
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

/// Wire Redis key for one rate-limit bucket written under `prefix`.
///
/// Rate-limit counters are hash-tagged — `{escaped-prefix:escaped-rate-key}`
/// followed by the suffix components — so tests must derive the key through the
/// same builder the gateway uses. Concatenating `prefix:rate_key:index` reads a
/// key that is never written.
fn redis_bucket_key(prefix: &str, rate_key: &str, suffix: &[&str]) -> String {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};

    let config = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": REDIS_URL,
            "redis_key_prefix": prefix,
        }),
        prefix,
    )
    .expect("redis config parses")
    .expect("redis mode enabled");
    RedisRateLimitClient::new(config, None, false, None).make_slot_key(rate_key, suffix)
}

/// Every `KEYS` glob a plugin's records may live under for `prefix`.
///
/// Two key families share these helpers: rate-limit counters are hash-tagged
/// (see [`redis_bucket_key`]) while `request_deduplication` records stay flat
/// (`prefix:component:…`). Matching both keeps one cleanup/observation helper
/// correct for every caller instead of silently missing one family.
fn redis_key_globs(prefix: &str) -> Vec<String> {
    // Derived from the production builder with an empty rate key, so the tag
    // escaping can never drift from the gateway's: `{escaped-prefix:}`. The
    // trailing separator is dropped so callers may pass a *partial* prefix
    // (a namespace without the plugin-config id, say) exactly as they can with
    // the flat glob.
    let empty_tag = redis_bucket_key(prefix, "", &[]);
    let open_tag = empty_tag
        .strip_suffix(":}")
        .expect("slot key ends with an empty rate key inside its hash tag");
    vec![format!("{prefix}*"), format!("{open_tag}*")]
}

/// Lua fragment iterating `body` over every glob for `prefix`.
///
/// `keys` is bound to the matches of one pattern per iteration.
fn redis_glob_loop(prefix: &str, body: &str) -> String {
    let patterns = redis_key_globs(prefix)
        .into_iter()
        .map(|pattern| format!("'{pattern}'"))
        .collect::<Vec<_>>()
        .join(",");
    format!(
        "for _,pattern in ipairs({{{patterns}}}) do \
         local keys = redis.call('KEYS',pattern) {body} end"
    )
}

/// Delete only Redis keys matching a specific prefix (DB 15).
/// Uses prefix-scoped deletion to avoid cross-test interference from FLUSHDB.
async fn delete_redis_keys_by_prefix(prefix: &str) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(stream) = tokio::net::TcpStream::connect("127.0.0.1:6379").await else {
        return;
    };
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = reader;
    let mut buf = vec![0u8; 8192];

    // SELECT 15
    writer
        .write_all(b"*2\r\n$6\r\nSELECT\r\n$2\r\n15\r\n")
        .await
        .unwrap();
    let _ = reader.read(&mut buf).await;

    // Use EVAL with Lua to atomically SCAN+DEL keys matching the patterns.
    // This avoids the race of KEYS returning stale results and is safe for
    // concurrent test execution since it only touches keys with our prefix.
    let lua_script = format!(
        "local deleted = 0 {} return deleted",
        redis_glob_loop(
            prefix,
            "for i=1,#keys do redis.call('DEL',keys[i]) deleted = deleted + 1 end",
        )
    );
    let lua_len = lua_script.len();
    let cmd = format!(
        "*3\r\n$4\r\nEVAL\r\n${}\r\n{}\r\n$1\r\n0\r\n",
        lua_len, lua_script
    );
    writer.write_all(cmd.as_bytes()).await.unwrap();
    let _ = reader.read(&mut buf).await;
}

async fn redis_key_count_by_prefix(prefix: &str) -> usize {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(stream) = tokio::net::TcpStream::connect("127.0.0.1:6379").await else {
        return 0;
    };
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = reader;
    let mut buf = vec![0u8; 8192];

    // SELECT 15
    if writer
        .write_all(b"*2\r\n$6\r\nSELECT\r\n$2\r\n15\r\n")
        .await
        .is_err()
    {
        return 0;
    }
    let _ = reader.read(&mut buf).await;

    let lua_script = format!(
        "local found = 0 {} return found",
        redis_glob_loop(prefix, "found = found + #keys")
    );
    let lua_len = lua_script.len();
    let cmd = format!(
        "*3\r\n$4\r\nEVAL\r\n${}\r\n{}\r\n$1\r\n0\r\n",
        lua_len, lua_script
    );
    if writer.write_all(cmd.as_bytes()).await.is_err() {
        return 0;
    }
    buf.fill(0);
    let Ok(n) = reader.read(&mut buf).await else {
        return 0;
    };
    let response = String::from_utf8_lossy(&buf[..n]);
    response
        .strip_prefix(':')
        .and_then(|value| value.split("\r\n").next())
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0)
}

/// Decode every flat request-deduplication record under `prefix` (DB 15).
///
/// Request-deduplication keys are opaque digests, so functional tests cannot
/// derive the exact suffix without reproducing the whole live request context.
/// Callers first isolate a UUID-scoped prefix; requiring exactly one decoded
/// record under it then proves the state of that operation instead of accepting
/// a broad "some key exists" observation.
async fn redis_dedup_records_by_prefix(prefix: &str) -> Vec<serde_json::Value> {
    let client = redis::Client::open(REDIS_URL).expect("valid Redis test URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect to Redis test instance");
    let mut keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{prefix}*"))
        .query_async(&mut connection)
        .await
        .expect("list request-deduplication records");
    keys.sort_unstable();

    let mut records = Vec::with_capacity(keys.len());
    for key in keys {
        let payload: Vec<u8> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .expect("read request-deduplication record");
        records.push(
            serde_json::from_slice(&payload).expect("request-deduplication record must be JSON"),
        );
    }
    records
}

fn assert_single_non_replayable_completion(records: &[serde_json::Value], phase: &str) {
    assert_eq!(
        records.len(),
        1,
        "{phase}: expected exactly one request-deduplication operation record"
    );
    assert_eq!(
        records[0].get("state").and_then(serde_json::Value::as_str),
        Some("completed"),
        "{phase}: operation record must be completed"
    );
    assert!(
        records[0].get("replay").is_none(),
        "{phase}: oversized completion must not carry a Redis replay payload"
    );
}

/// Sum integer Redis counters under `prefix` (DB 15).
///
/// Used to observe the post-reconcile `ai_rate_limiter` token bucket without
/// hard-coding the limit-by identity segment of the Redis key.
async fn redis_sum_counters_by_prefix(prefix: &str) -> i64 {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    let Ok(stream) = tokio::net::TcpStream::connect("127.0.0.1:6379").await else {
        return 0;
    };
    let (reader, mut writer) = tokio::io::split(stream);
    let mut reader = reader;
    let mut buf = vec![0u8; 8192];

    if writer
        .write_all(b"*2\r\n$6\r\nSELECT\r\n$2\r\n15\r\n")
        .await
        .is_err()
    {
        return 0;
    }
    let _ = reader.read(&mut buf).await;

    let lua_script = format!(
        "local sum = 0 {} return sum",
        redis_glob_loop(
            prefix,
            "for i=1,#keys do local v = redis.call('GET',keys[i]) \
             if v then sum = sum + (tonumber(v) or 0) end end",
        )
    );
    let lua_len = lua_script.len();
    let cmd = format!(
        "*3\r\n$4\r\nEVAL\r\n${}\r\n{}\r\n$1\r\n0\r\n",
        lua_len, lua_script
    );
    if writer.write_all(cmd.as_bytes()).await.is_err() {
        return 0;
    }
    buf.fill(0);
    let Ok(n) = reader.read(&mut buf).await else {
        return 0;
    };
    let response = String::from_utf8_lossy(&buf[..n]);
    response
        .strip_prefix(':')
        .and_then(|value| value.split("\r\n").next())
        .and_then(|value| value.parse::<i64>().ok())
        .unwrap_or(0)
}

async fn set_redis_counter(key: &str, value: u64, ttl_seconds: u64) {
    let client = redis::Client::open(REDIS_URL).expect("valid Redis test URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect to Redis test instance");
    let result: String = redis::cmd("SET")
        .arg(key)
        .arg(value)
        .arg("EX")
        .arg(ttl_seconds)
        .query_async(&mut connection)
        .await
        .expect("seed Redis rate-limit counter");
    assert_eq!(result, "OK");
}

async fn redis_counter_value(key: &str) -> Option<u64> {
    let client = redis::Client::open(REDIS_URL).expect("valid Redis test URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect to Redis test instance");
    redis::cmd("GET")
        .arg(key)
        .query_async(&mut connection)
        .await
        .expect("read Redis rate-limit counter")
}

// ============================================================================
// Test Harness (Database mode with Redis rate limiting)
// ============================================================================

struct RedisRateLimitHarness {
    _gw: TestGateway,
    proxy_base_url: String,
    admin_base_url: String,
}

impl RedisRateLimitHarness {
    async fn new() -> Result<Self, Box<dyn std::error::Error + Send + Sync>> {
        let run_id = Uuid::new_v4().simple().to_string();
        let gw = TestGateway::builder()
            .jwt_secret(format!("test-redis-rl-jwt-secret-1234567890-{run_id}"))
            .jwt_issuer(format!("ferrum-edge-redis-rl-test-{run_id}"))
            .log_level("debug")
            .env("FERRUM_TRUSTED_PROXIES", "127.0.0.1")
            .spawn()
            .await?;
        Ok(Self {
            proxy_base_url: gw.proxy_base_url.clone(),
            admin_base_url: gw.admin_base_url.clone(),
            _gw: gw,
        })
    }

    /// Wait for the DB poll to pick up config changes by actively probing a route.
    /// Falls back to a 5-second sleep if no path is provided.
    async fn wait_for_poll(&self) {
        sleep(Duration::from_secs(5)).await;
    }

    /// Wait until a route is served by the expected plugin configuration.
    /// A DB poll can observe the proxy row before a later proxy update attaches
    /// plugins, so route readiness alone is not enough for plugin assertions.
    async fn wait_for_response_header(&self, path: &str, header_name: &str) {
        let url = format!("{}{}", self.proxy_base_url, path);
        let client = reqwest::Client::new();
        let deadline = SystemTime::now() + Duration::from_secs(30);
        loop {
            if SystemTime::now() >= deadline {
                panic!(
                    "Route {} did not expose response header {} within 30 seconds",
                    path, header_name
                );
            }
            match client.get(&url).send().await {
                Ok(r) if r.headers().contains_key(header_name) => return,
                _ => sleep(Duration::from_millis(500)).await,
            }
        }
    }

    fn generate_admin_token(&self) -> String {
        self._gw.admin_token()
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

// ============================================================================
// Helpers
// ============================================================================

async fn spawn_file_gateway(config: String, extra_env: Vec<(String, String)>) -> TestGateway {
    // Do not pin FERRUM_PROXY_HTTP_PORT here. The harness allocates a fresh
    // proxy port on every spawn attempt; a caller-reserved bind-drop-rebind
    // port stays fixed across retries and turns the retry loop into a TOCTOU
    // port race. Tests must read `gateway.proxy_port` after a successful spawn.
    let mut builder = TestGateway::builder()
        .mode_file(config)
        .log_level("debug")
        .capture_output();
    for (key, value) in extra_env {
        assert!(
            key != "FERRUM_PROXY_HTTP_PORT" && key != "FERRUM_ADMIN_HTTP_PORT",
            "spawn_file_gateway must not pin {key}; let the harness allocate and read the effective port after spawn"
        );
        builder = builder.env(key, value);
    }
    builder
        .spawn()
        .await
        .expect("Failed to start gateway instance")
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

async fn start_blocking_counting_backend_on(
    listener: tokio::net::TcpListener,
    hits: Arc<AtomicUsize>,
    blocked: Arc<AtomicBool>,
    release: Arc<Notify>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let hits = Arc::clone(&hits);
            let blocked = Arc::clone(&blocked);
            let release = Arc::clone(&release);
            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut buf_reader = tokio::io::BufReader::new(reader);
                use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

                let mut request_line = String::new();
                if buf_reader.read_line(&mut request_line).await.is_err()
                    || !request_line.starts_with("POST ")
                {
                    return;
                }
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    let _ = buf_reader.read_line(&mut line).await;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((key, value)) = trimmed.split_once(':')
                        && key.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut body_buf = vec![0u8; content_length];
                    let _ = buf_reader.read_exact(&mut body_buf).await;
                }

                hits.fetch_add(1, Ordering::SeqCst);
                blocked.store(true, Ordering::SeqCst);
                release.notified().await;

                let body = json!({
                    "request_line": request_line.trim(),
                    "backend_hits": hits.load(Ordering::SeqCst),
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(handle)
}

async fn start_counting_backend_on(
    listener: tokio::net::TcpListener,
    hits: Arc<AtomicUsize>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let hits = Arc::clone(&hits);
            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut buf_reader = tokio::io::BufReader::new(reader);
                use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

                let mut request_line = String::new();
                if buf_reader.read_line(&mut request_line).await.is_err()
                    || !request_line.starts_with("POST ")
                {
                    return;
                }
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    let _ = buf_reader.read_line(&mut line).await;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((key, value)) = trimmed.split_once(':')
                        && key.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut body_buf = vec![0u8; content_length];
                    let _ = buf_reader.read_exact(&mut body_buf).await;
                }

                hits.fetch_add(1, Ordering::SeqCst);

                let body = json!({
                    "request_line": request_line.trim(),
                    "backend_hits": hits.load(Ordering::SeqCst),
                })
                .to_string();
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });
    Ok(handle)
}

async fn start_audit_collector_on(
    listener: tokio::net::TcpListener,
    records: Arc<tokio::sync::Mutex<Vec<serde_json::Value>>>,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let records = Arc::clone(&records);
            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut reader = tokio::io::BufReader::new(reader);
                use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
                loop {
                    let mut request_line = String::new();
                    if reader.read_line(&mut request_line).await.is_err() || request_line.is_empty()
                    {
                        return;
                    }
                    let mut content_length = 0usize;
                    loop {
                        let mut line = String::new();
                        if reader.read_line(&mut line).await.is_err() {
                            return;
                        }
                        let trimmed = line.trim();
                        if trimmed.is_empty() {
                            break;
                        }
                        if let Some((key, value)) = trimmed.split_once(':')
                            && key.trim().eq_ignore_ascii_case("content-length")
                        {
                            content_length = value.trim().parse().unwrap_or(0);
                        }
                    }
                    let mut body = vec![0u8; content_length];
                    if content_length > 0 && reader.read_exact(&mut body).await.is_err() {
                        return;
                    }
                    if let Ok(serde_json::Value::Array(batch)) =
                        serde_json::from_slice::<serde_json::Value>(&body)
                    {
                        records.lock().await.extend(batch);
                    }
                    if writer
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: keep-alive\r\n\r\n",
                        )
                        .await
                        .is_err()
                    {
                        return;
                    }
                }
            });
        }
    });
    Ok(handle)
}

async fn start_counting_large_function_on(
    listener: tokio::net::TcpListener,
    hits: Arc<AtomicUsize>,
    body_len: usize,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let body = Arc::new(vec![b'x'; body_len]);
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let hits = Arc::clone(&hits);
            let body = Arc::clone(&body);
            tokio::spawn(async move {
                let (reader, mut writer) = tokio::io::split(stream);
                let mut buf_reader = tokio::io::BufReader::new(reader);
                use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};

                let mut request_line = String::new();
                if buf_reader.read_line(&mut request_line).await.is_err()
                    || !request_line.starts_with("POST ")
                {
                    return;
                }
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    let _ = buf_reader.read_line(&mut line).await;
                    let trimmed = line.trim();
                    if trimmed.is_empty() {
                        break;
                    }
                    if let Some((key, value)) = trimmed.split_once(':')
                        && key.trim().eq_ignore_ascii_case("content-length")
                    {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut request_body = vec![0u8; content_length];
                    let _ = buf_reader.read_exact(&mut request_body).await;
                }

                hits.fetch_add(1, Ordering::SeqCst);
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    body.len()
                );
                let _ = writer.write_all(response.as_bytes()).await;
                let _ = writer.write_all(body.as_slice()).await;
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
    start_ai_backend_on(listener, total_tokens).await
}

async fn start_ai_backend_on(
    listener: tokio::net::TcpListener,
    total_tokens: u64,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    start_ai_backend_with_usage_on(listener, total_tokens / 2, total_tokens / 2).await
}

/// Start a mock LLM backend that returns explicit OpenAI-style usage fields.
async fn start_ai_backend_with_usage(
    port: u16,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let listener = tokio::net::TcpListener::bind(format!("127.0.0.1:{}", port)).await?;
    start_ai_backend_with_usage_on(listener, prompt_tokens, completion_tokens).await
}

async fn start_ai_backend_with_usage_on(
    listener: tokio::net::TcpListener,
    prompt_tokens: u64,
    completion_tokens: u64,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
    let handle = tokio::spawn(async move {
        loop {
            let Ok((stream, _)) = listener.accept().await else {
                continue;
            };
            let prompt = prompt_tokens;
            let completion = completion_tokens;
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

                let total = prompt.saturating_add(completion);
                let body = json!({
                    "id": "chatcmpl-test",
                    "object": "chat.completion",
                    "choices": [{
                        "index": 0,
                        "message": {"role": "assistant", "content": "Hello!"},
                        "finish_reason": "stop"
                    }],
                    "usage": {
                        "prompt_tokens": prompt,
                        "completion_tokens": completion,
                        "total_tokens": total
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
// The `Message::Ping(data)` arm consumes `data` (a `Bytes`) when forwarding
// to `Message::Pong(data)`. Collapsing into a match guard is rejected by the
// borrow checker (E0507) because variables bound in patterns cannot be moved
// from inside a pattern guard.
#[allow(clippy::collapsible_match)]
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
                            if sink.send(Message::Text(echo.into())).await.is_err() {
                                break;
                            }
                        }
                        Message::Binary(data) => {
                            let echo = format!("Echo binary: {} bytes", data.len());
                            if sink.send(Message::Text(echo.into())).await.is_err() {
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
    backend_scheme: &str,
    plugins: Vec<serde_json::Value>,
) -> Result<(), Box<dyn std::error::Error>> {
    harness
        .create_proxy(
            client,
            &json!({
                "id": proxy_id,
                "listen_path": listen_path,
                "backend_scheme": backend_scheme,
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
                "backend_scheme": backend_scheme,
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
                "expose_headers": true,
                "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 3}],
                "sync_mode": "redis",
                "redis_url": REDIS_URL,
                "redis_key_prefix": unique_prefix
            }
        })],
    )
    .await
    .unwrap();

    // Actively wait for the route plus plugin update to be loaded (more
    // reliable than fixed sleep or route-only readiness under CI load).
    harness
        .wait_for_response_header("/redis-rl/test", "x-ratelimit-limit")
        .await;

    // Clear only this test's rate limit keys (probe requests consumed quota).
    // Uses targeted key deletion instead of FLUSHDB to avoid interfering with
    // other Redis rate-limit tests that may be running concurrently.
    delete_redis_keys_by_prefix(&unique_prefix).await;

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

/// A full previous one-second Redis bucket must decay during the current
/// bucket. The old whole-second fraction stayed at zero and rejected this
/// candidate for the entire second.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_one_second_previous_bucket_decays() {
    if !redis_is_available().await {
        return;
    }

    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();
    let unique_prefix = format!("ferrum:test:rl-decay:{}", Uuid::new_v4().simple());
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-redis-rl-decay",
        "/redis-rl-decay",
        backend_port,
        "http",
        vec![json!({
            "id": "plugin-redis-rl-decay",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": "proxy-redis-rl-decay",
            "enabled": true,
            "config": {
                "expose_headers": true,
                "limits": [{"scope": "default", "window_seconds": 1, "max_requests": 10}],
                "sync_mode": "redis",
                "redis_url": REDIS_URL,
                "redis_key_prefix": unique_prefix
            }
        })],
    )
    .await
    .unwrap();
    harness
        .wait_for_response_header("/redis-rl-decay/test", "x-ratelimit-limit")
        .await;

    let url = format!("{}/redis-rl-decay/test", harness.proxy_base_url);
    let mut verified_without_boundary_cross = false;
    for _ in 0..3 {
        delete_redis_keys_by_prefix(&unique_prefix).await;

        // Leave at least ~450ms before the next boundary so the Redis seed and
        // HTTP request use the same current bucket even on a busy hosted runner.
        let current_index = loop {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .expect("system clock after Unix epoch");
            let fraction_nanos = now.subsec_nanos();
            if (300_000_000..=500_000_000).contains(&fraction_nanos) {
                break now.as_secs();
            }
            sleep(Duration::from_millis(5)).await;
        };

        let previous_key = redis_bucket_key(
            &unique_prefix,
            "ip:127.0.0.1",
            &[&current_index.saturating_sub(1).to_string()],
        );
        let current_key = redis_bucket_key(
            &unique_prefix,
            "ip:127.0.0.1",
            &[&current_index.to_string()],
        );
        set_redis_counter(&previous_key, 10, 3).await;

        let response = client
            .get(&url)
            .send()
            .await
            .expect("one-second Redis decay request");
        let finished_index = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch")
            .as_secs();
        if finished_index != current_index {
            continue;
        }

        assert_eq!(
            redis_counter_value(&current_key).await,
            Some(1),
            "request must increment the expected current Redis identity bucket"
        );
        assert_eq!(
            response.status().as_u16(),
            200,
            "a full prior bucket must decay enough to admit a mid-window candidate"
        );
        verified_without_boundary_cross = true;
        break;
    }

    assert!(
        verified_without_boundary_cross,
        "could not complete the Redis decay assertion without crossing a one-second boundary"
    );
    delete_redis_keys_by_prefix(&unique_prefix).await;
}

// ============================================================================
// Test: rate_limiting Redis fallback to local when Redis URL is unreachable
// ============================================================================

/// Verify that when Redis is configured but unreachable (bad port), the
/// explicit `redis_failure_policy: "local_fallback"` opt-in gracefully degrades
/// to local in-memory rate limiting.
///
/// GHSA-87rq-v4hx-8rcq: this is no longer the default. Per-process budgets let a
/// client multiply the configured limit by the number of reachable data planes,
/// so the fallback must be asked for; the companion test below proves the
/// default refuses instead.
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
                "expose_headers": true,
                "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 3}],
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:19999/0",
                "redis_failure_policy": "local_fallback",
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

/// GHSA-87rq-v4hx-8rcq: with the default `redis_failure_policy`, an
/// unreachable centralized store must refuse rather than admit on a budget only
/// this process can see. `503` (not `429`) because the caller is not over its
/// limit — the limit cannot be evaluated — and no rate-limit headers are
/// advertised for a budget nothing is enforcing.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_unavailable_fails_closed_by_default() {
    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();

    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-redis-fc",
        "/redis-fail-closed",
        backend_port,
        "http",
        vec![json!({
            "id": "plugin-redis-fc",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": "proxy-redis-fc",
            "enabled": true,
            "config": {
                "expose_headers": true,
                "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 3}],
                "sync_mode": "redis",
                "redis_url": "redis://127.0.0.1:19999/0",
                "redis_key_prefix": "ferrum:test:failclosed"
            }
        })],
    )
    .await
    .unwrap();

    harness.wait_for_poll().await;

    // The very first request already refuses: no per-process budget is granted.
    let resp = client
        .get(format!("{}/redis-fail-closed/test", harness.proxy_base_url))
        .send()
        .await
        .expect("Request failed");
    assert_eq!(
        resp.status().as_u16(),
        503,
        "an unprovable centralized budget must fail closed, not admit locally"
    );
    assert!(
        resp.headers().get("x-ratelimit-limit").is_none(),
        "a fail-closed refusal must not advertise a budget nothing is enforcing"
    );
    assert!(
        resp.headers().get("x-ratelimit-remaining").is_none(),
        "a fail-closed refusal must not advertise a budget nothing is enforcing"
    );

    // It stays refused: a per-process counter never accumulates admissions.
    for _ in 0..3 {
        let resp = client
            .get(format!("{}/redis-fail-closed/test", harness.proxy_base_url))
            .send()
            .await
            .expect("Request failed");
        assert_eq!(resp.status().as_u16(), 503);
    }

    println!("test_rate_limiting_redis_unavailable_fails_closed_by_default PASSED");
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
    delete_redis_keys_by_prefix(&unique_prefix).await;

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

/// Verify that ai_rate_limiter shares token budgets across gateway instances.
#[tokio::test]
#[ignore]
async fn test_ai_rate_limiter_redis_shared_across_instances() {
    if !redis_is_available().await {
        return;
    }

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let _backend = start_ai_backend_on(backend_listener, 500).await.unwrap();

    let unique_prefix = format!("ferrum:test:ai:shared:{}", Uuid::new_v4().simple());
    let config = |prefix: &str| {
        format!(
            r#"
version: "1"
proxies:
  - id: "shared-ai-proxy"
    listen_path: "/shared-ai"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "shared-ai-plugin"

consumers: []

plugin_configs:
  - id: "shared-ai-plugin"
    plugin_name: "ai_rate_limiter"
    scope: "proxy"
    proxy_id: "shared-ai-proxy"
    enabled: true
    config:
      token_limit: 1000
      window_seconds: 60
      limit_by: "ip"
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix}"
"#,
        )
    };

    let mut gw1 = spawn_file_gateway(
        config(&unique_prefix),
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;
    let mut gw2 = spawn_file_gateway(
        config(&unique_prefix),
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;
    let port1 = gw1.proxy_port;
    let port2 = gw2.proxy_port;

    let client = reqwest::Client::new();
    let request_body = r#"{"model":"test","messages":[{"role":"user","content":"hi"}]}"#;

    delete_redis_keys_by_prefix(&unique_prefix).await;
    sleep(Duration::from_millis(200)).await;

    let resp = client
        .post(format!(
            "http://127.0.0.1:{}/shared-ai/v1/chat/completions",
            port1
        ))
        .header("Content-Type", "application/json")
        .body(request_body)
        .send()
        .await
        .expect("GW1 AI request failed");
    assert_eq!(resp.status().as_u16(), 200, "GW1 request should succeed");
    let _ = resp.text().await;

    let resp = client
        .post(format!(
            "http://127.0.0.1:{}/shared-ai/v1/chat/completions",
            port2
        ))
        .header("Content-Type", "application/json")
        .body(request_body)
        .send()
        .await
        .expect("GW2 AI request failed");
    assert_eq!(
        resp.status().as_u16(),
        200,
        "GW2 request should succeed and consume the shared budget"
    );
    let _ = resp.text().await;

    let resp = client
        .post(format!(
            "http://127.0.0.1:{}/shared-ai/v1/chat/completions",
            port1
        ))
        .header("Content-Type", "application/json")
        .body(request_body)
        .send()
        .await
        .expect("Third shared AI request failed");
    assert_eq!(
        resp.status().as_u16(),
        429,
        "3rd shared AI request should be rejected after both instances consume 1000 tokens"
    );

    gw1.shutdown();
    gw2.shutdown();
    println!("test_ai_rate_limiter_redis_shared_across_instances PASSED");
}

/// #2261 Redis acceptance: client-visible expose headers must match the
/// post-reconcile Redis token bucket after a real OpenAI-style response.
///
/// Covers both a positive delta (actual usage > admission reservation) and a
/// negative delta (reservation > actual usage). Uses `count_mode:
/// completion_tokens` so the reservation equals `max_tokens` exactly.
///
/// Distinct from the unit test
/// `expose_headers_lifecycle_reflects_reconciled_usage_redis_fallback`, which
/// points at an unreachable Redis URL and only proves local failover.
#[tokio::test]
#[ignore]
async fn test_ai_rate_limiter_redis_expose_headers_match_reconciled_bucket() {
    if !redis_is_available().await {
        return;
    }

    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");
    let client = reqwest::Client::new();
    let token_limit: u64 = 1000;
    // Long window keeps the reservation and reconcile in the same Redis
    // bucket index so header usage equals the raw counter (no sliding-window
    // prev-term contribution / rollover race during the request).
    let window_seconds: u64 = 3600;

    // --- Positive delta: reserve 50 completion tokens, actual completion = 80 ---
    {
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend_listener.local_addr().unwrap().port();
        drop(backend_listener);
        let reserved: u64 = 50;
        let actual_completion: u64 = 80;
        let _backend = start_ai_backend_with_usage(backend_port, 10, actual_completion)
            .await
            .unwrap();
        let unique_prefix = format!("ferrum:test:ai:expose:pos:{}", Uuid::new_v4().simple());

        setup_proxy_with_plugins(
            &harness,
            &client,
            "proxy-ai-expose-pos",
            "/ai-expose-pos",
            backend_port,
            "http",
            vec![json!({
                "id": "plugin-ai-expose-pos",
                "plugin_name": "ai_rate_limiter",
                "scope": "proxy",
                "proxy_id": "proxy-ai-expose-pos",
                "enabled": true,
                "config": {
                    "token_limit": token_limit,
                    "window_seconds": window_seconds,
                    "count_mode": "completion_tokens",
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
        delete_redis_keys_by_prefix(&unique_prefix).await;

        let resp = client
            .post(format!(
                "{}/ai-expose-pos/v1/chat/completions",
                harness.proxy_base_url
            ))
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{"model":"test","messages":[{{"role":"user","content":"hi"}}],"max_tokens":{reserved}}}"#
            ))
            .send()
            .await
            .expect("positive-delta request failed");

        // Read headers before consuming the body so assertions use the
        // client-visible map as delivered on the wire.
        assert_eq!(resp.status().as_u16(), 200, "positive-delta must succeed");
        let usage_hdr = resp
            .headers()
            .get("x-ai-ratelimit-usage")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let remaining_hdr = resp
            .headers()
            .get("x-ai-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let _ = resp.text().await;

        assert_ne!(
            actual_completion, reserved,
            "fixture must exercise a non-zero positive reservation delta"
        );
        let expected_usage = actual_completion.to_string();
        let expected_remaining = (token_limit - actual_completion).to_string();
        assert_eq!(
            usage_hdr.as_deref(),
            Some(expected_usage.as_str()),
            "positive-delta headers must expose reconciled usage, not the admission estimate {reserved}"
        );
        assert_eq!(
            remaining_hdr.as_deref(),
            Some(expected_remaining.as_str()),
            "positive-delta remaining must match the post-reconcile Redis budget"
        );
        let redis_usage = redis_sum_counters_by_prefix(&unique_prefix).await;
        assert_eq!(
            redis_usage, actual_completion as i64,
            "Redis bucket after positive-delta reconcile must charge actual completion tokens"
        );
        let redis_usage_str = redis_usage.to_string();
        let redis_remaining_str = (token_limit as i64 - redis_usage).to_string();
        assert_eq!(
            usage_hdr.as_deref(),
            Some(redis_usage_str.as_str()),
            "client-visible usage must match the post-reconcile Redis bucket"
        );
        assert_eq!(
            remaining_hdr.as_deref(),
            Some(redis_remaining_str.as_str()),
            "client-visible remaining must match token_limit minus Redis usage"
        );

        delete_redis_keys_by_prefix(&unique_prefix).await;
    }

    // --- Negative delta: reserve 200 completion tokens, actual completion = 10 ---
    {
        let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let backend_port = backend_listener.local_addr().unwrap().port();
        drop(backend_listener);
        let reserved: u64 = 200;
        let actual_completion: u64 = 10;
        let _backend = start_ai_backend_with_usage(backend_port, 10, actual_completion)
            .await
            .unwrap();
        let unique_prefix = format!("ferrum:test:ai:expose:neg:{}", Uuid::new_v4().simple());

        setup_proxy_with_plugins(
            &harness,
            &client,
            "proxy-ai-expose-neg",
            "/ai-expose-neg",
            backend_port,
            "http",
            vec![json!({
                "id": "plugin-ai-expose-neg",
                "plugin_name": "ai_rate_limiter",
                "scope": "proxy",
                "proxy_id": "proxy-ai-expose-neg",
                "enabled": true,
                "config": {
                    "token_limit": token_limit,
                    "window_seconds": window_seconds,
                    "count_mode": "completion_tokens",
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
        delete_redis_keys_by_prefix(&unique_prefix).await;

        let resp = client
            .post(format!(
                "{}/ai-expose-neg/v1/chat/completions",
                harness.proxy_base_url
            ))
            .header("Content-Type", "application/json")
            .body(format!(
                r#"{{"model":"test","messages":[{{"role":"user","content":"hi"}}],"max_tokens":{reserved}}}"#
            ))
            .send()
            .await
            .expect("negative-delta request failed");

        assert_eq!(resp.status().as_u16(), 200, "negative-delta must succeed");
        let usage_hdr = resp
            .headers()
            .get("x-ai-ratelimit-usage")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let remaining_hdr = resp
            .headers()
            .get("x-ai-ratelimit-remaining")
            .and_then(|v| v.to_str().ok())
            .map(str::to_owned);
        let _ = resp.text().await;

        assert_ne!(
            actual_completion, reserved,
            "fixture must exercise a non-zero negative reservation delta"
        );
        let expected_usage = actual_completion.to_string();
        let expected_remaining = (token_limit - actual_completion).to_string();
        assert_eq!(
            usage_hdr.as_deref(),
            Some(expected_usage.as_str()),
            "negative-delta headers must expose reconciled usage, not the admission estimate {reserved}"
        );
        assert_eq!(
            remaining_hdr.as_deref(),
            Some(expected_remaining.as_str()),
            "negative-delta remaining must match the post-reconcile Redis budget"
        );
        let redis_usage = redis_sum_counters_by_prefix(&unique_prefix).await;
        assert_eq!(
            redis_usage, actual_completion as i64,
            "Redis bucket after negative-delta reconcile must charge actual completion tokens"
        );
        let redis_usage_str = redis_usage.to_string();
        let redis_remaining_str = (token_limit as i64 - redis_usage).to_string();
        assert_eq!(
            usage_hdr.as_deref(),
            Some(redis_usage_str.as_str()),
            "client-visible usage must match the post-reconcile Redis bucket"
        );
        assert_eq!(
            remaining_hdr.as_deref(),
            Some(redis_remaining_str.as_str()),
            "client-visible remaining must match token_limit minus Redis usage"
        );

        delete_redis_keys_by_prefix(&unique_prefix).await;
    }

    println!("test_ai_rate_limiter_redis_expose_headers_match_reconciled_bucket PASSED");
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

    let backend_port = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let unique_prefix = format!("ferrum:test:ws:{}", Uuid::new_v4().simple());
    delete_redis_keys_by_prefix(&unique_prefix).await;

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "ws-redis-proxy"
    listen_path: "/ws-redis"
    backend_scheme: http
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
    let mut gateway = spawn_file_gateway(
        config,
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;

    let url = format!("ws://127.0.0.1:{}/ws-redis", gateway.proxy_port);
    let (mut ws, _) = tokio_tungstenite::connect_async(&url)
        .await
        .expect("Failed to connect WebSocket");

    // Send messages within limit — should pass
    for i in 0..5 {
        let msg = format!("msg {}", i);
        ws.send(Message::Text(msg.clone().into())).await.unwrap();
        let reply = ws.next().await.unwrap().unwrap();
        assert_eq!(
            reply,
            Message::Text(format!("Echo: {}", msg).into()),
            "Message {} within limit should echo via Redis mode",
            i
        );
    }

    // Burst to exceed limit — should eventually close the connection
    let mut connection_closed = false;
    for i in 5..100 {
        let msg = format!("burst msg {}", i);
        match ws.send(Message::Text(msg.into())).await {
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

    gateway.shutdown();
    echo_handle.abort();
    println!("test_ws_rate_limiting_redis_centralized PASSED");
}

/// Verify that Redis-backed WebSocket frame rate limiting does not collide
/// across gateway instances that reuse the same local connection IDs.
#[tokio::test]
#[ignore]
async fn test_ws_rate_limiting_redis_namespaces_instance_connections() {
    if !redis_is_available().await {
        return;
    }

    let backend_port = {
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let p = l.local_addr().unwrap().port();
        drop(l);
        p
    };

    let echo_handle = tokio::spawn(start_ws_echo_server(backend_port));
    sleep(Duration::from_millis(300)).await;

    let unique_prefix = format!("ferrum:test:ws-shared:{}", Uuid::new_v4().simple());
    let config = |prefix: &str| {
        format!(
            r#"
version: "1"
proxies:
  - id: "ws-shared-redis-proxy"
    listen_path: "/ws-shared"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ws-shared-redis-rl"

consumers: []

plugin_configs:
  - id: "ws-shared-redis-rl"
    plugin_name: "ws_rate_limiting"
    scope: "proxy"
    proxy_id: "ws-shared-redis-proxy"
    enabled: true
    config:
      frames_per_second: 5
      burst_size: 5
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix}"
"#,
        )
    };

    let mut gw1 = spawn_file_gateway(
        config(&unique_prefix),
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;
    let mut gw2 = spawn_file_gateway(
        config(&unique_prefix),
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;

    delete_redis_keys_by_prefix(&unique_prefix).await;
    sleep(Duration::from_millis(200)).await;

    let url1 = format!("ws://127.0.0.1:{}/ws-shared", gw1.proxy_port);
    let url2 = format!("ws://127.0.0.1:{}/ws-shared", gw2.proxy_port);
    let (mut ws1, _) = tokio_tungstenite::connect_async(&url1)
        .await
        .expect("Failed to connect WebSocket to gateway 1");
    let (mut ws2, _) = tokio_tungstenite::connect_async(&url2)
        .await
        .expect("Failed to connect WebSocket to gateway 2");

    // Each echoed message consumes two frame budget units (client->backend and
    // backend->client). Two round-trips leave GW1 near the limit without
    // tripping it, so an old shared-key collision would still break GW2.
    for i in 0..2 {
        let msg = format!("gw1 msg {}", i);
        ws1.send(Message::Text(msg.clone().into())).await.unwrap();
        let reply = ws1.next().await.unwrap().unwrap();
        assert_eq!(
            reply,
            Message::Text(format!("Echo: {}", msg).into()),
            "Gateway 1 frame {} should stay within its own Redis-backed limit",
            i
        );
    }

    let msg = "gw2 independent msg".to_string();
    ws2.send(Message::Text(msg.clone().into())).await.unwrap();
    let reply = ws2
        .next()
        .await
        .expect("Gateway 2 should still have an open connection")
        .expect("Gateway 2 read failed");
    assert_eq!(
        reply,
        Message::Text(format!("Echo: {}", msg).into()),
        "Gateway 2's first connection should not inherit Gateway 1's Redis bucket"
    );

    let _ = ws1.close(None).await;
    let _ = ws2.close(None).await;
    gw1.shutdown();
    gw2.shutdown();
    echo_handle.abort();
    println!("test_ws_rate_limiting_redis_namespaces_instance_connections PASSED");
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

    // Start a shared backend
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let unique_prefix = format!("ferrum:test:shared:{}", Uuid::new_v4().simple());
    let config = |prefix: &str| {
        format!(
            r#"
version: "1"
proxies:
  - id: "shared-rl-proxy"
    listen_path: "/shared-rl"
    backend_scheme: http
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
      expose_headers: true
      limits:
        - scope: "default"
          window_seconds: 60
          max_requests: 4
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix}"
"#,
        )
    };

    // Allocate two gateway instances with harness-managed proxy ports so each
    // spawn attempt can retry on a fresh port rather than a dropped reservation.
    let mut gw1 = spawn_file_gateway(
        config(&unique_prefix),
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;
    let mut gw2 = spawn_file_gateway(
        config(&unique_prefix),
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;
    let port1 = gw1.proxy_port;
    let port2 = gw2.proxy_port;

    let client = reqwest::Client::new();

    // Clear only this test's counters so concurrent Redis tests keep their
    // own shared-state assertions intact.
    delete_redis_keys_by_prefix(&unique_prefix).await;
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

    gw1.shutdown();
    gw2.shutdown();
    println!("test_rate_limiting_redis_shared_across_instances PASSED");
}

/// GHSA-f72h-jm2p-mc73: the ownership fence that backs `request_deduplication`
/// Redis publication. A completion may only replace the publisher's own
/// still-current in-flight record; an expired or superseded owner writes
/// nothing, in either completion order.
#[tokio::test]
#[ignore]
async fn test_request_deduplication_redis_publication_is_ownership_fenced() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};

    if !redis_is_available().await {
        if std::env::var_os("FERRUM_REDIS_REQUIRED").is_some() {
            panic!("Redis is required for the request deduplication fencing CI gate");
        }
        return;
    }

    let prefix = format!("ferrum:test:dedupfence:{}", Uuid::new_v4().simple());
    let config = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            "redis_url": REDIS_URL,
            "redis_key_prefix": prefix,
        }),
        &prefix,
    )
    .expect("redis config parses")
    .expect("redis mode enabled");
    let client = RedisRateLimitClient::new(config, None, false, None);

    let key = client.make_key(&["fence"]);
    let owner_a = b"owner-a-inflight-record".to_vec();
    let owner_b = b"owner-b-inflight-record".to_vec();
    let result_a = b"owner-a-completed-record".to_vec();
    let result_b = b"owner-b-completed-record".to_vec();

    // Owner A acquires the operation with a short lease.
    assert!(
        client
            .set_bytes_nx_with_expire(&key, &owner_a, 60)
            .await
            .expect("acquire"),
    );

    // A successor cannot acquire while A owns it.
    assert!(
        !client
            .set_bytes_nx_with_expire(&key, &owner_b, 60)
            .await
            .expect("contended acquire")
    );

    // Simulate lease expiry plus successor acquisition.
    client.delete(&key).await.expect("expire owner A lease");
    assert!(
        client
            .set_bytes_nx_with_expire(&key, &owner_b, 60)
            .await
            .expect("successor acquire")
    );

    // Expired owner A must not publish over the successor's ownership.
    assert!(
        !client
            .set_bytes_with_expire_if_value_matches(&key, &owner_a, &result_a, 60)
            .await
            .expect("stale publication"),
        "an expired owner must not publish while a successor owns the operation"
    );
    assert_eq!(
        client.get_bytes(&key).await.expect("read record"),
        Some(owner_b.clone())
    );

    // The successor's own publication is the ownership transition.
    assert!(
        client
            .set_bytes_with_expire_if_value_matches(&key, &owner_b, &result_b, 60)
            .await
            .expect("successor publication")
    );
    assert_eq!(
        client.get_bytes(&key).await.expect("read record"),
        Some(result_b.clone())
    );

    // Reversed completion order: the stale owner still cannot overwrite the
    // successor's completed result.
    assert!(
        !client
            .set_bytes_with_expire_if_value_matches(&key, &owner_a, &result_a, 60)
            .await
            .expect("stale overwrite")
    );
    assert_eq!(
        client.get_bytes(&key).await.expect("read record"),
        Some(result_b)
    );

    // A completely absent record cannot be resurrected by a stale owner.
    client.delete(&key).await.expect("drop record");
    assert!(
        !client
            .set_bytes_with_expire_if_value_matches(&key, &owner_a, &result_a, 60)
            .await
            .expect("resurrect attempt")
    );
    assert_eq!(client.get_bytes(&key).await.expect("read record"), None);

    delete_redis_keys_by_prefix(&prefix).await;
    println!("test_request_deduplication_redis_publication_is_ownership_fenced PASSED");
}

/// Request deduplication must use Redis for in-flight exclusion, not only for
/// completed response replay. Two gateway instances sharing Redis should not
/// both execute the same idempotent POST concurrently.
///
/// Companion to `test_request_deduplication_redis_same_proxy_sibling_instances_do_not_self_conflict`
/// (#2379): corresponding copies of one `plugin_config_id` must still share
/// locks and completed values across gateways.
#[tokio::test]
#[ignore]
async fn test_request_deduplication_redis_blocks_concurrent_cross_instance() {
    if !redis_is_available().await {
        if std::env::var_os("FERRUM_REDIS_REQUIRED").is_some() {
            panic!("Redis is required for the request deduplication cross-instance CI gate");
        }
        return;
    }

    let audit_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let audit_port = audit_listener.local_addr().unwrap().port();
    let audit_records = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _audit_collector = start_audit_collector_on(audit_listener, Arc::clone(&audit_records))
        .await
        .unwrap();

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let backend_blocked = Arc::new(AtomicBool::new(false));
    let release_backend = Arc::new(Notify::new());
    let _backend = start_blocking_counting_backend_on(
        backend_listener,
        Arc::clone(&backend_hits),
        Arc::clone(&backend_blocked),
        Arc::clone(&release_backend),
    )
    .await
    .unwrap();

    // A body of this size fits the 1 MiB local retained-entry limit, while its
    // base64 Redis representation exceeds that limit and retains the owned
    // terminal in-flight lock.
    const LARGE_FUNCTION_BODY_LEN: usize = 800 * 1024;
    let function_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let function_port = function_listener.local_addr().unwrap().port();
    let function_hits = Arc::new(AtomicUsize::new(0));
    let _function = start_counting_large_function_on(
        function_listener,
        Arc::clone(&function_hits),
        LARGE_FUNCTION_BODY_LEN,
    )
    .await
    .unwrap();

    let unique_prefix = format!("ferrum:test:dedup:{}", Uuid::new_v4().simple());
    let config = |prefix: &str| {
        format!(
            r#"
version: "1"
proxies:
  - id: "shared-dedup-proxy"
    listen_path: "/shared-dedup"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "shared-dedup-plugin"
  - id: "terminal-dedup-proxy"
    listen_path: "/terminal-dedup"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "terminal-dedup-plugin"
      - plugin_config_id: "terminal-serverless-plugin"

consumers: []

plugin_configs:
  - id: "global-ai-audit"
    plugin_name: "ai_transcript_audit"
    scope: "global"
    enabled: true
    config:
      capture:
        request: true
        response: true
      sampling:
        rate: 1.0
      sink:
        type: "http"
        endpoint_url: "http://127.0.0.1:{audit_port}/audit"
        allow_insecure_loopback: true
        batch_size: 1
        flush_interval_ms: 100
  - id: "shared-dedup-plugin"
    plugin_name: "request_deduplication"
    scope: "proxy"
    proxy_id: "shared-dedup-proxy"
    enabled: true
    config:
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix}"
      ttl_seconds: 60
      inflight_ttl_seconds: 10
      scope_by_consumer: false
      applicable_methods: ["POST"]
  - id: "terminal-dedup-plugin"
    plugin_name: "request_deduplication"
    scope: "proxy"
    proxy_id: "terminal-dedup-proxy"
    enabled: true
    config:
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix}"
      ttl_seconds: 60
      inflight_ttl_seconds: 10
      max_entries: 1
      max_entry_size_bytes: 1048576
      max_total_size_bytes: 2097152
      scope_by_consumer: false
      applicable_methods: ["POST"]
  - id: "terminal-serverless-plugin"
    plugin_name: "serverless_function"
    scope: "proxy"
    proxy_id: "terminal-dedup-proxy"
    enabled: true
    config:
      provider: "gcp_cloud_functions"
      mode: "terminate"
      function_url: "http://127.0.0.1:{function_port}/invoke"
      max_response_body_bytes: 1048576
"#,
        )
    };

    let mut gw1 = spawn_file_gateway(
        config(&unique_prefix),
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;
    let mut gw2 = spawn_file_gateway(
        config(&unique_prefix),
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;
    let port1 = gw1.proxy_port;
    let port2 = gw2.proxy_port;

    delete_redis_keys_by_prefix(&unique_prefix).await;
    sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let body = r#"{"model":"gpt-test","messages":[{"role":"user","content":"order one"}]}"#;
    let idempotency_key = "shared-order-key";
    let authority = "orders.example";
    let url1 = format!("http://127.0.0.1:{port1}/shared-dedup/orders");
    let url2 = format!("http://127.0.0.1:{port2}/shared-dedup/orders");

    let first_client = client.clone();
    let first_url = url1.clone();
    let first_body = body.to_string();
    let first_key = idempotency_key.to_string();
    let first = tokio::spawn(async move {
        first_client
            .post(&first_url)
            .header("Idempotency-Key", first_key)
            .header("Host", authority)
            .header("Content-Type", "application/json")
            .body(first_body)
            .send()
            .await
    });

    // Ownership and completion share one operation record per logical key, so
    // the in-flight lease is visible as that record rather than a separate
    // `:inflight:` key (GHSA-f72h-jm2p-mc73).
    let record_prefix = format!("{unique_prefix}:");
    let deadline = SystemTime::now() + Duration::from_secs(5);
    loop {
        let backend_started = backend_blocked.load(Ordering::SeqCst);
        let redis_lock_visible = redis_key_count_by_prefix(&record_prefix).await > 0;
        if backend_started && redis_lock_visible {
            break;
        }
        if SystemTime::now() >= deadline {
            panic!(
                "first request did not hold Redis in-flight lock before assertion: backend_started={backend_started}, redis_lock_visible={redis_lock_visible}"
            );
        }
        sleep(Duration::from_millis(25)).await;
    }

    let second = client
        .post(&url2)
        .header("Idempotency-Key", idempotency_key)
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("second gateway request failed");
    assert_eq!(
        second.status().as_u16(),
        409,
        "peer gateway should see Redis in-flight conflict"
    );

    release_backend.notify_one();
    let first = first
        .await
        .expect("first request task panicked")
        .expect("first gateway request failed");
    assert_eq!(first.status().as_u16(), 200);
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "shared Redis in-flight lock must allow only one backend execution"
    );

    let replay = client
        .post(&url2)
        .header("Idempotency-Key", idempotency_key)
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("replay request failed");
    assert_eq!(replay.status().as_u16(), 200);
    assert_eq!(
        replay
            .headers()
            .get("x-idempotent-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true"),
        "completed Redis response should replay after the lock is released"
    );
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "Redis replay must not execute the backend again"
    );

    let deadline = SystemTime::now() + Duration::from_secs(10);
    loop {
        if audit_records.lock().await.len() >= 3 {
            break;
        }
        if SystemTime::now() >= deadline {
            panic!(
                "expected audit records for original, in-flight conflict, and Redis replay; got {}",
                audit_records.lock().await.len()
            );
        }
        sleep(Duration::from_millis(50)).await;
    }
    sleep(Duration::from_millis(200)).await;
    let records = audit_records.lock().await.clone();
    assert_eq!(
        records.len(),
        3,
        "each of the three client-visible AI transactions must emit exactly one audit record"
    );
    let replay_records: Vec<&serde_json::Value> = records
        .iter()
        .filter(|record| record["cache"]["request_deduplication.replayed"].as_str() == Some("true"))
        .collect();
    assert_eq!(
        replay_records.len(),
        1,
        "the Redis replay must emit exactly one bounded replay-marked audit record"
    );
    assert_eq!(replay_records[0]["status_code"], 200);
    assert!(replay_records[0]["response_body"].is_string());

    delete_redis_keys_by_prefix(&unique_prefix).await;
    sleep(Duration::from_millis(200)).await;

    let terminal_key = "local-terminal-replay-key";
    let terminal_url1 = format!("http://127.0.0.1:{port1}/terminal-dedup/invoke");
    let terminal_url2 = format!("http://127.0.0.1:{port2}/terminal-dedup/invoke");
    let first_terminal = client
        .post(&terminal_url1)
        .header("Idempotency-Key", terminal_key)
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("first terminal request failed");
    assert_eq!(first_terminal.status().as_u16(), 200);
    assert_eq!(
        first_terminal
            .bytes()
            .await
            .expect("first terminal body failed")
            .len(),
        LARGE_FUNCTION_BODY_LEN
    );
    assert_eq!(function_hits.load(Ordering::SeqCst), 1);
    assert_single_non_replayable_completion(
        &redis_dedup_records_by_prefix(&record_prefix).await,
        "original terminal completion",
    );

    // Reproduce Redis/local retention divergence deterministically. A Redis
    // restart, eviction, or earlier record expiry can remove the distributed
    // value while this gateway still retains the authoritative local response.
    // The retry below must repair Redis through its newly acquired ownership
    // before serving that local replay; releasing the ownership would leave a
    // peer free to execute the completed side effect again.
    delete_redis_keys_by_prefix(&unique_prefix).await;
    assert_eq!(
        redis_key_count_by_prefix(&record_prefix).await,
        0,
        "test precondition: distributed completion must be absent before local replay"
    );

    let local_replay = client
        .post(&terminal_url1)
        .header("Idempotency-Key", terminal_key)
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("same-gateway terminal retry failed");
    assert_eq!(local_replay.status().as_u16(), 200);
    assert_eq!(
        local_replay
            .headers()
            .get("x-idempotent-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true"),
        "the lock-owning gateway must replay its matching local completion"
    );
    assert_eq!(
        local_replay
            .bytes()
            .await
            .expect("local replay body failed")
            .len(),
        LARGE_FUNCTION_BODY_LEN
    );
    assert_eq!(function_hits.load(Ordering::SeqCst), 1);
    assert_single_non_replayable_completion(
        &redis_dedup_records_by_prefix(&record_prefix).await,
        "local replay repair",
    );

    let peer_retry = client
        .post(&terminal_url2)
        .header("Idempotency-Key", terminal_key)
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body("{}")
        .send()
        .await
        .expect("peer terminal retry failed");
    assert_eq!(
        peer_retry.status().as_u16(),
        409,
        "a peer without the local completion must honor the non-replayable completion record"
    );
    assert_eq!(function_hits.load(Ordering::SeqCst), 1);

    gw1.shutdown();
    gw2.shutdown();
    println!("test_request_deduplication_redis_blocks_concurrent_cross_instance PASSED");
}

/// Empty/no-body successful synthetic responses must release the exact Redis
/// in-flight lock even though the synthetic response-body hooks do not run.
/// A repeated identical request must therefore reach the later response_mock
/// again instead of receiving a stale request_deduplication 409.
#[tokio::test]
#[ignore]
async fn test_request_deduplication_redis_finalized_empty_synthetic_successes_release_locks() {
    if !redis_is_available().await {
        if std::env::var_os("FERRUM_REDIS_REQUIRED").is_some() {
            panic!("Redis is required for the finalized synthetic deduplication CI gate");
        }
        return;
    }

    let namespace = format!("dedup-synthetic-{}", Uuid::new_v4().simple());
    let default_prefix = format!("{namespace}:dedup");
    delete_redis_keys_by_prefix(&default_prefix).await;

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "orders"
    namespace: "{namespace}"
    listen_path: "/orders"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: 1
    strip_listen_path: true
    plugins:
      - plugin_config_id: "dedup"
      - plugin_config_id: "empty-successes"

consumers: []

plugin_configs:
  - id: "dedup"
    namespace: "{namespace}"
    plugin_name: "request_deduplication"
    scope: "proxy"
    proxy_id: "orders"
    enabled: true
    config:
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      ttl_seconds: 60
      inflight_ttl_seconds: 60
      scope_by_consumer: false
      applicable_methods: ["POST"]
  - id: "empty-successes"
    namespace: "{namespace}"
    plugin_name: "response_mock"
    scope: "proxy"
    proxy_id: "orders"
    enabled: true
    config:
      rules:
        - method: POST
          path: /empty-200
          status_code: 200
        - method: POST
          path: /no-content
          status_code: 204
"#
    );

    let mut gateway = spawn_file_gateway(
        config,
        vec![
            ("RUST_LOG".to_string(), "ferrum_edge=debug".to_string()),
            ("FERRUM_NAMESPACE".to_string(), namespace.clone()),
        ],
    )
    .await;
    let port = gateway.proxy_port;
    sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    for (path, expected_status, key) in [
        ("empty-200", 200, "redis-empty-200"),
        ("no-content", 204, "redis-no-content"),
    ] {
        let url = format!("http://127.0.0.1:{port}/orders/{path}");
        for attempt in 1..=2 {
            let response = client
                .post(&url)
                .header("Host", "orders.example")
                .header("Idempotency-Key", key)
                .body("{}")
                .send()
                .await
                .unwrap_or_else(|error| panic!("{path} attempt {attempt} failed: {error}"));
            assert_eq!(
                response.status().as_u16(),
                expected_status,
                "{path} attempt {attempt} must not observe a stale Redis in-flight lock"
            );
        }
    }

    delete_redis_keys_by_prefix(&default_prefix).await;
    gateway.shutdown();
    println!(
        "test_request_deduplication_redis_finalized_empty_synthetic_successes_release_locks PASSED"
    );
}

/// Two `request_deduplication` configs on one proxy must not self-conflict under
/// the shared default Redis prefix (`{FERRUM_NAMESPACE}:dedup`).
///
/// Before #2379, sibling instances hashed the same logical key (proxy +
/// identity + idempotency value only). The first acquired the operation record
/// at `{prefix}:<digest>` and the second treated that ownership as a peer
/// request, returning 409 before the backend ran. Stable `plugin_config_id`
/// partitioning keeps each instance's Redis ownership isolated while the
/// companion cross-gateway test still proves corresponding copies share state.
#[tokio::test]
#[ignore]
async fn test_request_deduplication_redis_same_proxy_sibling_instances_do_not_self_conflict() {
    if !redis_is_available().await {
        if std::env::var_os("FERRUM_REDIS_REQUIRED").is_some() {
            panic!("Redis is required for the request deduplication same-proxy sibling CI gate");
        }
        return;
    }

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let _backend = start_counting_backend_on(backend_listener, Arc::clone(&backend_hits))
        .await
        .unwrap();

    // Unique namespace per run so both sibling instances share the default
    // `{namespace}:dedup` prefix without colliding with other Redis tests.
    let namespace = format!("dedup-sibling-{}", Uuid::new_v4().simple());
    let default_prefix = format!("{namespace}:dedup");
    delete_redis_keys_by_prefix(&default_prefix).await;

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "orders"
    namespace: "{namespace}"
    listen_path: "/orders"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "dedup-short"
      - plugin_config_id: "dedup-long"

consumers: []

plugin_configs:
  - id: "dedup-short"
    namespace: "{namespace}"
    plugin_name: "request_deduplication"
    scope: "proxy"
    proxy_id: "orders"
    enabled: true
    config:
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      ttl_seconds: 60
      inflight_ttl_seconds: 10
      scope_by_consumer: false
      applicable_methods: ["POST"]
  - id: "dedup-long"
    namespace: "{namespace}"
    plugin_name: "request_deduplication"
    scope: "proxy"
    proxy_id: "orders"
    enabled: true
    config:
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      ttl_seconds: 600
      inflight_ttl_seconds: 10
      scope_by_consumer: false
      applicable_methods: ["POST"]
"#
    );

    let mut gw = spawn_file_gateway(
        config,
        vec![
            ("RUST_LOG".to_string(), "ferrum_edge=debug".to_string()),
            ("FERRUM_NAMESPACE".to_string(), namespace.clone()),
        ],
    )
    .await;
    let port = gw.proxy_port;

    sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let body = r#"{"order":1}"#;
    let idempotency_key = "order-1";
    let authority = "orders.example";
    let url = format!("http://127.0.0.1:{port}/orders");

    let response = client
        .post(&url)
        .header("Idempotency-Key", idempotency_key)
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("sibling-instance request failed");
    let status = response.status().as_u16();
    let response_body = response.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "two same-proxy Redis dedup instances must not 409 their own first request under the shared default prefix; body={response_body}"
    );
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "fresh request through sibling dedup instances must reach the backend exactly once"
    );

    // Corresponding completed values remain per-instance; a retry must still
    // replay without a second backend execution (either instance may replay).
    let replay = client
        .post(&url)
        .header("Idempotency-Key", idempotency_key)
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("sibling-instance replay failed");
    assert_eq!(replay.status().as_u16(), 200);
    assert_eq!(
        replay
            .headers()
            .get("x-idempotent-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true"),
        "completed Redis values from sibling instances must still replay"
    );
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "replay through sibling dedup instances must not re-execute the backend"
    );

    // Both instances should have published independent completed keys under the
    // shared default prefix (partitioned by plugin_config_id in the digest).
    let completed_keys = redis_key_count_by_prefix(&format!("{default_prefix}:v6:")).await;
    assert!(
        completed_keys >= 2,
        "expected at least two completed Redis keys under the shared default prefix, got {completed_keys}"
    );

    delete_redis_keys_by_prefix(&default_prefix).await;
    gw.shutdown();
    println!(
        "test_request_deduplication_redis_same_proxy_sibling_instances_do_not_self_conflict PASSED"
    );
}

/// Two same-proxy Redis instances with distinct headers and unique prefixes must
/// each complete/release independently (#2378).
///
/// Before instance-scoped completion ownership, both plugins wrote one shared
/// metadata slot; the earlier instance then attempted token-delete with the
/// later instance's key/token under the wrong prefix and left its lock until
/// TTL. Distinct prefixes keep this case independent of shared-prefix
/// self-conflict (#2379).
#[tokio::test]
#[ignore]
async fn test_request_deduplication_redis_distinct_header_instances_complete_independently() {
    if !redis_is_available().await {
        if std::env::var_os("FERRUM_REDIS_REQUIRED").is_some() {
            panic!(
                "Redis is required for the request deduplication distinct-header lifecycle CI gate"
            );
        }
        return;
    }

    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    let backend_hits = Arc::new(AtomicUsize::new(0));
    let _backend = start_counting_backend_on(backend_listener, Arc::clone(&backend_hits))
        .await
        .unwrap();

    let run_id = Uuid::new_v4().simple().to_string();
    let prefix_a = format!("orders:dedup:a:{run_id}");
    let prefix_b = format!("orders:dedup:b:{run_id}");
    delete_redis_keys_by_prefix(&prefix_a).await;
    delete_redis_keys_by_prefix(&prefix_b).await;

    let config = format!(
        r#"
version: "1"
proxies:
  - id: "orders"
    listen_path: "/orders"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "dedup-a"
      - plugin_config_id: "dedup-b"

consumers: []

plugin_configs:
  - id: "dedup-a"
    plugin_name: "request_deduplication"
    scope: "proxy"
    proxy_id: "orders"
    enabled: true
    config:
      header_name: "Idempotency-Key"
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix_a}"
      ttl_seconds: 60
      inflight_ttl_seconds: 30
      scope_by_consumer: false
      applicable_methods: ["POST"]
  - id: "dedup-b"
    plugin_name: "request_deduplication"
    scope: "proxy"
    proxy_id: "orders"
    enabled: true
    config:
      header_name: "X-Operation-Key"
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix_b}"
      ttl_seconds: 60
      inflight_ttl_seconds: 30
      scope_by_consumer: false
      applicable_methods: ["POST"]
"#
    );

    let mut gw = spawn_file_gateway(
        config,
        vec![("RUST_LOG".to_string(), "ferrum_edge=debug".to_string())],
    )
    .await;
    let port = gw.proxy_port;

    sleep(Duration::from_millis(200)).await;

    let client = reqwest::Client::new();
    let body = r#"{"order":1}"#;
    let authority = "orders.example";
    let url = format!("http://127.0.0.1:{port}/orders");

    let response = client
        .post(&url)
        .header("Idempotency-Key", "key-a")
        .header("X-Operation-Key", "key-b")
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("dual-header request failed");
    let status = response.status().as_u16();
    let response_body = response.text().await.unwrap_or_default();
    assert_eq!(
        status, 200,
        "distinct-header Redis instances must both acquire ownership without self-409; body={response_body}"
    );
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "fresh dual-header request must reach the backend exactly once"
    );

    // Both instances must have transitioned their operation record from
    // in-flight ownership to a published completion under their own prefix.
    // There is no separate `:inflight:` key: publication is the ownership
    // transition (GHSA-f72h-jm2p-mc73).
    assert_eq!(
        redis_key_count_by_prefix(&format!("{prefix_a}:inflight:")).await,
        0,
        "no separate in-flight key may exist for instance A"
    );
    assert_eq!(
        redis_key_count_by_prefix(&format!("{prefix_b}:inflight:")).await,
        0,
        "no separate in-flight key may exist for instance B"
    );
    assert!(
        redis_key_count_by_prefix(&format!("{prefix_a}:v6:")).await >= 1,
        "instance A must publish a completed Redis value under its unique prefix"
    );
    assert!(
        redis_key_count_by_prefix(&format!("{prefix_b}:v6:")).await >= 1,
        "instance B must publish a completed Redis value under its unique prefix"
    );

    // A retry must preserve the complete original request fingerprint. Each
    // deduplication instance excludes only its own idempotency header, so the
    // sibling header remains a semantic request header for that instance.
    let replay = client
        .post(&url)
        .header("Idempotency-Key", "key-a")
        .header("X-Operation-Key", "key-b")
        .header("Host", authority)
        .header("Content-Type", "application/json")
        .body(body)
        .send()
        .await
        .expect("dual-header replay failed");
    assert_eq!(replay.status().as_u16(), 200);
    assert_eq!(
        replay
            .headers()
            .get("x-idempotent-replayed")
            .and_then(|value| value.to_str().ok()),
        Some("true"),
        "an identical dual-header request must replay rather than encounter either stale in-flight lock"
    );
    assert_eq!(
        backend_hits.load(Ordering::SeqCst),
        1,
        "completed independent instances must not re-execute the backend on replay"
    );

    delete_redis_keys_by_prefix(&prefix_a).await;
    delete_redis_keys_by_prefix(&prefix_b).await;
    gw.shutdown();
    println!(
        "test_request_deduplication_redis_distinct_header_instances_complete_independently PASSED"
    );
}

/// Namespace-based Redis key prefix isolation.
///
/// Two gateways share the same Redis server with identical `rate_limiting`
/// config but different `FERRUM_NAMESPACE` values, and NO explicit
/// `redis_key_prefix`. The plugin default (`{FERRUM_NAMESPACE}:rate_limiting`)
/// must give each gateway its own key space so one namespace's traffic does
/// not count toward the other's rate limit.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_namespace_key_prefix_isolation() {
    if !redis_is_available().await {
        return;
    }

    // Shared backend.
    let backend_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    // Distinct namespaces per run so a reused Redis DB can't leak between
    // test invocations.
    let ns_run = Uuid::new_v4().simple().to_string();
    let ns_a = format!("nsiso-a-{}", ns_run);
    let ns_b = format!("nsiso-b-{}", ns_run);
    delete_redis_keys_by_prefix(&format!("{}:rate_limiting", ns_a)).await;
    delete_redis_keys_by_prefix(&format!("{}:rate_limiting", ns_b)).await;

    let config = |namespace: &str| {
        format!(
            r#"
version: "1"
proxies:
  - id: "ns-iso-proxy"
    namespace: "{namespace}"
    listen_path: "/ns-iso"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "ns-iso-rl"

consumers: []

plugin_configs:
  - id: "ns-iso-rl"
    namespace: "{namespace}"
    plugin_name: "rate_limiting"
    scope: "proxy"
    proxy_id: "ns-iso-proxy"
    enabled: true
    config:
      expose_headers: true
      limits:
        - scope: "default"
          window_seconds: 60
          max_requests: 2
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
"#
        )
    };

    let mut gw_a = spawn_file_gateway(
        config(&ns_a),
        vec![
            ("FERRUM_NAMESPACE".to_string(), ns_a.clone()),
            ("RUST_LOG".to_string(), "error".to_string()),
        ],
    )
    .await;
    let mut gw_b = spawn_file_gateway(
        config(&ns_b),
        vec![
            ("FERRUM_NAMESPACE".to_string(), ns_b.clone()),
            ("RUST_LOG".to_string(), "error".to_string()),
        ],
    )
    .await;
    let port_a = gw_a.proxy_port;
    let port_b = gw_b.proxy_port;

    let client = reqwest::Client::new();

    // Burn gateway A's budget (max_requests=2).
    for i in 1..=2 {
        let r = client
            .get(format!("http://127.0.0.1:{}/ns-iso/test", port_a))
            .send()
            .await
            .expect("A req");
        assert_eq!(r.status().as_u16(), 200, "A request {i} should succeed");
    }
    let r = client
        .get(format!("http://127.0.0.1:{}/ns-iso/test", port_a))
        .send()
        .await
        .expect("A req 3");
    assert_eq!(
        r.status().as_u16(),
        429,
        "A 3rd request must be rate limited"
    );

    // Gateway B should be unaffected — its counter lives under a different
    // Redis prefix (`{ns_b}:rate_limiting:...` vs `{ns_a}:rate_limiting:...`).
    for i in 1..=2 {
        let r = client
            .get(format!("http://127.0.0.1:{}/ns-iso/test", port_b))
            .send()
            .await
            .expect("B req");
        assert_eq!(
            r.status().as_u16(),
            200,
            "B request {i} must succeed — separate namespace = separate Redis keys"
        );
    }
    let r = client
        .get(format!("http://127.0.0.1:{}/ns-iso/test", port_b))
        .send()
        .await
        .expect("B req 3");
    assert_eq!(
        r.status().as_u16(),
        429,
        "B 3rd request must be rate limited on its own counter"
    );

    // Best-effort cleanup of the keys we created so the shared Redis DB
    // doesn't accumulate garbage across test runs.
    delete_redis_keys_by_prefix(&format!("{}:rate_limiting", ns_a)).await;
    delete_redis_keys_by_prefix(&format!("{}:rate_limiting", ns_b)).await;

    gw_a.shutdown();
    gw_b.shutdown();
    println!("test_rate_limiting_redis_namespace_key_prefix_isolation PASSED");
}

/// Drift guard: `spawn_file_gateway` must not pin a caller-reserved proxy port.
/// Pinning `FERRUM_PROXY_HTTP_PORT` across `TestGateway` retries reuses a
/// bind-drop-rebind reservation and turns every retry into the same TOCTOU
/// failure that flaked
/// `test_request_deduplication_redis_distinct_header_instances_complete_independently`.
#[test]
fn spawn_file_gateway_lets_harness_allocate_proxy_port_each_attempt() {
    const SOURCE: &str = include_str!(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/functional/functional_redis_rate_limiting_test.rs"
    ));
    let start = SOURCE
        .find("async fn spawn_file_gateway(")
        .expect("spawn_file_gateway helper must exist");
    let helper = &SOURCE[start..];
    let end = helper
        .find("\nasync fn ")
        .expect("spawn_file_gateway must be followed by another async fn");
    let helper = &helper[..end];

    assert!(
        !helper.contains(".env(\"FERRUM_PROXY_HTTP_PORT\""),
        "spawn_file_gateway must not pin FERRUM_PROXY_HTTP_PORT; harness retries need a fresh proxy port"
    );
    assert!(
        !helper.contains("proxy_port: u16"),
        "spawn_file_gateway must not take a fixed proxy_port argument"
    );
    assert!(
        helper.contains("capture_output()"),
        "spawn_file_gateway must capture child output so startup failures are diagnosable in hosted CI"
    );
    assert!(
        helper.contains("FERRUM_PROXY_HTTP_PORT") && helper.contains("must not pin"),
        "spawn_file_gateway must refuse sticky proxy-port overrides from extra_env"
    );
}
