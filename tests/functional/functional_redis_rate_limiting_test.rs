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

use crate::scaffolding::port_registry::TestSocket;

use crate::common::TestGateway;

use ferrum_edge::plugins::utils::redis_rate_limiter::RedisRateLimitClient;
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
            assert!(
                std::env::var("FERRUM_REDIS_REQUIRED").as_deref() != Ok("1"),
                "the Redis regression gate requires a reachable Redis service"
            );
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
    RedisRateLimitClient::new(config, None, false, None)
        .expect("construction without a CA path must succeed")
        .make_slot_key(rate_key, suffix)
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

/// Sum every counter under `prefix` (DB 15): the live charge on the rate-limit
/// windows once every detached compensation has landed.
async fn redis_counter_sum_by_prefix(prefix: &str) -> i64 {
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
        "local total = 0 {} return total",
        redis_glob_loop(
            prefix,
            "for i=1,#keys do local n = tonumber(redis.call('GET',keys[i])) \
             if n then total = total + n end end",
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

/// Wait until the counters under `prefix` sum to `expected`.
///
/// A refusal hands its charge back from a DETACHED compensation task, so the
/// shared counter is only eventually exact after a `429`. A test that resets or
/// re-reads the budget right after a refusal has to let that compensation land
/// first, or the `DECR` arrives on the reset counter and hands the next round
/// one admission more than the budget.
async fn wait_for_redis_counter_sum(prefix: &str, expected: i64) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
    loop {
        let total = redis_counter_sum_by_prefix(prefix).await;
        if total == expected {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "counters under {prefix} settled at {total}, expected {expected}"
        );
        tokio::time::sleep(Duration::from_millis(25)).await;
    }
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

/// Every key under `tag` with its raw value and remaining TTL, sorted by key.
///
/// `tag` is the hash tag a rate identity's counters share, built through the
/// production key builder, so a layout change cannot make a caller's comparison
/// vacuous.
async fn redis_counter_snapshot(tag: &str) -> Vec<(String, Option<String>, i64)> {
    let client = redis::Client::open(REDIS_URL).expect("valid Redis test URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect to Redis test instance");
    let mut keys: Vec<String> = redis::cmd("KEYS")
        .arg(format!("{tag}*"))
        .query_async(&mut connection)
        .await
        .expect("list Redis rate-limit counters");
    keys.sort();
    let mut snapshot = Vec::with_capacity(keys.len());
    for key in keys {
        let value: Option<String> = redis::cmd("GET")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .expect("read Redis rate-limit counter");
        let ttl: i64 = redis::cmd("TTL")
            .arg(&key)
            .query_async(&mut connection)
            .await
            .expect("read Redis rate-limit counter TTL");
        snapshot.push((key, value, ttl));
    }
    snapshot
}

/// Remaining TTL, in seconds, for `key`. `None` when the key is absent or has
/// no expiry.
async fn redis_key_ttl(key: &str) -> Option<i64> {
    let client = redis::Client::open(REDIS_URL).expect("valid Redis test URL");
    let mut connection = client
        .get_multiplexed_async_connection()
        .await
        .expect("connect to Redis test instance");
    let ttl: i64 = redis::cmd("TTL")
        .arg(key)
        .query_async(&mut connection)
        .await
        .expect("read Redis key TTL");
    (ttl >= 0).then_some(ttl)
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
    let listener = tokio::net::TcpListener::bind_test(format!("127.0.0.1:{}", port)).await?;
    start_header_echo_backend_on(listener).await
}

async fn start_header_echo_backend_on(
    listener: tokio::net::TcpListener,
) -> Result<tokio::task::JoinHandle<()>, Box<dyn std::error::Error>> {
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
    let listener = tokio::net::TcpListener::bind_test(format!("127.0.0.1:{}", port)).await?;
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
    let listener = tokio::net::TcpListener::bind_test(format!("127.0.0.1:{}", port)).await?;
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
    let listener = tokio::net::TcpListener::bind_test(format!("127.0.0.1:{}", port))
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

    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
                "redis_key_prefix": unique_prefix,
                // Every assertion below reads a CENTRALIZED counter. The
                // `rate_limiting` default is `local_fallback`, so a Redis
                // hiccup would hand this gateway its own per-process budget and
                // the counts would pass or fail for the wrong reason. Pinned so
                // an outage shows up as a clean 503 instead.
                "redis_failure_policy": "fail_closed"
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

/// Wait until the current instant sits comfortably inside a one-second Redis
/// sub-bucket, and return that sub-bucket's index.
///
/// A sixteen-second policy window splits into sixteen one-second sub-buckets,
/// so the index is just the epoch second. Landing 300-500ms in leaves a busy
/// hosted runner room to seed a counter and issue one HTTP request without the
/// two straddling a sub-bucket boundary.
async fn aligned_one_second_sub_bucket() -> u64 {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch");
        if (300_000_000..=500_000_000).contains(&now.subsec_nanos()) {
            // Derived by the production helper, not by an epoch division that
            // merely happens to agree with it today.
            return ferrum_edge::_test_support::redis_sub_bucket_at(now, 16).index;
        }
        sleep(Duration::from_millis(5)).await;
    }
}

fn current_one_second_sub_bucket() -> u64 {
    live_sub_bucket(16)
}

/// Wire key of one request-quota sub-bucket: `{tag}:{window_seconds}:{index}`.
fn sub_bucket_key(prefix: &str, window_seconds: u64, index: u64) -> String {
    redis_bucket_key(
        prefix,
        "ip:127.0.0.1",
        &[&window_seconds.to_string(), &index.to_string()],
    )
}

/// Poll until the route answers `200` with rate-limit headers.
///
/// A file-mode gateway can accept a connection before its plugin cache is
/// published. Timing assertions below must not spend their first request
/// proving readiness, so this absorbs that and leaves the quota to be reset by
/// the caller.
async fn wait_for_rate_limited_route(client: &reqwest::Client, url: &str) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        if let Ok(response) = client.get(url).send().await
            && response.status().as_u16() == 200
            && response.headers().contains_key("x-ratelimit-limit")
        {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the Redis-backed rate-limited route never became ready"
        );
        sleep(Duration::from_millis(50)).await;
    }
}

/// Block until the wall clock sits inside `offset` nanoseconds of the current
/// `window_nanos` epoch window.
///
/// Epoch windows are shared by every gateway, so aligning here is what makes a
/// "clustered at the end of a window" scenario reproducible.
async fn await_epoch_window_offset(window_nanos: u128, offset: std::ops::Range<u128>) {
    loop {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("system clock after Unix epoch");
        if offset.contains(&(now.as_nanos() % window_nanos)) {
            return;
        }
        sleep(Duration::from_millis(5)).await;
    }
}

/// The request-quota sub-bucket the limiter would charge for `window_seconds`
/// right now, derived by the PRODUCTION helper.
///
/// Wall-clock assertions below record this before and after the traffic they
/// generate, so a runner slow enough to move the traffic out of the window the
/// scenario needs is reported as a skip rather than passing vacuously.
fn live_sub_bucket(window_seconds: u64) -> u64 {
    ferrum_edge::_test_support::redis_sub_bucket(window_seconds).index
}

/// Issue one bounded GET and return its status.
///
/// A hosted runner that stalls a request past the window under test would
/// otherwise turn a timing scenario into an assertion about whatever window the
/// reply eventually landed in. `None` means the request did not answer inside
/// `budget`, which callers report as a skip.
async fn bounded_status(
    client: &reqwest::Client,
    url: &str,
    budget: Duration,
    what: &str,
) -> Option<u16> {
    match tokio::time::timeout(budget, client.get(url).send()).await {
        Ok(Ok(response)) => Some(response.status().as_u16()),
        Ok(Err(error)) => panic!("{what} failed: {error}"),
        Err(_) => None,
    }
}

/// Report a wall-clock scenario the runner was too slow to place, without
/// asserting anything the traffic never exercised.
fn skip_too_slow(what: &str, detail: String) {
    eprintln!("SKIP {what}: the runner could not place the scenario ({detail})");
}

/// Request quotas count their whole sub-bucket ladder at face value: a counter
/// inside the trailing window binds in FULL, and only a counter that has aged
/// past the ladder stops binding.
///
/// This replaces the old "a full previous one-second bucket must decay"
/// assertion. That decay is exactly what let a burst clustered at the end of an
/// epoch bucket be discounted while every one of its requests was still inside
/// the exact trailing window; it now survives only on the token-accounting
/// paths, which have their own reservation/reconciliation contract.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_trailing_sub_bucket_counts_in_full() {
    if !redis_is_available().await {
        return;
    }

    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");
    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let backend_port = backend_listener.local_addr().unwrap().port();
    drop(backend_listener);
    let _backend = start_header_echo_backend(backend_port).await.unwrap();

    let client = reqwest::Client::new();
    let unique_prefix = format!("ferrum:test:rl-ladder:{}", Uuid::new_v4().simple());
    setup_proxy_with_plugins(
        &harness,
        &client,
        "proxy-redis-rl-ladder",
        "/redis-rl-ladder",
        backend_port,
        "http",
        vec![json!({
            "id": "plugin-redis-rl-ladder",
            "plugin_name": "rate_limiting",
            "scope": "proxy",
            "proxy_id": "proxy-redis-rl-ladder",
            "enabled": true,
            "config": {
                "expose_headers": true,
                // Sixteen seconds splits into sixteen one-second sub-buckets,
                // so the seeded index below is just an epoch second.
                "limits": [{"scope": "default", "window_seconds": 16, "max_requests": 10}],
                "sync_mode": "redis",
                "redis_url": REDIS_URL,
                "redis_key_prefix": unique_prefix,
                // These assertions read the seeded centralized buckets; a
                // per-process fallback budget would answer from a map this test
                // never seeded. See `test_rate_limiting_redis_centralized`.
                "redis_failure_policy": "fail_closed"
            }
        })],
    )
    .await
    .unwrap();
    harness
        .wait_for_response_header("/redis-rl-ladder/test", "x-ratelimit-limit")
        .await;

    let url = format!("{}/redis-rl-ladder/test", harness.proxy_base_url);
    let mut verified_without_boundary_cross = false;
    for _ in 0..4 {
        // Fifteen sub-buckets back is inside the ladder (`current` plus the
        // seventeen before it), so a full counter there must bind at face value.
        delete_redis_keys_by_prefix(&unique_prefix).await;
        let index = aligned_one_second_sub_bucket().await;
        set_redis_counter(&sub_bucket_key(&unique_prefix, 16, index - 15), 10, 60).await;
        let refused = client.get(&url).send().await.expect("in-ladder probe");
        if current_one_second_sub_bucket() != index {
            continue;
        }
        assert_eq!(
            refused.status().as_u16(),
            429,
            "a full counter inside the trailing window must not be decayed away"
        );
        // The hand-back runs on a detached task, so settle it before reading
        // the charged sub-bucket: only the seeded 10 may remain.
        wait_for_redis_counter_sum(&unique_prefix, 10).await;
        assert_eq!(
            redis_counter_value(&sub_bucket_key(&unique_prefix, 16, index))
                .await
                .unwrap_or(0),
            0,
            "the refused probe must charge its own sub-bucket and hand it straight back"
        );

        // Eighteen sub-buckets back has aged past the ladder. The same counter
        // must stop binding, or the limiter is a lockout rather than a trailing
        // window.
        delete_redis_keys_by_prefix(&unique_prefix).await;
        let index = aligned_one_second_sub_bucket().await;
        set_redis_counter(&sub_bucket_key(&unique_prefix, 16, index - 18), 10, 60).await;
        let admitted = client.get(&url).send().await.expect("aged-out probe");
        if current_one_second_sub_bucket() != index {
            continue;
        }
        assert_eq!(
            admitted.status().as_u16(),
            200,
            "a counter older than the trailing window must stop binding"
        );
        assert_eq!(
            redis_counter_value(&sub_bucket_key(&unique_prefix, 16, index)).await,
            Some(1),
            "the admitted request must charge the expected sub-bucket"
        );
        verified_without_boundary_cross = true;
        break;
    }

    assert!(
        verified_without_boundary_cross,
        "could not complete the sub-bucket assertions without crossing a boundary"
    );
    delete_redis_keys_by_prefix(&unique_prefix).await;
}

/// A burst clustered at the END of an epoch window stays counted for the whole
/// trailing window that follows it.
///
/// This is the over-admission the retired two-window weighted estimate allowed:
/// it assumed the previous bucket's traffic was spread evenly through it, so
/// half a window later it discounted half the burst and re-opened the budget
/// while every one of those requests was still inside the exact trailing
/// window. Black box on purpose — no seeded counters, just a client behaving
/// like the attacker.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_boundary_clustered_burst_keeps_counting() {
    if !redis_is_available().await {
        return;
    }
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend = start_header_echo_backend_on(listener).await.unwrap();
    let prefix = format!("ferrum:test:boundary-burst:{}", Uuid::new_v4().simple());
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "burst", "listen_path": "/burst",
            "backend_scheme": "http", "backend_host": "127.0.0.1",
            "backend_port": backend_port, "strip_listen_path": true,
            "plugins": [{"plugin_config_id": "burst"}]
        }],
        "consumers": [],
        "plugin_configs": [{
            "id": "burst", "plugin_name": "rate_limiting", "scope": "proxy",
            "proxy_id": "burst", "enabled": true,
            "config": {
                "expose_headers": true, "sync_mode": "redis",
                "limits": [{"scope": "default", "window_seconds": 4, "max_requests": 5}],
                "redis_url": REDIS_URL, "redis_key_prefix": prefix,
                // A healthy store may never answer through the fallback budget.
                "redis_failure_policy": "fail_closed"
            }
        }]
    });
    let mut gateway = spawn_file_gateway(config.to_string(), vec![]).await;
    let client = reqwest::Client::new();
    let url = format!("{}/burst/test", gateway.proxy_base_url);

    // Prove the route and the Redis-backed policy are live, then start the
    // measurement from an empty budget.
    wait_for_rate_limited_route(&client, &url).await;
    delete_redis_keys_by_prefix(&prefix).await;

    // Everything timing-sensitive runs inside one block that reports an
    // unplaceable scenario as `Err(reason)` instead of asserting on traffic it
    // never managed to place. Teardown then runs once, on every path.
    let placement: Result<(), String> = async {
        // Cluster the whole quota into the last second of a four-second epoch
        // window, which is where the retired estimate discounted it hardest.
        // A four-second window has 250ms sub-buckets, sixteen to an epoch
        // window.
        await_epoch_window_offset(4_000_000_000, 2_800_000_000..3_200_000_000).await;
        let burst = tokio::time::Instant::now();
        let first_bucket = live_sub_bucket(4);
        for attempt in 1..=5 {
            let what = format!("burst request {attempt}");
            let Some(status) = bounded_status(&client, &url, Duration::from_secs(2), &what).await
            else {
                return Err(format!("{what} did not answer within 2s"));
            };
            assert_eq!(status, 200, "burst request {attempt} is within budget");
        }
        let last_bucket = live_sub_bucket(4);
        let spent = burst.elapsed();

        // The regression only exists when the whole burst lands in ONE epoch
        // window and the probe below lands in the NEXT one: that is the
        // boundary across which the retired weighted estimate decayed a live
        // burst. A burst that straddled the boundary would have been refused by
        // the retired estimate for its own reasons, and the assertion would
        // prove nothing. `/ 16` is the epoch window a sub-bucket belongs to.
        if first_bucket / 16 != last_bucket / 16 {
            return Err(format!(
                "the burst spanned epoch windows {}..={} (sub-buckets \
                 {first_bucket}..={last_bucket}) in {spent:?}; it must sit wholly in one",
                first_bucket / 16,
                last_bucket / 16
            ));
        }

        // Half a window past the epoch boundary the burst is still inside the
        // exact trailing four seconds. The weighted estimate admitted here.
        tokio::time::sleep_until(burst + Duration::from_millis(2_200)).await;
        // Placement FIRST, outcome second. A probe in sub-bucket `p` counts the
        // ladder `p - 17 ..= p + 1`, so the burst still binds exactly while
        // `p <= first_bucket + 17`, and the probe has to sit in the epoch window
        // immediately after the burst's — the boundary the retired estimate
        // decayed across.
        let probe_bucket = live_sub_bucket(4);
        if probe_bucket > first_bucket + 17 {
            return Err(format!(
                "the mid-window probe was scheduled into sub-bucket {probe_bucket}, past \
                 the trailing window of a burst in {first_bucket}"
            ));
        }
        if probe_bucket / 16 != last_bucket / 16 + 1 {
            return Err(format!(
                "the mid-window probe was scheduled into epoch window {}, not the one \
                 immediately after the burst's ({})",
                probe_bucket / 16,
                last_bucket / 16
            ));
        }
        let Some(status) =
            bounded_status(&client, &url, Duration::from_secs(2), "mid-window probe").await
        else {
            return Err("the mid-window probe did not answer within 2s".to_string());
        };
        // The request itself must also have been SERVED inside that ladder.
        let served_bucket = live_sub_bucket(4);
        if served_bucket > first_bucket + 17 {
            return Err(format!(
                "the mid-window probe was served in sub-bucket {served_bucket}, past the \
                 trailing window of a burst in {first_bucket}"
            ));
        }
        assert_eq!(
            status, 429,
            "a burst still inside the trailing window must keep binding"
        );

        // Once it ages out the budget is free again: a trailing window, not a
        // lockout for whoever bursts once. The refused probe hands its own
        // charge back from a detached task, so settle that first.
        wait_for_redis_counter_sum(&prefix, 5).await;
        tokio::time::sleep_until(burst + Duration::from_millis(7_000)).await;
        // The whole burst must be OUT of this probe's ladder, so the bound is
        // taken against the LATEST request of the burst.
        let aged_bucket = live_sub_bucket(4);
        if aged_bucket <= last_bucket + 17 {
            return Err(format!(
                "the aged-out probe was scheduled into sub-bucket {aged_bucket}, still \
                 inside the ladder of a burst ending in {last_bucket}"
            ));
        }
        let Some(status) =
            bounded_status(&client, &url, Duration::from_secs(2), "aged-out probe").await
        else {
            return Err("the aged-out probe did not answer within 2s".to_string());
        };
        assert_eq!(
            status, 200,
            "a burst that aged past the trailing window must stop binding"
        );
        Ok(())
    }
    .await;

    gateway.shutdown();
    backend.abort();
    delete_redis_keys_by_prefix(&prefix).await;
    if let Err(reason) = placement {
        skip_too_slow("boundary-clustered burst", reason);
    }
}

/// A client that spends its quota must be admitted again as soon as that spend
/// leaves the trailing window — it must not lose the whole next window.
///
/// This is the regression for the review finding on the first shape of this
/// change. A bare `previous + current` sum leaves `previous` sitting at the cap
/// for the entire epoch window after any window that reached it, so a client
/// sending exactly its configured rate is admitted for one window and refused
/// for the next, forever — about half its quota, permanently. The sub-bucket
/// ladder ages the spend out continuously instead.
///
/// A one-request quota keeps the timing crisp: one round trip fills the window,
/// so the assertions depend only on how long a single request takes.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_full_window_does_not_lock_out_the_next() {
    if !redis_is_available().await {
        return;
    }
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend = start_header_echo_backend_on(listener).await.unwrap();
    let prefix = format!("ferrum:test:next-window:{}", Uuid::new_v4().simple());
    let config = json!({
        "version": "1",
        "proxies": [{
            "id": "steady", "listen_path": "/steady",
            "backend_scheme": "http", "backend_host": "127.0.0.1",
            "backend_port": backend_port, "strip_listen_path": true,
            "plugins": [{"plugin_config_id": "steady"}]
        }],
        "consumers": [],
        "plugin_configs": [{
            "id": "steady", "plugin_name": "rate_limiting", "scope": "proxy",
            "proxy_id": "steady", "enabled": true,
            "config": {
                "expose_headers": true, "sync_mode": "redis",
                "limits": [{"scope": "default", "window_seconds": 2, "max_requests": 1}],
                "redis_url": REDIS_URL, "redis_key_prefix": prefix,
                // A healthy store may never answer through the fallback budget.
                "redis_failure_policy": "fail_closed"
            }
        }]
    });
    let mut gateway = spawn_file_gateway(config.to_string(), vec![]).await;
    let client = reqwest::Client::new();
    let url = format!("{}/steady/test", gateway.proxy_base_url);

    wait_for_rate_limited_route(&client, &url).await;
    delete_redis_keys_by_prefix(&prefix).await;

    // Everything timing-sensitive runs inside one block that reports an
    // unplaceable scenario as `Err(reason)` rather than asserting on traffic it
    // never managed to place. Teardown then runs once, on every path.
    let placement: Result<(), String> = async {
        // Start just after an epoch-window boundary so the spend lands in one
        // two-second epoch window and the next round lands in the FOLLOWING one
        // — the exact shape `previous + current` refuses outright. A two-second
        // window has 125ms sub-buckets, sixteen to an epoch window, so `/ 16`
        // is the epoch window a sub-bucket belongs to.
        await_epoch_window_offset(2_000_000_000, 0..200_000_000).await;
        let spent_at = tokio::time::Instant::now();
        let spend_bucket = live_sub_bucket(2);
        let Some(status) = bounded_status(
            &client,
            &url,
            Duration::from_secs(2),
            "first-window request",
        )
        .await
        else {
            return Err("the first-window request did not answer within 2s".to_string());
        };
        assert_eq!(status, 200, "the first request is the whole quota");
        // The charge landed somewhere in `spend_bucket..=served_bucket`; every
        // bound below is taken against the LATEST of those, so an imprecise
        // placement can only make this test stricter, never vacuous.
        let served_bucket = live_sub_bucket(2);
        let spent = spent_at.elapsed();
        if spend_bucket / 16 != served_bucket / 16 {
            return Err(format!(
                "the spend spanned epoch windows {}..={} (sub-buckets \
                 {spend_bucket}..={served_bucket}) in {spent:?}; it must sit wholly in one",
                spend_bucket / 16,
                served_bucket / 16
            ));
        }

        // Three and a half seconds (28 sub-buckets) is past the whole ladder
        // for a two-second window (the charged sub-bucket plus the seventeen
        // before it), and still inside the NEXT epoch window — which is exactly
        // where `previous + current` refuses and a trailing window must not.
        tokio::time::sleep_until(spent_at + Duration::from_millis(3_500)).await;
        // Placement FIRST. The spend must be OUT of this probe's ladder
        // (`p - 17 > served_bucket`) and the probe must sit in the epoch window
        // that immediately follows the spend's, or the scenario is not the one
        // `previous + current` fails.
        let probe_bucket = live_sub_bucket(2);
        if probe_bucket <= served_bucket + 17 {
            return Err(format!(
                "the next-window probe was scheduled into sub-bucket {probe_bucket}, still \
                 inside the ladder of a spend no later than {served_bucket}"
            ));
        }
        if probe_bucket / 16 != served_bucket / 16 + 1 {
            return Err(format!(
                "the next-window probe was scheduled into epoch window {}, not the one \
                 immediately after the spend's ({})",
                probe_bucket / 16,
                served_bucket / 16
            ));
        }
        let Some(status) =
            bounded_status(&client, &url, Duration::from_secs(2), "next-window request").await
        else {
            return Err("the next-window request did not answer within 2s".to_string());
        };
        // `sleep_until` schedules the probe; it does not guarantee the reply
        // came back before the window moved on. Re-read the placement and only
        // then assert.
        let served_probe = live_sub_bucket(2);
        if served_probe / 16 != served_bucket / 16 + 1 {
            return Err(format!(
                "the next-window probe was served in epoch window {}, not the one \
                 immediately after the spend's ({})",
                served_probe / 16,
                served_bucket / 16
            ));
        }
        assert_eq!(
            status, 200,
            "the next window must hand back the full configured rate, not a window \
             of refusals"
        );

        // The quota still binds: the request just admitted is itself inside the
        // trailing window.
        let Some(status) =
            bounded_status(&client, &url, Duration::from_secs(2), "over-quota request").await
        else {
            return Err("the over-quota request did not answer within 2s".to_string());
        };
        if live_sub_bucket(2) > served_probe + 17 {
            return Err(format!(
                "the over-quota request landed past the ladder of the admission in \
                 sub-bucket {served_probe}"
            ));
        }
        assert_eq!(status, 429, "the configured rate must still be enforced");
        Ok(())
    }
    .await;

    gateway.shutdown();
    backend.abort();
    delete_redis_keys_by_prefix(&prefix).await;
    if let Err(reason) = placement {
        skip_too_slow("full window does not lock out the next", reason);
    }
}

// ============================================================================
// Test: rate_limiting Redis fallback to local when Redis URL is unreachable
// ============================================================================

#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_database_selector_handshake() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };
    use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};

    if !redis_is_available().await {
        return;
    }
    for selector in ["", "/", "/0", "/15"] {
        let config = RedisConfig::from_plugin_config(
            &json!({
                "sync_mode": "redis",
                "redis_url": format!("redis://127.0.0.1:6379{selector}")
            }),
            &format!("selector-handshake:{}", Uuid::new_v4().simple()),
        )
        .unwrap()
        .unwrap();
        let redis =
            Arc::new(RedisRateLimitClient::for_request_quota(config, None, false, None).unwrap());
        let op = DynamicRateLimitOp::new(vec![RateLimitWindowSpec {
            limit: 1,
            duration: Duration::from_secs(6),
        }]);
        let algorithm = DynamicHttpRateLimitAlgorithm::new();
        let first = algorithm.check_redis(&redis, "client", &op).await.unwrap();
        let second = algorithm.check_redis(&redis, "client", &op).await.unwrap();
        assert!(first.allowed);
        assert!(!second.allowed);
    }
}

/// Issue #5517: a refusal by a later window must leave EVERY window's counter
/// exactly where it was — the tight window it refused on and the looser window
/// it had already charged on the way there.
///
/// This is the regression for the documented multi-window "phantom increment":
/// the per-day cap refuses while the per-hour cap still has 98 requests left,
/// and twenty refused attempts used to consume all of them.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_multi_window_rejections_leave_state_unchanged() {
    use ferrum_edge::plugins::utils::rate_limit::{
        DynamicHttpRateLimitAlgorithm, DynamicRateLimitOp, RateLimitAlgorithm, RateLimitWindowSpec,
    };
    use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};

    if !redis_is_available().await {
        return;
    }
    let prefix = format!("ferrum:test:atomic-windows:{}", Uuid::new_v4().simple());
    let config = RedisConfig::from_plugin_config(
        &json!({"sync_mode": "redis", "redis_url": REDIS_URL}),
        &prefix,
    )
    .unwrap()
    .unwrap();
    let redis =
        Arc::new(RedisRateLimitClient::for_request_quota(config, None, false, None).unwrap());
    let algorithm = DynamicHttpRateLimitAlgorithm::new();
    // Hour/day windows rather than minute/hour: neither index can roll over
    // inside a sub-second test, so the counter snapshots below are stable.
    let op = DynamicRateLimitOp::new(vec![
        RateLimitWindowSpec {
            limit: 100,
            duration: Duration::from_secs(3600),
        },
        RateLimitWindowSpec {
            limit: 2,
            duration: Duration::from_secs(86_400),
        },
    ]);
    for _ in 0..2 {
        let outcome = algorithm.check_redis(&redis, "client", &op).await.unwrap();
        assert!(outcome.allowed);
    }

    let tag = redis.make_slot_key("client", &[]);
    let before = redis_counter_snapshot(&tag).await;
    assert_eq!(
        before.len(),
        2,
        "both windows must carry their own counter: {before:?}"
    );
    assert!(
        before
            .iter()
            .all(|(_, value, _)| value.as_deref() == Some("2")),
        "each window must be charged exactly twice: {before:?}"
    );
    // The compensating transaction re-asserts EXPIRE on the keys it decrements,
    // because DECR on a key whose TTL elapsed in between would otherwise
    // recreate it with no expiry at all. Retention must stay bounded, so this
    // captures it rather than asserting a TTL is never refreshed.
    assert!(
        before.iter().all(|(_, _, ttl)| *ttl > 0),
        "every counter must carry a bounded retention: {before:?}"
    );

    for _ in 0..20 {
        let outcome = algorithm.check_redis(&redis, "client", &op).await.unwrap();
        assert!(!outcome.allowed);
        assert_eq!(outcome.limit, Some(2));
        assert_eq!(outcome.window_seconds, Some(86_400));
    }

    await_compensations(&redis).await;
    let after = redis_counter_snapshot(&tag).await;
    let values = |snapshot: &[(String, Option<String>, i64)]| {
        snapshot
            .iter()
            .map(|(key, value, _)| (key.clone(), value.clone()))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        values(&before),
        values(&after),
        "twenty refusals must leave every window's counter untouched"
    );
    assert!(
        after.iter().all(|(_, _, ttl)| *ttl > 0),
        "a compensated counter must keep a bounded retention: {after:?}"
    );
    delete_redis_keys_by_prefix(&prefix).await;
}

/// Wait until every detached rate-limit compensation this client issued has
/// completed.
///
/// A refusal hands its charge back from a task that owns the client `Arc`, not
/// from the request future (issue #5517 review): the refusal returns first, so
/// coverage that reads a counter straight afterwards must wait for the
/// hand-back instead of racing it.
async fn await_compensations(redis: &Arc<RedisRateLimitClient>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    while redis.pending_compensations_for_test() > 0 {
        assert!(
            tokio::time::Instant::now() < deadline,
            "detached rate-limit compensations did not drain"
        );
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

/// A controllable transport boundary for a LIVE Redis instance. Closing the
/// gate tears down existing sockets as well as rejecting newly accepted ones.
async fn gated_redis() -> (
    String,
    tokio::sync::watch::Sender<bool>,
    tokio::task::JoinHandle<()>,
) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let port = listener.local_addr().unwrap().port();
    let (enabled, state) = tokio::sync::watch::channel(true);
    let task = tokio::spawn(async move {
        loop {
            let (mut downstream, _) = listener.accept().await.unwrap();
            let mut state = state.clone();
            tokio::spawn(async move {
                if !*state.borrow_and_update() {
                    return;
                }
                let Ok(mut upstream) = tokio::net::TcpStream::connect("127.0.0.1:6379").await
                else {
                    return;
                };
                tokio::select! {
                    _ = state.changed() => {}
                    _ = tokio::io::copy_bidirectional(&mut downstream, &mut upstream) => {}
                }
            });
        }
    });
    (format!("redis://127.0.0.1:{port}/15"), enabled, task)
}

#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_default_outage_two_pods_and_recovery() {
    if !redis_is_available().await {
        return;
    }
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let backend_port = listener.local_addr().unwrap().port();
    let backend = start_header_echo_backend_on(listener).await.unwrap();
    let (redis_url, enabled, transport) = gated_redis().await;
    let prefix = format!("ferrum:test:outage:{}", Uuid::new_v4().simple());
    let config = json!({
        "version": "1",
        "consumers": [],
        "proxies": [{
            "id": "api", "listen_path": "/api", "backend_scheme": "http",
            "backend_host": "127.0.0.1", "backend_port": backend_port,
            "plugins": [{"plugin_config_id": "budget"}]
        }],
        "plugin_configs": [{
            "id": "budget", "plugin_name": "rate_limiting", "scope": "proxy",
            "proxy_id": "api", "enabled": true,
            "config": {
                "sync_mode": "redis", "redis_url": redis_url,
                "redis_key_prefix": prefix, "redis_connect_timeout_seconds": 1,
                "redis_health_check_interval_seconds": 1,
                "limits": [{"scope": "default", "window_seconds": 60, "max_requests": 2}]
            }
        }]
    });
    let mut first = spawn_file_gateway(config.to_string(), vec![]).await;
    let mut second = spawn_file_gateway(config.to_string(), vec![]).await;
    let client = reqwest::Client::new();
    // Retain one centralized admission across the outage. Recovery must see
    // exactly one remaining, not replay the fallback usage or reset Redis.
    assert_eq!(
        client
            .get(format!("{}/api/test", first.proxy_base_url))
            .send()
            .await
            .unwrap()
            .status()
            .as_u16(),
        200
    );
    enabled.send(false).unwrap();
    for gateway in [&first, &second] {
        for expected in [200, 200, 429, 429] {
            let response = client
                .get(format!("{}/api/test", gateway.proxy_base_url))
                .send()
                .await
                .unwrap();
            assert_eq!(response.status().as_u16(), expected);
        }
        let logs = gateway
            .wait_for_captured_output(
                |logs| logs.contains("falling back to local in-memory state"),
                Duration::from_secs(5),
            )
            .await
            .unwrap();
        assert_eq!(
            logs.matches("falling back to local in-memory state")
                .count(),
            1
        );
    }
    enabled.send(true).unwrap();
    // The fallback allowance is exhausted. Only a successful centralized
    // recovery can admit this request; poll that transition with a deadline.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        let response = client
            .get(format!("{}/api/test", first.proxy_base_url))
            .send()
            .await
            .unwrap();
        match response.status().as_u16() {
            200 => break,
            429 => {}
            status => panic!("unexpected recovery response: {status}"),
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "Redis did not recover"
        );
        sleep(Duration::from_millis(50)).await;
    }
    for gateway in [&first, &second] {
        assert_eq!(
            client
                .get(format!("{}/api/test", gateway.proxy_base_url))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16(),
            429
        );
    }
    first.shutdown();
    second.shutdown();
    transport.abort();
    backend.abort();
    delete_redis_keys_by_prefix(&prefix).await;
}

/// An omitted failure policy enforces pod-memory limits during a Redis outage.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_fallback_to_local() {
    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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

/// With explicit `redis_failure_policy: fail_closed`, an
/// unreachable centralized store must refuse rather than admit on a budget only
/// this process can see. `503` (not `429`) because the caller is not over its
/// limit — the limit cannot be evaluated — and no rate-limit headers are
/// advertised for a budget nothing is enforcing.
#[tokio::test]
#[ignore]
async fn test_rate_limiting_redis_unavailable_explicit_fail_closed() {
    let harness = RedisRateLimitHarness::new()
        .await
        .expect("Failed to create harness");

    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
                "redis_key_prefix": "ferrum:test:failclosed",
                "redis_failure_policy": "fail_closed"
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

    println!("test_rate_limiting_redis_unavailable_explicit_fail_closed PASSED");
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
    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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

    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
        let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .unwrap();
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
        let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .unwrap();
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
        let l = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .unwrap();
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
        let l = tokio::net::TcpListener::bind_test("127.0.0.1:0")
            .await
            .unwrap();
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
    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
      # Both gateways must answer from ONE centralized budget for the
      # "exactly 4 admitted out of 32 concurrent" assertion to mean anything.
      # Under the `local_fallback` default a Redis hiccup gives each pod its
      # own budget, so the shared-budget assertions could pass for the wrong
      # reason; fail closed instead.
      redis_failure_policy: "fail_closed"
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

    // Race two independent gateways on the same fresh budget. Each admission is
    // decided by its own atomic `INCR`, so concurrency can neither over-admit
    // nor manufacture a contention refusal: there is no optimistic retry to
    // exhaust, and a refused attempt's compensating `DECR` only ever hands back
    // a charge that request itself made.
    //
    // The two refusals above compensate from detached tasks. Both must land
    // before the budget is reset: a `DECR` arriving after the reset would put
    // the fresh counter below zero and hand the race one extra admission.
    wait_for_redis_counter_sum(&unique_prefix, 4).await;
    delete_redis_keys_by_prefix(&unique_prefix).await;
    let responses = futures_util::future::join_all((0..32).map(|index| {
        let client = client.clone();
        let port = if index % 2 == 0 { port1 } else { port2 };
        async move {
            client
                .get(format!("http://127.0.0.1:{port}/shared-rl/test"))
                .send()
                .await
                .unwrap()
                .status()
                .as_u16()
        }
    }))
    .await;
    assert_eq!(
        responses.iter().filter(|status| **status == 200).count(),
        4,
        "exactly the shared budget may be admitted under contention: {responses:?}"
    );
    assert!(
        responses.iter().all(|status| matches!(status, 200 | 429)),
        "a healthy store must never answer a concurrent race with 503: {responses:?}"
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
    let client = RedisRateLimitClient::new(config, None, false, None)
        .expect("construction without a CA path must succeed");

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

    let audit_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
    let audit_port = audit_listener.local_addr().unwrap().port();
    let audit_records = Arc::new(tokio::sync::Mutex::new(Vec::new()));
    let _audit_collector = start_audit_collector_on(audit_listener, Arc::clone(&audit_records))
        .await
        .unwrap();

    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
    let function_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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

    // Released deduplication profiles need GET for ownership release, but not
    // the semantic cache's EXISTS/STRLEN/GETRANGE bounded-read commands.
    let username = format!("dedup-release-{}", Uuid::new_v4().simple());
    let password = Uuid::new_v4().simple().to_string();
    let mut admin = redis::Client::open(REDIS_URL)
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let _: () = redis::cmd("ACL")
        .arg("SETUSER")
        .arg(&username)
        .arg("reset")
        .arg("on")
        .arg(format!(">{password}"))
        .arg(format!("~{default_prefix}*"))
        .arg("+auth")
        .arg("+hello")
        .arg("+select")
        .arg("+client")
        .arg("+ping")
        .arg("+info")
        .arg("+get")
        .arg("+set")
        .arg("+watch")
        .arg("+unwatch")
        .arg("+multi")
        .arg("+exec")
        .arg("+del")
        .query_async(&mut admin)
        .await
        .unwrap();
    let restricted_url = format!("redis://{username}:{password}@127.0.0.1:6379/15");
    let mut restricted = redis::Client::open(restricted_url.as_str())
        .unwrap()
        .get_multiplexed_async_connection()
        .await
        .unwrap();
    let probe_key = format!("{default_prefix}:acl-probe");
    for command in ["EXISTS", "STRLEN", "GETRANGE"] {
        let mut probe = redis::cmd(command);
        probe.arg(&probe_key);
        if command == "GETRANGE" {
            probe.arg(0).arg(1);
        }
        let result: Result<redis::Value, redis::RedisError> =
            probe.query_async(&mut restricted).await;
        assert_eq!(result.unwrap_err().code(), Some("NOPERM"));
    }

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
      redis_url: "{restricted_url}"
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
    let _: i64 = redis::cmd("ACL")
        .arg("DELUSER")
        .arg(&username)
        .query_async(&mut admin)
        .await
        .unwrap();
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

    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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

    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
    let backend_listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .unwrap();
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
      # Isolation is proven by the centralized per-namespace counters; a
      # per-process fallback budget would isolate for the wrong reason.
      redis_failure_policy: "fail_closed"
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

// ============================================================================
// Shared single-use replay authority — live cross-replica evidence
// (issues #3834 / #3837)
// ============================================================================
//
// `replay_scope: shared` / `dpop_replay_scope: shared` exist for exactly one
// reason: two gateway replicas behind a load balancer must not each accept the
// same proof once. Nothing below simulates that. Two independently spawned
// `ferrum-edge` processes share one Redis and one counting backend, and the
// load-bearing assertion is always the **backend mutation count** — "the
// gateway answered 401" is weaker than "the origin was contacted exactly once",
// because only the second rules out a duplicate side effect.
//
// Both replicas must see the same signed bytes, so every request carries an
// explicit `Host`. The HMAC v2 signing base binds the request authority and the
// DPoP `htu` binds scheme+host+path, so a per-port authority would make one
// replica's proof structurally unusable at the other and the cross-replica
// assertion would pass vacuously.

/// Fixed authority both HMAC replicas sign and present.
const REPLAY_HMAC_AUTHORITY: &str = "hmac-replay.example.test";
/// Fixed authority both DPoP replicas present, and the host inside every `htu`.
const REPLAY_DPOP_AUTHORITY: &str = "dpop-replay.example.test";
/// Exact issuer realm shared by the DPoP provider and access token.
const REPLAY_DPOP_ISSUER: &str = "https://dpop-replay.example.test";
const REPLAY_HMAC_SECRET: &str = "shared-replay-hmac-secret-at-least-32-bytes";

/// A backend that counts mutating application requests.
///
/// `/health` and non-mutating methods (`HEAD`/`GET`) are excluded so a
/// readiness probe, pool warmup, or capability `HEAD /` cannot be mistaken
/// for an HMAC/DPoP mutation.
async fn spawn_replay_counting_backend() -> (u16, Arc<AtomicUsize>) {
    let listener = tokio::net::TcpListener::bind_test("127.0.0.1:0")
        .await
        .expect("bind counting backend");
    let port = listener.local_addr().expect("backend addr").port();
    let mutations = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&mutations);

    tokio::spawn(async move {
        loop {
            let Ok((mut stream, _)) = listener.accept().await else {
                continue;
            };
            let counter = Arc::clone(&counter);
            tokio::spawn(async move {
                use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt};
                let (reader, mut writer) = stream.split();
                let mut buf_reader = tokio::io::BufReader::new(reader);
                let mut request_line = String::new();
                if buf_reader.read_line(&mut request_line).await.is_err() {
                    return;
                }
                let mut content_length = 0usize;
                loop {
                    let mut line = String::new();
                    if buf_reader.read_line(&mut line).await.is_err() {
                        return;
                    }
                    if line == "\r\n" || line == "\n" {
                        break;
                    }
                    let lower = line.to_ascii_lowercase();
                    if let Some(value) = lower.strip_prefix("content-length:") {
                        content_length = value.trim().parse().unwrap_or(0);
                    }
                }
                if content_length > 0 {
                    let mut body = vec![0u8; content_length];
                    let _ = buf_reader.read_exact(&mut body).await;
                }
                let is_health = request_line.contains(" /health ");
                let method = request_line
                    .split_whitespace()
                    .next()
                    .unwrap_or("")
                    .to_ascii_uppercase();
                let is_mutation = matches!(method.as_str(), "POST" | "PUT" | "PATCH" | "DELETE");
                if !is_health && is_mutation {
                    counter.fetch_add(1, Ordering::SeqCst);
                }
                let body = r#"{"ok":true}"#;
                let response = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                    body.len(),
                    body
                );
                let _ = writer.write_all(response.as_bytes()).await;
            });
        }
    });

    (port, mutations)
}

fn replay_hmac_config(backend_port: u16, prefix: &str) -> String {
    format!(
        r#"
version: "1"
proxies:
  - id: "hmac-replay-proxy"
    listen_path: "/hmac-replay"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "hmac-replay-plugin"

consumers:
  - id: "hmac-replay-consumer"
    username: "replayuser"
    credentials:
      hmac_auth:
        - secret: "{REPLAY_HMAC_SECRET}"

plugin_configs:
  - id: "hmac-replay-plugin"
    plugin_name: "hmac_auth"
    scope: "proxy"
    proxy_id: "hmac-replay-proxy"
    enabled: true
    config:
      clock_skew_seconds: 300
      replay_scope: "shared"
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix}"
"#,
    )
}

fn replay_hmac_authorization(nonce: &str, date: &str, digest: &str) -> String {
    crate::common::hmac_v2_authorization_header(
        &crate::common::HmacV2Request {
            method: "POST",
            path: "/hmac-replay",
            date,
            username: "replayuser",
            authority: REPLAY_HMAC_AUTHORITY,
            secret: REPLAY_HMAC_SECRET,
            digest_header: digest,
            nonce,
        },
        None,
    )
}

async fn send_replay_hmac(
    client: &reqwest::Client,
    port: u16,
    authorization: &str,
    date: &str,
    digest: &str,
) -> u16 {
    client
        .post(format!("http://127.0.0.1:{port}/hmac-replay"))
        .header("Host", REPLAY_HMAC_AUTHORITY)
        .header("Authorization", authorization)
        .header("Date", date)
        .header("Digest", digest)
        .send()
        .await
        .expect("hmac replay request completes")
        .status()
        .as_u16()
}

/// Issue #3837's backend-side acceptance evidence, on a live shared authority.
///
/// Two independently spawned gateway replicas share one Redis and one counting
/// backend. Covered here: a sequential replay, concurrent first-use copies of
/// one nonce raced across both replicas, a cross-replica replay, an equivalent
/// configuration reload (a fresh process, i.e. a fresh plugin cache), and a
/// fresh nonce adding exactly one mutation.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn test_hmac_v2_shared_redis_admits_one_backend_mutation_across_replicas() {
    if !redis_is_available().await {
        if std::env::var_os("FERRUM_REDIS_REQUIRED").is_some() {
            panic!("Redis is required for the shared single-use replay CI gate");
        }
        return;
    }

    let (backend_port, mutations) = spawn_replay_counting_backend().await;
    let prefix = format!("ferrum:test:hmacreplay:{}", Uuid::new_v4().simple());
    delete_redis_keys_by_prefix(&prefix).await;

    let config = replay_hmac_config(backend_port, &prefix);
    let warmup_off = vec![(
        "FERRUM_POOL_WARMUP_ENABLED".to_string(),
        "false".to_string(),
    )];
    let mut replica_a = spawn_file_gateway(config.clone(), warmup_off.clone()).await;
    let mut replica_b = spawn_file_gateway(config.clone(), warmup_off.clone()).await;
    let port_a = replica_a.proxy_port;
    let port_b = replica_b.proxy_port;

    let client = reqwest::Client::new();
    let date = chrono::Utc::now()
        .format("%a, %d %b %Y %H:%M:%S GMT")
        .to_string();
    let digest = crate::common::empty_digest_header();

    // 1. One accepted request reaches the backend exactly once.
    let first_nonce = crate::common::hmac_v2_nonce(0x3837_0001);
    let first = replay_hmac_authorization(&first_nonce, &date, &digest);
    assert_eq!(
        send_replay_hmac(&client, port_a, &first, &date, &digest).await,
        200,
        "a valid ferrum-hmac-v2 request must be accepted"
    );
    assert_eq!(mutations.load(Ordering::SeqCst), 1);

    // 2. Sequential replay against the same replica.
    assert_eq!(
        send_replay_hmac(&client, port_a, &first, &date, &digest).await,
        401,
        "a verbatim replay must be rejected"
    );
    // 3. Cross-replica replay: replica B never saw this request and must still
    //    refuse it, because the claim lives in the shared authority.
    assert_eq!(
        send_replay_hmac(&client, port_b, &first, &date, &digest).await,
        401,
        "a shared authority makes one proof single-use across replicas"
    );
    assert_eq!(
        mutations.load(Ordering::SeqCst),
        1,
        "replays must never reach the backend"
    );

    // 4. Concurrent first-use copies of ONE fresh nonce, raced across both
    //    replicas. Exactly one may win, and the backend may be mutated once.
    let raced_nonce = crate::common::hmac_v2_nonce(0x3837_0002);
    let raced = replay_hmac_authorization(&raced_nonce, &date, &digest);
    let mut attempts = Vec::new();
    for index in 0..8 {
        let client = client.clone();
        let raced = raced.clone();
        let date = date.clone();
        let digest = digest.clone();
        let port = if index % 2 == 0 { port_a } else { port_b };
        attempts.push(tokio::spawn(async move {
            send_replay_hmac(&client, port, &raced, &date, &digest).await
        }));
    }
    let mut accepted = 0usize;
    for attempt in attempts {
        match attempt.await.expect("raced request task completes") {
            200 => accepted += 1,
            401 => {}
            other => panic!("unexpected raced status {other}"),
        }
    }
    assert_eq!(
        accepted, 1,
        "exactly one concurrent first use may win a shared claim"
    );
    assert_eq!(
        mutations.load(Ordering::SeqCst),
        2,
        "the race added exactly one backend mutation"
    );

    // 5. An equivalent configuration reload — a fresh process with a fresh
    //    plugin cache — must not readmit either claimed nonce.
    replica_a.shutdown();
    let mut reloaded = spawn_file_gateway(config.clone(), warmup_off.clone()).await;
    let reloaded_port = reloaded.proxy_port;
    for authorization in [&first, &raced] {
        assert_eq!(
            send_replay_hmac(&client, reloaded_port, authorization, &date, &digest).await,
            401,
            "an equivalent reload must inherit the shared claim"
        );
    }
    assert_eq!(mutations.load(Ordering::SeqCst), 2);

    // 6. A fresh nonce is a new request and adds exactly one mutation.
    let fresh_nonce = crate::common::hmac_v2_nonce(0x3837_0003);
    let fresh = replay_hmac_authorization(&fresh_nonce, &date, &digest);
    assert_eq!(
        send_replay_hmac(&client, reloaded_port, &fresh, &date, &digest).await,
        200,
        "a fresh nonce with a recomputed signature must be accepted"
    );
    assert_eq!(
        mutations.load(Ordering::SeqCst),
        3,
        "a fresh nonce adds exactly one backend mutation"
    );

    delete_redis_keys_by_prefix(&prefix).await;
    reloaded.shutdown();
    replica_b.shutdown();
    println!("test_hmac_v2_shared_redis_admits_one_backend_mutation_across_replicas PASSED");
}

// ── DPoP (issue #3834) ──────────────────────────────────────────────

fn replay_der_from_pem(pem: &str) -> Vec<u8> {
    use base64::Engine as _;
    let b64: String = pem
        .lines()
        .filter(|line| !line.starts_with("-----"))
        .collect();
    base64::engine::general_purpose::STANDARD
        .decode(&b64)
        .expect("PEM base64")
}

fn replay_asn1_length(data: &[u8]) -> (usize, usize) {
    if data[0] < 0x80 {
        (data[0] as usize, 1)
    } else {
        let num_bytes = (data[0] & 0x7f) as usize;
        let mut length = 0usize;
        for &byte in &data[1..=num_bytes] {
            length = (length << 8) | byte as usize;
        }
        (length, 1 + num_bytes)
    }
}

/// `(modulus, exponent)` from a SubjectPublicKeyInfo RSA DER blob.
fn replay_rsa_public_parts(der: &[u8]) -> (Vec<u8>, Vec<u8>) {
    let mut pos = 0usize;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_, consumed) = replay_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (algo_len, consumed) = replay_asn1_length(&der[pos..]);
    pos += consumed + algo_len;
    assert_eq!(der[pos], 0x03);
    pos += 1;
    let (_, consumed) = replay_asn1_length(&der[pos..]);
    pos += consumed + 1;
    assert_eq!(der[pos], 0x30);
    pos += 1;
    let (_, consumed) = replay_asn1_length(&der[pos..]);
    pos += consumed;
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (n_len, consumed) = replay_asn1_length(&der[pos..]);
    pos += consumed;
    let mut n = der[pos..pos + n_len].to_vec();
    pos += n_len;
    if !n.is_empty() && n[0] == 0 {
        n.remove(0);
    }
    assert_eq!(der[pos], 0x02);
    pos += 1;
    let (e_len, consumed) = replay_asn1_length(&der[pos..]);
    pos += consumed;
    (n, der[pos..pos + e_len].to_vec())
}

struct DpopReplayFixture {
    jwks: serde_json::Value,
    access_token: String,
    private_key_pem: &'static [u8],
    jwk: serde_json::Value,
    ath: String,
}

fn build_dpop_replay_fixture() -> DpopReplayFixture {
    use base64::Engine as _;
    use base64::engine::general_purpose::URL_SAFE_NO_PAD;
    use ferrum_edge::plugins::utils::dpop::jwk_thumbprint_sha256;
    use jsonwebtoken::{EncodingKey, Header, encode};
    use sha2::{Digest, Sha256};

    let private_key_pem: &'static [u8] = include_bytes!("../fixtures/test_rsa_private.pem");
    let public_key_pem: &'static [u8] = include_bytes!("../fixtures/test_rsa_public.pem");
    let (n, e) = replay_rsa_public_parts(&replay_der_from_pem(
        std::str::from_utf8(public_key_pem).expect("public PEM is UTF-8"),
    ));
    let jwk = json!({
        "kty": "RSA",
        "kid": "dpop-replay-key",
        "use": "sig",
        "alg": "RS256",
        "n": URL_SAFE_NO_PAD.encode(&n),
        "e": URL_SAFE_NO_PAD.encode(&e),
    });
    let jwks = json!({"keys": [jwk.clone()]});

    let parsed_jwk: jsonwebtoken::jwk::Jwk =
        serde_json::from_value(jwk.clone()).expect("JWK parses");
    let jkt = jwk_thumbprint_sha256(&parsed_jwk).expect("JWK thumbprint");

    let now = chrono::Utc::now().timestamp();
    let mut access_header = Header::new(jsonwebtoken::Algorithm::RS256);
    access_header.kid = Some("dpop-replay-key".to_string());
    let access_token = encode(
        &access_header,
        &json!({
            "sub": "dpop-user",
            "iss": REPLAY_DPOP_ISSUER,
            "cnf": {"jkt": jkt},
            "exp": now + 900
        }),
        &EncodingKey::from_rsa_pem(private_key_pem).expect("RSA private key"),
    )
    .expect("access token");

    let mut hasher = Sha256::new();
    hasher.update(access_token.as_bytes());
    let ath = URL_SAFE_NO_PAD.encode(hasher.finalize());

    DpopReplayFixture {
        jwks,
        access_token,
        private_key_pem,
        jwk,
        ath,
    }
}

/// Mint one DPoP proof for `jti` bound to the fixture's key and access token.
fn dpop_replay_proof(fixture: &DpopReplayFixture, jti: &str) -> String {
    use jsonwebtoken::{EncodingKey, Header, encode};

    let now = chrono::Utc::now().timestamp();
    let mut header = Header::new(jsonwebtoken::Algorithm::RS256);
    header.typ = Some("dpop+jwt".to_string());
    header.jwk = Some(serde_json::from_value(fixture.jwk.clone()).expect("JWK parses"));
    encode(
        &header,
        &json!({
            "htm": "POST",
            "htu": format!("http://{REPLAY_DPOP_AUTHORITY}/dpop-replay"),
            "iat": now,
            "exp": now + 120,
            "jti": jti,
            "ath": fixture.ath,
        }),
        &EncodingKey::from_rsa_pem(fixture.private_key_pem).expect("RSA private key"),
    )
    .expect("dpop proof")
}

fn replay_dpop_config(backend_port: u16, prefix: &str, jwks: &serde_json::Value) -> String {
    let jwks_json = serde_json::to_string(jwks).expect("inline JWKS serializes");
    format!(
        r#"
version: "1"
proxies:
  - id: "dpop-replay-proxy"
    listen_path: "/dpop-replay"
    backend_scheme: http
    backend_host: "127.0.0.1"
    backend_port: {backend_port}
    strip_listen_path: true
    plugins:
      - plugin_config_id: "dpop-replay-plugin"

consumers: []

plugin_configs:
  - id: "dpop-replay-plugin"
    plugin_name: "jwks_auth"
    scope: "proxy"
    proxy_id: "dpop-replay-proxy"
    enabled: true
    config:
      sync_mode: "redis"
      redis_url: "{REDIS_URL}"
      redis_key_prefix: "{prefix}"
      providers:
        - jwks: '{jwks_json}'
          issuer: "{REPLAY_DPOP_ISSUER}"
          require_dpop: true
          dpop_replay_scope: "shared"
"#,
    )
}

async fn send_replay_dpop(
    client: &reqwest::Client,
    port: u16,
    fixture: &DpopReplayFixture,
    proof: &str,
) -> u16 {
    client
        .post(format!("http://127.0.0.1:{port}/dpop-replay"))
        .header("Host", REPLAY_DPOP_AUTHORITY)
        .header("Authorization", format!("Bearer {}", fixture.access_token))
        .header("DPoP", proof)
        .send()
        .await
        .expect("dpop replay request completes")
        .status()
        .as_u16()
}

/// Issue #3834's cross-replica acceptance criterion, on a live shared
/// authority: the same valid proof must be refused by a second, independently
/// constructed equivalent Ferrum policy, and a two-way race admits exactly one.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn test_dpop_shared_redis_admits_one_proof_across_replicas() {
    if !redis_is_available().await {
        if std::env::var_os("FERRUM_REDIS_REQUIRED").is_some() {
            panic!("Redis is required for the shared DPoP single-use CI gate");
        }
        return;
    }

    let (backend_port, mutations) = spawn_replay_counting_backend().await;
    let prefix = format!("ferrum:test:dpopreplay:{}", Uuid::new_v4().simple());
    delete_redis_keys_by_prefix(&prefix).await;

    let fixture = build_dpop_replay_fixture();
    let config = replay_dpop_config(backend_port, &prefix, &fixture.jwks);
    let warmup_off = vec![(
        "FERRUM_POOL_WARMUP_ENABLED".to_string(),
        "false".to_string(),
    )];
    let mut replica_a = spawn_file_gateway(config.clone(), warmup_off.clone()).await;
    let mut replica_b = spawn_file_gateway(config.clone(), warmup_off.clone()).await;
    let port_a = replica_a.proxy_port;
    let port_b = replica_b.proxy_port;

    let client = reqwest::Client::new();

    // One proof, accepted exactly once, by exactly one replica.
    let proof = dpop_replay_proof(&fixture, "dpop-replay-sequential");
    assert_eq!(
        send_replay_dpop(&client, port_a, &fixture, &proof).await,
        200,
        "a valid DPoP proof must be accepted once"
    );
    assert_eq!(mutations.load(Ordering::SeqCst), 1);

    assert_eq!(
        send_replay_dpop(&client, port_a, &fixture, &proof).await,
        401,
        "the same proof must not be accepted twice by one replica"
    );
    assert_eq!(
        send_replay_dpop(&client, port_b, &fixture, &proof).await,
        401,
        "a second independently constructed equivalent policy must refuse it too"
    );
    assert_eq!(
        mutations.load(Ordering::SeqCst),
        1,
        "a replayed proof must never reach the backend"
    );

    // A two-way race on a fresh proof: exactly one winner, one mutation.
    let raced_proof = dpop_replay_proof(&fixture, "dpop-replay-raced");
    let mut attempts = Vec::new();
    for index in 0..8 {
        let client = client.clone();
        let proof = raced_proof.clone();
        let access_token = fixture.access_token.clone();
        let port = if index % 2 == 0 { port_a } else { port_b };
        attempts.push(tokio::spawn(async move {
            client
                .post(format!("http://127.0.0.1:{port}/dpop-replay"))
                .header("Host", REPLAY_DPOP_AUTHORITY)
                .header("Authorization", format!("Bearer {access_token}"))
                .header("DPoP", proof)
                .send()
                .await
                .expect("raced dpop request completes")
                .status()
                .as_u16()
        }));
    }
    let mut accepted = 0usize;
    for attempt in attempts {
        match attempt.await.expect("raced dpop task completes") {
            200 => accepted += 1,
            401 => {}
            other => panic!("unexpected raced dpop status {other}"),
        }
    }
    assert_eq!(
        accepted, 1,
        "exactly one concurrent presentation of one proof may win"
    );
    assert_eq!(
        mutations.load(Ordering::SeqCst),
        2,
        "the race added exactly one backend mutation"
    );

    // A fresh proof under the same key is a new request.
    let fresh_proof = dpop_replay_proof(&fixture, "dpop-replay-fresh");
    assert_eq!(
        send_replay_dpop(&client, port_b, &fixture, &fresh_proof).await,
        200
    );
    assert_eq!(mutations.load(Ordering::SeqCst), 3);

    delete_redis_keys_by_prefix(&prefix).await;
    replica_a.shutdown();
    replica_b.shutdown();
    println!("test_dpop_shared_redis_admits_one_proof_across_replicas PASSED");
}

// ── the shared authority primitive, against a live Redis ────────────

/// The atomic path itself: independent clients and independent authorities —
/// the cross-process shape — see exactly one winner for one marker, distinct
/// markers all win, an existing key's TTL is never shortened, and an
/// unreachable store never falls back to local acceptance.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore]
async fn test_shared_replay_authority_live_redis_admits_exactly_one_winner() {
    use ferrum_edge::plugins::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};
    use ferrum_edge::plugins::utils::replay_authority::{
        ReplayAdmission, ReplayAuthority, ReplayDomain,
    };

    if !redis_is_available().await {
        if std::env::var_os("FERRUM_REDIS_REQUIRED").is_some() {
            panic!("Redis is required for the shared replay authority CI gate");
        }
        return;
    }

    let prefix = format!("ferrum:test:replayauth:{}", Uuid::new_v4().simple());
    delete_redis_keys_by_prefix(&prefix).await;
    let retention = Duration::from_secs(601);

    let build_client = || {
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
        // A separate client per authority: independent connection pools, exactly
        // as two gateway replicas have.
        Arc::new(
            RedisRateLimitClient::for_replay_authority(config, None, false, None)
                .expect("construction without a CA path must succeed"),
        )
    };

    let domain = ReplayDomain::new(
        "ferrum-hmac-v2",
        "ferrum",
        "hmac_auth",
        &prefix,
        "live-shared",
    );
    let clients: Vec<Arc<RedisRateLimitClient>> = (0..4).map(|_| build_client()).collect();
    let authorities: Vec<Arc<ReplayAuthority>> = clients
        .iter()
        .map(|client| {
            let authority = ReplayAuthority::shared(Arc::clone(client), retention);
            authority.activate();
            Arc::new(authority)
        })
        .collect();
    for (index, client) in clients.iter().enumerate() {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !client.is_available() {
            if std::time::Instant::now() > deadline {
                panic!("live Redis replica {index} did not pass a topology-screened probe");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }

    // 1. One marker, raced across four independent clients: exactly one winner.
    let contested = domain.marker(&[b"consumer-1", b"nonce-contested"]);
    let mut attempts = Vec::new();
    for index in 0..16 {
        let authority = Arc::clone(&authorities[index % authorities.len()]);
        attempts.push(tokio::spawn(
            async move { authority.admit(&contested).await },
        ));
    }
    let mut admitted = 0usize;
    for attempt in attempts {
        match attempt.await.expect("raced claim completes") {
            ReplayAdmission::Admitted => admitted += 1,
            ReplayAdmission::Replay => {}
            other => panic!("a live shared claim must not report {other:?}"),
        }
    }
    assert_eq!(
        admitted, 1,
        "an atomic SET NX admits exactly one concurrent claim"
    );

    // 2. Distinct markers all succeed — the authority bounds proofs, not traffic.
    for index in 0..8u32 {
        let marker = domain.marker(&[b"consumer-1", format!("nonce-{index}").as_bytes()]);
        assert_eq!(
            authorities[0].admit(&marker).await,
            ReplayAdmission::Admitted,
            "a distinct marker must be admitted"
        );
    }

    // 3. A later claim must never SHORTEN an existing key's TTL. `SET NX` does
    //    not touch a key it did not create, which is what makes a rolling
    //    deployment safe even if a generation declared a shorter horizon.
    let short_lived_client = build_client();
    let short_lived = Arc::new(ReplayAuthority::shared(
        Arc::clone(&short_lived_client),
        Duration::from_secs(5),
    ));
    short_lived.activate();
    {
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        while !short_lived_client.is_available() {
            if std::time::Instant::now() > deadline {
                panic!("short-horizon replica did not pass a topology-screened probe");
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }
    let ttl_marker = domain.marker(&[b"consumer-1", b"nonce-ttl"]);
    assert_eq!(
        authorities[0].admit(&ttl_marker).await,
        ReplayAdmission::Admitted
    );
    assert_eq!(
        short_lived.admit(&ttl_marker).await,
        ReplayAdmission::Replay,
        "the shorter-horizon generation observes the existing claim"
    );
    let marker_hex = hex::encode(ttl_marker.digest());
    let marker_key = build_client().make_key(&["replay", marker_hex.as_str()]);
    let ttl = redis_key_ttl(&marker_key)
        .await
        .expect("the marker key exists");
    assert!(
        ttl > 60,
        "a later shorter-horizon claim must not shorten a live marker's TTL, saw {ttl}s"
    );

    // 4. An unreachable store never degrades into local acceptance.
    let unreachable_config = RedisConfig::from_plugin_config(
        &json!({
            "sync_mode": "redis",
            // Port 1 is reserved and never listening.
            "redis_url": "redis://127.0.0.1:1",
            "redis_connect_timeout_seconds": 1,
            "redis_key_prefix": prefix,
        }),
        &prefix,
    )
    .expect("redis config parses")
    .expect("redis mode enabled");
    let unreachable_authority = ReplayAuthority::shared(
        Arc::new(
            RedisRateLimitClient::for_replay_authority(unreachable_config, None, false, None)
                .expect("construction without a CA path must succeed"),
        ),
        retention,
    );
    unreachable_authority.activate();
    let unseen = domain.marker(&[b"consumer-1", b"nonce-never-claimed"]);
    for _ in 0..3 {
        assert_eq!(
            unreachable_authority.admit(&unseen).await,
            ReplayAdmission::AuthorityUnavailable,
            "an unreachable shared store must reject, never admit locally"
        );
    }
    // Nothing was written, so the reachable authority still sees it as fresh.
    assert_eq!(
        authorities[0].admit(&unseen).await,
        ReplayAdmission::Admitted,
        "a refused claim must not have written a marker"
    );

    delete_redis_keys_by_prefix(&prefix).await;
    println!("test_shared_replay_authority_live_redis_admits_exactly_one_winner PASSED");
}

/// Real independent gateway processes must agree on dispatch provenance.
#[tokio::test]
#[ignore]
async fn test_request_deduplication_redis_dispatch_failures_preserve_execution_provenance() {
    if !redis_is_available().await {
        assert!(
            std::env::var_os("FERRUM_REDIS_REQUIRED").is_none(),
            "Redis required for dispatch provenance gate"
        );
        return;
    }
    let prefix = format!("ferrum:test:dedup-dispatch:{}", Uuid::new_v4().simple());
    crate::scaffolding::dedup_dispatch::assert_dispatch_provenance(Some(json!({
        "sync_mode": "redis", "redis_url": REDIS_URL, "redis_key_prefix": prefix
    })))
    .await;
    delete_redis_keys_by_prefix(&prefix).await;
}
