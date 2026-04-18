//! AI Semantic Cache Plugin (v1 — Exact-Match)
//!
//! Caches LLM responses keyed by normalized prompts to avoid redundant API calls.
//! When the same (or equivalently formatted) prompt arrives again within the TTL,
//! the cached response is returned immediately without contacting the backend.
//!
//! # v1 — Normalized Exact Match
//!
//! Prompts are normalized before hashing:
//! - Messages array is sorted by role, then by content
//! - Content text is lowercased and whitespace-collapsed
//! - Model name is included in the key (different models = different cache entries)
//! - Temperature, top_p, and other sampling parameters are optionally included
//!
//! This catches the most common duplicate case: identical or trivially reformatted
//! prompts from different users/requests.
//!
//! # v2 Roadmap — Semantic Similarity (Future)
//!
//! A future v2 could add embedding-based similarity matching:
//! - Compute embeddings via a configurable embedding endpoint (OpenAI, local model)
//! - Store embeddings in an in-memory vector index (e.g., HNSW)
//! - Match prompts by cosine similarity above a configurable threshold (e.g., 0.95)
//! - This would require: an embedding API dependency (adds latency), a vector
//!   similarity data structure (e.g., `instant-distance` or `hnsw` crate), and
//!   careful concurrency handling for the index. The embedding call could be
//!   amortized by batching or made async with a write-behind cache.
//!
//! # Storage
//!
//! - **local** (default): In-memory `DashMap` with TTL-based eviction
//! - **redis**: Centralized cache via Redis/Valkey for multi-instance deployments,
//!   using the shared `RedisRateLimitClient` infrastructure

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

use super::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

/// A cached LLM response.
#[derive(Debug, Clone)]
struct CacheEntry {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
    inserted_at: Instant,
    approx_size: usize,
}

pub struct AiSemanticCache {
    /// Cache TTL.
    ttl: Duration,
    /// Maximum number of cached entries.
    max_entries: usize,
    /// Maximum size of a single cached response body in bytes.
    max_entry_size_bytes: usize,
    /// Maximum total cache size in bytes.
    max_total_size_bytes: usize,
    /// Whether to include the model name in the cache key.
    include_model_in_key: bool,
    /// Whether to include sampling parameters (temperature, top_p) in the cache key.
    include_params_in_key: bool,
    /// Whether to scope cache entries by authenticated consumer.
    scope_by_consumer: bool,
    /// Local in-memory cache.
    cache: Arc<DashMap<String, CacheEntry>>,
    /// Total approximate size of all cached entries.
    total_size: Arc<AtomicUsize>,
    /// Optional Redis client for centralized caching.
    redis_client: Option<Arc<RedisRateLimitClient>>,
    /// Counter for periodic cleanup scheduling.
    last_cleanup: AtomicU64,
}

/// Serializable form of CacheEntry for Redis storage.
#[allow(dead_code)]
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableCacheEntry {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

impl AiSemanticCache {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let ttl_seconds = config["ttl_seconds"].as_u64().unwrap_or(300);
        if ttl_seconds == 0 {
            return Err("ai_semantic_cache: ttl_seconds must be greater than 0".to_string());
        }
        let ttl = Duration::from_secs(ttl_seconds);

        let max_entries = config["max_entries"].as_u64().unwrap_or(10_000) as usize;
        let max_entry_size_bytes =
            config["max_entry_size_bytes"].as_u64().unwrap_or(1_048_576) as usize; // 1 MiB default
        let max_total_size_bytes = config["max_total_size_bytes"]
            .as_u64()
            .unwrap_or(104_857_600) as usize; // 100 MiB default

        let include_model_in_key = config["include_model_in_key"].as_bool().unwrap_or(true);
        let include_params_in_key = config["include_params_in_key"].as_bool().unwrap_or(false);
        let scope_by_consumer = config["scope_by_consumer"].as_bool().unwrap_or(false);

        // Build optional Redis client
        let redis_client = RedisConfig::from_plugin_config(
            config,
            &format!("{}:ai_cache", http_client.namespace()),
        )
        .map(|redis_config| {
            let dns_cache = http_client.dns_cache();
            let tls_no_verify = http_client.tls_no_verify();
            let tls_ca_bundle_path = http_client.tls_ca_bundle_path();
            Arc::new(RedisRateLimitClient::new(
                redis_config,
                dns_cache.cloned(),
                tls_no_verify,
                tls_ca_bundle_path,
            ))
        });

        Ok(Self {
            ttl,
            max_entries,
            max_entry_size_bytes,
            max_total_size_bytes,
            include_model_in_key,
            include_params_in_key,
            scope_by_consumer,
            cache: Arc::new(DashMap::new()),
            total_size: Arc::new(AtomicUsize::new(0)),
            redis_client,
            last_cleanup: AtomicU64::new(0),
        })
    }

    /// Build a normalized cache key from the request body.
    ///
    /// Normalization steps:
    /// 1. Parse the JSON request body
    /// 2. Extract and sort the messages array by (role, content)
    /// 3. Lowercase and collapse whitespace in content fields
    /// 4. Optionally include model name and sampling parameters
    /// 5. SHA-256 hash the normalized representation
    fn build_cache_key(&self, ctx: &RequestContext, body: &Value) -> Option<String> {
        let mut key_parts: Vec<String> = Vec::new();

        // Proxy scope
        if let Some(ref proxy) = ctx.matched_proxy {
            key_parts.push(proxy.id.clone());
        }

        // Consumer scope
        if self.scope_by_consumer
            && let Some(identity) = ctx.effective_identity()
        {
            key_parts.push(identity.to_string());
        }

        // Model
        if self.include_model_in_key
            && let Some(model) = body.get("model").and_then(|m| m.as_str())
        {
            key_parts.push(format!("m:{}", model.to_ascii_lowercase()));
        }

        // Sampling parameters
        if self.include_params_in_key {
            if let Some(temp) = body.get("temperature").and_then(|t| t.as_f64()) {
                key_parts.push(format!("t:{:.2}", temp));
            }
            if let Some(top_p) = body.get("top_p").and_then(|t| t.as_f64()) {
                key_parts.push(format!("p:{:.2}", top_p));
            }
            if let Some(max_tokens) = body.get("max_tokens").and_then(|t| t.as_u64()) {
                key_parts.push(format!("mt:{}", max_tokens));
            }
        }

        // Messages — the core of the cache key
        if let Some(messages) = body.get("messages").and_then(|m| m.as_array()) {
            let mut normalized_messages: Vec<String> = Vec::with_capacity(messages.len());
            for msg in messages {
                let role = msg
                    .get("role")
                    .and_then(|r| r.as_str())
                    .unwrap_or("unknown");
                let content = self.extract_message_content(msg);
                normalized_messages.push(format!("{}:{}", role, content));
            }
            // Sort for order-independence (optional — most LLM APIs are order-sensitive,
            // but we sort to catch trivial reorderings of system/user messages)
            // Actually, message order matters for conversation context, so we preserve order
            // and only normalize content within each message.
            key_parts.push(normalized_messages.join("|"));
        } else {
            // No messages array — not a chat completion request, skip caching
            return None;
        }

        // Hash the key parts into a fixed-size cache key
        let key_input = key_parts.join("\n");
        let hash = Sha256::digest(key_input.as_bytes());
        Some(hex::encode(hash))
    }

    /// Extract and normalize message content text.
    fn extract_message_content(&self, msg: &Value) -> String {
        let raw = if let Some(content) = msg.get("content").and_then(|c| c.as_str()) {
            content.to_string()
        } else if let Some(parts) = msg.get("content").and_then(|c| c.as_array()) {
            // Multimodal: extract text parts only
            let mut texts = Vec::new();
            for part in parts {
                if part.get("type").and_then(|t| t.as_str()) == Some("text")
                    && let Some(text) = part.get("text").and_then(|t| t.as_str())
                {
                    texts.push(text.to_string());
                }
            }
            texts.join(" ")
        } else {
            String::new()
        };

        // Normalize: lowercase and collapse whitespace
        normalize_text(&raw)
    }

    /// Periodic cleanup of expired entries.
    fn cleanup_expired(&self) {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        let last = self.last_cleanup.load(Ordering::Relaxed);
        if now_epoch.saturating_sub(last) < 30 {
            return;
        }
        if self
            .last_cleanup
            .compare_exchange(last, now_epoch, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }

        let now = Instant::now();
        let mut removed_size = 0usize;
        self.cache.retain(|_, entry| {
            if now.duration_since(entry.inserted_at) >= self.ttl {
                removed_size += entry.approx_size;
                false
            } else {
                true
            }
        });
        if removed_size > 0 {
            self.total_size.fetch_sub(removed_size, Ordering::Relaxed);
        }

        // Enforce max entries by removing oldest. Use partial-select
        // (`select_nth_unstable_by_key`, average O(n)) instead of a full
        // sort (O(n log n)) — we only need to identify the k oldest, not
        // sort the entire cache.
        if self.cache.len() > self.max_entries {
            let mut entries_with_time: Vec<(String, Instant)> = self
                .cache
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().inserted_at))
                .collect();

            let to_remove = self.cache.len().saturating_sub(self.max_entries);
            if to_remove > 0 && to_remove < entries_with_time.len() {
                // After this call, indices [0..to_remove) hold the
                // `to_remove` oldest entries (in unspecified order among
                // themselves), which is all we need for eviction.
                entries_with_time.select_nth_unstable_by_key(to_remove - 1, |(_, t)| *t);
            }

            for (key, _) in entries_with_time.into_iter().take(to_remove) {
                if let Some((_, removed)) = self.cache.remove(&key) {
                    self.total_size
                        .fetch_sub(removed.approx_size, Ordering::Relaxed);
                }
            }
        }
    }
}

/// Exact-match sensitive response headers. Comparisons are ASCII
/// case-insensitive (RFC 9110 §5.1). See `SENSITIVE_HEADER_PREFIXES` for
/// families that must match by prefix instead (provider rate-limit
/// variants, multi-header B3 tracing).
///
/// Hop-by-hop headers (RFC 9110 §7.6.1: `connection`, `keep-alive`,
/// `proxy-authenticate`, `proxy-connection`, `te`, `trailer`,
/// `transfer-encoding`, `upgrade`) are intentionally NOT listed here —
/// they are stripped upstream by the proxy response-collection paths
/// (`collect_response_headers`, `collect_hyper_response_headers`,
/// `grpc_proxy`, `http3/server`) before `on_final_response_body` runs,
/// so they cannot reach this plugin.
const SENSITIVE_EXACT_HEADERS: &[&str] = &[
    // Per-response identity / session state.
    "set-cookie",
    "set-cookie2",
    "authorization",
    "www-authenticate",
    "x-api-key",
    "x-amz-security-token",
    "x-amzn-requestid",
    // Per-request trace identifiers — replaying these would splice the
    // original request's trace into every subsequent cache hit.
    "x-request-id",
    "x-correlation-id",
    "x-trace-id",
    "traceparent",
    "tracestate",
    // Zipkin B3 single-header format (RFC-less; defined by openzipkin/b3-propagation).
    // Multi-header B3 (`x-b3-traceid`, `x-b3-spanid`, `x-b3-parentspanid`,
    // `x-b3-sampled`, `x-b3-flags`) is covered by the `x-b3-` prefix below.
    "b3",
    // Per-request retry signal — the stored value reflects the original
    // response's retry timing and is misleading on a cache hit.
    "retry-after",
];

/// Case-insensitive prefixes for sensitive header families. These exist
/// because providers emit suffixed variants that an exact-match list
/// cannot enumerate safely:
///
/// - `x-ratelimit-` covers the IETF-draft canonical names
///   (`x-ratelimit-limit`, `-remaining`, `-reset`) AND provider variants
///   like OpenAI's `x-ratelimit-limit-requests`, `-limit-tokens`,
///   `-remaining-requests`, `-remaining-tokens`, `-reset-requests`,
///   `-reset-tokens`.
/// - `x-ai-ratelimit-` covers Ferrum Edge's own `ai_rate_limiter` output
///   (`-limit`, `-remaining`, `-window`, `-usage`) and future additions.
/// - `anthropic-ratelimit-` covers Anthropic's rate-limit family
///   (`anthropic-ratelimit-requests-limit`, `-tokens-remaining`, etc.).
/// - `x-b3-` covers the multi-header B3 tracing variant
///   (`x-b3-traceid`, `-spanid`, `-parentspanid`, `-sampled`, `-flags`).
const SENSITIVE_HEADER_PREFIXES: &[&str] = &[
    "x-ratelimit-",
    "x-ai-ratelimit-",
    "anthropic-ratelimit-",
    "x-b3-",
];

/// Case-insensitive check for whether a header name is sensitive.
/// Uses byte-slice `eq_ignore_ascii_case` to avoid a per-call
/// `to_ascii_lowercase` allocation. Prefix match is safe on byte
/// boundaries because all prefixes are ASCII.
fn is_sensitive_header(name: &str) -> bool {
    if SENSITIVE_EXACT_HEADERS
        .iter()
        .any(|s| name.eq_ignore_ascii_case(s))
    {
        return true;
    }
    let name_bytes = name.as_bytes();
    SENSITIVE_HEADER_PREFIXES.iter().any(|prefix| {
        let prefix_bytes = prefix.as_bytes();
        name_bytes.len() >= prefix_bytes.len()
            && name_bytes[..prefix_bytes.len()].eq_ignore_ascii_case(prefix_bytes)
    })
}

/// Strip security-sensitive headers from a response header map before the
/// cache stores or replays it.
fn sanitize_cached_headers(headers: &HashMap<String, String>) -> HashMap<String, String> {
    headers
        .iter()
        .filter(|(name, _)| !is_sensitive_header(name))
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

/// Normalize text: lowercase, collapse whitespace to single spaces, trim.
///
/// Single-pass: previously called `to_ascii_lowercase()` first (one extra
/// allocation) then iterated chars to collapse whitespace. The lowercase
/// step is now folded into the iteration so the function does one pass and
/// one allocation instead of two.
fn normalize_text(text: &str) -> String {
    let mut result = String::with_capacity(text.len());
    let mut prev_was_space = true; // trim leading
    for ch in text.chars() {
        if ch.is_whitespace() {
            if !prev_was_space {
                result.push(' ');
                prev_was_space = true;
            }
        } else {
            result.push(ch.to_ascii_lowercase());
            prev_was_space = false;
        }
    }
    // Trim trailing space
    if result.ends_with(' ') {
        result.pop();
    }
    result
}

#[async_trait]
impl Plugin for AiSemanticCache {
    fn name(&self) -> &str {
        "ai_semantic_cache"
    }

    fn priority(&self) -> u16 {
        super::priority::AI_SEMANTIC_CACHE
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_request_body_before_before_proxy(&self) -> bool {
        true
    }

    fn should_buffer_request_body(&self, ctx: &RequestContext) -> bool {
        ctx.method == "POST"
            && ctx
                .headers
                .get("content-type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only cache POST requests with JSON body
        if ctx.method != "POST" {
            return PluginResult::Continue;
        }

        let content_type = headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if !content_type.contains("json") {
            return PluginResult::Continue;
        }

        // Get request body
        let body_str = match ctx.metadata.get("request_body") {
            Some(b) if !b.is_empty() => b.clone(),
            _ => return PluginResult::Continue,
        };

        let json: Value = match serde_json::from_str(&body_str) {
            Ok(v) => v,
            Err(_) => return PluginResult::Continue,
        };

        // Build cache key
        let cache_key = match self.build_cache_key(ctx, &json) {
            Some(k) => k,
            None => return PluginResult::Continue,
        };

        // Periodic cleanup
        self.cleanup_expired();

        // Check Redis first (centralized cache across instances)
        if let Some(ref redis) = self.redis_client
            && redis.is_available()
        {
            let redis_key = redis.make_key(&[&cache_key]);
            if let Ok(Some(data)) = redis.get_bytes(&redis_key).await
                && let Ok(entry) = serde_json::from_slice::<SerializableCacheEntry>(&data)
            {
                debug!(
                    cache_key = %cache_key,
                    "ai_semantic_cache: Redis cache HIT, returning cached response"
                );
                let mut response_headers = entry.headers.clone();
                response_headers.insert("x-ai-cache-status".to_string(), "HIT".to_string());
                ctx.metadata
                    .insert("ai_cache_status".to_string(), "HIT".to_string());
                return PluginResult::RejectBinary {
                    status_code: entry.status_code,
                    body: Bytes::from(entry.body),
                    headers: response_headers,
                };
            }
        }

        // Check local cache
        if let Some(entry) = self.cache.get(&cache_key) {
            if Instant::now().duration_since(entry.inserted_at) < self.ttl {
                debug!(
                    cache_key = %cache_key,
                    "ai_semantic_cache: cache HIT, returning cached response"
                );
                let mut response_headers = entry.headers.clone();
                response_headers.insert("x-ai-cache-status".to_string(), "HIT".to_string());
                ctx.metadata
                    .insert("ai_cache_status".to_string(), "HIT".to_string());
                return PluginResult::RejectBinary {
                    status_code: entry.status_code,
                    body: entry.body.clone(),
                    headers: response_headers,
                };
            }
            // Expired — remove
            drop(entry);
            if let Some((_, removed)) = self.cache.remove(&cache_key) {
                self.total_size
                    .fetch_sub(removed.approx_size, Ordering::Relaxed);
            }
        }

        // Cache miss — store the key for on_final_response_body
        debug!(
            cache_key = %cache_key,
            "ai_semantic_cache: cache MISS"
        );
        ctx.metadata.insert("_ai_cache_key".to_string(), cache_key);
        ctx.metadata
            .insert("ai_cache_status".to_string(), "MISS".to_string());

        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Inject cache status header
        if let Some(status) = ctx.metadata.get("ai_cache_status") {
            response_headers.insert("x-ai-cache-status".to_string(), status.clone());
        }
        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only cache successful JSON responses
        if !(200..300).contains(&response_status) {
            return PluginResult::Continue;
        }

        let cache_key = match ctx.metadata.get("_ai_cache_key") {
            Some(k) => k.clone(),
            None => return PluginResult::Continue,
        };

        // Don't cache streaming responses
        let content_type = response_headers
            .get("content-type")
            .map(|s| s.as_str())
            .unwrap_or("");
        if content_type.contains("event-stream") {
            debug!("ai_semantic_cache: skipping SSE streaming response");
            return PluginResult::Continue;
        }

        // Size checks
        if body.len() > self.max_entry_size_bytes {
            debug!(
                cache_key = %cache_key,
                body_size = body.len(),
                max_size = self.max_entry_size_bytes,
                "ai_semantic_cache: response exceeds max_entry_size_bytes, skipping"
            );
            return PluginResult::Continue;
        }

        let current_total = self.total_size.load(Ordering::Relaxed);
        if current_total.saturating_add(body.len()) > self.max_total_size_bytes {
            debug!(
                cache_key = %cache_key,
                "ai_semantic_cache: total cache size would exceed limit, skipping"
            );
            return PluginResult::Continue;
        }

        // Strip security-sensitive headers before caching. Cookies, auth
        // tokens, per-request trace IDs, and rate-limit counters from the
        // original response would otherwise be replayed verbatim to every
        // cache-hit consumer — leaking session state and misleading
        // downstream clients about their own rate-limit/trace context.
        let safe_headers = sanitize_cached_headers(response_headers);

        let entry = CacheEntry {
            status_code: response_status,
            headers: safe_headers.clone(),
            body: Bytes::from(body.to_vec()),
            inserted_at: Instant::now(),
            approx_size: body.len(),
        };

        // Remove old entry size if replacing
        if let Some((_, old)) = self.cache.remove(&cache_key) {
            self.total_size
                .fetch_sub(old.approx_size, Ordering::Relaxed);
        }
        self.total_size
            .fetch_add(entry.approx_size, Ordering::Relaxed);
        self.cache.insert(cache_key.clone(), entry);

        // Also store in Redis if configured
        if let Some(ref redis) = self.redis_client
            && redis.is_available()
        {
            let serializable = SerializableCacheEntry {
                status_code: response_status,
                headers: safe_headers,
                body: body.to_vec(),
            };
            if let Ok(data) = serde_json::to_vec(&serializable) {
                let redis_key = redis.make_key(&[&cache_key]);
                let ttl_seconds = self.ttl.as_secs().max(1);
                let _ = redis
                    .set_bytes_with_expire(&redis_key, &data, ttl_seconds)
                    .await;
            }
        }

        PluginResult::Continue
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        if let Some(ref redis) = self.redis_client {
            redis.warmup_hostname().into_iter().collect()
        } else {
            Vec::new()
        }
    }

    fn tracked_keys_count(&self) -> Option<usize> {
        Some(self.cache.len())
    }
}

#[cfg(test)]
mod tests {
    //! Inline tests that need access to private fields (the cache map and
    //! the gated `cleanup_expired` helper).
    use super::*;
    use crate::plugins::PluginHttpClient;
    use serde_json::json;

    /// Insert a synthetic cache entry directly so tests can populate the
    /// cache without driving the full request/response lifecycle.
    fn insert_synthetic(plugin: &AiSemanticCache, key: &str, inserted_at: Instant) {
        let entry = CacheEntry {
            status_code: 200,
            body: Bytes::from_static(b"\x00\x00\x00\x00\x00\x00\x00\x00"),
            headers: HashMap::new(),
            inserted_at,
            approx_size: 8,
        };
        plugin
            .total_size
            .fetch_add(entry.approx_size, Ordering::Relaxed);
        plugin.cache.insert(key.to_string(), entry);
    }

    /// Force cleanup to run regardless of the 30-second cooldown gate by
    /// resetting the gate before the call.
    fn force_cleanup(plugin: &AiSemanticCache) {
        plugin.last_cleanup.store(0, Ordering::Relaxed);
        plugin.cleanup_expired();
    }

    #[test]
    fn eviction_keeps_newest_when_max_entries_exceeded() {
        // Verifies the partial-select eviction (`select_nth_unstable_by_key`)
        // preserves oldest-first semantics: when the cache exceeds
        // `max_entries`, the oldest are evicted and the newest are kept.
        let plugin = AiSemanticCache::new(
            &json!({"ttl_seconds": 600, "max_entries": 3}),
            PluginHttpClient::default(),
        )
        .unwrap();

        let now = Instant::now();
        // Insert oldest → newest. Use 100ms spacing so ordering is well-defined
        // without needing real wall-clock waits.
        for (i, name) in ["a", "b", "c", "d", "e"].iter().enumerate() {
            let ts = now - Duration::from_millis(500 - (i as u64) * 100);
            insert_synthetic(&plugin, name, ts);
        }
        assert_eq!(plugin.cache.len(), 5);

        force_cleanup(&plugin);

        assert!(
            plugin.cache.len() <= 3,
            "max_entries=3 must be honored after eviction (got {})",
            plugin.cache.len()
        );
        // The two oldest entries ('a' and 'b') must be evicted.
        assert!(
            !plugin.cache.contains_key("a"),
            "oldest 'a' must be evicted"
        );
        assert!(
            !plugin.cache.contains_key("b"),
            "second-oldest 'b' must be evicted"
        );
        // The newest entries must survive.
        assert!(
            plugin.cache.contains_key("e"),
            "newest 'e' must be retained"
        );
    }

    #[test]
    fn normalize_text_collapses_whitespace_and_lowercases() {
        // Sanity-check the optimized single-pass normalize_text.
        assert_eq!(normalize_text("  Hello   World  "), "hello world");
        assert_eq!(
            normalize_text("MULTIPLE\nLINES\tof\rtext"),
            "multiple lines of text"
        );
        assert_eq!(normalize_text(""), "");
        assert_eq!(normalize_text("   "), "");
    }

    #[test]
    fn sanitize_cached_headers_strips_security_sensitive_keys() {
        // Cached responses must never replay per-response identity (cookies,
        // auth tokens, trace IDs) or per-request rate-limit counters to a
        // different consumer. The stripper is case-insensitive because HTTP
        // header names are case-insensitive.
        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("Set-Cookie".to_string(), "session=abc123".to_string());
        headers.insert("authorization".to_string(), "Bearer xyz".to_string());
        headers.insert("X-Request-Id".to_string(), "req-12345-abcdef".to_string());
        headers.insert("X-AI-RateLimit-Remaining".to_string(), "42".to_string());
        headers.insert("retry-after".to_string(), "30".to_string());
        headers.insert("x-custom-app-header".to_string(), "keep-me".to_string());

        let sanitized = sanitize_cached_headers(&headers);
        // Safe headers are retained
        assert_eq!(
            sanitized.get("content-type").map(String::as_str),
            Some("application/json")
        );
        assert_eq!(
            sanitized.get("x-custom-app-header").map(String::as_str),
            Some("keep-me")
        );
        // Sensitive headers are stripped, regardless of case
        assert!(!sanitized.contains_key("Set-Cookie"));
        assert!(!sanitized.contains_key("authorization"));
        assert!(!sanitized.contains_key("X-Request-Id"));
        assert!(!sanitized.contains_key("X-AI-RateLimit-Remaining"));
        assert!(!sanitized.contains_key("retry-after"));
    }

    #[test]
    fn sanitize_cached_headers_strips_provider_ratelimit_suffix_variants() {
        // Providers emit rate-limit headers with request/token suffixes
        // (OpenAI: x-ratelimit-*-requests / -tokens; Anthropic:
        // anthropic-ratelimit-requests-* / -tokens-*). Exact-match against
        // a canonical list would miss these and replay the original
        // consumer's quota to every cache hit. Prefix matching catches the
        // whole family.
        let mut headers = HashMap::new();
        // OpenAI-style (exact canonical + suffix variants).
        headers.insert("x-ratelimit-limit".to_string(), "3500".to_string());
        headers.insert("x-ratelimit-limit-requests".to_string(), "3500".to_string());
        headers.insert("X-RateLimit-Limit-Tokens".to_string(), "90000".to_string());
        headers.insert(
            "x-ratelimit-remaining-requests".to_string(),
            "3499".to_string(),
        );
        headers.insert("x-ratelimit-reset-tokens".to_string(), "6ms".to_string());
        // Anthropic family.
        headers.insert(
            "anthropic-ratelimit-requests-limit".to_string(),
            "50".to_string(),
        );
        headers.insert(
            "anthropic-ratelimit-tokens-remaining".to_string(),
            "39000".to_string(),
        );
        // Ferrum Edge's own ai_rate_limiter (covered by x-ai-ratelimit-).
        headers.insert("x-ai-ratelimit-usage".to_string(), "12".to_string());
        // B3 multi-header tracing (x-b3-) and single-header (b3).
        headers.insert(
            "X-B3-TraceId".to_string(),
            "80f198ee56343ba864fe8b2a57d3eff7".to_string(),
        );
        headers.insert("x-b3-sampled".to_string(), "1".to_string());
        headers.insert("b3".to_string(), "80f198ee-e457912e-1".to_string());
        // Safe headers that share neighbouring namespaces but must not match.
        headers.insert("x-ai-cache-status".to_string(), "HIT".to_string());
        headers.insert(
            "x-ratelimited-by".to_string(), // no trailing dash — different prefix
            "upstream".to_string(),
        );
        headers.insert("content-type".to_string(), "application/json".to_string());

        let sanitized = sanitize_cached_headers(&headers);
        // All rate-limit / tracing variants stripped.
        assert!(!sanitized.contains_key("x-ratelimit-limit"));
        assert!(!sanitized.contains_key("x-ratelimit-limit-requests"));
        assert!(!sanitized.contains_key("X-RateLimit-Limit-Tokens"));
        assert!(!sanitized.contains_key("x-ratelimit-remaining-requests"));
        assert!(!sanitized.contains_key("x-ratelimit-reset-tokens"));
        assert!(!sanitized.contains_key("anthropic-ratelimit-requests-limit"));
        assert!(!sanitized.contains_key("anthropic-ratelimit-tokens-remaining"));
        assert!(!sanitized.contains_key("x-ai-ratelimit-usage"));
        assert!(!sanitized.contains_key("X-B3-TraceId"));
        assert!(!sanitized.contains_key("x-b3-sampled"));
        assert!(!sanitized.contains_key("b3"));
        // Near-miss names that share a neighbouring namespace are retained.
        assert_eq!(
            sanitized.get("x-ai-cache-status").map(String::as_str),
            Some("HIT"),
        );
        assert_eq!(
            sanitized.get("x-ratelimited-by").map(String::as_str),
            Some("upstream"),
        );
        assert_eq!(
            sanitized.get("content-type").map(String::as_str),
            Some("application/json"),
        );
    }
}
