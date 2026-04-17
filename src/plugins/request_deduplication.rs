//! Request Deduplication Plugin
//!
//! Prevents duplicate API calls by tracking idempotency keys. When a request
//! arrives with an idempotency key header (e.g., `Idempotency-Key`) and the
//! same key was seen within the configured TTL, the plugin returns the cached
//! response instead of forwarding to the backend.
//!
//! Supports two storage modes:
//! - **local** (default): In-memory `DashMap` with TTL-based eviction. Suitable
//!   for single-instance deployments.
//! - **redis**: Centralized storage via Redis/Valkey/DragonflyDB/KeyDB/Garnet.
//!   Enables deduplication across multiple gateway instances. Uses the shared
//!   `RedisRateLimitClient` infrastructure with automatic local fallback when
//!   Redis is unreachable.
//!
//! Only applies to non-safe HTTP methods (POST, PUT, PATCH by default).

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

use super::utils::redis_rate_limiter::{RedisConfig, RedisRateLimitClient};
use super::{Plugin, PluginHttpClient, PluginResult, RequestContext};

/// A cached response stored for deduplication replay.
#[derive(Debug, Clone)]
struct CachedResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
    inserted_at: Instant,
}

/// In-flight marker to handle concurrent duplicate requests.
///
/// `InFlight` carries the timestamp it was inserted so stale markers (from
/// requests that died after `before_proxy` but before `on_final_response_body`,
/// e.g., backend timeout, downstream plugin reject, dropped connection) can be
/// detected and replaced rather than indefinitely returning 409 Conflict.
#[derive(Debug, Clone)]
enum DeduplicationEntry {
    /// Request is currently being processed. `started_at` allows stale-marker
    /// detection so abandoned in-flight entries don't permanently block retries.
    InFlight { started_at: Instant },
    /// Response has been cached.
    Completed(CachedResponse),
}

pub struct RequestDeduplication {
    /// Header name to read the idempotency key from.
    header_name: String,
    /// Time-to-live for cached responses.
    ttl: Duration,
    /// How long an `InFlight` marker remains valid before being treated as
    /// stale and replaced by a new request. Must be set at or above the
    /// longest backend request that should be protected from concurrent
    /// duplicate execution; set too low, slow legitimate requests could have
    /// duplicate retries bypass the in-flight lock and re-execute side-effecting
    /// operations. Defaults to `ttl_seconds`.
    inflight_ttl: Duration,
    /// Maximum number of cached entries (local mode).
    max_entries: usize,
    /// HTTP methods to apply deduplication to.
    applicable_methods: Vec<String>,
    /// Whether to scope keys by authenticated consumer identity.
    scope_by_consumer: bool,
    /// Whether to require the idempotency header (reject if missing).
    enforce_required: bool,
    /// Local in-memory cache.
    local_cache: Arc<DashMap<String, DeduplicationEntry>>,
    /// Optional Redis client for centralized deduplication.
    redis_client: Option<Arc<RedisRateLimitClient>>,
    /// Counter for background cleanup scheduling.
    last_cleanup: AtomicU64,
}

impl RequestDeduplication {
    pub fn new(config: &Value, http_client: PluginHttpClient) -> Result<Self, String> {
        let header_name = config["header_name"]
            .as_str()
            .unwrap_or("Idempotency-Key")
            .to_ascii_lowercase();

        let ttl_seconds = config["ttl_seconds"].as_u64().unwrap_or(300);
        if ttl_seconds == 0 {
            return Err("request_deduplication: ttl_seconds must be greater than 0".to_string());
        }
        let ttl = Duration::from_secs(ttl_seconds);

        let inflight_ttl_seconds = config["inflight_ttl_seconds"]
            .as_u64()
            .unwrap_or(ttl_seconds);
        if inflight_ttl_seconds == 0 {
            return Err(
                "request_deduplication: inflight_ttl_seconds must be greater than 0".to_string(),
            );
        }
        let inflight_ttl = Duration::from_secs(inflight_ttl_seconds);

        let max_entries = config["max_entries"].as_u64().unwrap_or(10_000) as usize;

        let applicable_methods: Vec<String> = config["applicable_methods"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_ascii_uppercase()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["POST".to_string(), "PUT".to_string(), "PATCH".to_string()]);

        if applicable_methods.is_empty() {
            return Err("request_deduplication: applicable_methods must not be empty".to_string());
        }

        let scope_by_consumer = config["scope_by_consumer"].as_bool().unwrap_or(true);
        let enforce_required = config["enforce_required"].as_bool().unwrap_or(false);

        // Build optional Redis client
        let redis_client =
            RedisConfig::from_plugin_config(config, &format!("{}:dedup", http_client.namespace()))
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
            header_name,
            ttl,
            inflight_ttl,
            max_entries,
            applicable_methods,
            scope_by_consumer,
            enforce_required,
            local_cache: Arc::new(DashMap::new()),
            redis_client,
            last_cleanup: AtomicU64::new(0),
        })
    }

    /// Build the deduplication key from the request context and idempotency value.
    fn build_key(&self, ctx: &RequestContext, idempotency_value: &str) -> String {
        let proxy_id = ctx
            .matched_proxy
            .as_ref()
            .map(|p| p.id.as_str())
            .unwrap_or("_");

        if self.scope_by_consumer
            && let Some(identity) = ctx.effective_identity()
        {
            return format!("{}:{}:{}", proxy_id, identity, idempotency_value);
        }

        format!("{}:{}", proxy_id, idempotency_value)
    }

    /// Try to retrieve a cached response from Redis.
    async fn redis_get(&self, key: &str) -> Option<CachedResponse> {
        let redis = self.redis_client.as_ref()?;
        if !redis.is_available() {
            return None;
        }

        let redis_key = redis.make_key(&[key]);
        let data = match redis.get_bytes(&redis_key).await {
            Ok(Some(d)) => d,
            Ok(None) => return None,
            Err(()) => return None,
        };

        serde_json::from_slice::<SerializableCachedResponse>(&data)
            .ok()
            .map(|s| CachedResponse {
                status_code: s.status_code,
                headers: s.headers,
                body: Bytes::from(s.body),
                inserted_at: Instant::now(), // Not meaningful for Redis entries
            })
    }

    /// Store a cached response in Redis with TTL.
    async fn redis_set(&self, key: &str, response: &CachedResponse) {
        let Some(redis) = self.redis_client.as_ref() else {
            return;
        };
        if !redis.is_available() {
            return;
        }

        let serializable = SerializableCachedResponse {
            status_code: response.status_code,
            headers: response.headers.clone(),
            body: response.body.to_vec(),
        };

        let data = match serde_json::to_vec(&serializable) {
            Ok(d) => d,
            Err(_) => return,
        };

        let redis_key = redis.make_key(&[key]);
        let ttl_seconds = self.ttl.as_secs().max(1);
        if let Err(()) = redis
            .set_bytes_with_expire(&redis_key, &data, ttl_seconds)
            .await
        {
            debug!("request_deduplication: Redis SET failed for key '{}'", key);
        }
    }

    /// Evict expired entries from local cache.
    fn cleanup_local_cache(&self) {
        let now_epoch = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // Only run cleanup every 30 seconds
        let last = self.last_cleanup.load(Ordering::Relaxed);
        if now_epoch.saturating_sub(last) < 30 {
            return;
        }
        if self
            .last_cleanup
            .compare_exchange(last, now_epoch, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return; // Another thread is doing cleanup
        }

        let now = Instant::now();
        self.local_cache.retain(|_, entry| match entry {
            DeduplicationEntry::Completed(cached) => {
                now.duration_since(cached.inserted_at) < self.ttl
            }
            // Drop in-flight markers that have exceeded inflight_ttl — the
            // originating request must have died (timeout, downstream reject,
            // connection drop) without ever reaching `on_final_response_body`.
            // Without this, duplicate requests would receive 409 Conflict
            // forever (until LRU max-entries eviction).
            DeduplicationEntry::InFlight { started_at } => {
                now.duration_since(*started_at) < self.inflight_ttl
            }
        });

        // Enforce max entries by removing oldest Completed entries first. Active
        // (non-stale) InFlight markers are NEVER evicted by LRU because evicting
        // them would release the in-flight lock while the original request is
        // still executing — a duplicate retry for that key would then bypass the
        // lock and re-execute side-effecting operations. Stale InFlight markers
        // (age >= inflight_ttl) are already dropped by the retain() above. This
        // means max_entries can be temporarily exceeded if the cache is
        // saturated with active in-flight work; correctness (no duplicate
        // writes) is strictly preferred over hitting the memory cap.
        if self.local_cache.len() > self.max_entries {
            let mut completed_with_time: Vec<(String, Instant)> = self
                .local_cache
                .iter()
                .filter_map(|entry| match entry.value() {
                    DeduplicationEntry::Completed(cached) => {
                        Some((entry.key().clone(), cached.inserted_at))
                    }
                    DeduplicationEntry::InFlight { .. } => None,
                })
                .collect();
            completed_with_time.sort_by_key(|(_, t)| *t);

            let to_remove = self.local_cache.len().saturating_sub(self.max_entries);
            for (key, _) in completed_with_time.into_iter().take(to_remove) {
                self.local_cache.remove(&key);
            }
        }
    }
}

/// Serializable form of CachedResponse for Redis storage.
#[derive(serde::Serialize, serde::Deserialize)]
struct SerializableCachedResponse {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Vec<u8>,
}

#[async_trait]
impl Plugin for RequestDeduplication {
    fn name(&self) -> &str {
        "request_deduplication"
    }

    fn priority(&self) -> u16 {
        super::priority::REQUEST_DEDUPLICATION
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    async fn before_proxy(
        &self,
        ctx: &mut RequestContext,
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Only apply to configured methods
        if !self
            .applicable_methods
            .iter()
            .any(|m| m.eq_ignore_ascii_case(&ctx.method))
        {
            return PluginResult::Continue;
        }

        // Get idempotency key from headers
        let idempotency_value = headers.get(&self.header_name).cloned();

        let idempotency_value = match idempotency_value {
            Some(v) if !v.is_empty() => v,
            _ => {
                if self.enforce_required {
                    return PluginResult::Reject {
                        status_code: 400,
                        body: format!(
                            r#"{{"error":"Missing required idempotency header: {}"}}"#,
                            self.header_name,
                        ),
                        headers: HashMap::new(),
                    };
                }
                return PluginResult::Continue;
            }
        };

        let key = self.build_key(ctx, &idempotency_value);

        // Periodic cleanup
        self.cleanup_local_cache();

        // Check Redis first (centralized dedup across instances)
        if self.redis_client.is_some()
            && let Some(cached) = self.redis_get(&key).await
        {
            debug!(
                "request_deduplication: Redis cache hit for key '{}', replaying response",
                idempotency_value
            );
            let mut response_headers = cached.headers.clone();
            response_headers.insert("x-idempotent-replayed".to_string(), "true".to_string());
            return PluginResult::RejectBinary {
                status_code: cached.status_code,
                body: cached.body.clone(),
                headers: response_headers,
            };
        }

        // Check local cache
        let now = Instant::now();
        if let Some(entry) = self.local_cache.get(&key) {
            match entry.value() {
                DeduplicationEntry::Completed(cached) => {
                    // Check TTL
                    if now.duration_since(cached.inserted_at) < self.ttl {
                        debug!(
                            "request_deduplication: cache hit for key '{}', replaying response",
                            idempotency_value
                        );
                        let mut response_headers = cached.headers.clone();
                        response_headers
                            .insert("x-idempotent-replayed".to_string(), "true".to_string());
                        return PluginResult::RejectBinary {
                            status_code: cached.status_code,
                            body: cached.body.clone(),
                            headers: response_headers,
                        };
                    }
                    // Expired — remove and continue
                    drop(entry);
                    self.local_cache.remove(&key);
                }
                DeduplicationEntry::InFlight { started_at } => {
                    // If the in-flight marker has exceeded inflight_ttl, the
                    // original request must have died without ever reaching
                    // on_final_response_body. Treat as a fresh request and
                    // replace the marker rather than blocking forever.
                    if now.duration_since(*started_at) >= self.inflight_ttl {
                        debug!(
                            "request_deduplication: stale in-flight marker for key '{}' (age >= {:?}), treating as fresh request",
                            idempotency_value, self.inflight_ttl
                        );
                        drop(entry);
                        // Fall through to insert new InFlight marker below
                    } else {
                        // Another request with the same key is in-flight.
                        // Return 409 Conflict rather than both hitting the backend.
                        drop(entry);
                        return PluginResult::Reject {
                            status_code: 409,
                            body: r#"{"error":"A request with this idempotency key is already in progress"}"#
                                .to_string(),
                            headers: HashMap::new(),
                        };
                    }
                }
            }
        }

        // Mark as in-flight (replacing any expired marker)
        self.local_cache.insert(
            key.clone(),
            DeduplicationEntry::InFlight { started_at: now },
        );

        // Store the key in metadata so on_final_response_body can cache the response
        ctx.metadata.insert("_dedup_key".to_string(), key);

        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Only cache if we have a dedup key from before_proxy
        let key = match ctx.metadata.get("_dedup_key") {
            Some(k) => k.clone(),
            None => return PluginResult::Continue,
        };

        let cached = CachedResponse {
            status_code: response_status,
            headers: response_headers.clone(),
            body: Bytes::from(body.to_vec()),
            inserted_at: Instant::now(),
        };

        // Store in local cache
        self.local_cache
            .insert(key.clone(), DeduplicationEntry::Completed(cached.clone()));

        // Also store in Redis if available
        if self.redis_client.is_some() {
            self.redis_set(&key, &cached).await;
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
        Some(self.local_cache.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::plugins::PluginHttpClient;
    use serde_json::json;

    /// LRU eviction under `max_entries` pressure must NOT evict active in-flight
    /// markers. Evicting a live InFlight entry would release the in-flight lock
    /// while the original request is still executing, so a duplicate retry for
    /// the same idempotency key would bypass the lock and re-execute the
    /// side-effecting operation.
    #[test]
    fn cleanup_preserves_active_inflight_over_max_entries() {
        let config = json!({ "max_entries": 2 });
        let plugin = RequestDeduplication::new(&config, PluginHttpClient::default()).unwrap();

        // 3 active in-flight markers, cap is 2 → over limit.
        let now = Instant::now();
        for i in 0..3 {
            plugin.local_cache.insert(
                format!("inflight-{i}"),
                DeduplicationEntry::InFlight { started_at: now },
            );
        }
        assert_eq!(plugin.local_cache.len(), 3);

        // Force cleanup to run (bypass the 30s gate).
        plugin.last_cleanup.store(0, Ordering::Relaxed);
        plugin.cleanup_local_cache();

        // All 3 active in-flight entries must still be present — LRU eviction
        // is not allowed to drop active locks.
        assert_eq!(plugin.local_cache.len(), 3);
        for i in 0..3 {
            assert!(plugin.local_cache.contains_key(&format!("inflight-{i}")));
        }
    }

    /// Completed entries ARE LRU-eligible. When over `max_entries`, the oldest
    /// Completed entries get evicted while active InFlight markers are kept.
    #[test]
    fn cleanup_evicts_oldest_completed_preserves_inflight() {
        let config = json!({ "max_entries": 2 });
        let plugin = RequestDeduplication::new(&config, PluginHttpClient::default()).unwrap();

        let now = Instant::now();
        // 1 active in-flight
        plugin.local_cache.insert(
            "inflight-key".to_string(),
            DeduplicationEntry::InFlight { started_at: now },
        );
        // 3 completed entries with increasing age (oldest first)
        for i in 0..3 {
            let inserted = now - Duration::from_secs(10 - i);
            plugin.local_cache.insert(
                format!("completed-{i}"),
                DeduplicationEntry::Completed(CachedResponse {
                    status_code: 200,
                    headers: HashMap::new(),
                    body: Bytes::new(),
                    inserted_at: inserted,
                }),
            );
        }
        assert_eq!(plugin.local_cache.len(), 4);

        plugin.last_cleanup.store(0, Ordering::Relaxed);
        plugin.cleanup_local_cache();

        // Cap is 2. InFlight kept. 2 oldest Completed evicted, 1 newest Completed kept.
        assert!(plugin.local_cache.contains_key("inflight-key"));
        assert!(!plugin.local_cache.contains_key("completed-0"));
        assert!(!plugin.local_cache.contains_key("completed-1"));
        assert!(plugin.local_cache.contains_key("completed-2"));
    }
}
