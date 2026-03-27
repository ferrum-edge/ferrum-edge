//! Response Caching Plugin
//!
//! Caches backend responses in-memory for cacheable endpoints, reducing
//! backend load for repeated identical requests. Supports Cache-Control
//! header awareness, configurable TTL, entry size limits, and automatic
//! eviction.
//!
//! Cache hits short-circuit the request pipeline via `PluginResult::Reject`
//! in `before_proxy`, returning the cached response without contacting
//! the backend (same pattern as `request_termination`).

use async_trait::async_trait;
use bytes::Bytes;
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::{debug, warn};

use super::{Plugin, PluginResult, RequestContext};

/// Maximum cache entries before triggering eviction of expired entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default TTL when no Cache-Control header is present (5 minutes).
const DEFAULT_TTL_SECONDS: u64 = 300;

/// Default maximum size of a single cached response body (1 MiB).
const DEFAULT_MAX_ENTRY_SIZE_BYTES: usize = 1_048_576;

/// Default maximum total cache size (100 MiB).
const DEFAULT_MAX_TOTAL_SIZE_BYTES: usize = 104_857_600;

/// A cached response entry.
#[derive(Debug, Clone)]
struct CacheEntry {
    status_code: u16,
    headers: HashMap<String, String>,
    body: Bytes,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_expired(&self) -> bool {
        self.inserted_at.elapsed() >= self.ttl
    }

    /// Approximate memory footprint of this entry (for total size tracking).
    fn approx_size(&self) -> usize {
        self.body.len()
            + self
                .headers
                .iter()
                .map(|(k, v)| k.len() + v.len())
                .sum::<usize>()
            + 64 // struct overhead estimate
    }
}

/// Parsed Cache-Control directives relevant to proxy caching.
#[derive(Debug, Default)]
struct CacheControlDirectives {
    no_store: bool,
    no_cache: bool,
    private: bool,
    max_age: Option<u64>,
    s_maxage: Option<u64>,
}

fn parse_cache_control(header_value: &str) -> CacheControlDirectives {
    let mut directives = CacheControlDirectives::default();

    for part in header_value.split(',') {
        let part = part.trim().to_lowercase();
        if part == "no-store" {
            directives.no_store = true;
        } else if part == "no-cache" {
            directives.no_cache = true;
        } else if part == "private" {
            directives.private = true;
        } else if let Some(val) = part.strip_prefix("s-maxage=") {
            directives.s_maxage = val.trim().parse().ok();
        } else if let Some(val) = part.strip_prefix("max-age=") {
            directives.max_age = val.trim().parse().ok();
        }
    }

    directives
}

/// Plugin configuration.
#[derive(Debug, Clone)]
struct ResponseCachingConfig {
    ttl_seconds: u64,
    max_entries: usize,
    max_entry_size_bytes: usize,
    max_total_size_bytes: usize,
    cacheable_methods: Vec<String>,
    cacheable_status_codes: Vec<u16>,
    respect_cache_control: bool,
    respect_no_cache: bool,
    vary_by_headers: Vec<String>,
    cache_key_include_query: bool,
    cache_key_include_consumer: bool,
    add_cache_status_header: bool,
    invalidate_on_unsafe_methods: bool,
}

impl ResponseCachingConfig {
    fn from_json(config: &Value) -> Self {
        let cacheable_methods = config["cacheable_methods"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_uppercase()))
                    .collect()
            })
            .unwrap_or_else(|| vec!["GET".to_string(), "HEAD".to_string()]);

        let cacheable_status_codes = config["cacheable_status_codes"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_u64().map(|n| n as u16))
                    .collect()
            })
            .unwrap_or_else(|| vec![200, 301, 404]);

        let vary_by_headers = config["vary_by_headers"]
            .as_array()
            .map(|arr| {
                arr.iter()
                    .filter_map(|v| v.as_str().map(|s| s.to_lowercase()))
                    .collect()
            })
            .unwrap_or_default();

        Self {
            ttl_seconds: config["ttl_seconds"]
                .as_u64()
                .unwrap_or(DEFAULT_TTL_SECONDS),
            max_entries: config["max_entries"]
                .as_u64()
                .unwrap_or(DEFAULT_MAX_ENTRIES as u64) as usize,
            max_entry_size_bytes: config["max_entry_size_bytes"]
                .as_u64()
                .unwrap_or(DEFAULT_MAX_ENTRY_SIZE_BYTES as u64)
                as usize,
            max_total_size_bytes: config["max_total_size_bytes"]
                .as_u64()
                .unwrap_or(DEFAULT_MAX_TOTAL_SIZE_BYTES as u64)
                as usize,
            cacheable_methods,
            cacheable_status_codes,
            respect_cache_control: config["respect_cache_control"].as_bool().unwrap_or(true),
            respect_no_cache: config["respect_no_cache"].as_bool().unwrap_or(true),
            vary_by_headers,
            cache_key_include_query: config["cache_key_include_query"].as_bool().unwrap_or(true),
            cache_key_include_consumer: config["cache_key_include_consumer"]
                .as_bool()
                .unwrap_or(false),
            add_cache_status_header: config["add_cache_status_header"].as_bool().unwrap_or(true),
            invalidate_on_unsafe_methods: config["invalidate_on_unsafe_methods"]
                .as_bool()
                .unwrap_or(true),
        }
    }
}

pub struct ResponseCaching {
    config: ResponseCachingConfig,
    cache: Arc<DashMap<String, CacheEntry>>,
    total_size: Arc<AtomicUsize>,
}

impl ResponseCaching {
    pub fn new(config: &Value) -> Self {
        let config = ResponseCachingConfig::from_json(config);

        if config.cacheable_methods.is_empty() {
            warn!("response_caching: no cacheable_methods configured — plugin will cache nothing");
        }

        Self {
            config,
            cache: Arc::new(DashMap::new()),
            total_size: Arc::new(AtomicUsize::new(0)),
        }
    }

    /// Build a cache key from request context.
    fn build_cache_key(&self, ctx: &RequestContext) -> String {
        let proxy_id = ctx
            .matched_proxy
            .as_ref()
            .map(|p| p.id.as_str())
            .unwrap_or("_");

        let query_part = if self.config.cache_key_include_query {
            let mut params: Vec<(&String, &String)> = ctx.query_params.iter().collect();
            params.sort_by_key(|(k, _)| k.as_str());
            params
                .iter()
                .map(|(k, v)| format!("{}={}", k, v))
                .collect::<Vec<_>>()
                .join("&")
        } else {
            String::new()
        };

        let consumer_part = if self.config.cache_key_include_consumer {
            ctx.identified_consumer
                .as_ref()
                .map(|c| c.username.as_str())
                .unwrap_or("_anon")
        } else {
            ""
        };

        let vary_part = if !self.config.vary_by_headers.is_empty() {
            self.config
                .vary_by_headers
                .iter()
                .map(|h| {
                    ctx.headers
                        .get(h.as_str())
                        .map(|v| v.as_str())
                        .unwrap_or("")
                })
                .collect::<Vec<_>>()
                .join("|")
        } else {
            String::new()
        };

        format!(
            "{}:{}:{}:{}:{}:{}",
            proxy_id, ctx.method, ctx.path, query_part, consumer_part, vary_part
        )
    }

    /// Check if the request method is cacheable.
    fn is_cacheable_method(&self, method: &str) -> bool {
        self.config.cacheable_methods.iter().any(|m| m == method)
    }

    /// Evict expired entries when cache exceeds max_entries.
    fn evict_if_needed(&self) {
        if self.cache.len() <= self.config.max_entries {
            return;
        }

        // First pass: remove expired entries
        let mut removed_size = 0usize;
        self.cache.retain(|_, entry| {
            if entry.is_expired() {
                removed_size += entry.approx_size();
                false
            } else {
                true
            }
        });
        self.total_size.fetch_sub(removed_size, Ordering::Relaxed);

        // If still over limit after removing expired, evict oldest entries
        if self.cache.len() > self.config.max_entries {
            let mut entries: Vec<(String, Instant)> = self
                .cache
                .iter()
                .map(|e| (e.key().clone(), e.value().inserted_at))
                .collect();
            entries.sort_by_key(|(_, ts)| *ts);

            let to_remove = self.cache.len() - self.config.max_entries;
            for (key, _) in entries.into_iter().take(to_remove) {
                if let Some((_, removed)) = self.cache.remove(&key) {
                    self.total_size
                        .fetch_sub(removed.approx_size(), Ordering::Relaxed);
                }
            }
        }
    }

    /// Invalidate cache entries matching a path pattern.
    /// Called when an unsafe method (POST/PUT/PATCH/DELETE) hits a path.
    fn invalidate_path(&self, ctx: &RequestContext) {
        let proxy_id = ctx
            .matched_proxy
            .as_ref()
            .map(|p| p.id.as_str())
            .unwrap_or("_");
        let prefix = format!("{}:", proxy_id);

        // Remove entries whose key starts with the proxy_id and contains the same path
        let path = &ctx.path;
        let mut removed_size = 0usize;
        self.cache.retain(|key, entry| {
            if key.starts_with(&prefix) && key.contains(path) {
                removed_size += entry.approx_size();
                debug!(
                    cache_key = %key,
                    method = %ctx.method,
                    "response_caching: invalidated cache entry due to unsafe method"
                );
                false
            } else {
                true
            }
        });
        if removed_size > 0 {
            self.total_size.fetch_sub(removed_size, Ordering::Relaxed);
        }
    }
}

#[async_trait]
impl Plugin for ResponseCaching {
    fn name(&self) -> &str {
        "response_caching"
    }

    fn priority(&self) -> u16 {
        super::priority::RESPONSE_CACHING
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
        _headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Invalidate on unsafe methods
        if !self.is_cacheable_method(&ctx.method) {
            if self.config.invalidate_on_unsafe_methods {
                self.invalidate_path(ctx);
            }
            ctx.metadata
                .insert("cache_status".to_string(), "BYPASS".to_string());
            return PluginResult::Continue;
        }

        // Check client Cache-Control for no-cache
        if self.config.respect_no_cache
            && let Some(cc) = ctx.headers.get("cache-control")
        {
            let directives = parse_cache_control(cc);
            if directives.no_cache || directives.no_store {
                ctx.metadata
                    .insert("cache_status".to_string(), "BYPASS".to_string());
                // Store the cache key so we can still cache the response
                let cache_key = self.build_cache_key(ctx);
                ctx.metadata.insert("cache_key".to_string(), cache_key);
                return PluginResult::Continue;
            }
        }

        let cache_key = self.build_cache_key(ctx);

        // Cache lookup
        if let Some(entry) = self.cache.get(&cache_key) {
            if !entry.is_expired() {
                debug!(
                    cache_key = %cache_key,
                    "response_caching: cache HIT"
                );

                let mut headers = entry.headers.clone();
                if self.config.add_cache_status_header {
                    headers.insert("x-cache-status".to_string(), "HIT".to_string());
                }

                // Return cached response body as string — works for JSON/text API responses
                let body = String::from_utf8(entry.body.to_vec()).unwrap_or_else(|e| {
                    // Lossy conversion for binary responses
                    String::from_utf8_lossy(e.as_bytes()).into_owned()
                });

                return PluginResult::Reject {
                    status_code: entry.status_code,
                    body,
                    headers,
                };
            }

            // Entry expired — remove it
            drop(entry);
            if let Some((_, removed)) = self.cache.remove(&cache_key) {
                self.total_size
                    .fetch_sub(removed.approx_size(), Ordering::Relaxed);
            }
        }

        // Cache MISS — store key for after_proxy to use
        ctx.metadata.insert("cache_key".to_string(), cache_key);
        ctx.metadata
            .insert("cache_status".to_string(), "MISS".to_string());

        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        // Add X-Cache-Status header
        if self.config.add_cache_status_header {
            let status = ctx
                .metadata
                .get("cache_status")
                .map(|s| s.as_str())
                .unwrap_or("MISS");
            response_headers.insert("x-cache-status".to_string(), status.to_string());
        }

        // Determine if response is cacheable (cache_key was set in before_proxy)
        if !ctx.metadata.contains_key("cache_key") {
            return PluginResult::Continue;
        }

        // Check if status code is cacheable
        if !self
            .config
            .cacheable_status_codes
            .contains(&response_status)
        {
            ctx.metadata.remove("cache_key");
            return PluginResult::Continue;
        }

        // Parse Cache-Control from backend response
        let mut ttl = Duration::from_secs(self.config.ttl_seconds);
        if self.config.respect_cache_control
            && let Some(cc) = response_headers.get("cache-control")
        {
            let directives = parse_cache_control(cc);

            // Do not cache no-store or private responses
            if directives.no_store || directives.private {
                ctx.metadata.remove("cache_key");
                return PluginResult::Continue;
            }

            // s-maxage takes precedence for shared caches
            if let Some(sma) = directives.s_maxage {
                ttl = Duration::from_secs(sma);
            } else if let Some(ma) = directives.max_age {
                ttl = Duration::from_secs(ma);
            }

            // no-cache: treat as TTL=0 (always revalidate)
            if directives.no_cache {
                ctx.metadata.remove("cache_key");
                return PluginResult::Continue;
            }
        }

        // Store TTL in metadata for on_response_body
        ctx.metadata
            .insert("cache_ttl_secs".to_string(), ttl.as_secs().to_string());
        // Keep cache_key in metadata for on_response_body

        // Store response headers in metadata (serialized as JSON)
        // so on_response_body can reconstruct the cache entry.
        if let Ok(headers_json) = serde_json::to_string(response_headers) {
            ctx.metadata
                .insert("cache_response_headers".to_string(), headers_json);
        }
        ctx.metadata.insert(
            "cache_response_status".to_string(),
            response_status.to_string(),
        );

        PluginResult::Continue
    }

    async fn on_response_body(
        &self,
        ctx: &RequestContext,
        _response_status: u16,
        _response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Check if we should cache this response
        let cache_key = match ctx.metadata.get("cache_key") {
            Some(key) => key.clone(),
            None => return PluginResult::Continue,
        };

        // Check body size limit
        if body.len() > self.config.max_entry_size_bytes {
            debug!(
                cache_key = %cache_key,
                body_size = body.len(),
                max_size = self.config.max_entry_size_bytes,
                "response_caching: response body exceeds max_entry_size_bytes, skipping cache"
            );
            return PluginResult::Continue;
        }

        // Reconstruct cached headers from metadata
        let cached_headers: HashMap<String, String> = ctx
            .metadata
            .get("cache_response_headers")
            .and_then(|json| serde_json::from_str(json).ok())
            .unwrap_or_default();

        let status_code: u16 = ctx
            .metadata
            .get("cache_response_status")
            .and_then(|s| s.parse().ok())
            .unwrap_or(200);

        let ttl_secs: u64 = ctx
            .metadata
            .get("cache_ttl_secs")
            .and_then(|s| s.parse().ok())
            .unwrap_or(self.config.ttl_seconds);

        let entry = CacheEntry {
            status_code,
            headers: cached_headers,
            body: Bytes::copy_from_slice(body),
            inserted_at: Instant::now(),
            ttl: Duration::from_secs(ttl_secs),
        };

        let entry_size = entry.approx_size();

        // Check total size limit
        let current_total = self.total_size.load(Ordering::Relaxed);
        if current_total + entry_size > self.config.max_total_size_bytes {
            debug!(
                cache_key = %cache_key,
                current_total = current_total,
                entry_size = entry_size,
                max_total = self.config.max_total_size_bytes,
                "response_caching: total cache size would exceed limit, skipping cache"
            );
            return PluginResult::Continue;
        }

        // Insert into cache
        if let Some(old) = self.cache.insert(cache_key.clone(), entry) {
            // Replacing an existing entry — adjust total size
            self.total_size
                .fetch_sub(old.approx_size(), Ordering::Relaxed);
        }
        self.total_size.fetch_add(entry_size, Ordering::Relaxed);

        debug!(
            cache_key = %cache_key,
            entry_size = entry_size,
            ttl_secs = ttl_secs,
            "response_caching: cached response"
        );

        // Evict if needed
        self.evict_if_needed();

        PluginResult::Continue
    }
}
