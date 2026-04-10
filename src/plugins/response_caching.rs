//! Response Caching Plugin
//!
//! Caches backend responses in-memory for cacheable endpoints, reducing
//! backend load for repeated identical requests. Supports Cache-Control,
//! ETag/Last-Modified revalidation, backend `Vary` awareness, binary bodies,
//! configurable TTL, entry size limits, and automatic eviction.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use dashmap::DashMap;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};
use tracing::debug;

use super::{Plugin, PluginResult, RequestContext};

/// Maximum cache entries before triggering eviction of expired entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default TTL when no Cache-Control header is present (5 minutes).
const DEFAULT_TTL_SECONDS: u64 = 300;

/// Default maximum size of a single cached response body (1 MiB).
const DEFAULT_MAX_ENTRY_SIZE_BYTES: usize = 1_048_576;

/// Default maximum total cache size (100 MiB).
const DEFAULT_MAX_TOTAL_SIZE_BYTES: usize = 104_857_600;

const CACHE_BASE_KEY: &str = "cache_base_key";
const CACHE_STATUS: &str = "cache_status";

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
#[derive(Debug, Default, Clone, Copy)]
struct CacheControlDirectives {
    no_store: bool,
    no_cache: bool,
    private: bool,
    public: bool,
    must_revalidate: bool,
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
        } else if part == "public" {
            directives.public = true;
        } else if part == "must-revalidate" {
            directives.must_revalidate = true;
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

/// Bounded LRU tracker of keys known to be uncacheable.
/// Prevents wasted cache lock acquisition for assets that were historically uncacheable.
struct UncacheablePredictor {
    /// Keys known to be uncacheable, mapped to the epoch second when recorded.
    keys: DashMap<String, u64>,
    /// Maximum entries before oldest are evicted.
    max_entries: usize,
}

impl UncacheablePredictor {
    fn new(max_entries: usize) -> Self {
        Self {
            keys: DashMap::with_capacity(max_entries / 4),
            max_entries,
        }
    }

    /// Returns true if this key is predicted to be cacheable (not in the uncacheable set).
    fn is_predicted_cacheable(&self, key: &str) -> bool {
        !self.keys.contains_key(key)
    }

    /// Mark a key as uncacheable. If the map is full, remove ~25% of entries by oldest timestamp.
    fn mark_uncacheable(&self, key: &str) {
        if self.keys.len() >= self.max_entries {
            // Evict oldest 25%
            let target = self.max_entries / 4;
            let mut entries: Vec<(String, u64)> = self
                .keys
                .iter()
                .map(|e| (e.key().clone(), *e.value()))
                .collect();
            entries.sort_by_key(|(_, ts)| *ts);
            for (k, _) in entries.into_iter().take(target) {
                self.keys.remove(&k);
            }
        }
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();
        self.keys.insert(key.to_string(), now);
    }

    /// Remove a key from the uncacheable set (it became cacheable).
    fn mark_cacheable(&self, key: &str) {
        self.keys.remove(key);
    }
}

pub struct ResponseCaching {
    config: ResponseCachingConfig,
    cache: Arc<DashMap<String, CacheEntry>>,
    vary_index: Arc<DashMap<String, Vec<String>>>,
    total_size: Arc<AtomicUsize>,
    uncacheable_predictor: UncacheablePredictor,
}

impl ResponseCaching {
    pub fn new(config: &Value) -> Result<Self, String> {
        let config = ResponseCachingConfig::from_json(config);

        if config.cacheable_methods.is_empty() {
            return Err(
                "response_caching: no cacheable_methods configured — plugin will cache nothing"
                    .to_string(),
            );
        }

        let predictor_size = config.max_entries / 10; // 10% of cache size
        Ok(Self {
            config,
            cache: Arc::new(DashMap::new()),
            vary_index: Arc::new(DashMap::new()),
            total_size: Arc::new(AtomicUsize::new(0)),
            uncacheable_predictor: UncacheablePredictor::new(predictor_size.max(100)),
        })
    }

    fn build_base_cache_key(&self, ctx: &RequestContext) -> String {
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
            ctx.effective_identity().unwrap_or("_anon")
        } else {
            ""
        };

        format!(
            "{}:{}:{}:{}:{}",
            proxy_id, ctx.method, ctx.path, query_part, consumer_part
        )
    }

    fn build_cache_key(
        &self,
        ctx: &RequestContext,
        vary_headers: &[String],
        request_headers: &HashMap<String, String>,
    ) -> String {
        let base_key = self.build_base_cache_key(ctx);
        if vary_headers.is_empty() {
            return base_key;
        }

        let vary_part = vary_headers
            .iter()
            .map(|header| {
                let value = request_headers
                    .get(header.as_str())
                    .map(String::as_str)
                    .unwrap_or("");
                format!("{}={}", header, value)
            })
            .collect::<Vec<_>>()
            .join("|");

        format!("{}:{}", base_key, vary_part)
    }

    /// Check if the request method is cacheable.
    fn is_cacheable_method(&self, method: &str) -> bool {
        self.config.cacheable_methods.iter().any(|m| m == method)
    }

    fn cache_lookup_vary_headers(&self, base_key: &str) -> Vec<String> {
        self.vary_index
            .get(base_key)
            .map(|headers| headers.clone())
            .unwrap_or_else(|| self.config.vary_by_headers.clone())
    }

    fn merged_vary_headers(
        &self,
        response_headers: &HashMap<String, String>,
    ) -> Option<Vec<String>> {
        let mut vary_headers = self.config.vary_by_headers.clone();

        if let Some(vary) = response_headers.get("vary") {
            for header in vary.split(',') {
                let header = header.trim().to_lowercase();
                if header.is_empty() {
                    continue;
                }
                if header == "*" {
                    return None;
                }
                if !vary_headers.iter().any(|existing| existing == &header) {
                    vary_headers.push(header);
                }
            }
        }

        vary_headers.sort();
        Some(vary_headers)
    }

    fn is_fresh_conditional_hit(
        &self,
        request_headers: &HashMap<String, String>,
        entry: &CacheEntry,
    ) -> bool {
        if let Some(if_none_match) = request_headers.get("if-none-match") {
            return entry
                .headers
                .get("etag")
                .is_some_and(|etag| if_none_match_matches(if_none_match, etag));
        }

        if let Some(if_modified_since) = request_headers.get("if-modified-since") {
            return entry
                .headers
                .get("last-modified")
                .and_then(|last_modified| parse_http_date(last_modified))
                .zip(parse_http_date(if_modified_since))
                .is_some_and(|(last_modified, if_modified_since)| {
                    last_modified <= if_modified_since
                });
        }

        false
    }

    fn not_modified_headers(&self, entry: &CacheEntry) -> HashMap<String, String> {
        let mut headers = HashMap::new();
        for key in [
            "cache-control",
            "content-location",
            "date",
            "etag",
            "expires",
            "last-modified",
            "vary",
        ] {
            if let Some(value) = entry.headers.get(key) {
                headers.insert(key.to_string(), value.clone());
            }
        }

        if self.config.add_cache_status_header {
            headers.insert("x-cache-status".to_string(), "REVALIDATED".to_string());
        }

        headers
    }

    fn invalidate_base_key(&self, base_key: &str) {
        let variant_prefix = format!("{}:", base_key);
        let mut removed_size = 0usize;
        self.cache.retain(|key, entry| {
            if key == base_key || key.starts_with(&variant_prefix) {
                removed_size += entry.approx_size();
                false
            } else {
                true
            }
        });

        if removed_size > 0 {
            self.total_size.fetch_sub(removed_size, Ordering::Relaxed);
        }
        self.vary_index.remove(base_key);
    }

    /// Evict expired entries when cache exceeds max_entries.
    fn evict_if_needed(&self) {
        if self.cache.len() <= self.config.max_entries {
            return;
        }

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

        if self.cache.len() > self.config.max_entries {
            let mut entries: Vec<(String, Instant)> = self
                .cache
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().inserted_at))
                .collect();
            entries.sort_by_key(|(_, inserted_at)| *inserted_at);

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
        let path = &ctx.path;
        let mut removed_size = 0usize;

        self.cache.retain(|key, entry| {
            if key.starts_with(&prefix) && cache_key_path_matches(key, path) {
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

    fn add_cache_status_header(&self, headers: &mut HashMap<String, String>, value: &str) {
        if self.config.add_cache_status_header {
            headers.insert("x-cache-status".to_string(), value.to_string());
        }
    }

    fn shared_cache_allows_authorized_response(
        &self,
        ctx: &RequestContext,
        directives: CacheControlDirectives,
    ) -> bool {
        if self.config.cache_key_include_consumer || !ctx.headers.contains_key("authorization") {
            return true;
        }

        directives.public || directives.must_revalidate || directives.s_maxage.is_some()
    }
}

/// Check if a cache key's path segment matches the invalidation path.
///
/// Cache key format: `proxy_id:method:path:query:consumer[:vary...]`.
/// Returns true if the cached path equals `target_path` or starts with it
/// as a proper path prefix (followed by `/` or end of string).
fn cache_key_path_matches(cache_key: &str, target_path: &str) -> bool {
    let after_proxy_id = match cache_key.find(':') {
        Some(i) => &cache_key[i + 1..],
        None => return false,
    };
    let after_method = match after_proxy_id.find(':') {
        Some(i) => &after_proxy_id[i + 1..],
        None => return false,
    };
    let cached_path = match after_method.find(':') {
        Some(i) => &after_method[..i],
        None => after_method,
    };

    cached_path == target_path
        || (cached_path.starts_with(target_path)
            && cached_path.as_bytes().get(target_path.len()) == Some(&b'/'))
}

fn normalize_etag(tag: &str) -> &str {
    let tag = tag.trim();
    let tag = tag
        .strip_prefix("W/")
        .or_else(|| tag.strip_prefix("w/"))
        .unwrap_or(tag);
    tag.trim()
}

fn if_none_match_matches(if_none_match: &str, etag: &str) -> bool {
    if_none_match
        .split(',')
        .map(str::trim)
        .any(|candidate| candidate == "*" || normalize_etag(candidate) == normalize_etag(etag))
}

fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc2822(value)
        .ok()
        .map(|dt| dt.with_timezone(&Utc))
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
        headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if !self.is_cacheable_method(&ctx.method) {
            if self.config.invalidate_on_unsafe_methods {
                self.invalidate_path(ctx);
            }
            ctx.metadata
                .insert(CACHE_STATUS.to_string(), "BYPASS".to_string());
            return PluginResult::Continue;
        }

        let base_key = self.build_base_cache_key(ctx);
        ctx.metadata
            .insert(CACHE_BASE_KEY.to_string(), base_key.clone());

        if self.config.respect_no_cache
            && let Some(cc) = headers.get("cache-control")
        {
            let directives = parse_cache_control(cc);
            if directives.no_cache || directives.no_store {
                ctx.metadata
                    .insert(CACHE_STATUS.to_string(), "BYPASS".to_string());
                return PluginResult::Continue;
            }
        }

        // Fast-path: skip cache lookup if predicted uncacheable
        if !self.uncacheable_predictor.is_predicted_cacheable(&base_key) {
            ctx.metadata
                .insert(CACHE_STATUS.to_string(), "PREDICTED-BYPASS".to_string());
            return PluginResult::Continue;
        }

        let vary_headers = self.cache_lookup_vary_headers(&base_key);
        let cache_key = self.build_cache_key(ctx, &vary_headers, headers);

        if let Some(entry) = self.cache.get(&cache_key) {
            if entry.is_expired() {
                drop(entry);
                if let Some((_, removed)) = self.cache.remove(&cache_key) {
                    self.total_size
                        .fetch_sub(removed.approx_size(), Ordering::Relaxed);
                }
            } else {
                debug!(cache_key = %cache_key, "response_caching: cache HIT");

                if self.is_fresh_conditional_hit(headers, &entry) {
                    ctx.metadata
                        .insert(CACHE_STATUS.to_string(), "REVALIDATED".to_string());
                    return PluginResult::RejectBinary {
                        status_code: 304,
                        body: Bytes::new(),
                        headers: self.not_modified_headers(&entry),
                    };
                }

                let mut headers = entry.headers.clone();
                self.add_cache_status_header(&mut headers, "HIT");
                ctx.metadata
                    .insert(CACHE_STATUS.to_string(), "HIT".to_string());

                return PluginResult::RejectBinary {
                    status_code: entry.status_code,
                    body: entry.body.clone(),
                    headers,
                };
            }
        }

        ctx.metadata
            .insert(CACHE_STATUS.to_string(), "MISS".to_string());
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let status = ctx
            .metadata
            .get(CACHE_STATUS)
            .map(String::as_str)
            .unwrap_or("MISS");
        self.add_cache_status_header(response_headers, status);
        PluginResult::Continue
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        let base_key = match ctx.metadata.get(CACHE_BASE_KEY) {
            Some(base_key) => base_key.clone(),
            None => return PluginResult::Continue,
        };

        if !self
            .config
            .cacheable_status_codes
            .contains(&response_status)
        {
            self.uncacheable_predictor.mark_uncacheable(&base_key);
            return PluginResult::Continue;
        }

        let directives = if self.config.respect_cache_control {
            response_headers
                .get("cache-control")
                .map(|cc| parse_cache_control(cc))
                .unwrap_or_default()
        } else {
            CacheControlDirectives::default()
        };

        if directives.no_store || directives.private || directives.no_cache {
            self.invalidate_base_key(&base_key);
            self.uncacheable_predictor.mark_uncacheable(&base_key);
            return PluginResult::Continue;
        }

        // Never cache responses with Set-Cookie headers. These are
        // per-client and replaying them from a shared cache would leak
        // session cookies to other users (RFC 7234 §8).
        if response_headers.contains_key("set-cookie") {
            debug!("response_caching: skipping cache — response contains Set-Cookie header");
            self.uncacheable_predictor.mark_uncacheable(&base_key);
            return PluginResult::Continue;
        }

        if !self.shared_cache_allows_authorized_response(ctx, directives) {
            self.uncacheable_predictor.mark_uncacheable(&base_key);
            return PluginResult::Continue;
        }

        let ttl = if let Some(s_maxage) = directives.s_maxage {
            Duration::from_secs(s_maxage)
        } else if let Some(max_age) = directives.max_age {
            Duration::from_secs(max_age)
        } else {
            Duration::from_secs(self.config.ttl_seconds)
        };

        if ttl.is_zero() {
            self.invalidate_base_key(&base_key);
            self.uncacheable_predictor.mark_uncacheable(&base_key);
            return PluginResult::Continue;
        }

        let vary_headers = match self.merged_vary_headers(response_headers) {
            Some(vary_headers) => vary_headers,
            None => {
                self.invalidate_base_key(&base_key);
                self.uncacheable_predictor.mark_uncacheable(&base_key);
                return PluginResult::Continue;
            }
        };
        let cache_key = self.build_cache_key(ctx, &vary_headers, &ctx.headers);

        if body.len() > self.config.max_entry_size_bytes {
            debug!(
                cache_key = %cache_key,
                body_size = body.len(),
                max_size = self.config.max_entry_size_bytes,
                "response_caching: response body exceeds max_entry_size_bytes, skipping cache"
            );
            return PluginResult::Continue;
        }

        let entry = CacheEntry {
            status_code: response_status,
            headers: response_headers.clone(),
            body: Bytes::copy_from_slice(body),
            inserted_at: Instant::now(),
            ttl,
        };
        let entry_size = entry.approx_size();

        let current_total = self.total_size.load(Ordering::Relaxed);
        if current_total.saturating_add(entry_size) > self.config.max_total_size_bytes {
            debug!(
                cache_key = %cache_key,
                current_total = current_total,
                entry_size = entry_size,
                max_total = self.config.max_total_size_bytes,
                "response_caching: total cache size would exceed limit, skipping cache"
            );
            return PluginResult::Continue;
        }

        if let Some(old) = self.cache.insert(cache_key.clone(), entry) {
            self.total_size
                .fetch_sub(old.approx_size(), Ordering::Relaxed);
        }
        self.total_size.fetch_add(entry_size, Ordering::Relaxed);
        // Response was cacheable — remove from predictor if previously marked uncacheable
        self.uncacheable_predictor.mark_cacheable(&base_key);
        self.vary_index.insert(base_key, vary_headers);

        debug!(
            cache_key = %cache_key,
            entry_size = entry_size,
            ttl_secs = ttl.as_secs(),
            "response_caching: cached response"
        );

        self.evict_if_needed();
        PluginResult::Continue
    }
}
