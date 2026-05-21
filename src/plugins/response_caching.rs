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
use http::{HeaderName, Method};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
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
const CACHE_PREDICT_KEY: &str = "cache_predict_key";
/// JSON-serialized snapshot of the request header values `before_proxy` saw
/// while building the cache key. `on_final_response_body` reads it back to
/// build the storage cache key from the *same* header view, even when an
/// earlier plugin's `transform_request_headers` mutated the outbound
/// headers map — see [`ResponseCaching::stash_request_headers_snapshot`]
/// and the bug it fixes.
const CACHE_REQUEST_HEADERS_SNAPSHOT: &str = "cache_request_headers_snapshot";

fn sha256_hex(value: &str) -> String {
    hex::encode(Sha256::digest(value.as_bytes()))
}

fn cache_key_host_part(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    if host.is_empty() {
        String::new()
    } else {
        let digest = sha256_hex(&host);
        let mut part = String::with_capacity(2 + digest.len());
        part.push_str("h-");
        part.push_str(&digest);
        part
    }
}

fn is_sensitive_vary_header(header: &str) -> bool {
    header.eq_ignore_ascii_case("authorization")
        || header.eq_ignore_ascii_case("proxy-authorization")
        || header.eq_ignore_ascii_case("cookie")
}

fn cache_key_vary_value(header: &str, value: &str) -> String {
    if is_sensitive_vary_header(header) {
        let digest = sha256_hex(value);
        let mut hashed = String::with_capacity(7 + digest.len());
        hashed.push_str("sha256-");
        hashed.push_str(&digest);
        hashed
    } else {
        value.to_string()
    }
}

/// Cache keys use `:` as a structural delimiter, but URL paths legitimately
/// contain `:` (e.g. `/users:1/details`, matrix params, FHIR `$everything`).
/// Encode path bytes into a cache-key-safe representation before joining so
/// path/query boundaries can be recovered unambiguously and invalidation
/// matches the full path rather than truncating at the first `:`.
///
/// The encoding must be bijective for raw URI paths. In particular, `%` must
/// be escaped before `:` so `/users:1/details` and `/users%3A1/details` remain
/// distinct cache keys.
fn encode_path_for_cache_key(path: &str) -> Cow<'_, str> {
    if !path.as_bytes().iter().any(|b| matches!(b, b'%' | b':')) {
        return Cow::Borrowed(path);
    }

    let mut encoded = String::with_capacity(path.len());
    for byte in path.bytes() {
        match byte {
            b'%' => encoded.push_str("%25"),
            b':' => encoded.push_str("%3A"),
            _ => encoded.push(char::from(byte)),
        }
    }
    Cow::Owned(encoded)
}

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
        let part = part.trim();
        if part.eq_ignore_ascii_case("no-store") {
            directives.no_store = true;
        } else if part.eq_ignore_ascii_case("no-cache") {
            directives.no_cache = true;
        } else if part.eq_ignore_ascii_case("private") {
            directives.private = true;
        } else if part.eq_ignore_ascii_case("public") {
            directives.public = true;
        } else if part.eq_ignore_ascii_case("must-revalidate") {
            directives.must_revalidate = true;
        } else if let Some(val) = strip_prefix_ascii_case(part, "s-maxage=") {
            directives.s_maxage = val.trim().parse().ok();
        } else if let Some(val) = strip_prefix_ascii_case(part, "max-age=") {
            directives.max_age = val.trim().parse().ok();
        }
    }

    directives
}

fn strip_prefix_ascii_case<'a>(value: &'a str, prefix: &str) -> Option<&'a str> {
    let head = value.get(..prefix.len())?;
    head.eq_ignore_ascii_case(prefix)
        .then_some(&value[prefix.len()..])
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
    fn from_json(config: &Value) -> Result<Self, String> {
        if !config.is_object() {
            return Err("response_caching: config must be an object".to_string());
        }

        let cacheable_methods = parse_method_list(config, "cacheable_methods")?
            .unwrap_or_else(|| vec!["GET".to_string(), "HEAD".to_string()]);
        let cacheable_status_codes = parse_status_code_list(config, "cacheable_status_codes")?
            .unwrap_or_else(|| vec![200, 301, 404]);
        let vary_by_headers = parse_header_list(config, "vary_by_headers")?.unwrap_or_default();

        Ok(Self {
            ttl_seconds: optional_u64(config, "ttl_seconds")?.unwrap_or(DEFAULT_TTL_SECONDS),
            max_entries: optional_positive_usize(config, "max_entries")?
                .unwrap_or(DEFAULT_MAX_ENTRIES),
            max_entry_size_bytes: optional_positive_usize(config, "max_entry_size_bytes")?
                .unwrap_or(DEFAULT_MAX_ENTRY_SIZE_BYTES),
            max_total_size_bytes: optional_positive_usize(config, "max_total_size_bytes")?
                .unwrap_or(DEFAULT_MAX_TOTAL_SIZE_BYTES),
            cacheable_methods,
            cacheable_status_codes,
            respect_cache_control: optional_bool(config, "respect_cache_control")?.unwrap_or(true),
            respect_no_cache: optional_bool(config, "respect_no_cache")?.unwrap_or(true),
            vary_by_headers,
            cache_key_include_query: optional_bool(config, "cache_key_include_query")?
                .unwrap_or(true),
            cache_key_include_consumer: optional_bool(config, "cache_key_include_consumer")?
                .unwrap_or(false),
            add_cache_status_header: optional_bool(config, "add_cache_status_header")?
                .unwrap_or(true),
            invalidate_on_unsafe_methods: optional_bool(config, "invalidate_on_unsafe_methods")?
                .unwrap_or(true),
        })
    }
}

fn optional_bool(config: &Value, field: &'static str) -> Result<Option<bool>, String> {
    match config.get(field) {
        Some(Value::Bool(value)) => Ok(Some(*value)),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!("response_caching: '{field}' must be a boolean")),
    }
}

fn optional_u64(config: &Value, field: &'static str) -> Result<Option<u64>, String> {
    match config.get(field) {
        Some(Value::Number(value)) => value
            .as_u64()
            .ok_or_else(|| format!("response_caching: '{field}' must be an unsigned integer"))
            .map(Some),
        Some(Value::Null) | None => Ok(None),
        Some(_) => Err(format!(
            "response_caching: '{field}' must be an unsigned integer"
        )),
    }
}

fn optional_positive_usize(config: &Value, field: &'static str) -> Result<Option<usize>, String> {
    let Some(value) = optional_u64(config, field)? else {
        return Ok(None);
    };
    let value =
        usize::try_from(value).map_err(|_| format!("response_caching: '{field}' is too large"))?;
    if value == 0 {
        return Err(format!(
            "response_caching: '{field}' must be greater than zero"
        ));
    }
    Ok(Some(value))
}

fn parse_method_list(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("response_caching: '{field}' must be an array"));
    };
    if values.is_empty() {
        return Err(format!("response_caching: '{field}' must not be empty"));
    }

    let mut methods = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(method) = value.as_str() else {
            return Err(format!(
                "response_caching: '{field}[{index}]' must be a string"
            ));
        };
        if method.is_empty() {
            return Err(format!(
                "response_caching: '{field}[{index}]' must not be empty"
            ));
        }
        Method::from_bytes(method.as_bytes()).map_err(|_| {
            format!("response_caching: '{field}[{index}]' is not a valid HTTP method")
        })?;
        methods.push(method.to_ascii_uppercase());
    }
    Ok(Some(methods))
}

fn parse_status_code_list(config: &Value, field: &'static str) -> Result<Option<Vec<u16>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("response_caching: '{field}' must be an array"));
    };
    if values.is_empty() {
        return Err(format!("response_caching: '{field}' must not be empty"));
    }

    let mut status_codes = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(code) = value.as_u64() else {
            return Err(format!(
                "response_caching: '{field}[{index}]' must be an unsigned integer"
            ));
        };
        if !(100..=599).contains(&code) {
            return Err(format!(
                "response_caching: '{field}[{index}]' must be an HTTP status code"
            ));
        }
        status_codes.push(code as u16);
    }
    Ok(Some(status_codes))
}

fn parse_header_list(config: &Value, field: &'static str) -> Result<Option<Vec<String>>, String> {
    let Some(value) = config.get(field) else {
        return Ok(None);
    };
    let Some(values) = value.as_array() else {
        return Err(format!("response_caching: '{field}' must be an array"));
    };

    let mut headers = Vec::with_capacity(values.len());
    for (index, value) in values.iter().enumerate() {
        let Some(header) = value.as_str() else {
            return Err(format!(
                "response_caching: '{field}[{index}]' must be a string"
            ));
        };
        if header.is_empty() {
            return Err(format!(
                "response_caching: '{field}[{index}]' must not be empty"
            ));
        }
        let header_name = HeaderName::from_bytes(header.as_bytes()).map_err(|_| {
            format!("response_caching: '{field}[{index}]' is not a valid HTTP header name")
        })?;
        headers.push(header_name.to_string());
    }
    Ok(Some(headers))
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
        let config = ResponseCachingConfig::from_json(config)?;

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

    /// Build the base cache key (proxy_id + Host + method + path + query + consumer).
    ///
    /// `request_headers` is supplied separately because in `before_proxy` the
    /// gateway may have temporarily moved `ctx.headers` out of the context to
    /// satisfy the borrow checker (zero-allocation hot path when no plugin
    /// modifies headers). Always pass the same `headers` map you got from the
    /// `before_proxy(ctx, headers)` parameter, or `&ctx.headers` from
    /// post-proxy phases where the headers have been restored.
    fn build_base_cache_key(
        &self,
        ctx: &RequestContext,
        request_headers: &HashMap<String, String>,
    ) -> String {
        let proxy_id = ctx
            .matched_proxy
            .as_ref()
            .map(|p| p.id.as_str())
            .unwrap_or("_");

        // Include the request `Host` header in the base key so multi-host
        // proxies (e.g. `hosts: ["a.example.com", "b.example.com"]`) don't
        // collide. Hash the ASCII-lowercased host before putting it into the
        // colon-delimited key so host:port and bracketed IPv6 literals cannot
        // be mistaken for structural delimiters during invalidation.
        let host_part: String = request_headers
            .get("host")
            .map(|h| cache_key_host_part(h))
            .unwrap_or_default();

        let mut query_part = String::new();
        if self.config.cache_key_include_query && !ctx.query_params.is_empty() {
            let mut params: Vec<(&String, &String)> = ctx.query_params.iter().collect();
            params.sort_by_key(|(k, _)| k.as_str());
            for (index, (key, value)) in params.iter().enumerate() {
                if index > 0 {
                    query_part.push('&');
                }
                // Encode as length-prefixed fields to avoid delimiter
                // ambiguity after query percent-decoding.
                query_part.push_str(&key.len().to_string());
                query_part.push(':');
                query_part.push_str(key);
                query_part.push('=');
                query_part.push_str(&value.len().to_string());
                query_part.push(':');
                query_part.push_str(value);
            }
        }

        let consumer_part = if self.config.cache_key_include_consumer {
            ctx.effective_identity().unwrap_or("_anon")
        } else {
            ""
        };

        let encoded_path = encode_path_for_cache_key(&ctx.path);
        let mut key = String::with_capacity(
            proxy_id.len()
                + host_part.len()
                + ctx.method.len()
                + encoded_path.len()
                + query_part.len()
                + consumer_part.len()
                + 5,
        );
        key.push_str(proxy_id);
        key.push(':');
        key.push_str(&host_part);
        key.push(':');
        key.push_str(&ctx.method);
        key.push(':');
        key.push_str(&encoded_path);
        key.push(':');
        key.push_str(&query_part);
        key.push(':');
        key.push_str(consumer_part);
        key
    }

    fn build_cache_key(
        &self,
        ctx: &RequestContext,
        vary_headers: &[String],
        request_headers: &HashMap<String, String>,
    ) -> String {
        let base_key = self.build_base_cache_key(ctx, request_headers);
        if vary_headers.is_empty() {
            return base_key;
        }

        let mut cache_key = base_key;
        cache_key.push(':');
        for (index, header) in vary_headers.iter().enumerate() {
            if index > 0 {
                cache_key.push('|');
            }
            let value = request_headers
                .get(header.as_str())
                .map(String::as_str)
                .unwrap_or("");
            let value = cache_key_vary_value(header, value);
            cache_key.push_str(header);
            cache_key.push('=');
            cache_key.push_str(&value);
        }

        cache_key
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
                let header = header.trim().to_ascii_lowercase();
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
        let mut variant_prefix = String::with_capacity(base_key.len() + 1);
        variant_prefix.push_str(base_key);
        variant_prefix.push(':');
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
        let mut prefix = String::with_capacity(proxy_id.len() + 1);
        prefix.push_str(proxy_id);
        prefix.push(':');
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
        if self.config.cache_key_include_consumer {
            return true;
        }

        if ctx.effective_identity().is_none() {
            return true;
        }

        directives.public || directives.must_revalidate || directives.s_maxage.is_some()
    }

    /// Stash the transformed-header values `before_proxy` saw for every
    /// key that can land in the cache key — `host`, `authorization`, and
    /// each configured `vary_by_headers` entry. `on_final_response_body`
    /// reads it back via [`Self::restore_request_headers_view`] so the
    /// storage cache key is derived from the same header view as the
    /// lookup. Without this, a request-side transformer that touches a
    /// vary header (e.g. injecting `X-Tenant` from a consumer property)
    /// would make the storage key disagree with the lookup key and the
    /// cache would never hit.
    ///
    /// Snapshot is intentionally narrow: only headers we know we will
    /// consume go into it. Headers that show up later via the response
    /// `Vary` directive — which can be any header at all — fall through
    /// to `ctx.headers` at storage time. That's the same value we'd have
    /// had to read at lookup time anyway, so the lookup/storage symmetry
    /// is still preserved for them.
    fn stash_request_headers_snapshot(
        &self,
        ctx: &mut RequestContext,
        headers: &HashMap<String, String>,
    ) {
        let mut snapshot: Vec<(String, String)> =
            Vec::with_capacity(self.config.vary_by_headers.len() + 2);
        let mut push_if_present = |key: &str| {
            if let Some(value) = headers.get(key) {
                snapshot.push((key.to_string(), value.clone()));
            }
        };
        push_if_present("host");
        push_if_present("authorization");
        for header in &self.config.vary_by_headers {
            // Skip duplicates that match the always-stashed pair above.
            if header == "host" || header == "authorization" {
                continue;
            }
            push_if_present(header);
        }
        if snapshot.is_empty() {
            // Nothing to remember — the cache key only contains route
            // metadata, which we can rebuild from `ctx` alone.
            return;
        }
        if let Ok(serialized) = serde_json::to_string(&snapshot) {
            ctx.metadata
                .insert(CACHE_REQUEST_HEADERS_SNAPSHOT.to_string(), serialized);
        }
    }

    /// Rebuild the request-headers view used to derive the storage cache
    /// key. Layers `before_proxy`'s snapshot on top of `ctx.headers` so
    /// snapshotted keys reflect the transformed values seen at lookup
    /// time while any other key (typically a header added by the
    /// response's own `Vary` directive) falls back to the original.
    fn restore_request_headers_view(&self, ctx: &RequestContext) -> HashMap<String, String> {
        let mut view = ctx.headers.clone();
        if let Some(serialized) = ctx.metadata.get(CACHE_REQUEST_HEADERS_SNAPSHOT)
            && let Ok(snapshot) = serde_json::from_str::<Vec<(String, String)>>(serialized)
        {
            for (key, value) in snapshot {
                view.insert(key, value);
            }
        }
        view
    }
}

/// Check if a cache key's path segment matches the invalidation path.
///
/// Cache key format: `proxy_id:host_hash:method:path:query:consumer[:vary...]`.
/// The `path` segment has any `:` percent-encoded (see
/// [`encode_path_for_cache_key`]) so it cannot be confused with a structural
/// delimiter. Returns true if the cached path equals the encoded `target_path`
/// or starts with it as a proper path prefix (followed by `/`).
fn cache_key_path_matches(cache_key: &str, target_path: &str) -> bool {
    let after_proxy_id = match cache_key.find(':') {
        Some(i) => &cache_key[i + 1..],
        None => return false,
    };
    let after_host = match after_proxy_id.find(':') {
        Some(i) => &after_proxy_id[i + 1..],
        None => return false,
    };
    let after_method = match after_host.find(':') {
        Some(i) => &after_host[i + 1..],
        None => return false,
    };
    let cached_path = match after_method.find(':') {
        Some(i) => &after_method[..i],
        None => after_method,
    };

    let encoded_target = encode_path_for_cache_key(target_path);
    let encoded_target = encoded_target.as_ref();
    cached_path == encoded_target
        || (cached_path.starts_with(encoded_target)
            && cached_path.as_bytes().get(encoded_target.len()) == Some(&b'/'))
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

    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        // Skip body buffering for SSE requests (`Accept: text/event-stream`).
        // Buffering an unbounded event stream would collect frames until the
        // configured `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` ceiling is hit and
        // then 502, instead of streaming events to the client. SSE responses
        // are not cacheable anyway — `before_proxy` will see no cache hit and
        // `on_final_response_body` will not be invoked, so the cache state
        // stays correct without any other code paths needing to special-case
        // SSE.
        !super::utils::sse::is_sse_request(ctx)
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

        if super::utils::sse::headers_accept_sse(headers) {
            ctx.metadata
                .insert(CACHE_STATUS.to_string(), "BYPASS".to_string());
            return PluginResult::Continue;
        }

        // Use the `headers` parameter (not `ctx.headers`) — the gateway hot
        // path may have temporarily moved `ctx.headers` out of the context
        // before invoking `before_proxy` (zero-alloc when no plugin modifies
        // headers). The `headers` parameter is the single source of truth
        // during this phase.
        let base_key = self.build_base_cache_key(ctx, headers);
        ctx.metadata
            .insert(CACHE_BASE_KEY.to_string(), base_key.clone());
        // Snapshot every header value that could end up in the cache key
        // so `on_final_response_body` can rebuild the same key from
        // metadata. The transformed `headers` view is only available
        // during `before_proxy`; by storage time `on_final_response_body`
        // has only `ctx.headers` (the original, untransformed map). Without
        // this snapshot a request-side transformer that touches a
        // configured `vary_by_headers` value, or rewrites `Host`, would
        // make the lookup and storage keys disagree and cache every hit
        // would miss.
        self.stash_request_headers_snapshot(ctx, headers);

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

        let vary_headers = self.cache_lookup_vary_headers(&base_key);
        let cache_key = self.build_cache_key(ctx, &vary_headers, headers);
        // Store the full cache key (with Vary dimensions) so on_final_response_body
        // can mark the correct variant-specific key in the uncacheable predictor.
        ctx.metadata
            .insert(CACHE_PREDICT_KEY.to_string(), cache_key.clone());

        // Fast-path: skip cache lookup if this specific variant is predicted uncacheable.
        // Uses the full cache_key (including Vary dimensions) so that one uncacheable
        // variant does not suppress lookups for other variants of the same route.
        if !self
            .uncacheable_predictor
            .is_predicted_cacheable(&cache_key)
        {
            ctx.metadata
                .insert(CACHE_STATUS.to_string(), "PREDICTED-BYPASS".to_string());
            return PluginResult::Continue;
        }

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
        // Use the variant-specific predict key (set during before_proxy) for
        // predictor marking so that uncacheability of one Vary variant does not
        // suppress cache lookups for other variants of the same route.
        let predict_key = ctx
            .metadata
            .get(CACHE_PREDICT_KEY)
            .cloned()
            .unwrap_or_else(|| base_key.clone());

        if !self
            .config
            .cacheable_status_codes
            .contains(&response_status)
        {
            self.uncacheable_predictor.mark_uncacheable(&predict_key);
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
            self.uncacheable_predictor.mark_uncacheable(&predict_key);
            return PluginResult::Continue;
        }

        // Never cache responses with Set-Cookie headers. These are
        // per-client and replaying them from a shared cache would leak
        // session cookies to other users (RFC 7234 §8).
        if response_headers.contains_key("set-cookie") {
            debug!("response_caching: skipping cache — response contains Set-Cookie header");
            self.uncacheable_predictor.mark_uncacheable(&predict_key);
            return PluginResult::Continue;
        }

        // Restore the same header view `before_proxy` used so the
        // shared-cache authorization check and the storage cache key
        // both see the transformed values, not the untransformed
        // `ctx.headers`. See `restore_request_headers_view` for why.
        let lookup_headers = self.restore_request_headers_view(ctx);

        if !self.shared_cache_allows_authorized_response(ctx, directives) {
            self.uncacheable_predictor.mark_uncacheable(&predict_key);
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
            self.uncacheable_predictor.mark_uncacheable(&predict_key);
            return PluginResult::Continue;
        }

        let mut vary_headers = match self.merged_vary_headers(response_headers) {
            Some(vary_headers) => vary_headers,
            None => {
                self.invalidate_base_key(&base_key);
                self.uncacheable_predictor.mark_uncacheable(&predict_key);
                return PluginResult::Continue;
            }
        };

        // Per RFC 7234 §3.2, a shared cache MUST NOT serve a cached response
        // to a request other than the one that produced it when the original
        // request carried an `Authorization` header — unless the response
        // explicitly opted-in via `Cache-Control: public` / `must-revalidate`
        // / `s-maxage`. `shared_cache_allows_authorized_response` already
        // gates that decision above. Once we've decided to cache, we MUST
        // also key the cache entry by the Authorization value so two users
        // presenting different bearer tokens land on different cache entries.
        //
        // Auto-merge `authorization` into the Vary list whenever the request
        // had an Authorization header. Operators don't need to remember to
        // configure `cache_key_include_consumer: true` or list `authorization`
        // in `vary_by_headers` — the safe default is to never share cached
        // authorized responses across distinct credentials. The merged list
        // is sorted and re-stored in `vary_index` so the same dimension
        // applies to every subsequent lookup at this base key.
        //
        // `lookup_headers` was built above from
        // `restore_request_headers_view`: it layers `before_proxy`'s header
        // snapshot on top of `ctx.headers`, so configured `vary_by_headers`
        // / `host` / `authorization` reflect the transformed values that
        // were live during lookup. Response-added Vary headers fall back to
        // `ctx.headers`, the same source any future lookup would use for
        // them, so the lookup/storage symmetry holds for those too.
        let storage_auth_present = lookup_headers.contains_key("authorization");
        if storage_auth_present && !vary_headers.iter().any(|h| h == "authorization") {
            vary_headers.push("authorization".to_string());
            vary_headers.sort();
        }

        let cache_key = self.build_cache_key(ctx, &vary_headers, &lookup_headers);

        if body.len() > self.config.max_entry_size_bytes {
            debug!(
                cache_key = %cache_key,
                body_size = body.len(),
                max_size = self.config.max_entry_size_bytes,
                "response_caching: response body exceeds max_entry_size_bytes, skipping cache"
            );
            return PluginResult::Continue;
        }

        // Mirror the keyed Vary list onto the cached response's `Vary` header
        // so downstream caches and clients observe the same dimension we keyed
        // by. In particular this surfaces the auto-merged `authorization`
        // entry so any intermediate shared cache will also key by it (or
        // refuse to cache, if it doesn't honor Vary).
        let mut cached_response_headers = response_headers.clone();
        if !vary_headers.is_empty() {
            let merged_vary = vary_headers.join(", ");
            cached_response_headers.insert("vary".to_string(), merged_vary);
        }

        let entry = CacheEntry {
            status_code: response_status,
            headers: cached_response_headers,
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
        self.uncacheable_predictor.mark_cacheable(&predict_key);
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

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn plugin_with_config(config: serde_json::Value) -> ResponseCaching {
        match ResponseCaching::new(&config) {
            Ok(plugin) => plugin,
            Err(error) => panic!("response_caching config should be valid: {error}"),
        }
    }

    fn make_ctx(method: &str, path: &str) -> RequestContext {
        RequestContext::new(
            "127.0.0.1".to_string(),
            method.to_string(),
            path.to_string(),
        )
    }

    #[tokio::test]
    async fn sensitive_vary_values_are_hashed_in_predict_and_storage_keys() {
        let plugin = plugin_with_config(json!({
            "ttl_seconds": 60,
            "vary_by_headers": ["authorization"]
        }));
        let bearer = "Bearer reviewer-secret-token";

        let mut ctx = make_ctx("GET", "/api/public-auth");
        ctx.headers
            .insert("authorization".to_string(), bearer.to_string());
        let mut request_headers = ctx.headers.clone();

        let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
        assert!(matches!(result, PluginResult::Continue));

        let Some(predict_key) = ctx.metadata.get(CACHE_PREDICT_KEY) else {
            panic!("before_proxy should store variant predict key");
        };
        assert!(!predict_key.contains(bearer));
        assert!(!predict_key.contains("reviewer-secret-token"));
        assert!(predict_key.contains("authorization=sha256-"));

        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"authorized-body")
            .await;

        let cache_keys: Vec<String> = plugin
            .cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        assert_eq!(cache_keys.len(), 1);
        let stored_key = &cache_keys[0];
        assert!(!stored_key.contains(bearer));
        assert!(!stored_key.contains("reviewer-secret-token"));
        assert!(stored_key.contains("authorization=sha256-"));
    }

    #[test]
    fn encode_path_for_cache_key_passes_through_paths_without_colons() {
        let plain = encode_path_for_cache_key("/users/42/details");
        assert!(matches!(plain, Cow::Borrowed(_)));
        assert_eq!(plain.as_ref(), "/users/42/details");
    }

    #[test]
    fn encode_path_for_cache_key_percent_encodes_colons() {
        let encoded = encode_path_for_cache_key("/users:1/details");
        assert_eq!(encoded.as_ref(), "/users%3A1/details");
    }

    #[test]
    fn encode_path_for_cache_key_percent_encodes_literal_percent() {
        let encoded = encode_path_for_cache_key("/users%3A1/details");
        assert_eq!(encoded.as_ref(), "/users%253A1/details");
    }

    #[test]
    fn encode_path_for_cache_key_is_bijective_for_colon_and_percent_forms() {
        let colon = encode_path_for_cache_key("/users:1/details");
        let pct = encode_path_for_cache_key("/users%3A1/details");
        assert_ne!(colon.as_ref(), pct.as_ref());
    }

    #[test]
    fn cache_key_path_matches_handles_paths_containing_colons() {
        // Build cache_key the same way build_base_cache_key does, with the
        // path segment percent-encoded. The matcher must accept the same
        // unencoded path as the invalidation target.
        let cache_key = format!(
            "proxy:host:GET:{}:q=1:_anon",
            encode_path_for_cache_key("/users:1/details")
        );
        assert!(cache_key_path_matches(&cache_key, "/users:1/details"));
    }

    #[test]
    fn cache_key_path_matches_unrelated_short_path_does_not_match_longer_colon_path() {
        // `/users` must NOT match a cached entry for `/users:1/details` —
        // the old colon-truncating matcher returned `/users` as the cached
        // path and wrongly matched on equality.
        let cache_key = format!(
            "proxy:host:GET:{}:q=1:_anon",
            encode_path_for_cache_key("/users:1/details")
        );
        assert!(!cache_key_path_matches(&cache_key, "/users"));
    }

    #[test]
    fn cache_key_path_matches_targeted_colon_path_does_not_match_unrelated_short_cache() {
        // Conversely, `/users:1/details` must NOT invalidate a cached
        // entry for `/users` (no false-positive prefix expansion through
        // the colon).
        let cache_key = "proxy:host:GET:/users:q=1:_anon".to_string();
        assert!(!cache_key_path_matches(&cache_key, "/users:1/details"));
    }

    #[test]
    fn cache_key_path_matches_proper_path_prefix_with_trailing_slash_still_works() {
        let cache_key = "proxy:host:GET:/api/items/42:q=1:_anon".to_string();
        assert!(cache_key_path_matches(&cache_key, "/api/items"));
    }

    #[tokio::test]
    async fn unsafe_method_invalidates_cached_path_containing_colon() {
        let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

        let mut get_ctx = make_ctx("GET", "/users:1/details");
        get_ctx
            .headers
            .insert("host".to_string(), "example.com".to_string());
        let mut get_headers = get_ctx.headers.clone();
        plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
        plugin
            .on_final_response_body(&mut get_ctx, 200, &HashMap::new(), b"body")
            .await;
        assert_eq!(plugin.cache.len(), 1);

        let mut post_ctx = make_ctx("POST", "/users:1/details");
        post_ctx
            .headers
            .insert("host".to_string(), "example.com".to_string());
        let mut post_headers = post_ctx.headers.clone();
        plugin.before_proxy(&mut post_ctx, &mut post_headers).await;

        assert!(
            plugin.cache.is_empty(),
            "unsafe method on same colon-containing path should invalidate the cached entry"
        );
    }

    #[tokio::test]
    async fn unsafe_method_does_not_invalidate_unrelated_path_with_colon_prefix_clash() {
        // GET /users:1/details cached.
        // POST /users (unrelated) must NOT invalidate it.
        let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

        let mut get_ctx = make_ctx("GET", "/users:1/details");
        get_ctx
            .headers
            .insert("host".to_string(), "example.com".to_string());
        let mut get_headers = get_ctx.headers.clone();
        plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
        plugin
            .on_final_response_body(&mut get_ctx, 200, &HashMap::new(), b"body")
            .await;
        assert_eq!(plugin.cache.len(), 1);

        let mut post_ctx = make_ctx("POST", "/users");
        post_ctx
            .headers
            .insert("host".to_string(), "example.com".to_string());
        let mut post_headers = post_ctx.headers.clone();
        plugin.before_proxy(&mut post_ctx, &mut post_headers).await;

        assert_eq!(
            plugin.cache.len(),
            1,
            "unsafe method on unrelated /users must NOT invalidate /users:1/details"
        );
    }

    #[tokio::test]
    async fn cache_key_uses_transformed_headers_when_vary_header_modified_by_earlier_plugin() {
        // Regression test: when an earlier `before_proxy` plugin
        // (request_transformer-style) injects or rewrites a vary header,
        // the storage and lookup cache keys must agree on the
        // transformed value. Otherwise the cache stores under one key
        // and the next identical request looks up under another — every
        // request misses and entries pile up.
        let plugin = plugin_with_config(json!({
            "ttl_seconds": 60,
            "vary_by_headers": ["x-tenant"]
        }));

        let mut ctx = make_ctx("GET", "/api/items");
        ctx.headers
            .insert("host".to_string(), "example.com".to_string());
        // ctx.headers does NOT carry x-tenant — the originating request
        // doesn't have it.
        let mut transformed_headers = ctx.headers.clone();
        // Simulate a request_transformer injecting the vary header.
        transformed_headers.insert("x-tenant".to_string(), "acme".to_string());

        let result = plugin
            .before_proxy(&mut ctx, &mut transformed_headers)
            .await;
        assert!(matches!(result, PluginResult::Continue));

        let predict_key = ctx
            .metadata
            .get(CACHE_PREDICT_KEY)
            .expect("predict_key stored")
            .clone();
        assert!(
            predict_key.contains("x-tenant=acme"),
            "lookup key must carry the transformer-injected tenant: {predict_key}"
        );

        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"tenant-acme")
            .await;

        let cache_keys: Vec<String> = plugin.cache.iter().map(|e| e.key().clone()).collect();
        assert_eq!(cache_keys.len(), 1);
        assert!(
            cache_keys[0].contains("x-tenant=acme"),
            "storage key must carry the transformer-injected tenant — \
             otherwise the next identical request will miss: {}",
            cache_keys[0]
        );
        assert_eq!(
            predict_key, cache_keys[0],
            "lookup and storage keys must be identical when no Vary \
             header is added by the response"
        );
    }

    #[tokio::test]
    async fn cache_key_uses_transformed_host_header_when_rewritten_by_earlier_plugin() {
        // Equivalent regression for the `Host` rewrite case. The base
        // cache key hashes the Host value; if the lookup uses the
        // transformed Host and storage uses the original, the cache
        // permanently misses across requests that share the same path.
        let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

        let mut ctx = make_ctx("GET", "/api/items");
        ctx.headers
            .insert("host".to_string(), "client.example.com".to_string());
        let mut transformed_headers = ctx.headers.clone();
        transformed_headers.insert("host".to_string(), "backend.internal".to_string());

        let result = plugin
            .before_proxy(&mut ctx, &mut transformed_headers)
            .await;
        assert!(matches!(result, PluginResult::Continue));
        let predict_key = ctx
            .metadata
            .get(CACHE_PREDICT_KEY)
            .expect("predict_key stored")
            .clone();

        plugin
            .on_final_response_body(&mut ctx, 200, &HashMap::new(), b"host-acme")
            .await;

        let cache_keys: Vec<String> = plugin.cache.iter().map(|e| e.key().clone()).collect();
        assert_eq!(cache_keys.len(), 1);
        assert_eq!(
            predict_key, cache_keys[0],
            "lookup and storage cache keys must be identical when Host \
             is rewritten by an earlier before_proxy plugin"
        );
    }

    #[tokio::test]
    async fn unsafe_method_invalidates_cached_hosts_with_ports_and_ipv6_literals() {
        for host in ["Example.com:8443", "[::1]:8443"] {
            let plugin = plugin_with_config(json!({"ttl_seconds": 60}));

            let mut get_ctx = make_ctx("GET", "/api/items");
            get_ctx.headers.insert("host".to_string(), host.to_string());
            let mut get_headers = get_ctx.headers.clone();
            plugin.before_proxy(&mut get_ctx, &mut get_headers).await;
            plugin
                .on_final_response_body(&mut get_ctx, 200, &HashMap::new(), b"cached-items")
                .await;

            let cache_keys: Vec<String> = plugin
                .cache
                .iter()
                .map(|entry| entry.key().clone())
                .collect();
            assert_eq!(cache_keys.len(), 1);
            assert!(!cache_keys[0].contains(host));

            let mut post_ctx = make_ctx("POST", "/api/items");
            post_ctx
                .headers
                .insert("host".to_string(), host.to_string());
            let mut post_headers = post_ctx.headers.clone();
            plugin.before_proxy(&mut post_ctx, &mut post_headers).await;

            assert!(
                plugin.cache.is_empty(),
                "unsafe method should invalidate cached key for host {host}"
            );
        }
    }
}
