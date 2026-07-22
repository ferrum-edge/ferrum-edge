//! Response Caching Plugin
//!
//! Caches backend responses in-memory for cacheable endpoints, reducing
//! backend load for repeated identical requests. Supports Cache-Control,
//! ETag/Last-Modified revalidation, backend `Vary` awareness, binary bodies,
//! configurable TTL, entry size limits, and automatic eviction.

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, NaiveDateTime, Utc};
use dashmap::DashMap;
use http::{HeaderName, Method};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::borrow::Cow;
use std::collections::{HashMap, HashSet};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, LazyLock, Mutex, MutexGuard};
use std::time::{Duration, Instant};
use tracing::debug;

use crate::util::unknown_keys::reject_unknown_keys;

use super::{Plugin, PluginResult, RequestContext};

/// Authoritative closed set of top-level `response_caching` configuration keys.
///
/// Constructor admission, OpenAPI `ResponseCachingConfig`, and operator docs must
/// stay in lockstep with this list. Unknown root properties fail closed so a
/// misspelled Vary, consumer, query, Cache-Control, status/method, capacity, or
/// invalidation field cannot silently fall back to a weaker default partition
/// or retention policy.
pub const RESPONSE_CACHING_CONFIG_KEYS: &[&str] = &[
    "add_cache_status_header",
    "cache_key_include_consumer",
    "cache_key_include_query",
    "cacheable_methods",
    "cacheable_status_codes",
    "invalidate_on_unsafe_methods",
    "max_entries",
    "max_entry_size_bytes",
    "max_total_size_bytes",
    "respect_cache_control",
    "respect_no_cache",
    "ttl_seconds",
    "vary_by_headers",
];

/// Maximum cache entries before triggering eviction of expired entries.
const DEFAULT_MAX_ENTRIES: usize = 10_000;

/// Default TTL when no Cache-Control header is present (5 minutes).
const DEFAULT_TTL_SECONDS: u64 = 300;

/// Default maximum size of a single cached response body (1 MiB).
const DEFAULT_MAX_ENTRY_SIZE_BYTES: usize = 1_048_576;

/// Default maximum total cache size (100 MiB).
const DEFAULT_MAX_TOTAL_SIZE_BYTES: usize = 104_857_600;

/// Request-metadata namespace prefix. Each plugin instance appends its
/// process-unique [`ResponseCaching::instance_id`] so multiple
/// `response_caching` configs on one proxy cannot overwrite one another's
/// staged base key, status, predictor key, timing, or header snapshot.
const METADATA_NAMESPACE_PREFIX: &str = "response_caching.";
const CACHE_BASE_KEY_SUFFIX: &str = "cache_base_key";
const CACHE_STATUS_SUFFIX: &str = "cache_status";
const CACHE_PREDICT_KEY_SUFFIX: &str = "cache_predict_key";
const CACHE_REQUEST_STARTED_MONOTONIC_NANOS_SUFFIX: &str = "cache_request_started_monotonic_nanos";
/// JSON-serialized snapshot of the request header values `before_proxy` saw
/// while building the cache key. `on_final_response_body` reads it back to
/// build the storage cache key from the *same* header view, even when an
/// earlier plugin's `transform_request_headers` mutated the outbound
/// headers map — see [`ResponseCaching::stash_request_headers_snapshot`]
/// and the bug it fixes. The full metadata key is
/// `response_caching.<instance_id>.cache_request_headers_snapshot`.
const CACHE_REQUEST_HEADERS_SNAPSHOT_SUFFIX: &str = "cache_request_headers_snapshot";

static CACHE_CLOCK_EPOCH: LazyLock<Instant> = LazyLock::new(Instant::now);
static NEXT_RESPONSE_CACHING_INSTANCE_ID: AtomicU64 = AtomicU64::new(1);

fn staging_metadata_key(instance_id: u64, suffix: &str) -> String {
    let mut key = String::with_capacity(METADATA_NAMESPACE_PREFIX.len() + 20 + 1 + suffix.len());
    key.push_str(METADATA_NAMESPACE_PREFIX);
    {
        use std::fmt::Write;
        let _ = write!(key, "{instance_id}");
    }
    key.push('.');
    key.push_str(suffix);
    key
}

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

/// Render an authenticated principal as the `sha256-<hex>` `consumer_part` of
/// a cache key. SHA-256-hashing keeps a username or SPIFFE ID (which may carry
/// the `:` / `|` key delimiters and can surface in debug logs) out of the key
/// verbatim. Built with `String::with_capacity` + `push_str` rather than
/// `format!` because `build_base_cache_key` runs on the `before_proxy` hot path
/// for every authenticated request (mirrors [`cache_key_host_part`]).
fn cache_key_identity_part(identity: &str) -> String {
    let digest = sha256_hex(identity);
    let mut part = String::with_capacity(7 + digest.len());
    part.push_str("sha256-");
    part.push_str(&digest);
    part
}

/// Render the exact raw query string as a bounded cache-key part.
///
/// The raw query is hashed as received, without parsing, sorting,
/// percent-decoding, or normalizing, so duplicate keys, pair order,
/// percent-encoding, and bare/empty values remain distinct.
fn cache_key_query_part(raw_query: &str) -> String {
    let digest = sha256_hex(raw_query);
    let mut part = String::with_capacity(2 + digest.len());
    part.push_str("q-");
    part.push_str(&digest);
    part
}

/// Request headers whose presence makes a cacheable response automatically vary
/// by that header.
///
/// These are credentials or session identifiers, so they are auto-added to the
/// keyed `Vary` set at storage time (see `on_final_response_body`) and
/// SHA-256-hashed by [`cache_key_vary_value`] when they appear in a cache key.
/// Additional operator-configured or backend-supplied Vary headers are also
/// hashed when their header name matches the centralized log-redaction
/// sensitivity rules.
const SENSITIVE_VARY_HEADERS: [&str; 3] = ["authorization", "proxy-authorization", "cookie"];

fn is_auto_sensitive_vary_header(header: &str) -> bool {
    SENSITIVE_VARY_HEADERS
        .iter()
        .any(|sensitive| header.eq_ignore_ascii_case(sensitive))
}

fn should_hash_vary_header_value(header: &str) -> bool {
    is_auto_sensitive_vary_header(header)
        || super::utils::metadata_redaction::is_sensitive_metadata_key(header)
}

fn should_snapshot_header_value_as_cache_key_part(header: &str) -> bool {
    !header.eq_ignore_ascii_case("host") && should_hash_vary_header_value(header)
}

fn cache_key_vary_value(header: &str, value: &str) -> String {
    if should_hash_vary_header_value(header) {
        let digest = sha256_hex(value);
        let mut hashed = String::with_capacity(7 + digest.len());
        hashed.push_str("sha256-");
        hashed.push_str(&digest);
        hashed
    } else {
        value.to_string()
    }
}

#[derive(Debug, Deserialize, Serialize)]
struct RequestHeaderSnapshotEntry {
    header: String,
    value: String,
    value_is_cache_key_part: bool,
}

struct RestoredRequestHeadersView {
    headers: HashMap<String, String>,
    cache_key_ready_headers: HashSet<String>,
}

fn merge_vary_header(vary_headers: &mut Vec<String>, header: &str) -> bool {
    if vary_headers.iter().any(|existing| existing == header) {
        return false;
    }
    vary_headers.push(header.to_string());
    true
}

fn header_value<'a>(headers: &'a HashMap<String, String>, name: &str) -> Option<&'a str> {
    headers.get(name).map(String::as_str).or_else(|| {
        headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    })
}

fn vary_index_prune_slack(cache_len: usize) -> usize {
    if cache_len == 0 { 0 } else { cache_len / 4 + 1 }
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
    stored_at: Duration,
    freshness_lifetime: Duration,
    corrected_initial_age: Duration,
    /// Byte length of the base-key prefix of this entry's full cache key.
    ///
    /// A full cache key is always its base key optionally followed by
    /// `:<vary dimensions>` (see [`ResponseCaching::build_cache_key`]), so
    /// `&key[..base_key_len]` recovers the base key without re-parsing the
    /// colon-delimited (and query-colon-bearing) structure.
    /// [`prune_vary_index_locked`] uses it to reclaim `vary_index` mappings
    /// whose base key has no surviving variant.
    ///
    /// [`prune_vary_index_locked`]: ResponseCaching::prune_vary_index_locked
    base_key_len: usize,
}

impl CacheEntry {
    fn current_age(&self, now: Duration) -> Duration {
        duration_saturating_add(
            self.corrected_initial_age,
            now.saturating_sub(self.stored_at),
        )
    }

    fn is_fresh_at(&self, now: Duration) -> bool {
        self.current_age(now) < self.freshness_lifetime
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

fn duration_saturating_add(lhs: Duration, rhs: Duration) -> Duration {
    lhs.checked_add(rhs).unwrap_or(Duration::MAX)
}

fn duration_from_nanos_u128(nanos: u128) -> Duration {
    const NANOS_PER_SECOND: u128 = 1_000_000_000;
    let secs = nanos / NANOS_PER_SECOND;
    if secs > u64::MAX as u128 {
        return Duration::MAX;
    }

    duration_saturating_add(
        Duration::from_secs(secs as u64),
        Duration::from_nanos((nanos % NANOS_PER_SECOND) as u64),
    )
}

fn duration_from_monotonic_nanos_str(value: &str) -> Option<Duration> {
    value
        .trim()
        .parse::<u128>()
        .ok()
        .map(duration_from_nanos_u128)
}

fn parse_age_header(value: &str) -> Option<Duration> {
    let value = value.trim();
    if value.is_empty() || !value.as_bytes().iter().all(|byte| byte.is_ascii_digit()) {
        return None;
    }

    match value.parse::<u64>() {
        Ok(seconds) => Some(Duration::from_secs(seconds)),
        Err(_) => Some(Duration::MAX),
    }
}

fn age_header_value(age: Duration) -> String {
    age.as_secs().to_string()
}

fn duration_since_http_date(now: DateTime<Utc>, date: DateTime<Utc>) -> Duration {
    now.signed_duration_since(date).to_std().unwrap_or_default()
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
        let object = config
            .as_object()
            .ok_or_else(|| "response_caching: config must be an object".to_string())?;
        reject_unknown_keys(
            object,
            "config",
            RESPONSE_CACHING_CONFIG_KEYS,
            "response_caching: ",
        )?;

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
    /// Process-unique ownership key for request-private staging metadata.
    /// Fresh on every constructor call so reload generations and sibling
    /// instances never share `RequestContext.metadata` slots.
    instance_id: u64,
    /// Precomputed `response_caching.<id>.cache_base_key` (hot-path insert/get).
    meta_base_key: String,
    /// Precomputed `response_caching.<id>.cache_status`.
    meta_status: String,
    /// Precomputed `response_caching.<id>.cache_predict_key`.
    meta_predict_key: String,
    /// Precomputed `response_caching.<id>.cache_request_started_monotonic_nanos`.
    meta_request_started: String,
    /// Precomputed `response_caching.<id>.cache_request_headers_snapshot`.
    meta_headers_snapshot: String,
    config: ResponseCachingConfig,
    cache: Arc<DashMap<String, CacheEntry>>,
    vary_index: Arc<DashMap<String, Vec<String>>>,
    total_size: Arc<AtomicUsize>,
    accounting_lock: Arc<Mutex<()>>,
    clock_offset_nanos: Arc<AtomicU64>,
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

        let instance_id = NEXT_RESPONSE_CACHING_INSTANCE_ID.fetch_add(1, Ordering::Relaxed);
        let predictor_size = config.max_entries / 10; // 10% of cache size
        Ok(Self {
            instance_id,
            meta_base_key: staging_metadata_key(instance_id, CACHE_BASE_KEY_SUFFIX),
            meta_status: staging_metadata_key(instance_id, CACHE_STATUS_SUFFIX),
            meta_predict_key: staging_metadata_key(instance_id, CACHE_PREDICT_KEY_SUFFIX),
            meta_request_started: staging_metadata_key(
                instance_id,
                CACHE_REQUEST_STARTED_MONOTONIC_NANOS_SUFFIX,
            ),
            meta_headers_snapshot: staging_metadata_key(
                instance_id,
                CACHE_REQUEST_HEADERS_SNAPSHOT_SUFFIX,
            ),
            config,
            cache: Arc::new(DashMap::new()),
            vary_index: Arc::new(DashMap::new()),
            total_size: Arc::new(AtomicUsize::new(0)),
            accounting_lock: Arc::new(Mutex::new(())),
            clock_offset_nanos: Arc::new(AtomicU64::new(0)),
            uncacheable_predictor: UncacheablePredictor::new(predictor_size.max(100)),
        })
    }

    /// Process-unique staging namespace for this instance (tests / diagnostics).
    #[allow(dead_code)]
    pub(crate) fn instance_id_for_tests(&self) -> u64 {
        self.instance_id
    }

    /// Namespaced metadata key for `suffix` under this instance's staging
    /// namespace (tests assert isolation without hard-coding id digits).
    #[allow(dead_code)]
    pub(crate) fn staging_metadata_key_for_tests(&self, suffix: &str) -> String {
        staging_metadata_key(self.instance_id, suffix)
    }

    fn set_cache_status(&self, ctx: &mut RequestContext, status: &str) {
        ctx.metadata
            .insert(self.meta_status.clone(), status.to_string());
        if matches!(status, "HIT" | "REVALIDATED") {
            ctx.mark_response_cache_hit();
        }
    }

    fn cache_status<'a>(&self, ctx: &'a RequestContext) -> Option<&'a str> {
        ctx.metadata.get(&self.meta_status).map(String::as_str)
    }

    /// Drop this instance's lookup/store staging inputs without touching
    /// sibling instances' namespaced keys. Used on method/SSE bypass and
    /// HIT/REVALIDATED so leftover base/snapshot/predict/timing from an
    /// earlier phase of this instance cannot leak into a later final hook.
    fn clear_lookup_staging(&self, ctx: &mut RequestContext) {
        ctx.metadata.remove(&self.meta_base_key);
        ctx.metadata.remove(&self.meta_predict_key);
        ctx.metadata.remove(&self.meta_request_started);
        ctx.metadata.remove(&self.meta_headers_snapshot);
    }

    fn accounting_guard(&self) -> MutexGuard<'_, ()> {
        self.accounting_lock
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Current value of the running cache-size accountant.
    ///
    /// Exposed for tests so they can assert the size accounting never
    /// underflow-wraps under concurrent stores/invalidations (finding #62).
    #[allow(dead_code)]
    pub(crate) fn current_total_size_for_tests(&self) -> usize {
        self.total_size.load(Ordering::Relaxed)
    }

    #[allow(dead_code)]
    pub(crate) fn size_accounting_snapshot_for_tests(&self) -> (usize, usize) {
        let _guard = self.accounting_guard();
        (
            self.total_size.load(Ordering::Relaxed),
            self.actual_total_size_locked(),
        )
    }

    fn actual_total_size_locked(&self) -> usize {
        self.cache
            .iter()
            .map(|entry| entry.value().approx_size())
            .sum()
    }

    fn sub_total_size_locked(&self, n: usize) {
        if n == 0 {
            return;
        }
        let current = self.total_size.load(Ordering::Relaxed);
        self.total_size
            .store(current.saturating_sub(n), Ordering::Relaxed);
    }

    /// Advance this plugin instance's clock without sleeping.
    ///
    /// Routed through `_test_support` so external tests can validate cache
    /// freshness and Age arithmetic deterministically without pausing the runtime.
    #[allow(dead_code)]
    pub(crate) fn advance_clock_for_tests(&self, duration: Duration) {
        let nanos = u64::try_from(duration.as_nanos()).unwrap_or(u64::MAX);
        let _ =
            self.clock_offset_nanos
                .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |current| {
                    Some(current.saturating_add(nanos))
                });
    }

    fn clock_offset(&self) -> Duration {
        duration_from_nanos_u128(self.clock_offset_nanos.load(Ordering::Relaxed) as u128)
    }

    fn now_monotonic(&self) -> Duration {
        duration_saturating_add(CACHE_CLOCK_EPOCH.elapsed(), self.clock_offset())
    }

    fn now_wall(&self) -> DateTime<Utc> {
        match chrono::Duration::from_std(self.clock_offset()) {
            Ok(offset) => Utc::now() + offset,
            Err(_) => Utc::now(),
        }
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

        let query_part = if self.config.cache_key_include_query {
            ctx.raw_query_string()
                .map(cache_key_query_part)
                .unwrap_or_default()
        } else {
            String::new()
        };

        // Bind the cache entry to the authenticated principal whenever the
        // request is authenticated by ANY mechanism — a gateway Consumer
        // (key_auth / mtls_auth / basic_auth / hmac_auth) or an external
        // `authenticated_identity` emitted by jwks_auth / oidc. Without this,
        // two principals authenticated by a non-`Authorization` scheme (API
        // key, mTLS, JWT carried in a custom header) share one cache entry
        // whenever the backend marks the response `public` / `s-maxage`,
        // serving one principal's private response to another. The identity
        // is SHA-256-hashed so a username or SPIFFE ID (which may contain the
        // `:` / `|` key delimiters and can surface in debug logs) never lands
        // in the key verbatim. `cache_key_include_consumer` remains an
        // explicit opt-in that additionally keys *anonymous* requests as
        // `_anon`.
        let consumer_part: Cow<'_, str> = match ctx.effective_identity() {
            Some(identity) => Cow::Owned(cache_key_identity_part(identity)),
            None if self.config.cache_key_include_consumer => Cow::Borrowed("_anon"),
            None => Cow::Borrowed(""),
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
        key.push_str(&consumer_part);
        key
    }

    fn build_cache_key(
        &self,
        ctx: &RequestContext,
        vary_headers: &[String],
        request_headers: &HashMap<String, String>,
    ) -> String {
        self.build_cache_key_with_ready_values(ctx, vary_headers, request_headers, None)
    }

    fn build_cache_key_with_ready_values(
        &self,
        ctx: &RequestContext,
        vary_headers: &[String],
        request_headers: &HashMap<String, String>,
        cache_key_ready_headers: Option<&HashSet<String>>,
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
            cache_key.push_str(header);
            cache_key.push('=');
            if let Some(ready_headers) = cache_key_ready_headers
                && ready_headers.contains(header)
            {
                cache_key.push_str(value);
            } else {
                let value = cache_key_vary_value(header, value);
                cache_key.push_str(&value);
            }
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

    fn merge_present_sensitive_vary_headers(
        &self,
        vary_headers: &mut Vec<String>,
        request_headers: &HashMap<String, String>,
    ) -> bool {
        let mut added = false;
        for sensitive in SENSITIVE_VARY_HEADERS {
            if request_headers.contains_key(sensitive) {
                added |= merge_vary_header(vary_headers, sensitive);
            }
        }
        if added {
            vary_headers.sort();
        }
        added
    }

    fn merge_existing_vary_headers(&self, base_key: &str, vary_headers: &mut Vec<String>) -> bool {
        let Some(existing_headers) = self.vary_index.get(base_key).map(|headers| headers.clone())
        else {
            return false;
        };

        let mut added = false;
        for header in existing_headers {
            added |= merge_vary_header(vary_headers, &header);
        }
        if added {
            vary_headers.sort();
        }
        added
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

    fn not_modified_headers(
        &self,
        entry: &CacheEntry,
        current_age: Duration,
    ) -> HashMap<String, String> {
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

        self.add_age_header(&mut headers, current_age);
        if self.config.add_cache_status_header {
            headers.insert("x-cache-status".to_string(), "REVALIDATED".to_string());
        }

        headers
    }

    fn invalidate_base_key(&self, base_key: &str) {
        let _guard = self.accounting_guard();
        self.invalidate_base_key_locked(base_key);
    }

    fn invalidate_base_key_locked(&self, base_key: &str) {
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
            self.sub_total_size_locked(removed_size);
        }
        self.vary_index.remove(base_key);
    }

    fn invalidate_cache_key(&self, base_key: &str, cache_key: &str) {
        let _guard = self.accounting_guard();
        self.invalidate_cache_key_locked(base_key, cache_key);
    }

    fn invalidate_cache_key_locked(&self, base_key: &str, cache_key: &str) {
        let Some((_, entry)) = self.cache.remove(cache_key) else {
            return;
        };

        self.sub_total_size_locked(entry.approx_size());
        if cache_key == base_key {
            self.vary_index.remove(base_key);
        }
    }

    fn invalidate_zero_freshness_response(
        &self,
        base_key: &str,
        predict_key: Option<&str>,
        ctx: &RequestContext,
        response_headers: &HashMap<String, String>,
        lookup_headers: &RestoredRequestHeadersView,
    ) {
        if let Some(predict_key) = predict_key {
            self.invalidate_cache_key(base_key, predict_key);
        }

        match self.merged_vary_headers(response_headers) {
            Some(mut vary_headers) => {
                self.merge_existing_vary_headers(base_key, &mut vary_headers);
                self.merge_present_sensitive_vary_headers(
                    &mut vary_headers,
                    &lookup_headers.headers,
                );
                let response_key = self.build_cache_key_with_ready_values(
                    ctx,
                    &vary_headers,
                    &lookup_headers.headers,
                    Some(&lookup_headers.cache_key_ready_headers),
                );
                if predict_key != Some(response_key.as_str()) {
                    self.invalidate_cache_key(base_key, &response_key);
                }
            }
            None => self.invalidate_base_key(base_key),
        }
    }

    fn mark_uncacheable_if_no_cached_entry(&self, predict_key: Option<&str>) {
        let Some(predict_key) = predict_key else {
            return;
        };
        if !self.cache.contains_key(predict_key) {
            self.uncacheable_predictor.mark_uncacheable(predict_key);
        }
    }

    /// Evict expired entries when cache exceeds max_entries.
    fn evict_if_needed_locked(&self) {
        if self.cache.len() <= self.config.max_entries {
            return;
        }

        let now = self.now_monotonic();
        let mut removed_size = 0usize;
        self.cache.retain(|_, entry| {
            if !entry.is_fresh_at(now) {
                removed_size += entry.approx_size();
                false
            } else {
                true
            }
        });
        self.sub_total_size_locked(removed_size);

        if self.cache.len() > self.config.max_entries {
            let mut entries: Vec<(String, Duration)> = self
                .cache
                .iter()
                .map(|entry| (entry.key().clone(), entry.value().stored_at))
                .collect();
            entries.sort_by_key(|(_, stored_at)| *stored_at);

            let to_remove = self.cache.len() - self.config.max_entries;
            for (key, _) in entries.into_iter().take(to_remove) {
                if let Some((_, removed)) = self.cache.remove(&key) {
                    self.sub_total_size_locked(removed.approx_size());
                }
            }
        }
    }

    /// Reclaim `vary_index` mappings whose base key has no surviving cache
    /// variant.
    ///
    /// `vary_index` is keyed by base key and otherwise pruned only in
    /// [`Self::invalidate_base_key`]; eviction, expiry, and path invalidation
    /// drop entries from `self.cache` but leave their `vary_index` mapping
    /// behind. Because the base key now embeds the per-principal `consumer_part`
    /// (see [`Self::build_base_cache_key`]), a workload with high principal
    /// cardinality (JWT `sub`s, ephemeral SPIFFE IDs) would otherwise grow
    /// `vary_index` without bound even though `self.cache` stays capped at
    /// `max_entries`. A stale mapping is only ever fail-safe — it over-specifies
    /// the vary list for a base key with no live entry, so the next lookup
    /// simply MISSes and re-stores — making this a pure memory reclaim, not a
    /// correctness fix.
    ///
    /// The number of distinct live base keys can never exceed
    /// `self.cache.len()`, so `vary_index.len() > self.cache.len()` is a
    /// necessary precondition for any stale mapping to exist. The sweep is
    /// deliberately batched with slack so a saturated, high-cardinality cache
    /// reclaims stale mappings in groups instead of cloning every live base key
    /// on every store.
    fn prune_vary_index_locked(&self) {
        let cache_len = self.cache.len();
        if self.vary_index.len() <= cache_len.saturating_add(vary_index_prune_slack(cache_len)) {
            return;
        }

        // Materialize the live base keys (owned) before touching `vary_index`
        // so no `self.cache` read guards are held across the `retain` below.
        let live_base_keys: HashSet<String> = self
            .cache
            .iter()
            .filter_map(|entry| {
                entry
                    .key()
                    .get(..entry.value().base_key_len)
                    .map(str::to_string)
            })
            .collect();

        let before = self.vary_index.len();
        self.vary_index
            .retain(|base_key, _| live_base_keys.contains(base_key));

        let removed = before.saturating_sub(self.vary_index.len());
        if removed > 0 {
            debug!(
                removed = removed,
                vary_index_len = self.vary_index.len(),
                "response_caching: pruned stale vary_index entries"
            );
        }
    }

    /// Invalidate cache entries matching a path pattern.
    /// Called when an unsafe method (POST/PUT/PATCH/DELETE) hits a path.
    fn invalidate_path(&self, ctx: &RequestContext) {
        let _guard = self.accounting_guard();
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
            self.sub_total_size_locked(removed_size);
        }
        // A path sweep can strand many base keys' `vary_index` mappings at once
        // (every principal/variant of the invalidated path); reclaim them now
        // rather than waiting for the next store.
        self.prune_vary_index_locked();
    }

    fn add_cache_status_header(&self, headers: &mut HashMap<String, String>, value: &str) {
        if self.config.add_cache_status_header {
            headers.insert("x-cache-status".to_string(), value.to_string());
        }
    }

    fn add_age_header(&self, headers: &mut HashMap<String, String>, current_age: Duration) {
        headers.insert("age".to_string(), age_header_value(current_age));
    }

    fn stash_request_started_at(&self, ctx: &mut RequestContext, request_time: Duration) {
        ctx.metadata.insert(
            self.meta_request_started.clone(),
            request_time.as_nanos().to_string(),
        );
    }

    fn response_delay(&self, ctx: &RequestContext, response_time: Duration) -> Duration {
        ctx.metadata
            .get(&self.meta_request_started)
            .and_then(|value| duration_from_monotonic_nanos_str(value))
            .map(|request_time| response_time.saturating_sub(request_time))
            .unwrap_or_default()
    }

    fn freshness_lifetime(&self, directives: CacheControlDirectives) -> Duration {
        if let Some(s_maxage) = directives.s_maxage {
            Duration::from_secs(s_maxage)
        } else if let Some(max_age) = directives.max_age {
            Duration::from_secs(max_age)
        } else {
            Duration::from_secs(self.config.ttl_seconds)
        }
    }

    fn corrected_initial_age(
        &self,
        ctx: &RequestContext,
        response_headers: &HashMap<String, String>,
        response_time_monotonic: Duration,
        response_time_wall: DateTime<Utc>,
    ) -> Duration {
        let apparent_age = header_value(response_headers, "date")
            .and_then(parse_http_date)
            .map(|date| duration_since_http_date(response_time_wall, date))
            .unwrap_or_default();

        let age_value = header_value(response_headers, "age")
            .and_then(parse_age_header)
            .unwrap_or_default();
        let corrected_age_value =
            duration_saturating_add(age_value, self.response_delay(ctx, response_time_monotonic));
        apparent_age.max(corrected_age_value)
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
    /// key that can land in the cache key — `host`, the sensitive
    /// credential/session headers in [`SENSITIVE_VARY_HEADERS`]
    /// (`authorization`, `proxy-authorization`, `cookie`), and each configured
    /// `vary_by_headers` entry. `on_final_response_body` reads it back via
    /// [`Self::restore_request_headers_view`] so the storage cache key is
    /// derived from the same header view as the lookup. Without this, a
    /// request-side transformer that touches one of these headers (e.g.
    /// injecting `X-Tenant` from a consumer property, or rewriting `cookie`)
    /// would make the storage key disagree with the lookup key and the cache
    /// would never hit.
    ///
    /// Non-Host values that match the centralized metadata-redaction
    /// sensitivity rules are stashed as the same SHA-256 cache-key component
    /// [`cache_key_vary_value`] would produce. The restore path marks those
    /// headers as cache-key-ready so storage does not hash them a second time.
    /// This keeps raw cookies, credentials, and operator-redacted Vary header
    /// values out of `ctx.metadata`, which is copied into transaction log
    /// metadata. Host stays raw in the snapshot because it feeds the base-key
    /// host hash, not a Vary dimension.
    ///
    /// The auto-sensitive headers are stashed unconditionally because the
    /// storage path auto-Varies them (see `on_final_response_body`), so they are
    /// load-bearing cache-key dimensions even when the operator never lists them
    /// in `vary_by_headers`.
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
        let mut snapshot: Vec<RequestHeaderSnapshotEntry> = Vec::with_capacity(
            self.config.vary_by_headers.len() + 1 + SENSITIVE_VARY_HEADERS.len(),
        );
        let mut push_if_present = |key: &str| {
            if let Some(value) = headers.get(key) {
                let value_is_cache_key_part = should_snapshot_header_value_as_cache_key_part(key);
                let value = if value_is_cache_key_part {
                    cache_key_vary_value(key, value)
                } else {
                    value.clone()
                };
                snapshot.push(RequestHeaderSnapshotEntry {
                    header: key.to_string(),
                    value,
                    value_is_cache_key_part,
                });
            }
        };
        push_if_present("host");
        for header in SENSITIVE_VARY_HEADERS {
            push_if_present(header);
        }
        for header in &self.config.vary_by_headers {
            // Skip duplicates that match the always-stashed keys above.
            if header == "host" || is_auto_sensitive_vary_header(header) {
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
                .insert(self.meta_headers_snapshot.clone(), serialized);
        }
    }

    /// Rebuild the request-headers view used to derive the storage cache
    /// key. Layers `before_proxy`'s snapshot on top of `ctx.headers` so
    /// snapshotted keys reflect the transformed values seen at lookup
    /// time while any other key (typically a header added by the
    /// response's own `Vary` directive) falls back to the original.
    fn restore_request_headers_view(&self, ctx: &RequestContext) -> RestoredRequestHeadersView {
        let mut headers = ctx.headers.clone();
        let mut cache_key_ready_headers = HashSet::new();
        if let Some(serialized) = ctx.metadata.get(&self.meta_headers_snapshot)
            && let Ok(snapshot) =
                serde_json::from_str::<Vec<RequestHeaderSnapshotEntry>>(serialized)
        {
            for entry in snapshot {
                if entry.value_is_cache_key_part
                    && should_snapshot_header_value_as_cache_key_part(&entry.header)
                {
                    cache_key_ready_headers.insert(entry.header.clone());
                }
                headers.insert(entry.header, entry.value);
            }
        }
        RestoredRequestHeadersView {
            headers,
            cache_key_ready_headers,
        }
    }
}

/// Check if a cache key's path segment matches the invalidation path.
///
/// Cache key format: `proxy_id:host_hash:method:path:query_hash:consumer[:vary...]`.
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

/// Parse an HTTP-date for conditional-request handling.
///
/// RFC 9110 §5.6.7 requires recipients to accept all three historic date
/// formats. `parse_from_rfc2822` covers the dominant IMF-fixdate form
/// (`Sun, 06 Nov 1994 08:49:37 GMT`), but rejects the two obsolete forms a
/// recipient must still accept: RFC 850 (`Sunday, 06-Nov-94 08:49:37 GMT`)
/// and asctime (`Sun Nov  6 08:49:37 1994`). Falling back across all three
/// keeps conditional revalidation (`If-Modified-Since` → `304`) working
/// against legacy origins and clients instead of silently serving a full
/// `200` from cache. Each fixed-offset format is interpreted as UTC, matching
/// the obsolete `GMT` zone these formats always use.
pub(crate) fn parse_http_date(value: &str) -> Option<DateTime<Utc>> {
    if let Ok(dt) = DateTime::parse_from_rfc2822(value) {
        return Some(dt.with_timezone(&Utc));
    }
    // IMF-fixdate (e.g. `Sun, 06 Nov 1994 08:49:37 GMT`), RFC 850
    // (`Sunday, 06-Nov-94 08:49:37 GMT`), then asctime
    // (`Sun Nov  6 08:49:37 1994`). asctime has no zone; the dashed/comma
    // forms always carry `GMT`, which these patterns consume literally.
    const FORMATS: [&str; 3] = [
        "%a, %d %b %Y %H:%M:%S GMT",
        "%A, %d-%b-%y %H:%M:%S GMT",
        "%a %b %e %H:%M:%S %Y",
    ];
    for format in FORMATS {
        if let Ok(naive) = NaiveDateTime::parse_from_str(value, format) {
            return Some(naive.and_utc());
        }
    }
    None
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
            // Clear only this instance's staging so a sibling cache keeps
            // its independently staged base/snapshot/status.
            self.clear_lookup_staging(ctx);
            self.set_cache_status(ctx, "BYPASS");
            return PluginResult::Continue;
        }

        if super::utils::sse::headers_accept_sse(headers) {
            self.clear_lookup_staging(ctx);
            self.set_cache_status(ctx, "BYPASS");
            return PluginResult::Continue;
        }

        // Use the `headers` parameter (not `ctx.headers`) — the gateway hot
        // path may have temporarily moved `ctx.headers` out of the context
        // before invoking `before_proxy` (zero-alloc when no plugin modifies
        // headers). The `headers` parameter is the single source of truth
        // during this phase.
        let base_key = self.build_base_cache_key(ctx, headers);
        ctx.metadata
            .insert(self.meta_base_key.clone(), base_key.clone());
        self.stash_request_started_at(ctx, self.now_monotonic());
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

        let mut vary_headers = self.cache_lookup_vary_headers(&base_key);
        // A request that carries credentials/session headers must never probe
        // the unvaried base key, even if this base key has only seen anonymous
        // responses so far. Storage also merges these dimensions so the
        // `vary_index` stays widened for future anonymous lookups.
        self.merge_present_sensitive_vary_headers(&mut vary_headers, headers);
        let cache_key = self.build_cache_key(ctx, &vary_headers, headers);
        // Store the full cache key (with Vary dimensions) so on_final_response_body
        // can mark the correct variant-specific key in the uncacheable predictor.
        ctx.metadata
            .insert(self.meta_predict_key.clone(), cache_key.clone());

        if self.config.respect_no_cache
            && let Some(cc) = headers.get("cache-control")
        {
            let directives = parse_cache_control(cc);
            if directives.no_cache || directives.no_store {
                // Keep this instance's staged base/snapshot/predict so a
                // no-cache refresh can still store the replacement response
                // under the same instance-owned key inputs.
                self.set_cache_status(ctx, "BYPASS");
                return PluginResult::Continue;
            }
        }

        // Fast-path: skip cache lookup if this specific variant is predicted uncacheable.
        // Uses the full cache_key (including Vary dimensions) so that one uncacheable
        // variant does not suppress lookups for other variants of the same route.
        if !self
            .uncacheable_predictor
            .is_predicted_cacheable(&cache_key)
        {
            self.set_cache_status(ctx, "PREDICTED-BYPASS");
            return PluginResult::Continue;
        }

        if let Some(entry) = self.cache.get(&cache_key) {
            let now = self.now_monotonic();
            let current_age = entry.current_age(now);
            if !entry.is_fresh_at(now) {
                drop(entry);
                self.invalidate_cache_key(&base_key, &cache_key);
            } else {
                debug!(cache_key = %cache_key, "response_caching: cache HIT");

                if self.is_fresh_conditional_hit(headers, &entry) {
                    self.set_cache_status(ctx, "REVALIDATED");
                    // HIT/REVALIDATED will not store; drop this instance's
                    // lookup staging so a later final hook cannot mix it with
                    // another instance's store path.
                    self.clear_lookup_staging(ctx);
                    return PluginResult::RejectBinary {
                        status_code: 304,
                        body: Bytes::new(),
                        headers: self.not_modified_headers(&entry, current_age),
                    };
                }

                let mut headers = entry.headers.clone();
                self.add_age_header(&mut headers, current_age);
                self.add_cache_status_header(&mut headers, "HIT");
                self.set_cache_status(ctx, "HIT");
                self.clear_lookup_staging(ctx);

                return PluginResult::RejectBinary {
                    status_code: entry.status_code,
                    body: entry.body.clone(),
                    headers,
                };
            }
        }

        self.set_cache_status(ctx, "MISS");
        PluginResult::Continue
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        _response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        let Some(status) = self.cache_status(ctx) else {
            // A preceding sibling may already have short-circuited with a HIT
            // before this instance reached `before_proxy`. Do not invent MISS
            // state and overwrite that instance's client-visible header.
            return PluginResult::Continue;
        };
        self.add_cache_status_header(response_headers, status);
        PluginResult::Continue
    }

    /// `x-cache-status` is an unconditional gateway `insert`, so a backend that
    /// sends the identical value (`MISS` is trivially guessable) hides the write
    /// from net-diff mutation tracking — and a later body/committed hook that
    /// exhausts the gRPC deadline would then rebuild the DEADLINE_EXCEEDED
    /// response without it. Declared owned only when the header is actually
    /// configured to be written.
    fn owns_deadline_response_header(&self, ctx: &RequestContext, name: &str) -> bool {
        self.config.add_cache_status_header
            && self.cache_status(ctx).is_some()
            && name.eq_ignore_ascii_case("x-cache-status")
    }

    async fn on_final_response_body(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &HashMap<String, String>,
        body: &[u8],
    ) -> PluginResult {
        // Synthetic short-circuit guard. When a request was short-circuited by a
        // `before_proxy` plugin (including this plugin's own cache HIT/REVALIDATED
        // surfaced via `RejectBinary`, an `ai_semantic_cache` hit, a
        // `fault_injection`/`response_mock`/`serverless` abort, etc.), the
        // synthetic body now flows back through the response-body hooks (the
        // generic 2xx short-circuit path). Re-running the entire store path over a
        // body that never came from the backend would take `accounting_guard()`,
        // do a full body copy on every hit (a hot-path regression), and needlessly
        // churn the vary index / uncacheable predictor — and for a served cache
        // HIT the entry is already cached and unchanged, so there is nothing to
        // store. `apply_synthetic_response_body_hooks` sets this marker only for
        // the duration of the synthetic body-hook phase, so its presence is a
        // precise signal; a genuine backend response (the only legitimate store /
        // replacement path) never carries it and falls through to store normally.
        // Mirrors `request_deduplication`'s synthetic short-circuit guard and
        // `ai_semantic_cache`'s miss-only buffering key.
        if ctx
            .metadata
            .contains_key(crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY)
        {
            return PluginResult::Continue;
        }

        let base_key = match ctx.metadata.get(&self.meta_base_key) {
            Some(base_key) => base_key.clone(),
            None => return PluginResult::Continue,
        };
        // Use the variant-specific predict key (set during before_proxy) for
        // predictor marking so that uncacheability of one Vary variant does not
        // suppress cache lookups for other variants of the same route.
        let predict_key = ctx.metadata.get(&self.meta_predict_key).cloned();

        if !self
            .config
            .cacheable_status_codes
            .contains(&response_status)
        {
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
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
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        // Restore the same header view `before_proxy` used so the
        // shared-cache authorization check and the storage cache key
        // both see the transformed values, not the untransformed
        // `ctx.headers`. See `restore_request_headers_view` for why.
        let lookup_headers = self.restore_request_headers_view(ctx);
        let freshness_lifetime = self.freshness_lifetime(directives);

        if freshness_lifetime.is_zero() {
            self.invalidate_zero_freshness_response(
                &base_key,
                predict_key.as_deref(),
                ctx,
                response_headers,
                &lookup_headers,
            );
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        // Never cache responses with Set-Cookie headers. These are
        // per-client and replaying them from a shared cache would leak
        // session cookies to other users (RFC 7234 §8).
        if response_headers.contains_key("set-cookie") {
            debug!("response_caching: skipping cache — response contains Set-Cookie header");
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        if !self.shared_cache_allows_authorized_response(ctx, directives) {
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        let response_time_monotonic = self.now_monotonic();
        let response_time_wall = self.now_wall();
        let corrected_initial_age = self.corrected_initial_age(
            ctx,
            response_headers,
            response_time_monotonic,
            response_time_wall,
        );

        if corrected_initial_age >= freshness_lifetime {
            self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
            return PluginResult::Continue;
        }

        let mut vary_headers = match self.merged_vary_headers(response_headers) {
            Some(vary_headers) => vary_headers,
            None => {
                self.invalidate_base_key(&base_key);
                self.mark_uncacheable_if_no_cached_entry(predict_key.as_deref());
                return PluginResult::Continue;
            }
        };

        // Never narrow the indexed Vary dimensions for a base key. Once a
        // credential/session or backend Vary dimension has been introduced,
        // later responses that lack that header still need to store under an
        // explicit empty-valued variant rather than replacing the index with a
        // smaller set and making credential-bearing lookups probe the base key.
        self.merge_existing_vary_headers(&base_key, &mut vary_headers);

        // Per RFC 7234 §3.2 / §8, a shared cache MUST NOT serve a stored
        // response to a request other than the one that produced it when the
        // original request carried credentials — unless the response
        // explicitly opted in via `Cache-Control: public` / `must-revalidate`
        // / `s-maxage`. `shared_cache_allows_authorized_response` gates that
        // decision above. Once we've decided to cache, we MUST also key the
        // entry by the credential so two clients presenting different
        // credentials land on different cache entries.
        //
        // Auto-merge every credential/session header the request carried
        // (`authorization`, `proxy-authorization`, `cookie`) into the keyed
        // Vary list. Operators don't need to remember to set
        // `cache_key_include_consumer: true` or list these in
        // `vary_by_headers` — the safe default is to never share a cached
        // response across distinct credentials or sessions. The merged list is
        // sorted and re-stored in `vary_index` so the same dimension applies to
        // every subsequent lookup at this base key.
        //
        // This is complementary to the per-principal `consumer_part` in
        // `build_base_cache_key`: that isolates *authenticated* principals
        // (API key / mTLS / JWT) even when the credential rides a non-standard
        // header; this isolates the raw credential/session headers themselves,
        // including anonymous `Cookie`-only sessions that have no
        // `effective_identity`.
        //
        // `lookup_headers` was built above from
        // `restore_request_headers_view`: it layers `before_proxy`'s header
        // snapshot on top of `ctx.headers`, so configured `vary_by_headers`
        // / `host` / the sensitive headers reflect the transformed values that
        // were live during lookup. Response-added Vary headers fall back to
        // `ctx.headers`, the same source any future lookup would use for them,
        // so the lookup/storage symmetry holds for those too.
        self.merge_present_sensitive_vary_headers(&mut vary_headers, &lookup_headers.headers);

        let cache_key = self.build_cache_key_with_ready_values(
            ctx,
            &vary_headers,
            &lookup_headers.headers,
            Some(&lookup_headers.cache_key_ready_headers),
        );
        debug_assert_eq!(
            base_key,
            self.build_base_cache_key(ctx, &lookup_headers.headers),
            "response_caching base-key inputs must be reproduced by the request-header snapshot"
        );

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
            stored_at: response_time_monotonic,
            freshness_lifetime,
            corrected_initial_age,
            // `cache_key` is `base_key` plus an optional `:<vary>` suffix, so
            // `base_key.len()` is the prefix that `prune_vary_index_locked`
            // slices back out to recover this entry's base key.
            base_key_len: base_key.len(),
        };
        let entry_size = entry.approx_size();

        {
            // Lock ordering: acquire `accounting_lock` before mutating
            // `cache`, `vary_index`, or `total_size`, and never acquire it
            // while holding a DashMap entry guard. Cache-hit reads do not take
            // this lock.
            let _guard = self.accounting_guard();
            let old_size = self
                .cache
                .get(&cache_key)
                .map(|old_entry| old_entry.approx_size())
                .unwrap_or(0);
            let current_total = self.total_size.load(Ordering::Relaxed);
            let next_total = current_total
                .saturating_sub(old_size)
                .saturating_add(entry_size);

            if entry_size > self.config.max_total_size_bytes
                || next_total > self.config.max_total_size_bytes
            {
                debug!(
                    cache_key = %cache_key,
                    current_total = current_total,
                    old_size = old_size,
                    entry_size = entry_size,
                    next_total = next_total,
                    max_total = self.config.max_total_size_bytes,
                    "response_caching: total cache size would exceed limit, skipping cache"
                );
                return PluginResult::Continue;
            }

            if let Some(old) = self.cache.insert(cache_key.clone(), entry) {
                debug_assert_eq!(
                    old.approx_size(),
                    old_size,
                    "response_caching replacement size must match admitted old entry"
                );
            }
            self.total_size.store(next_total, Ordering::Relaxed);
            self.vary_index.insert(base_key, vary_headers);
            self.evict_if_needed_locked();
            // The store above is the only path that grows `vary_index`; prune
            // here so a high-cardinality principal stream can't leak it
            // unboundedly.
            self.prune_vary_index_locked();
        }
        // Response was cacheable; remove the exact cache key from the predictor
        // even for client no-cache bypass refreshes, which return before
        // this instance's predict-key metadata is available.
        self.uncacheable_predictor.mark_cacheable(&cache_key);

        debug!(
            cache_key = %cache_key,
            entry_size = entry_size,
            freshness_lifetime_secs = freshness_lifetime.as_secs(),
            corrected_initial_age_secs = corrected_initial_age.as_secs(),
            "response_caching: cached response"
        );

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
    async fn cache_hit_does_not_restore_over_served_body() {
        // Regression: synthetic 2xx short-circuit bodies (cache HITs surfaced
        // via `RejectBinary{200}`) now flow back through the response-body
        // hooks. Without the synthetic short-circuit guard in
        // `on_final_response_body` every fresh hit would re-run the full store
        // path over the body it just served (a lock + body copy hot-path
        // regression). This asserts a HIT leaves the cached entry untouched.
        let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

        // 1) MISS: store an entry.
        let mut miss_ctx = make_ctx("GET", "/cached");
        let mut miss_headers = miss_ctx.headers.clone();
        let miss_result = plugin.before_proxy(&mut miss_ctx, &mut miss_headers).await;
        assert!(matches!(miss_result, PluginResult::Continue));
        assert_eq!(plugin.cache_status(&miss_ctx), Some("MISS"));
        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut miss_ctx, 200, &response_headers, b"cached-A")
            .await;
        assert_eq!(plugin.cache.len(), 1, "miss should store exactly one entry");
        let cache_key = plugin
            .cache
            .iter()
            .next()
            .map(|e| e.key().clone())
            .expect("entry stored");
        let stored_at_before = plugin
            .cache
            .get(&cache_key)
            .map(|e| e.stored_at)
            .expect("entry present");

        // 2) HIT: a second request short-circuits with the cached body.
        let mut hit_ctx = make_ctx("GET", "/cached");
        let mut hit_headers = hit_ctx.headers.clone();
        let hit_result = plugin.before_proxy(&mut hit_ctx, &mut hit_headers).await;
        assert!(
            matches!(
                hit_result,
                PluginResult::RejectBinary {
                    status_code: 200,
                    ..
                }
            ),
            "second request should be served from cache"
        );
        assert_eq!(plugin.cache_status(&hit_ctx), Some("HIT"));

        // 3) The synthetic-response-body path now re-runs on_final_response_body
        // over the HIT body. In production `apply_synthetic_response_body_hooks`
        // sets the synthetic short-circuit marker for the duration of this phase;
        // replicate that here so the guard sees the same precise signal it does at
        // runtime. Feed a DIFFERENT body to prove the guard prevents a re-store:
        // if the entry were re-stored it would now hold the tampered body and a
        // new stored_at.
        hit_ctx.metadata.insert(
            crate::proxy::SYNTHETIC_SHORT_CIRCUIT_METADATA_KEY.to_string(),
            "true".to_string(),
        );
        let store_result = plugin
            .on_final_response_body(&mut hit_ctx, 200, &response_headers, b"tampered-B")
            .await;
        assert!(matches!(store_result, PluginResult::Continue));

        assert_eq!(
            plugin.cache.len(),
            1,
            "HIT must not create or duplicate cache entries"
        );
        let entry = plugin.cache.get(&cache_key).expect("entry still present");
        assert_eq!(
            &entry.body[..],
            b"cached-A".as_slice(),
            "HIT must not overwrite the cached body"
        );
        assert_eq!(
            entry.stored_at, stored_at_before,
            "HIT must not advance stored_at (no re-store)"
        );
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

        let Some(predict_key) = ctx.metadata.get(&plugin.meta_predict_key) else {
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

    #[tokio::test]
    async fn cookie_is_auto_varied_and_hashed_without_explicit_config() {
        // No `vary_by_headers` configured and no authenticated identity: the
        // storage path must still auto-Vary `cookie` so distinct sessions
        // never share one `public` entry, and the raw cookie value must be
        // SHA-256-hashed out of the key. (finding #15)
        let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

        let mut ctx = make_ctx("GET", "/dashboard");
        ctx.headers
            .insert("cookie".to_string(), "session=top-secret".to_string());
        let mut request_headers = ctx.headers.clone();
        let result = plugin.before_proxy(&mut ctx, &mut request_headers).await;
        assert!(matches!(result, PluginResult::Continue));

        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"dashboard-body")
            .await;

        let cache_keys: Vec<String> = plugin
            .cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        assert_eq!(cache_keys.len(), 1);
        let stored_key = &cache_keys[0];
        assert!(
            !stored_key.contains("top-secret"),
            "raw cookie leaked into cache key: {stored_key}"
        );
        assert!(
            stored_key.contains("cookie=sha256-"),
            "cookie was not auto-varied into the cache key: {stored_key}"
        );
    }

    #[tokio::test]
    async fn authenticated_principal_keyed_into_base_key_without_consumer_flag() {
        // Default config (`cache_key_include_consumer: false`). An identity
        // authenticated by a non-`Authorization` scheme must still be bound
        // into the cache key (SHA-256-hashed), so a `public` per-user response
        // is never shared across principals. (finding #1)
        let plugin = plugin_with_config(json!({ "ttl_seconds": 60 }));

        let mut ctx = make_ctx("GET", "/api/profile");
        ctx.authenticated_identity = Some("alice@example.com".to_string());
        let mut request_headers = ctx.headers.clone();
        plugin.before_proxy(&mut ctx, &mut request_headers).await;

        let mut response_headers = HashMap::new();
        response_headers.insert(
            "cache-control".to_string(),
            "public, max-age=60".to_string(),
        );
        plugin
            .on_final_response_body(&mut ctx, 200, &response_headers, b"alice-body")
            .await;

        let cache_keys: Vec<String> = plugin
            .cache
            .iter()
            .map(|entry| entry.key().clone())
            .collect();
        assert_eq!(cache_keys.len(), 1);
        let stored_key = &cache_keys[0];
        assert!(
            !stored_key.contains("alice@example.com"),
            "raw identity leaked into cache key: {stored_key}"
        );
        assert!(
            stored_key.contains(&format!("sha256-{}", sha256_hex("alice@example.com"))),
            "authenticated principal was not bound into the base key: {stored_key}"
        );
    }

    #[tokio::test]
    async fn vary_index_stays_bounded_under_high_principal_cardinality() {
        // Binding the principal into the base key (the fix above) means each
        // distinct identity gets its own base key — and `vary_index` is keyed
        // by base key. `vary_index` was only ever pruned in
        // `invalidate_base_key`, so a stream of distinct principals (JWT `sub`s,
        // ephemeral SPIFFE IDs) would leak it without bound even though
        // `self.cache` stays capped at `max_entries`. `prune_vary_index_locked`
        // must reclaim mappings whose base key has no surviving cache variant.
        let max_entries = 4;
        let plugin = plugin_with_config(json!({
            "ttl_seconds": 60,
            "max_entries": max_entries,
        }));

        let principals = 40;
        for i in 0..principals {
            let mut ctx = make_ctx("GET", "/api/profile");
            ctx.authenticated_identity = Some(format!("user-{i}"));
            // A `cookie` makes the full key `base(principal):cookie=sha256-…`,
            // so the base key is a strict prefix of the full key — this also
            // exercises `base_key_len` slicing on a vary-suffixed key.
            ctx.headers
                .insert("cookie".to_string(), "session=shared".to_string());
            let mut request_headers = ctx.headers.clone();
            plugin.before_proxy(&mut ctx, &mut request_headers).await;

            let mut response_headers = HashMap::new();
            response_headers.insert(
                "cache-control".to_string(),
                "public, max-age=60".to_string(),
            );
            plugin
                .on_final_response_body(&mut ctx, 200, &response_headers, b"profile-body")
                .await;
        }

        // Cache is capped by eviction, and `vary_index` is reclaimed alongside
        // it — not left at `principals` (40) entries as it would be without the
        // prune. Distinct live base keys can never exceed the live cache.
        //
        // `== max_entries` (not `<=`): 40 distinct non-expiring entries must
        // pin the cache exactly at its cap, which also proves the responses
        // were actually stored — otherwise the `vary_index` bounds below would
        // pass vacuously.
        assert_eq!(
            plugin.cache.len(),
            max_entries,
            "expected the cache pinned at max_entries; got {}",
            plugin.cache.len()
        );
        let max_vary_index_entries =
            plugin.cache.len() + vary_index_prune_slack(plugin.cache.len());
        assert!(
            plugin.vary_index.len() <= max_vary_index_entries,
            "vary_index leaked past cache+slack bound ({}): {} entries — prune_vary_index_locked did not reclaim stale base keys",
            max_vary_index_entries,
            plugin.vary_index.len()
        );
        assert!(
            plugin.vary_index.len() <= max_entries + vary_index_prune_slack(max_entries),
            "vary_index ({}) outgrew max_entries plus prune slack ({})",
            plugin.vary_index.len(),
            max_entries + vary_index_prune_slack(max_entries)
        );
    }

    #[test]
    fn host_snapshot_values_are_not_marked_cache_key_ready() {
        assert!(!should_snapshot_header_value_as_cache_key_part("host"));
        assert!(!should_snapshot_header_value_as_cache_key_part("Host"));
        assert!(should_snapshot_header_value_as_cache_key_part("cookie"));
        assert!(should_snapshot_header_value_as_cache_key_part("x-api-key"));
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
            .get(&plugin.meta_predict_key)
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
            .get(&plugin.meta_predict_key)
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
