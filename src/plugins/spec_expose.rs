//! Spec Expose plugin — serves API specifications (OpenAPI, WSDL, WADL) on a
//! `/specz` sub-path of each proxy's listen path.
//!
//! When a `GET` request arrives at `{listen_path}/specz`, the plugin fetches
//! the specification document from the configured `spec_url` and returns it to
//! the caller with the upstream's `Content-Type` preserved. The `/specz`
//! endpoint is unauthenticated — it short-circuits before the authentication
//! phase so consumers can discover API contracts without credentials.
//!
//! Only compatible with prefix-based `listen_path` proxies (not regex, not
//! host-only or port-only routing) and HTTP protocol types.
//!
//! # Caching
//!
//! Per CLAUDE.md ("Performance Rules": pre-compute / cache at config-reload
//! time), the fetched spec body is cached in-process with a TTL so that
//! `/specz` requests do not re-fetch the upstream document on every call.
//! The cache is opportunistic: the first request triggers a fetch and stores
//! the body+content-type; subsequent requests within the TTL serve directly
//! from memory. On TTL expiry, the next request re-fetches. Failures are not
//! cached — every failed fetch is retried until a success populates the cache.
//!
//! TTL is controlled by `cache_ttl_seconds` (default 300s = 5 min).
//! Set to 0 to disable caching entirely.
//!
//! # Configuration
//!
//! ```json
//! {
//!   "spec_url": "https://internal-service/docs/openapi.yaml",
//!   "content_type": "application/yaml",    // optional override
//!   "tls_no_verify": false,                // optional, skip TLS verification
//!   "cache_ttl_seconds": 300               // optional, 0 = disable
//! }
//! ```

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use serde_json::Value;
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;

use crate::dns::DnsCacheResolver;

use super::{Plugin, PluginResult, RequestContext};

/// Default cache TTL for fetched spec bodies (5 minutes).
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;

/// A cached spec response (body + content-type + insertion time).
#[derive(Clone)]
struct CachedSpec {
    body: Bytes,
    content_type: String,
    inserted_at: Instant,
}

/// Spec Expose plugin — serves API spec documents on `{listen_path}/specz`.
pub struct SpecExpose {
    spec_url: String,
    content_type_override: Option<String>,
    cache_ttl: Duration,
    cache: ArcSwap<Option<CachedSpec>>,
    /// Single-flight lock around the upstream fetch. Concurrent cache-miss
    /// callers serialize here; whoever acquires first does the upstream fetch
    /// and populates the cache, and the rest observe the fresh entry via
    /// `cached_spec()` after the lock releases. Prevents a cold-cache request
    /// flood from fanning out to the upstream document store (the exact DoS
    /// the cache was added to prevent).
    fetch_lock: Mutex<()>,
    http_client: reqwest::Client,
}

impl SpecExpose {
    pub fn new(
        config: &Value,
        plugin_http_client: super::PluginHttpClient,
    ) -> Result<Self, String> {
        let spec_url = config["spec_url"]
            .as_str()
            .filter(|s| !s.is_empty() && *s != "default")
            .ok_or_else(|| {
                "spec_expose: 'spec_url' is required and must be a non-empty URL string".to_string()
            })?
            .to_string();

        // Validate URL format and require a fetchable scheme.
        let parsed = url::Url::parse(&spec_url)
            .map_err(|e| format!("spec_expose: 'spec_url' is not a valid URL: {e}"))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(format!(
                    "spec_expose: 'spec_url' must use http or https scheme, got '{other}'"
                ));
            }
        }

        let content_type_override = match config.get("content_type") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_string())
                }
            }
            Some(other) => {
                return Err(format!(
                    "spec_expose: 'content_type' must be a string, got: {other}"
                ));
            }
        };

        let tls_no_verify = config["tls_no_verify"]
            .as_bool()
            .unwrap_or(plugin_http_client.tls_no_verify());

        let cache_ttl_seconds = match config.get("cache_ttl_seconds") {
            None | Some(Value::Null) => DEFAULT_CACHE_TTL_SECONDS,
            Some(v) => v.as_u64().ok_or_else(|| {
                format!("spec_expose: 'cache_ttl_seconds' must be a non-negative integer, got: {v}")
            })?,
        };
        let cache_ttl = Duration::from_secs(cache_ttl_seconds);

        // Build a dedicated reqwest client for spec fetching.
        // We use a separate client so we can honour the per-plugin tls_no_verify
        // setting independently of the shared plugin HTTP client, but we still
        // wire the gateway's shared DNS cache for consistent resolution + TTL.
        let mut builder = reqwest::Client::builder()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            .danger_accept_invalid_certs(tls_no_verify);

        if let Some(dns_cache) = plugin_http_client.dns_cache() {
            builder = builder.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())));
        }

        // Load custom CA bundle when not skipping verification.
        if !tls_no_verify && let Some(ca_path) = plugin_http_client.tls_ca_bundle_path() {
            match std::fs::read(ca_path) {
                Ok(ca_pem) => match reqwest::Certificate::from_pem(&ca_pem) {
                    Ok(cert) => {
                        builder = builder
                            .tls_built_in_root_certs(false)
                            .add_root_certificate(cert);
                    }
                    Err(e) => {
                        tracing::warn!("spec_expose: failed to parse CA bundle at {ca_path}: {e}");
                    }
                },
                Err(e) => {
                    tracing::warn!("spec_expose: failed to read CA bundle at {ca_path}: {e}");
                }
            }
        }

        let http_client = builder
            .build()
            .map_err(|e| format!("spec_expose: failed to build HTTP client: {e}"))?;

        Ok(Self {
            spec_url,
            content_type_override,
            cache_ttl,
            cache: ArcSwap::from_pointee(None),
            fetch_lock: Mutex::new(()),
            http_client,
        })
    }

    /// Check whether the request path is exactly `{listen_path}/specz`.
    pub fn is_specz_request(path: &str, listen_path: &str) -> bool {
        // For root listen_path "/", the specz path is "/specz"
        if listen_path == "/" {
            return path == "/specz";
        }
        // For other listen paths like "/api/v1", check for "/api/v1/specz"
        if let Some(remainder) = path.strip_prefix(listen_path) {
            remainder == "/specz"
        } else {
            false
        }
    }

    /// Returns a cached spec when present and not expired. Caching is disabled
    /// (TTL = 0) → always returns None so the next call refetches from origin.
    fn cached_spec(&self) -> Option<CachedSpec> {
        if self.cache_ttl.is_zero() {
            return None;
        }
        let snapshot = self.cache.load();
        let entry = snapshot.as_ref().as_ref()?;
        if entry.inserted_at.elapsed() < self.cache_ttl {
            Some(entry.clone())
        } else {
            None
        }
    }

    /// Fetch the spec from the upstream and cache it on success. Returns the
    /// fresh spec on success or a [`PluginResult::Reject`] describing the
    /// upstream failure mode (502). Failures are NOT cached — the next call
    /// will re-attempt the fetch.
    async fn fetch_and_cache(&self) -> Result<CachedSpec, PluginResult> {
        let response = self
            .http_client
            .get(&self.spec_url)
            .send()
            .await
            .map_err(|e| {
                tracing::warn!(
                    spec_url = %self.spec_url,
                    error = %e,
                    "spec_expose: failed to fetch spec document"
                );
                let mut headers = HashMap::new();
                headers.insert("content-type".to_string(), "application/json".to_string());
                PluginResult::Reject {
                    status_code: 502,
                    body: r#"{"error":"Failed to fetch API specification from upstream"}"#
                        .to_string(),
                    headers,
                }
            })?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            tracing::warn!(
                spec_url = %self.spec_url,
                upstream_status = status,
                "spec_expose: upstream returned non-success status"
            );
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            return Err(PluginResult::Reject {
                status_code: 502,
                body: format!(r#"{{"error":"Upstream spec endpoint returned status {status}"}}"#),
                headers,
            });
        }

        // Determine content-type: plugin override > upstream response > default.
        // Computed before consuming the response.
        let content_type = self
            .content_type_override
            .clone()
            .or_else(|| {
                response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(|s| s.to_string())
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let body = response.bytes().await.map_err(|e| {
            tracing::warn!(
                spec_url = %self.spec_url,
                error = %e,
                "spec_expose: failed to read spec response body"
            );
            let mut headers = HashMap::new();
            headers.insert("content-type".to_string(), "application/json".to_string());
            PluginResult::Reject {
                status_code: 502,
                body: r#"{"error":"Failed to read API specification response body"}"#.to_string(),
                headers,
            }
        })?;

        let entry = CachedSpec {
            body,
            content_type,
            inserted_at: Instant::now(),
        };

        if !self.cache_ttl.is_zero() {
            self.cache.store(Arc::new(Some(entry.clone())));
        }
        Ok(entry)
    }
}

#[async_trait]
impl Plugin for SpecExpose {
    fn name(&self) -> &str {
        "spec_expose"
    }

    fn priority(&self) -> u16 {
        super::priority::SPEC_EXPOSE
    }

    fn supported_protocols(&self) -> &'static [super::ProxyProtocol] {
        super::HTTP_ONLY_PROTOCOLS
    }

    fn warmup_hostnames(&self) -> Vec<String> {
        if let Ok(url) = url::Url::parse(&self.spec_url)
            && let Some(host) = url.host_str()
        {
            return vec![host.to_string()];
        }
        Vec::new()
    }

    async fn on_request_received(&self, ctx: &mut RequestContext) -> PluginResult {
        // Only intercept GET requests
        if ctx.method != "GET" {
            return PluginResult::Continue;
        }

        // Need a matched proxy with a prefix listen_path (not regex)
        let proxy = match ctx.matched_proxy.as_ref() {
            Some(p) => p,
            None => return PluginResult::Continue,
        };

        // Host-only proxies (listen_path == None) and regex listen_paths
        // don't expose a deterministic /specz path — skip them.
        let Some(listen_path) = proxy.listen_path.as_deref() else {
            return PluginResult::Continue;
        };
        if listen_path.starts_with('~') {
            return PluginResult::Continue;
        }

        if !Self::is_specz_request(&ctx.path, listen_path) {
            return PluginResult::Continue;
        }

        // Try the cache first; on miss or expiry, fetch and (when caching is
        // enabled) serialize through the single-flight lock so a burst of
        // cold-cache requests does not fan out to the upstream document store.
        //
        // When caching is disabled (TTL=0) we bypass the lock entirely — every
        // request is expected to re-fetch, so serializing them would collapse
        // throughput into strictly-sequential upstream calls.
        let entry = if self.cache_ttl.is_zero() {
            match self.fetch_and_cache().await {
                Ok(entry) => entry,
                Err(reject) => return reject,
            }
        } else {
            match self.cached_spec() {
                Some(entry) => entry,
                None => {
                    let _guard = self.fetch_lock.lock().await;
                    // Re-check the cache after acquiring the lock: another task
                    // may have populated it while we were waiting.
                    if let Some(entry) = self.cached_spec() {
                        entry
                    } else {
                        match self.fetch_and_cache().await {
                            Ok(entry) => entry,
                            Err(reject) => return reject,
                        }
                    }
                }
            }
        };

        let mut headers = HashMap::new();
        headers.insert("content-type".to_string(), entry.content_type);
        PluginResult::RejectBinary {
            status_code: 200,
            body: entry.body,
            headers,
        }
    }
}
