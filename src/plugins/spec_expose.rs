//! Spec Expose plugin — serves API specifications (OpenAPI, WSDL, WADL) on a
//! `/specz` sub-path of each proxy's listen path.
//!
//! When a `GET` request arrives at `{listen_path}/specz`, the plugin fetches
//! the specification document from the configured `spec_url` and returns it to
//! the caller. The `/specz` endpoint is unauthenticated — it short-circuits
//! before the authentication phase so consumers can discover API contracts
//! without credentials. Because it is anonymous and the upstream may be a
//! distinct, less-trusted service, the served response sets
//! `X-Content-Type-Options: nosniff` and constrains an upstream-derived
//! `Content-Type` to an allow-list of spec media types (the operator-set
//! `content_type` override is trusted and forwarded as-is).
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
//!   "cache_ttl_seconds": 300,              // optional, 0 = disable
//!   "max_response_body_bytes": 26214400    // optional, default 25 MiB
//! }
//! ```

use arc_swap::ArcSwap;
use async_trait::async_trait;
use bytes::Bytes;
use http::header::HeaderValue;
use serde_json::{Value, json};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::Mutex;
use url::{Host, Url};

use crate::dns::DnsCacheResolver;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

use super::utils::response_body::{
    BoundedReadError, parse_max_response_body_bytes, read_response_body_bounded,
};
use super::{Plugin, PluginResult, RequestContext};

/// Default cache TTL for fetched spec bodies (5 minutes).
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;
/// Default maximum upstream spec body size (25 MiB).
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 25 * 1024 * 1024;

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
    warmup_hostname: Option<String>,
    cache_ttl: Duration,
    max_response_body_bytes: usize,
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
            .map(str::trim)
            .filter(|s| !s.is_empty() && *s != "default")
            .ok_or_else(|| {
                "spec_expose: 'spec_url' is required and must be a non-empty URL string".to_string()
            })?;

        // Validate URL format and require a fetchable scheme.
        let parsed = Url::parse(spec_url)
            .map_err(|e| format!("spec_expose: 'spec_url' is not a valid URL: {e}"))?;
        match parsed.scheme() {
            "http" | "https" => {}
            other => {
                return Err(format!(
                    "spec_expose: 'spec_url' must use http or https scheme, got '{other}'"
                ));
            }
        }
        if !has_non_empty_authority(spec_url) {
            return Err(
                "spec_expose: 'spec_url' must include a hostname or IP address".to_string(),
            );
        }
        // Screen a literal-IP spec_url against the egress policy at config-load
        // (the shared client's DNS-cache screen still applies at fetch time).
        crate::plugins::utils::log_helpers::screen_url_host_egress(
            "spec_expose",
            "spec_url",
            &parsed,
            plugin_http_client.backend_allow_ips(),
        )?;
        let warmup_hostname = Some(spec_url_hostname(&parsed)?);
        let spec_url = parsed.to_string();

        let content_type_override = match config.get("content_type") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) => {
                let trimmed = s.trim();
                if trimmed.is_empty() {
                    return Err(
                        "spec_expose: 'content_type' must be a non-empty string when set"
                            .to_string(),
                    );
                }
                HeaderValue::from_str(trimmed).map_err(|_| {
                    "spec_expose: 'content_type' contains characters not permitted in HTTP header values"
                        .to_string()
                })?;
                Some(trimmed.to_string())
            }
            Some(other) => {
                return Err(format!(
                    "spec_expose: 'content_type' must be a string, got: {other}"
                ));
            }
        };

        let tls_no_verify = match config.get("tls_no_verify") {
            None | Some(Value::Null) => plugin_http_client.tls_no_verify(),
            Some(Value::Bool(value)) => *value,
            Some(other) => {
                return Err(format!(
                    "spec_expose: 'tls_no_verify' must be a boolean, got: {other}"
                ));
            }
        };

        let cache_ttl_seconds = match config.get("cache_ttl_seconds") {
            None | Some(Value::Null) => DEFAULT_CACHE_TTL_SECONDS,
            Some(v) => v.as_u64().ok_or_else(|| {
                format!("spec_expose: 'cache_ttl_seconds' must be a non-negative integer, got: {v}")
            })?,
        };
        let cache_ttl = Duration::from_secs(cache_ttl_seconds);

        let max_response_body_bytes = parse_max_response_body_bytes(
            config,
            "spec_expose",
            "max_response_body_bytes",
            DEFAULT_MAX_RESPONSE_BODY_BYTES,
        )?;

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
            let source = CertSource::parse(ca_path, MaterialKind::CaBundle);
            match load_material_blocking(&source, MaterialKind::CaBundle) {
                Ok(ca_material) => {
                    match reqwest::Certificate::from_pem(ca_material.bytes.expose_secret()) {
                        Ok(cert) => {
                            // reqwest 0.13: `tls_certs_only` replaces the trust
                            // store entirely (CA exclusivity).
                            builder = builder.tls_certs_only([cert]);
                        }
                        Err(e) => {
                            tracing::warn!(
                                "spec_expose: failed to parse CA bundle at {}: {e}",
                                ca_material.source_id
                            );
                        }
                    }
                }
                Err(e) => {
                    tracing::warn!("spec_expose: failed to load CA bundle: {e}");
                }
            }
        }

        let http_client = builder
            .build()
            .map_err(|e| format!("spec_expose: failed to build HTTP client: {e}"))?;

        Ok(Self {
            spec_url,
            content_type_override,
            warmup_hostname,
            cache_ttl,
            max_response_body_bytes,
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
                reject_502_json("Failed to fetch API specification from upstream")
            })?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            tracing::warn!(
                spec_url = %self.spec_url,
                upstream_status = status,
                "spec_expose: upstream returned non-success status"
            );
            return Err(reject_502_json(format!(
                "Upstream spec endpoint returned status {status}"
            )));
        }

        // Content-Length is an untrusted upstream hint, so this is only a
        // cooperative fast path. The streaming guard below is authoritative.
        // A lying inflated Content-Length is conservatively rejected even when
        // the eventual payload might be smaller; the unauthenticated /specz
        // endpoint should not spend memory or time proving an oversized hint
        // wrong.
        // The plugin HTTP client is built without reqwest auto-decompression
        // features today. If that changes, do not rely on this hint for safety:
        // the streaming guard still remains authoritative.
        if let Some(content_length) = response.content_length()
            && content_length > self.max_response_body_bytes as u64
        {
            tracing::warn!(
                spec_url = %self.spec_url,
                content_length,
                max_response_body_bytes = self.max_response_body_bytes,
                "spec_expose: upstream spec response body exceeds configured limit"
            );
            return Err(body_too_large_reject());
        }

        // Determine content-type: plugin override > upstream response > default.
        // Computed before consuming the response. The operator-configured
        // override is trusted; the upstream-derived value is sanitized against
        // an allow-list of spec media types so a compromised/untrusted upstream
        // cannot make this unauthenticated endpoint serve e.g. `text/html`.
        let content_type = self
            .content_type_override
            .clone()
            .or_else(|| {
                response
                    .headers()
                    .get("content-type")
                    .and_then(|v| v.to_str().ok())
                    .map(sanitize_upstream_content_type)
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());

        let body = read_response_body_bounded(response, self.max_response_body_bytes)
            .await
            .map_err(|e| match e {
                BoundedReadError::LimitExceeded { read_so_far, .. } => {
                    tracing::warn!(
                        spec_url = %self.spec_url,
                        max_response_body_bytes = self.max_response_body_bytes,
                        read_so_far,
                        "spec_expose: upstream spec response body exceeded configured limit while streaming"
                    );
                    body_too_large_reject()
                }
                BoundedReadError::Stream(e) => {
                    tracing::warn!(
                        spec_url = %self.spec_url,
                        error = %e,
                        "spec_expose: failed to read spec response body"
                    );
                    reject_502_json("Failed to read API specification response body")
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

/// Media types `spec_expose` will forward verbatim from an upstream response.
///
/// `/specz` is served unauthenticated and short-circuits before the auth
/// phase, so the upstream (a distinct, potentially less-trusted service)
/// must not be able to dictate an arbitrary `Content-Type` — e.g. `text/html`
/// with an attacker-influenced body would let the gateway's own origin serve
/// reflected HTML/JS to anonymous browsers. Only the media types an API spec
/// legitimately uses are allowed through; anything else falls back to
/// `application/octet-stream`. The operator-configured `content_type` override
/// path is trusted and is not constrained by this list.
const ALLOWED_SPEC_MEDIA_TYPES: [&str; 13] = [
    "application/json",
    "application/openapi+json",
    "application/openapi+yaml",
    "application/vnd.oai.openapi",
    "application/yaml",
    "application/vnd.oai.openapi+json",
    "application/wsdl+xml",
    "application/vnd.sun.wadl+xml",
    "text/yaml",
    "application/x-yaml",
    "application/xml",
    "text/xml",
    "text/plain",
];

/// Constrain an upstream-derived `content-type` to a known spec media type.
///
/// Compares the media type (the part before any `;` parameters, trimmed and
/// case-insensitive) against [`ALLOWED_SPEC_MEDIA_TYPES`]. On a match the
/// original header value is preserved (including any `charset` parameter); on
/// any other value it falls back to `application/octet-stream` so the browser
/// receives an inert type rather than an attacker-chosen one.
///
/// Exposed (like [`SpecExpose::is_specz_request`]) so the allow-list can be
/// unit-tested directly.
pub fn sanitize_upstream_content_type(raw: &str) -> String {
    let media_type = raw.split(';').next().unwrap_or("").trim();
    if ALLOWED_SPEC_MEDIA_TYPES
        .iter()
        .any(|allowed| media_type.eq_ignore_ascii_case(allowed))
    {
        raw.to_string()
    } else {
        "application/octet-stream".to_string()
    }
}

fn spec_url_hostname(parsed: &Url) -> Result<String, String> {
    let host = parsed.host().ok_or_else(|| {
        "spec_expose: 'spec_url' must include a hostname or IP address".to_string()
    })?;

    Ok(match host {
        Host::Domain(hostname) => hostname.to_string(),
        Host::Ipv4(address) => address.to_string(),
        Host::Ipv6(address) => address.to_string(),
    })
}

fn has_non_empty_authority(spec_url: &str) -> bool {
    let Some((_, after_scheme)) = spec_url.split_once(':') else {
        return false;
    };
    let Some(authority_and_path) = after_scheme.strip_prefix("//") else {
        return false;
    };
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());

    authority_end > 0
}

/// Build a 502 rejection for an oversized upstream spec body.
///
/// **Security:** `/specz` is intentionally unauthenticated, so the public error
/// body intentionally omits the configured `max_response_body_bytes` value to
/// avoid leaking operator config to anonymous probes. Operator-facing detail
/// (the configured cap and how many bytes were observed) stays in the
/// structured `tracing::warn!` at the call site. Do not "improve" the message
/// by adding the limit back — the tests at
/// `tests/unit/plugins/spec_expose_tests.rs` explicitly assert the public body
/// does NOT contain `max_response_body_bytes`.
fn body_too_large_reject() -> PluginResult {
    reject_502_json("API specification response too large")
}

/// Build a 502 `Reject` with a JSON `{"error": message}` body.
///
/// Uses `serde_json::json!` to escape the message safely — never inline
/// user-controlled or upstream-derived strings into the response with raw
/// `format!`. Callers should keep operator-facing detail (URL, cap value,
/// upstream status) in structured `tracing::warn!` logs rather than the
/// response body, since `/specz` is unauthenticated.
fn reject_502_json(message: impl Into<String>) -> PluginResult {
    let mut headers = HashMap::with_capacity(1);
    headers.insert("content-type".to_string(), "application/json".to_string());
    PluginResult::Reject {
        status_code: 502,
        body: json!({ "error": message.into() }).to_string(),
        headers,
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
        self.warmup_hostname.iter().cloned().collect()
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

        // Host-only proxies (listen_path == None), regex listen_paths, and
        // exact listen_paths don't expose a deterministic /specz sub-path.
        let Some(listen_path) = proxy.listen_path.as_deref() else {
            return PluginResult::Continue;
        };
        if listen_path.starts_with('~') || listen_path.starts_with('=') {
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
        // `/specz` is unauthenticated and serves an upstream-influenced body, so
        // prevent browsers from MIME-sniffing it into HTML/JS execution in the
        // gateway's own origin even if the (sanitized) content-type is permissive.
        headers.insert("x-content-type-options".to_string(), "nosniff".to_string());
        PluginResult::RejectBinary {
            status_code: 200,
            body: entry.body,
            headers,
        }
    }
}
