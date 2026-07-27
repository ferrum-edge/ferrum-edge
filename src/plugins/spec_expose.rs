//! Spec Expose plugin — serves API specifications (OpenAPI, WSDL, WADL) on a
//! `/specz` sub-path of each proxy's listen path.
//!
//! When a `GET` or `HEAD` request arrives at `{listen_path}/specz`, the plugin
//! fetches the specification document from the configured `spec_url` and
//! returns it to the caller (`HEAD` retains the GET representation through
//! response-body policy, then returns its final status and headers without a
//! wire body). The `/specz` endpoint is unauthenticated — it short-circuits
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
//! from memory. On TTL expiry, the next request re-fetches. Failed fetches are
//! negatively cached with bounded exponential backoff, and at most a fixed
//! number of callers can wait for the single in-flight fetch. This keeps the
//! anonymous endpoint from accumulating unbounded tasks during an origin
//! outage. A zero TTL disables the durable positive cache, but concurrent
//! callers already admitted to the same fetch generation still share its
//! successful completion.
//!
//! TTL is controlled by `cache_ttl_seconds` (default 300s = 5 min).
//! Set to 0 to disable durable positive caching; callers admitted before an
//! in-flight fetch completes still share that fetch regardless of scheduling
//! delay.
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
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::Duration;
use tokio::sync::{Notify, OwnedSemaphorePermit, Semaphore};
use tokio::time::Instant;
use url::{Host, Url};

use crate::dns::DnsCacheResolver;
use crate::retry::classify_reqwest_error;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};

use super::utils::response_body::{
    BoundedReadError, parse_max_response_body_bytes, read_response_body_bounded,
};
use super::{Plugin, PluginResult, RequestContext};
use crate::proxy::SYNTHETIC_RESPONSE_METHOD_OVERRIDE_METADATA_KEY;

/// Default cache TTL for fetched spec bodies (5 minutes).
const DEFAULT_CACHE_TTL_SECONDS: u64 = 300;
/// Default maximum upstream spec body size (25 MiB).
const DEFAULT_MAX_RESPONSE_BODY_BYTES: usize = 25 * 1024 * 1024;
/// Maximum number of anonymous cache-miss callers admitted per plugin
/// instance, including the one performing the upstream fetch.
const MAX_PENDING_FETCHES: usize = 32;
/// Failed fetches back off from one second to a maximum of thirty seconds.
const FAILURE_BACKOFF_BASE_SECONDS: u64 = 1;
const FAILURE_BACKOFF_MAX_SECONDS: u64 = 30;
const FETCH_BUSY_BODY: &[u8] =
    br#"{"error":"API specification fetch is busy; retry after the indicated delay"}"#;
const FETCH_BUSY_BODY_LENGTH: &str = "76";
/// Private request marker kept only until the rejection-response hook phase.
/// It ensures HEAD carries the full GET representation through body policy and
/// suppresses it only after those hooks have established the final metadata.
const HEAD_RESPONSE_MARKER: &str = "ferrum:spec_expose_head_response";

const CONFIG_KEYS: [&str; 5] = [
    "spec_url",
    "content_type",
    "tls_no_verify",
    "cache_ttl_seconds",
    "max_response_body_bytes",
];

/// A cached spec response (body + content-type + insertion time).
#[derive(Clone)]
struct CachedSpec {
    body: Bytes,
    content_type: String,
    inserted_at: Instant,
}

/// A sanitized failure response retained during the negative-cache window.
/// It deliberately contains no origin URL or transport error text.
#[derive(Clone)]
struct FetchFailure {
    status_code: u16,
    body: String,
    retry_after_seconds: u64,
}

impl FetchFailure {
    fn into_plugin_result(self) -> PluginResult {
        let mut headers = HashMap::with_capacity(3);
        headers.insert("content-type".to_string(), "application/json".to_string());
        headers.insert("content-length".to_string(), self.body.len().to_string());
        headers.insert(
            "retry-after".to_string(),
            self.retry_after_seconds.max(1).to_string(),
        );
        PluginResult::Reject {
            status_code: self.status_code,
            body: self.body,
            headers,
        }
    }
}

#[derive(Clone)]
struct CachedFailure {
    failure: FetchFailure,
    retry_at: Instant,
}

type FetchOutcome = Result<CachedSpec, FetchFailure>;

/// A fetch generation whose completion is published by an independently owned
/// task. Request cancellation can drop any or every waiter without cancelling
/// the origin request or losing its positive/negative cache outcome.
struct InFlightFetch {
    outcome: OnceLock<FetchOutcome>,
    notify: Notify,
}

impl InFlightFetch {
    fn new() -> Self {
        Self {
            outcome: OnceLock::new(),
            notify: Notify::new(),
        }
    }

    fn publish(&self, outcome: FetchOutcome) {
        if self.outcome.set(outcome).is_ok() {
            self.notify.notify_waiters();
        }
    }

    async fn wait(&self) -> FetchOutcome {
        loop {
            // Register before checking the durable cell so publication cannot
            // fall between the check and the wait and strand this caller.
            let notified = self.notify.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(outcome) = self.outcome.get() {
                return outcome.clone();
            }
            notified.await;
        }
    }
}

struct FetchAdmission {
    _permit: OwnedSemaphorePermit,
    cell: Arc<InFlightFetch>,
    starts_fetch: bool,
}

fn lock_in_flight_fetch(
    slot: &Mutex<Option<Arc<InFlightFetch>>>,
) -> MutexGuard<'_, Option<Arc<InFlightFetch>>> {
    match slot.lock() {
        Ok(guard) => guard,
        Err(poisoned) => {
            tracing::warn!("spec_expose: recovering poisoned in-flight fetch state");
            poisoned.into_inner()
        }
    }
}

/// Spec Expose plugin — serves API spec documents on `{listen_path}/specz`.
#[derive(Clone)]
pub struct SpecExpose {
    spec_url: String,
    /// Credential-free origin label used for every diagnostic. The request URL
    /// remains private even when its path/query contains a signed token.
    spec_origin: String,
    content_type_override: Option<String>,
    warmup_hostname: Option<String>,
    cache_ttl: Duration,
    max_response_body_bytes: usize,
    cache: Arc<ArcSwap<Option<CachedSpec>>>,
    failure_cache: Arc<ArcSwap<Option<CachedFailure>>>,
    consecutive_failures: Arc<AtomicU32>,
    /// One transient single-flight completion shared only by callers admitted
    /// before it finishes. Completion removes the plugin-owned reference;
    /// admitted waiters retain their own `Arc`, so a zero-TTL body lives only
    /// until that fetch group drains.
    in_flight_fetch: Arc<Mutex<Option<Arc<InFlightFetch>>>>,
    /// Bounds both the in-flight fetch and callers waiting for its completion.
    /// Excess anonymous requests fail quickly instead of growing a mutex queue.
    fetch_admission: Arc<Semaphore>,
    http_client: reqwest::Client,
}

impl SpecExpose {
    pub fn new(
        config: &Value,
        plugin_http_client: super::PluginHttpClient,
    ) -> Result<Self, String> {
        let config_object = config.as_object().ok_or_else(|| {
            "spec_expose: configuration must be an object with a 'spec_url' field".to_string()
        })?;
        let mut unknown_keys = config_object
            .keys()
            .filter(|key| !CONFIG_KEYS.contains(&key.as_str()))
            .map(String::as_str)
            .collect::<Vec<_>>();
        if !unknown_keys.is_empty() {
            unknown_keys.sort_unstable();
            let unknown = unknown_keys
                .into_iter()
                .map(|key| format!("'{key}'"))
                .collect::<Vec<_>>()
                .join(", ");
            return Err(format!(
                "spec_expose: unsupported configuration key(s): {unknown}; supported keys are: {}",
                CONFIG_KEYS
                    .iter()
                    .map(|key| format!("'{key}'"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }

        let spec_url = config_object
            .get("spec_url")
            .and_then(Value::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty() && *value != "default")
            .ok_or_else(|| {
                "spec_expose: 'spec_url' is required and must be a non-empty URL string".to_string()
            })?;

        // Validate URL format and require a fetchable scheme.
        let mut parsed = Url::parse(spec_url)
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
        if url_has_userinfo(spec_url)
            || !parsed.username().is_empty()
            || parsed.password().is_some()
        {
            return Err(
                "spec_expose: 'spec_url' must not contain URL userinfo; use a credential-free origin URL"
                    .to_string(),
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
        let spec_origin = parsed.origin().ascii_serialization();
        // URL fragments are never part of an HTTP request. Drop them before
        // retaining the private fetch URL so fragment credentials cannot be
        // propagated accidentally by future diagnostics or metadata.
        parsed.set_fragment(None);
        let spec_url = parsed.to_string();

        let content_type_override = match config_object.get("content_type") {
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

        let tls_no_verify = match config_object.get("tls_no_verify") {
            None | Some(Value::Null) => plugin_http_client.tls_no_verify(),
            Some(Value::Bool(value)) => *value,
            Some(other) => {
                return Err(format!(
                    "spec_expose: 'tls_no_verify' must be a boolean, got: {other}"
                ));
            }
        };

        let cache_ttl_seconds = match config_object.get("cache_ttl_seconds") {
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
            // Ignore ambient HTTP_PROXY/HTTPS_PROXY/ALL_PROXY/NO_PROXY process
            // state: a selected proxy would resolve and dial the spec host
            // itself, so the ultimate destination would never reach the
            // `DnsCacheResolver` egress screen wired below.
            .no_proxy()
            .connect_timeout(Duration::from_secs(10))
            .timeout(Duration::from_secs(30))
            // Do not follow redirects: a 3xx from an allowed spec host could
            // otherwise bounce the fetch to an egress-policy-denied IP (matches
            // the shared PluginHttpClient redirect policy). The literal-IP first
            // hop is screened above; this closes the redirect bypass.
            .redirect(reqwest::redirect::Policy::none())
            .danger_accept_invalid_certs(tls_no_verify);

        if let Some(dns_cache) = plugin_http_client.dns_cache() {
            builder = builder.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())));
        }

        // Load custom CA bundle when not skipping verification.
        if !tls_no_verify && let Some(ca_path) = plugin_http_client.tls_ca_bundle_path() {
            let source = CertSource::parse(ca_path, MaterialKind::CaBundle);
            let source_id = source.redacted_source_id();
            let ca_material = load_material_blocking(&source, MaterialKind::CaBundle).map_err(
                |error| {
                    format!(
                        "spec_expose: configured CA bundle '{source_id}' could not be loaded; refusing to widen trust: {error}"
                    )
                },
            )?;
            let certificates =
                reqwest::Certificate::from_pem_bundle(ca_material.bytes.expose_secret()).map_err(
                    |error| {
                        format!(
                            "spec_expose: configured CA bundle '{}' is invalid; refusing to widen trust: {error}",
                            ca_material.display_source_id
                        )
                    },
                )?;
            if certificates.is_empty() {
                return Err(format!(
                    "spec_expose: configured CA bundle '{}' contains no certificates; refusing to widen trust",
                    ca_material.display_source_id
                ));
            }
            // reqwest 0.13: `tls_certs_only` replaces the trust store entirely
            // (CA exclusivity). All load/parse failures above abort construction.
            builder = builder.tls_certs_only(certificates);
        }

        let http_client = builder
            .build()
            .map_err(|e| format!("spec_expose: failed to build HTTP client: {e}"))?;

        Ok(Self {
            spec_url,
            spec_origin,
            content_type_override,
            warmup_hostname,
            cache_ttl,
            max_response_body_bytes,
            cache: Arc::new(ArcSwap::from_pointee(None)),
            failure_cache: Arc::new(ArcSwap::from_pointee(None)),
            consecutive_failures: Arc::new(AtomicU32::new(0)),
            in_flight_fetch: Arc::new(Mutex::new(None)),
            fetch_admission: Arc::new(Semaphore::new(MAX_PENDING_FETCHES)),
            http_client,
        })
    }

    /// Check whether the request path is exactly `{listen_path}/specz`.
    pub fn is_specz_request(path: &str, listen_path: &str) -> bool {
        // RequestContext paths do not include queries on H1/H2/H3, but keep
        // this public helper robust for callers that pass a full request target.
        let path = path.split_once('?').map_or(path, |(path, _)| path);
        let normalized_listen_path = listen_path.trim_end_matches('/');
        // For root listen_path "/", the normalized prefix is empty.
        if normalized_listen_path.is_empty() {
            return path == "/specz";
        }
        // Trimming the configured suffix means both "/api" and "/api/" own
        // the canonical "/api/specz" path. Requiring the exact remainder
        // deliberately leaves "/api//specz" unintercepted.
        if let Some(remainder) = path.strip_prefix(normalized_listen_path) {
            remainder == "/specz"
        } else {
            false
        }
    }

    /// Returns a durable cached spec when present and not expired. A zero
    /// configured TTL deliberately has no request-to-request fast path.
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

    /// Atomically registers a bounded caller with the current fetch group.
    /// Registration and group retirement share the same short synchronous
    /// critical section, so every caller admitted before completion owns the
    /// group cell even if it is not scheduled again until much later.
    fn admit_fetch(&self) -> Option<FetchAdmission> {
        let mut active = lock_in_flight_fetch(&self.in_flight_fetch);
        let permit = match Arc::clone(&self.fetch_admission).try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => return None,
        };
        let (cell, starts_fetch) = match active.as_ref() {
            Some(cell) => (Arc::clone(cell), false),
            None => {
                let cell = Arc::new(InFlightFetch::new());
                *active = Some(Arc::clone(&cell));
                (cell, true)
            }
        };
        Some(FetchAdmission {
            _permit: permit,
            cell,
            starts_fetch,
        })
    }

    fn retire_fetch(&self, cell: &Arc<InFlightFetch>) {
        let mut active = lock_in_flight_fetch(&self.in_flight_fetch);
        if active
            .as_ref()
            .is_some_and(|current| Arc::ptr_eq(current, cell))
        {
            *active = None;
        }
    }

    fn cached_failure(&self) -> Option<FetchFailure> {
        let snapshot = self.failure_cache.load();
        let entry = snapshot.as_ref().as_ref()?;
        let remaining = entry.retry_at.saturating_duration_since(Instant::now());
        if remaining.is_zero() {
            return None;
        }
        let mut failure = entry.failure.clone();
        failure.retry_after_seconds = remaining
            .as_secs()
            .saturating_add(u64::from(remaining.subsec_nanos() != 0));
        Some(failure)
    }

    fn record_failure(&self, mut failure: FetchFailure) -> FetchFailure {
        let previous = self
            .consecutive_failures
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |value| {
                Some(value.saturating_add(1))
            })
            .unwrap_or_else(|value| value);
        let exponent = previous.min(5);
        let retry_after_seconds = FAILURE_BACKOFF_BASE_SECONDS
            .saturating_mul(1_u64 << exponent)
            .min(FAILURE_BACKOFF_MAX_SECONDS);
        failure.retry_after_seconds = retry_after_seconds;
        self.failure_cache.store(Arc::new(Some(CachedFailure {
            failure: failure.clone(),
            retry_at: Instant::now() + Duration::from_secs(retry_after_seconds),
        })));
        failure
    }

    fn record_success(&self, entry: &CachedSpec) {
        if !self.cache_ttl.is_zero() {
            self.cache.store(Arc::new(Some(entry.clone())));
        }
        self.failure_cache.store(Arc::new(None));
        self.consecutive_failures.store(0, Ordering::Relaxed);
    }

    /// Fetch the spec from the upstream. The caller publishes either the fresh
    /// success or a sanitized negative-cache completion.
    async fn fetch_spec(&self) -> Result<CachedSpec, FetchFailure> {
        let response = self
            .http_client
            .get(&self.spec_url)
            .send()
            .await
            .map_err(|e| {
                let error_class = classify_reqwest_error(&e);
                tracing::warn!(
                    spec_origin = %self.spec_origin,
                    error_class = %error_class,
                    "spec_expose: failed to fetch spec document"
                );
                fetch_failure(502, "Failed to fetch API specification from upstream")
            })?;

        if !response.status().is_success() {
            let status = response.status().as_u16();
            tracing::warn!(
                spec_origin = %self.spec_origin,
                upstream_status = status,
                "spec_expose: upstream returned non-success status"
            );
            return Err(fetch_failure(
                502,
                format!("Upstream spec endpoint returned status {status}"),
            ));
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
                spec_origin = %self.spec_origin,
                content_length,
                max_response_body_bytes = self.max_response_body_bytes,
                "spec_expose: upstream spec response body exceeds configured limit"
            );
            return Err(body_too_large_failure());
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
                        spec_origin = %self.spec_origin,
                        max_response_body_bytes = self.max_response_body_bytes,
                        read_so_far,
                        "spec_expose: upstream spec response body exceeded configured limit while streaming"
                    );
                    body_too_large_failure()
                }
                BoundedReadError::Stream(e) => {
                    let error_class = classify_reqwest_error(&e);
                    tracing::warn!(
                        spec_origin = %self.spec_origin,
                        error_class = %error_class,
                        "spec_expose: failed to read spec response body"
                    );
                    fetch_failure(502, "Failed to read API specification response body")
                }
            })?;

        let entry = CachedSpec {
            body,
            content_type,
            inserted_at: Instant::now(),
        };

        Ok(entry)
    }

    /// Complete one fetch generation independently of the request that created
    /// it. The worker owns a clone of all shared cache/admission state, so a
    /// disconnected anonymous caller cannot cancel the origin fetch and make
    /// the next caller restart it.
    async fn complete_fetch(self, cell: Arc<InFlightFetch>) {
        let outcome = match self.fetch_spec().await {
            Ok(entry) => {
                self.record_success(&entry);
                Ok(entry)
            }
            Err(failure) => Err(self.record_failure(failure)),
        };
        cell.publish(outcome);
        // Retire only after publishing the outcome. Callers that registered
        // earlier retain this cell; later zero-TTL callers create a fresh group.
        self.retire_fetch(&cell);
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
    raw_url_authority(spec_url).is_some_and(|authority| !authority.is_empty())
}

fn url_has_userinfo(spec_url: &str) -> bool {
    raw_url_authority(spec_url).is_some_and(|authority| authority.contains('@'))
}

fn raw_url_authority(spec_url: &str) -> Option<&str> {
    let (_, after_scheme) = spec_url.split_once(':')?;
    let authority_and_path = after_scheme.strip_prefix("//")?;
    let authority_end = authority_and_path
        .find(['/', '?', '#'])
        .unwrap_or(authority_and_path.len());

    Some(&authority_and_path[..authority_end])
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
fn body_too_large_failure() -> FetchFailure {
    fetch_failure(502, "API specification response too large")
}

/// Build a sanitized failure with a JSON `{"error": message}` body.
///
/// Uses `serde_json::json!` to escape the message safely — never inline
/// user-controlled or upstream-derived strings into the response with raw
/// `format!`. Callers should keep operator-facing detail (URL, cap value,
/// upstream status) in structured `tracing::warn!` logs rather than the
/// response body, since `/specz` is unauthenticated.
fn fetch_failure(status_code: u16, message: impl Into<String>) -> FetchFailure {
    FetchFailure {
        status_code,
        body: json!({ "error": message.into() }).to_string(),
        retry_after_seconds: 1,
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
        // GET and HEAD own the same representation; all other methods continue.
        let is_head = ctx.method == "HEAD";
        if ctx.method != "GET" && !is_head {
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

        if is_head {
            ctx.metadata
                .insert(HEAD_RESPONSE_MARKER.to_string(), "true".to_string());
            ctx.metadata.insert(
                SYNTHETIC_RESPONSE_METHOD_OVERRIDE_METADATA_KEY.to_string(),
                "GET".to_string(),
            );
        } else {
            ctx.metadata.remove(HEAD_RESPONSE_MARKER);
            ctx.metadata
                .remove(SYNTHETIC_RESPONSE_METHOD_OVERRIDE_METADATA_KEY);
        }

        // Fast paths are lock-free. A cached failure is the completion state
        // shared by every caller during the backoff window.
        if let Some(entry) = self.cached_spec() {
            return spec_response(entry);
        }
        if let Some(failure) = self.cached_failure() {
            return failure.into_plugin_result();
        }

        // Admit only a fixed number of cache-miss callers. One performs the
        // fetch; the rest wait for the same completion. Excess callers receive
        // a stable retry signal immediately instead of joining an anonymous,
        // unbounded mutex queue.
        let admission = match self.admit_fetch() {
            Some(admission) => admission,
            None => return fetch_busy_response(),
        };

        if admission.starts_fetch {
            // Only the generation creator performs the durable re-check. It
            // publishes an already-completed outcome for concurrent joiners;
            // otherwise it starts an independently owned worker before this
            // request reaches another await/cancellation point.
            if let Some(entry) = self.cached_spec() {
                admission.cell.publish(Ok(entry));
                self.retire_fetch(&admission.cell);
            } else if let Some(failure) = self.cached_failure() {
                admission.cell.publish(Err(failure));
                self.retire_fetch(&admission.cell);
            } else {
                let worker = self.clone();
                let cell = Arc::clone(&admission.cell);
                tokio::spawn(async move {
                    worker.complete_fetch(cell).await;
                });
            }
        }

        let outcome = admission.cell.wait().await;

        match outcome {
            Ok(entry) => spec_response(entry),
            Err(failure) => failure.into_plugin_result(),
        }
    }

    async fn after_proxy(
        &self,
        ctx: &mut RequestContext,
        response_status: u16,
        response_headers: &mut HashMap<String, String>,
    ) -> PluginResult {
        if ctx.metadata.remove(HEAD_RESPONSE_MARKER).as_deref() != Some("true") {
            return PluginResult::Continue;
        }

        // Synthetic response-body transforms and guards have already run when
        // reject-path after_proxy hooks execute. Replace only the wire body now
        // while retaining their final GET status and representation metadata.
        PluginResult::RejectBinary {
            status_code: response_status,
            body: Bytes::new(),
            headers: response_headers.clone(),
        }
    }

    fn applies_after_proxy_on_reject(&self) -> bool {
        true
    }

    fn may_replace_rejection_response(&self) -> bool {
        true
    }

    fn warn_on_rejection_response_replacement(&self) -> bool {
        false
    }
}

fn spec_response(entry: CachedSpec) -> PluginResult {
    let mut headers = HashMap::with_capacity(3);
    headers.insert("content-type".to_string(), entry.content_type);
    headers.insert("content-length".to_string(), entry.body.len().to_string());
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

fn fetch_busy_response() -> PluginResult {
    // PluginResult owns its header map, but the response body and every
    // derived header value are static so overload shedding does not serialize
    // JSON or format lengths on the anonymous request path.
    let mut headers = HashMap::with_capacity(3);
    headers.insert("content-type".to_string(), "application/json".to_string());
    headers.insert(
        "content-length".to_string(),
        FETCH_BUSY_BODY_LENGTH.to_string(),
    );
    headers.insert("retry-after".to_string(), "1".to_string());
    PluginResult::RejectBinary {
        status_code: 503,
        body: Bytes::from_static(FETCH_BUSY_BODY),
        headers,
    }
}

#[cfg(test)]
mod tests {
    use super::{CachedSpec, SpecExpose};
    use crate::plugins::PluginHttpClient;
    use bytes::Bytes;
    use tokio::time::Instant;

    #[test]
    fn zero_ttl_success_is_not_retained_in_durable_cache() {
        let plugin = SpecExpose::new(
            &serde_json::json!({
                "spec_url": "http://example.com/openapi.yaml",
                "cache_ttl_seconds": 0
            }),
            PluginHttpClient::default(),
        )
        .expect("zero-TTL spec expose config");
        let entry = CachedSpec {
            body: Bytes::from_static(b"openapi: 3.0.0\n"),
            content_type: "application/yaml".to_string(),
            inserted_at: Instant::now(),
        };

        plugin.record_success(&entry);

        assert!(plugin.cache.load().as_ref().is_none());
    }
}
