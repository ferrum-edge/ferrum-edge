//! Shared HTTP client for plugins that make outbound network calls.
//!
//! Plugins like `http_logging` (Splunk, Datadog, etc.), future OpenTelemetry
//! exporters, webhook notifiers, etc. all need to make HTTP/HTTPS requests.
//! Instead of each plugin creating its own `reqwest::Client` per call (which
//! means no connection reuse, full TCP+TLS handshake every time), they share
//! a single pre-configured client that leverages the gateway's pool settings:
//!
//! - **Connection pooling**: `max_idle_per_host` idle connections kept warm
//! - **Keep-alive**: TCP keep-alive probes detect dead connections
//! - **HTTP/2 multiplexing**: Multiple log/metric streams over one connection
//! - **Idle timeout**: Stale connections cleaned up automatically
//! - **DNS caching**: Uses the gateway's `DnsCache` for shared, warmed DNS
//!
//! # Usage for plugin authors
//!
//! If your plugin makes outbound HTTP calls, accept a `PluginHttpClient` in
//! your constructor and use `client.get()` to get the shared `reqwest::Client`:
//!
//! ```ignore
//! pub struct MyPlugin {
//!     http_client: PluginHttpClient,
//!     endpoint: String,
//! }
//!
//! impl MyPlugin {
//!     pub fn new(config: &Value, http_client: PluginHttpClient) -> Self {
//!         Self { http_client, endpoint: "...".into() }
//!     }
//! }
//!
//! #[async_trait]
//! impl Plugin for MyPlugin {
//!     async fn log(&self, summary: &TransactionSummary) {
//!         // Uses pooled connections + gateway DNS cache - no per-call overhead.
//!         // execute() automatically logs slow calls and can retry
//!         // safe/idempotent requests on transport failures.
//!         let req = self.http_client.get()
//!             .post(&self.endpoint)
//!             .json(summary);
//!         let _ = self.http_client.execute(req, "my_plugin").await;
//!     }
//! }
//! ```

use crate::config::PoolConfig;
use crate::dns::{DnsCache, DnsCacheResolver};
use crate::retry::{ErrorClass, classify_reqwest_error};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Shared, pooled HTTP client for plugin outbound calls.
///
/// Wraps a `reqwest::Client` configured with the gateway's connection pool
/// settings and DNS cache. Clone-cheap (Arc internally) - pass freely to all plugins.
///
/// Includes optional slow-request logging: when `slow_threshold` is set,
/// calls via [`execute`] that exceed the threshold emit a warning log with
/// the elapsed time and a caller-provided label.
#[derive(Clone)]
pub struct PluginHttpClient {
    client: Arc<reqwest::Client>,
    /// Threshold above which outbound plugin HTTP calls are logged as slow.
    /// Configured via `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS` (default: 1000ms).
    slow_threshold: Duration,
    /// Maximum retry attempts for safe/idempotent outbound plugin HTTP calls
    /// on transport-level failures. Configured via
    /// `FERRUM_PLUGIN_HTTP_MAX_RETRIES` (default: 0).
    max_retries: u32,
    /// Delay between plugin HTTP transport retries.
    /// Configured via `FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS` (default: 100ms).
    retry_delay: Duration,
    /// The gateway's shared DNS cache, available for plugins that need to resolve
    /// hostnames outside of reqwest (e.g., Redis connections for rate limiting).
    dns_cache: Option<DnsCache>,
    /// Whether to skip TLS certificate verification for outbound connections.
    /// Mirrors `FERRUM_TLS_NO_VERIFY` - shared with Redis rate limiting clients.
    tls_no_verify: bool,
    /// Path to a PEM CA bundle for verifying outbound TLS connections.
    /// Mirrors `FERRUM_TLS_CA_BUNDLE_PATH` - shared with Redis rate limiting clients.
    tls_ca_bundle_path: Option<String>,
    /// The gateway's namespace (`FERRUM_NAMESPACE`). Used by plugins that store
    /// state in external systems (Redis, Prometheus, StatsD) to prevent key/metric
    /// collisions when multiple gateway instances with different namespaces share
    /// the same external backend.
    namespace: String,
}

impl std::fmt::Debug for PluginHttpClient {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PluginHttpClient")
            .field("slow_threshold", &self.slow_threshold)
            .field("max_retries", &self.max_retries)
            .field("retry_delay", &self.retry_delay)
            .field("has_dns_cache", &self.dns_cache.is_some())
            .field("tls_no_verify", &self.tls_no_verify)
            .field("has_tls_ca_bundle", &self.tls_ca_bundle_path.is_some())
            .field("namespace", &self.namespace)
            .finish()
    }
}

impl PluginHttpClient {
    /// Build a plugin HTTP client from the gateway's global pool configuration,
    /// using the gateway's DNS cache for hostname resolution.
    ///
    /// The client is configured with:
    /// - `pool_max_idle_per_host` from PoolConfig (connection reuse)
    /// - `pool_idle_timeout` from PoolConfig (stale connection cleanup)
    /// - TCP keep-alive from PoolConfig (dead connection detection)
    /// - HTTP/2 keep-alive from PoolConfig (multiplexed stream health)
    /// - Gateway DNS cache (shared TTL, stale-while-revalidate, background refresh)
    /// - Custom CA bundle from `FERRUM_TLS_CA_BUNDLE_PATH` (internal CAs)
    /// - `FERRUM_TLS_NO_VERIFY` support (skip TLS verification)
    /// - 30s connect timeout, 60s request timeout (generous for log sinks)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_config: &PoolConfig,
        dns_cache: DnsCache,
        slow_threshold_ms: u64,
        max_retries: u32,
        retry_delay_ms: u64,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
        namespace: &str,
    ) -> Self {
        let dns_cache_clone = dns_cache.clone();
        let resolver = DnsCacheResolver::new(dns_cache);

        let mut builder = reqwest::Client::builder()
            .pool_max_idle_per_host(pool_config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .danger_accept_invalid_certs(tls_no_verify)
            .dns_resolver(Arc::new(resolver));

        // Load custom CA bundle for verifying internal/corporate CAs.
        // - Custom CA configured -> disable built-in roots, trust ONLY the custom CA
        // - No CA configured -> reqwest uses webpki/system roots by default
        if !tls_no_verify && let Some(ca_path) = tls_ca_bundle_path {
            match std::fs::read(ca_path) {
                Ok(ca_pem) => match reqwest::Certificate::from_pem(&ca_pem) {
                    Ok(cert) => {
                        // reqwest 0.13: `tls_certs_only` replaces the trust
                        // store entirely (CA exclusivity).
                        builder = builder.tls_certs_only([cert]);
                    }
                    Err(e) => {
                        tracing::warn!("Failed to parse CA bundle from {}: {}", ca_path, e);
                    }
                },
                Err(e) => {
                    tracing::warn!("Failed to read CA bundle from {}: {}", ca_path, e);
                }
            }
        }

        if pool_config.enable_http_keep_alive {
            builder = builder.tcp_keepalive(Duration::from_secs(pool_config.tcp_keepalive_seconds));
        }

        if pool_config.enable_http2 {
            builder = builder
                .http2_keep_alive_interval(Duration::from_secs(
                    pool_config.http2_keep_alive_interval_seconds,
                ))
                .http2_keep_alive_timeout(Duration::from_secs(
                    pool_config.http2_keep_alive_timeout_seconds,
                ));
        }

        let client = builder.build().unwrap_or_else(|e| {
            tracing::error!("Failed to build plugin HTTP client: {}, using default", e);
            reqwest::Client::new()
        });

        Self {
            client: Arc::new(client),
            slow_threshold: Duration::from_millis(slow_threshold_ms),
            max_retries,
            retry_delay: Duration::from_millis(retry_delay_ms),
            dns_cache: Some(dns_cache_clone),
            tls_no_verify,
            tls_ca_bundle_path: tls_ca_bundle_path.map(|s| s.to_string()),
            namespace: namespace.to_string(),
        }
    }

    /// Build a plugin HTTP client from pool config without a DNS cache.
    ///
    /// Uses reqwest's default DNS resolution. Prefer `new()` in production
    /// to share the gateway's DNS cache across all plugins.
    pub fn from_pool_config(config: &PoolConfig) -> Self {
        let mut builder = reqwest::Client::builder()
            .pool_max_idle_per_host(config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(config.idle_timeout_seconds))
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60));

        if config.enable_http_keep_alive {
            builder = builder.tcp_keepalive(Duration::from_secs(config.tcp_keepalive_seconds));
        }

        if config.enable_http2 {
            builder = builder
                .http2_keep_alive_interval(Duration::from_secs(
                    config.http2_keep_alive_interval_seconds,
                ))
                .http2_keep_alive_timeout(Duration::from_secs(
                    config.http2_keep_alive_timeout_seconds,
                ));
        }

        let client = builder.build().unwrap_or_else(|e| {
            tracing::error!("Failed to build plugin HTTP client: {}, using default", e);
            reqwest::Client::new()
        });

        Self {
            client: Arc::new(client),
            slow_threshold: Duration::from_millis(1000),
            max_retries: 0,
            retry_delay: Duration::from_millis(100),
            dns_cache: None,
            tls_no_verify: false,
            tls_ca_bundle_path: None,
            namespace: crate::config::types::DEFAULT_NAMESPACE.to_string(),
        }
    }

    /// Build a plugin HTTP client from pool config with a custom slow threshold
    /// and no DNS cache.
    ///
    /// Useful for tests that need to verify slow-call logging behavior with
    /// a specific threshold.
    #[allow(dead_code)] // Used by integration tests in tests/unit/plugins/
    pub fn from_pool_config_with_threshold(config: &PoolConfig, slow_threshold_ms: u64) -> Self {
        let mut client = Self::from_pool_config(config);
        client.slow_threshold = Duration::from_millis(slow_threshold_ms);
        client
    }

    /// Build a plugin HTTP client from pool config with custom slow-call and
    /// retry settings, without a DNS cache.
    ///
    /// Useful for tests that need to verify retry behavior deterministically.
    #[allow(dead_code)] // Used by integration tests in tests/unit/plugins/
    pub fn from_pool_config_with_settings(
        config: &PoolConfig,
        slow_threshold_ms: u64,
        max_retries: u32,
        retry_delay_ms: u64,
    ) -> Self {
        let mut client = Self::from_pool_config(config);
        client.slow_threshold = Duration::from_millis(slow_threshold_ms);
        client.max_retries = max_retries;
        client.retry_delay = Duration::from_millis(retry_delay_ms);
        client
    }

    /// Get the gateway's shared DNS cache, if available.
    ///
    /// Returns `Some` when the client was built with `new()` (production path).
    /// Returns `None` when built with `from_pool_config()` (tests / fallback).
    /// Used by plugins that make non-HTTP connections (e.g., Redis for centralized
    /// rate limiting) and need to resolve hostnames through the gateway's DNS cache.
    pub fn dns_cache(&self) -> Option<&DnsCache> {
        self.dns_cache.as_ref()
    }

    /// Whether TLS certificate verification is disabled (gateway-level setting).
    ///
    /// Used by plugins that make non-HTTP TLS connections (e.g., Redis for
    /// centralized rate limiting) to share the gateway's `FERRUM_TLS_NO_VERIFY` setting.
    pub fn tls_no_verify(&self) -> bool {
        self.tls_no_verify
    }

    /// Path to the gateway's CA bundle for outbound TLS verification.
    ///
    /// Used by plugins that make non-HTTP TLS connections (e.g., Redis for
    /// centralized rate limiting) to share the gateway's `FERRUM_TLS_CA_BUNDLE_PATH`.
    pub fn tls_ca_bundle_path(&self) -> Option<&str> {
        self.tls_ca_bundle_path.as_deref()
    }

    /// The gateway's namespace (`FERRUM_NAMESPACE`).
    ///
    /// Used by plugins to namespace Redis keys and metric labels when multiple
    /// gateway instances share a single external backend. When this returns the
    /// default namespace (`"ferrum"`), plugins use their standard key prefixes
    /// for backward compatibility.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Get the underlying `reqwest::Client` for building requests.
    ///
    /// The returned client uses pooled connections - no per-call overhead.
    /// Prefer [`execute`] over calling `.send()` directly so that slow
    /// outbound calls are automatically logged with the destination URL.
    pub fn get(&self) -> &reqwest::Client {
        &self.client
    }

    /// Send a pre-built request with automatic slow-call logging.
    ///
    /// Times the network round-trip and emits a `warn!` if the elapsed time
    /// exceeds the configured `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS`. The
    /// `label` identifies the caller in log output (e.g. "http_logging",
    /// "jwks_fetch", "jwks_auth_oidc_discovery", "otel_export").
    ///
    /// Safe/idempotent requests (`GET`, `HEAD`, `OPTIONS`) are retried on
    /// transport-level failures when `FERRUM_PLUGIN_HTTP_MAX_RETRIES` is set.
    ///
    /// The destination URL is extracted from the request and included in the
    /// slow-call warning so operators can identify which external endpoint is slow.
    pub async fn execute(
        &self,
        request: reqwest::RequestBuilder,
        label: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let request = request.build()?;
        self.execute_request(request, label, None).await
    }

    /// Send a request and accumulate the elapsed time into a shared counter.
    ///
    /// Identical to [`execute`] but atomically adds the round-trip time
    /// (in nanoseconds) to `accumulator`. Used by plugins that make
    /// external HTTP calls during the request lifecycle so the gateway
    /// can report `latency_plugin_external_io_ms` in transaction logs.
    #[allow(dead_code)] // Available for plugins to opt into; not yet called by built-in plugins
    pub async fn execute_tracked(
        &self,
        request: reqwest::RequestBuilder,
        label: &str,
        accumulator: &AtomicU64,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let request = request.build()?;
        self.execute_request(request, label, Some(accumulator))
            .await
    }

    async fn execute_request(
        &self,
        request: reqwest::Request,
        label: &str,
        accumulator: Option<&AtomicU64>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let url = request.url().to_string();
        let method = request.method().clone();
        let total_start = std::time::Instant::now();
        let retry_template = request.try_clone();
        let can_retry = self.max_retries > 0
            && matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS")
            && retry_template.is_some();

        let mut current_request = request;
        let mut attempt = 0_u32;

        loop {
            let attempt_start = std::time::Instant::now();
            let result = self.client.execute(current_request).await;
            let attempt_elapsed = attempt_start.elapsed();
            if let Some(accumulator) = accumulator {
                accumulator.fetch_add(attempt_elapsed.as_nanos() as u64, Ordering::Relaxed);
            }

            if can_retry
                && attempt < self.max_retries
                && result
                    .as_ref()
                    .err()
                    .is_some_and(Self::is_retryable_transport_error)
            {
                if let Some(error) = result.as_ref().err() {
                    let error_class = classify_reqwest_error(error);
                    tracing::warn!(
                        plugin = label,
                        method = %method,
                        url = %url,
                        attempt = attempt + 1,
                        max_retries = self.max_retries,
                        retry_delay_ms = self.retry_delay.as_millis() as u64,
                        error_class = %error_class,
                        "Retrying plugin HTTP call after transport failure"
                    );
                }

                tokio::time::sleep(self.retry_delay).await;

                let Some(template) = retry_template.as_ref() else {
                    return self.finish_request(result, label, &url, total_start);
                };
                let Some(next_request) = template.try_clone() else {
                    return self.finish_request(result, label, &url, total_start);
                };
                current_request = next_request;
                attempt += 1;
                continue;
            }

            return self.finish_request(result, label, &url, total_start);
        }
    }

    fn finish_request(
        &self,
        result: Result<reqwest::Response, reqwest::Error>,
        label: &str,
        url: &str,
        start: std::time::Instant,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let elapsed = start.elapsed();
        if elapsed > self.slow_threshold {
            tracing::warn!(
                plugin = label,
                url = %url,
                elapsed_ms = elapsed.as_millis() as u64,
                threshold_ms = self.slow_threshold.as_millis() as u64,
                "Slow plugin HTTP call"
            );
        }
        result
    }

    fn is_retryable_transport_error(error: &reqwest::Error) -> bool {
        matches!(
            classify_reqwest_error(error),
            ErrorClass::ConnectionTimeout
                | ErrorClass::ConnectionRefused
                | ErrorClass::ReadWriteTimeout
                | ErrorClass::ConnectionReset
                | ErrorClass::ConnectionClosed
                | ErrorClass::DnsLookupError
                | ErrorClass::ProtocolError
                | ErrorClass::RequestError
        )
    }
}

impl Default for PluginHttpClient {
    /// Creates a client with default pool settings and no DNS cache.
    ///
    /// Prefer `new()` in production to inherit the gateway's
    /// tuned settings and DNS cache. This default is provided for tests and fallback.
    fn default() -> Self {
        Self::from_pool_config(&PoolConfig::default())
    }
}
