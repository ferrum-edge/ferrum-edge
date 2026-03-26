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
//!         // Uses pooled connections + gateway DNS cache — no per-call overhead.
//!         // execute() automatically logs a warning when the call exceeds the
//!         // configured FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS threshold.
//!         let req = self.http_client.get()
//!             .post(&self.endpoint)
//!             .json(summary);
//!         let _ = self.http_client.execute(req, "my_plugin").await;
//!     }
//! }
//! ```

use crate::config::PoolConfig;
use crate::dns::{DnsCache, DnsCacheResolver};
use std::sync::Arc;
use std::time::Duration;

/// Shared, pooled HTTP client for plugin outbound calls.
///
/// Wraps a `reqwest::Client` configured with the gateway's connection pool
/// settings and DNS cache. Clone-cheap (Arc internally) — pass freely to all plugins.
///
/// Includes optional slow-request logging: when `slow_threshold` is set,
/// calls via [`execute`] that exceed the threshold emit a warning log with
/// the elapsed time and a caller-provided label.
#[derive(Clone, Debug)]
pub struct PluginHttpClient {
    client: Arc<reqwest::Client>,
    /// Threshold above which outbound plugin HTTP calls are logged as slow.
    /// Configured via `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS` (default: 1000ms).
    slow_threshold: Duration,
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
    /// - 30s connect timeout, 60s request timeout (generous for log sinks)
    pub fn new(pool_config: &PoolConfig, dns_cache: DnsCache, slow_threshold_ms: u64) -> Self {
        let resolver = DnsCacheResolver::new(dns_cache);

        let mut builder = reqwest::Client::builder()
            .pool_max_idle_per_host(pool_config.max_idle_per_host)
            .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
            .connect_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(60))
            .dns_resolver(Arc::new(resolver));

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

    /// Get the underlying `reqwest::Client` for building requests.
    ///
    /// The returned client uses pooled connections — no per-call overhead.
    /// Prefer [`execute`] over calling `.send()` directly so that slow
    /// outbound calls are automatically logged.
    pub fn get(&self) -> &reqwest::Client {
        &self.client
    }

    /// Send a pre-built request with automatic slow-call logging.
    ///
    /// Times the network round-trip and emits a `warn!` if the elapsed time
    /// exceeds the configured `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS`. The
    /// `label` identifies the caller in log output (e.g. "http_logging",
    /// "oauth2_introspection", "jwks_fetch", "otel_export").
    pub async fn execute(
        &self,
        request: reqwest::RequestBuilder,
        label: &str,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let start = std::time::Instant::now();
        let result = request.send().await;
        let elapsed = start.elapsed();
        if elapsed > self.slow_threshold {
            tracing::warn!(
                plugin = label,
                elapsed_ms = elapsed.as_millis() as u64,
                threshold_ms = self.slow_threshold.as_millis() as u64,
                "Slow plugin HTTP call"
            );
        }
        result
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
