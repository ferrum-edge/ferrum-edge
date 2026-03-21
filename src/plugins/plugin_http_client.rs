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
//!         // Uses pooled connections — no per-call overhead
//!         let _ = self.http_client.get()
//!             .post(&self.endpoint)
//!             .json(summary)
//!             .send()
//!             .await;
//!     }
//! }
//! ```

use crate::config::PoolConfig;
use std::sync::Arc;
use std::time::Duration;

/// Shared, pooled HTTP client for plugin outbound calls.
///
/// Wraps a `reqwest::Client` configured with the gateway's connection pool
/// settings. Clone-cheap (Arc internally) — pass freely to all plugins.
#[derive(Clone, Debug)]
pub struct PluginHttpClient {
    client: Arc<reqwest::Client>,
}

impl PluginHttpClient {
    /// Build a plugin HTTP client from the gateway's global pool configuration.
    ///
    /// The client is configured with:
    /// - `pool_max_idle_per_host` from PoolConfig (connection reuse)
    /// - `pool_idle_timeout` from PoolConfig (stale connection cleanup)
    /// - TCP keep-alive from PoolConfig (dead connection detection)
    /// - HTTP/2 keep-alive from PoolConfig (multiplexed stream health)
    /// - 30s connect timeout, 60s request timeout (generous for log sinks)
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

        let client = builder.build().expect("Failed to build plugin HTTP client");

        Self {
            client: Arc::new(client),
        }
    }

    /// Get the underlying `reqwest::Client` for making requests.
    ///
    /// The returned client uses pooled connections — no per-call overhead.
    pub fn get(&self) -> &reqwest::Client {
        &self.client
    }
}

impl Default for PluginHttpClient {
    /// Creates a client with default pool settings.
    ///
    /// Prefer `from_pool_config()` in production to inherit the gateway's
    /// tuned settings. This default is provided for tests and fallback.
    fn default() -> Self {
        Self::from_pool_config(&PoolConfig::default())
    }
}
