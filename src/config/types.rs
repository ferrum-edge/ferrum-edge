use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;

/// Load balancing algorithm for distributing requests across upstream targets.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum LoadBalancerAlgorithm {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    LeastConnections,
    ConsistentHashing,
    Random,
}

/// A single backend target within an upstream group.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpstreamTarget {
    pub host: String,
    pub port: u16,
    #[serde(default = "default_weight")]
    pub weight: u32,
    #[serde(default)]
    pub tags: HashMap<String, String>,
}

fn default_weight() -> u32 {
    1
}

/// Active health check configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ActiveHealthCheck {
    #[serde(default = "default_health_path")]
    pub http_path: String,
    #[serde(default = "default_health_interval")]
    pub interval_seconds: u64,
    #[serde(default = "default_health_timeout")]
    pub timeout_ms: u64,
    #[serde(default = "default_healthy_threshold")]
    pub healthy_threshold: u32,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_healthy_status_codes")]
    pub healthy_status_codes: Vec<u16>,
    /// Use HTTPS for health check probes instead of HTTP.
    #[serde(default)]
    pub use_tls: bool,
}

impl Default for ActiveHealthCheck {
    fn default() -> Self {
        Self {
            http_path: default_health_path(),
            interval_seconds: default_health_interval(),
            timeout_ms: default_health_timeout(),
            healthy_threshold: default_healthy_threshold(),
            unhealthy_threshold: default_unhealthy_threshold(),
            healthy_status_codes: default_healthy_status_codes(),
            use_tls: false,
        }
    }
}

fn default_health_path() -> String {
    "/health".to_string()
}
fn default_health_interval() -> u64 {
    10
}
fn default_health_timeout() -> u64 {
    5000
}
fn default_healthy_threshold() -> u32 {
    3
}
fn default_unhealthy_threshold() -> u32 {
    3
}
fn default_healthy_status_codes() -> Vec<u16> {
    vec![200, 302]
}

/// Passive health check configuration.
///
/// When a target accumulates `unhealthy_threshold` failures (matching
/// `unhealthy_status_codes`) within `unhealthy_window_seconds`, it is
/// marked unhealthy and removed from the load balancer rotation.
///
/// Recovery happens via two mechanisms:
/// 1. **Automatic timer**: After `healthy_after_seconds` (default 30s),
///    the target is automatically restored to the rotation, giving it
///    a fresh chance — similar to a circuit breaker's half-open state.
/// 2. **On-success recovery**: If a request to the target succeeds
///    (e.g., via the all-unhealthy fallback path), it is immediately
///    marked healthy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PassiveHealthCheck {
    #[serde(default = "default_passive_unhealthy_codes")]
    pub unhealthy_status_codes: Vec<u16>,
    #[serde(default = "default_unhealthy_threshold")]
    pub unhealthy_threshold: u32,
    #[serde(default = "default_passive_window")]
    pub unhealthy_window_seconds: u64,
    /// Seconds after which an unhealthy target is automatically restored
    /// to the rotation. Acts as a recovery timer / half-open circuit breaker.
    /// Default: 30 seconds. Set to 0 to disable automatic recovery (rely
    /// on active health checks or all-unhealthy fallback only).
    #[serde(default = "default_passive_healthy_after")]
    pub healthy_after_seconds: u64,
}

impl Default for PassiveHealthCheck {
    fn default() -> Self {
        Self {
            unhealthy_status_codes: default_passive_unhealthy_codes(),
            unhealthy_threshold: default_unhealthy_threshold(),
            unhealthy_window_seconds: default_passive_window(),
            healthy_after_seconds: default_passive_healthy_after(),
        }
    }
}

fn default_passive_healthy_after() -> u64 {
    30
}

fn default_passive_unhealthy_codes() -> Vec<u16> {
    vec![500, 502, 503, 504]
}
fn default_passive_window() -> u64 {
    30
}

/// Health check configuration for an upstream.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HealthCheckConfig {
    #[serde(default)]
    pub active: Option<ActiveHealthCheck>,
    #[serde(default)]
    pub passive: Option<PassiveHealthCheck>,
}

/// An upstream defines a group of backend targets with load balancing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub targets: Vec<UpstreamTarget>,
    #[serde(default)]
    pub algorithm: LoadBalancerAlgorithm,
    #[serde(default)]
    pub hash_on: Option<String>,
    #[serde(default)]
    pub health_checks: Option<HealthCheckConfig>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Circuit breaker configuration for a proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CircuitBreakerConfig {
    #[serde(default = "default_failure_threshold")]
    pub failure_threshold: u32,
    #[serde(default = "default_success_threshold")]
    pub success_threshold: u32,
    #[serde(default = "default_circuit_timeout")]
    pub timeout_seconds: u64,
    #[serde(default = "default_failure_status_codes")]
    pub failure_status_codes: Vec<u16>,
    #[serde(default = "default_half_open_max")]
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            timeout_seconds: default_circuit_timeout(),
            failure_status_codes: default_failure_status_codes(),
            half_open_max_requests: default_half_open_max(),
        }
    }
}

fn default_failure_threshold() -> u32 {
    5
}
fn default_success_threshold() -> u32 {
    3
}
fn default_circuit_timeout() -> u64 {
    30
}
fn default_failure_status_codes() -> Vec<u16> {
    vec![500, 502, 503, 504]
}
fn default_half_open_max() -> u32 {
    1
}

/// Retry backoff strategy.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BackoffStrategy {
    Fixed { delay_ms: u64 },
    Exponential { base_ms: u64, max_ms: u64 },
}

impl Default for BackoffStrategy {
    fn default() -> Self {
        Self::Fixed { delay_ms: 100 }
    }
}

/// Retry configuration for a proxy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RetryConfig {
    #[serde(default = "default_max_retries")]
    pub max_retries: u32,
    #[serde(default = "default_retryable_status_codes")]
    pub retryable_status_codes: Vec<u16>,
    #[serde(default = "default_retryable_methods")]
    pub retryable_methods: Vec<String>,
    #[serde(default)]
    pub backoff: BackoffStrategy,
    /// Whether to retry on TCP/connection failures (connect refused, timeout,
    /// DNS resolution failure, TLS handshake error). Defaults to true.
    /// This is independent of `retryable_status_codes` — a connection failure
    /// never reaches the HTTP layer, so it would not be retried by status code
    /// matching alone.
    #[serde(default = "default_retry_on_connect_failure")]
    pub retry_on_connect_failure: bool,
}

impl Default for RetryConfig {
    fn default() -> Self {
        Self {
            max_retries: default_max_retries(),
            retryable_status_codes: default_retryable_status_codes(),
            retryable_methods: default_retryable_methods(),
            backoff: BackoffStrategy::default(),
            retry_on_connect_failure: default_retry_on_connect_failure(),
        }
    }
}

fn default_max_retries() -> u32 {
    3
}
fn default_retryable_status_codes() -> Vec<u16> {
    vec![502, 503, 504]
}
fn default_retryable_methods() -> Vec<String> {
    vec![
        "GET".to_string(),
        "HEAD".to_string(),
        "OPTIONS".to_string(),
        "PUT".to_string(),
        "DELETE".to_string(),
    ]
}
fn default_retry_on_connect_failure() -> bool {
    true
}

/// Backend protocol for a proxy resource.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum BackendProtocol {
    Http,
    Https,
    Ws,
    Wss,
    Grpc,
    Grpcs,
    H3,
}

impl std::fmt::Display for BackendProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Http => write!(f, "http"),
            Self::Https => write!(f, "https"),
            Self::Ws => write!(f, "ws"),
            Self::Wss => write!(f, "wss"),
            Self::Grpc => write!(f, "grpc"),
            Self::Grpcs => write!(f, "grpcs"),
            Self::H3 => write!(f, "h3"),
        }
    }
}

/// Authentication mode for a proxy.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AuthMode {
    #[default]
    Single,
    Multi,
}

/// Controls whether proxy responses are streamed or buffered before
/// being forwarded to the client.
///
/// - **Stream** (default): Response chunks are forwarded to the client as
///   they arrive from the backend. Lower memory usage and lower latency
///   for large responses. Incompatible with plugins that need to inspect
///   or modify the full response body — those will automatically force
///   buffering regardless of this setting.
/// - **Buffer**: The entire response body is collected in memory before
///   forwarding. Required when a plugin needs access to the complete
///   response body (e.g., response body transformation).
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ResponseBodyMode {
    #[default]
    Stream,
    Buffer,
}

/// Plugin scope (global or per-proxy).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginScope {
    Global,
    Proxy,
}

/// A proxy resource defines a route from a listen_path to a backend.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    pub listen_path: String,
    pub backend_protocol: BackendProtocol,
    pub backend_host: String,
    pub backend_port: u16,
    #[serde(default)]
    pub backend_path: Option<String>,
    #[serde(default = "default_true")]
    pub strip_listen_path: bool,
    #[serde(default)]
    pub preserve_host_header: bool,
    #[serde(default = "default_connect_timeout")]
    pub backend_connect_timeout_ms: u64,
    #[serde(default = "default_read_timeout")]
    pub backend_read_timeout_ms: u64,
    #[serde(default = "default_write_timeout")]
    pub backend_write_timeout_ms: u64,
    #[serde(default)]
    pub backend_tls_client_cert_path: Option<String>,
    #[serde(default)]
    pub backend_tls_client_key_path: Option<String>,
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    #[serde(default)]
    pub backend_tls_server_ca_cert_path: Option<String>,
    #[serde(default)]
    pub dns_override: Option<String>,
    #[serde(default)]
    pub dns_cache_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default)]
    pub plugins: Vec<PluginAssociation>,
    // Connection pooling settings (optional - override global defaults)
    #[serde(default)]
    pub pool_max_idle_per_host: Option<usize>,
    #[serde(default)]
    pub pool_idle_timeout_seconds: Option<u64>,
    #[serde(default)]
    pub pool_enable_http_keep_alive: Option<bool>,
    #[serde(default)]
    pub pool_enable_http2: Option<bool>,
    #[serde(default)]
    pub pool_tcp_keepalive_seconds: Option<u64>,
    #[serde(default)]
    pub pool_http2_keep_alive_interval_seconds: Option<u64>,
    #[serde(default)]
    pub pool_http2_keep_alive_timeout_seconds: Option<u64>,
    /// Optional upstream ID for load-balanced backends.
    /// When set, overrides backend_host/backend_port with upstream target selection.
    #[serde(default)]
    pub upstream_id: Option<String>,
    /// Circuit breaker configuration.
    #[serde(default)]
    pub circuit_breaker: Option<CircuitBreakerConfig>,
    /// Retry configuration.
    #[serde(default)]
    pub retry: Option<RetryConfig>,
    /// Response body mode: `stream` (default) or `buffer`.
    /// Streaming forwards response chunks as they arrive from the backend.
    /// Buffering collects the entire response before forwarding. Plugins
    /// that require the full response body will force buffering regardless
    /// of this setting.
    #[serde(default)]
    pub response_body_mode: ResponseBodyMode,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Links a proxy to a plugin configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginAssociation {
    pub plugin_config_id: String,
}

/// A consumer resource (API user).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Consumer {
    pub id: String,
    pub username: String,
    #[serde(default)]
    pub custom_id: Option<String>,
    #[serde(default)]
    pub credentials: HashMap<String, serde_json::Value>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// A plugin configuration resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    pub id: String,
    pub plugin_name: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub scope: PluginScope,
    #[serde(default)]
    pub proxy_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Full gateway configuration snapshot.
#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct GatewayConfig {
    /// Configuration schema version. Defaults to "1" for backwards compatibility
    /// with config files that predate the versioning system.
    #[serde(default = "default_config_version")]
    pub version: String,
    pub proxies: Vec<Proxy>,
    pub consumers: Vec<Consumer>,
    pub plugin_configs: Vec<PluginConfig>,
    #[serde(default)]
    pub upstreams: Vec<Upstream>,
    #[serde(default = "Utc::now")]
    pub loaded_at: DateTime<Utc>,
}

/// The current config schema version. Increment this when adding config migrations.
pub const CURRENT_CONFIG_VERSION: &str = "1";

fn default_config_version() -> String {
    "1".to_string()
}

impl GatewayConfig {
    /// Validate that all proxy listen_paths are unique.
    pub fn validate_unique_listen_paths(&self) -> Result<(), Vec<String>> {
        let mut seen = HashMap::new();
        let mut duplicates = Vec::new();
        for proxy in &self.proxies {
            if let Some(existing) = seen.insert(&proxy.listen_path, &proxy.id) {
                duplicates.push(format!(
                    "Duplicate listen_path '{}' found in proxy '{}' (conflicts with '{}')",
                    proxy.listen_path, proxy.id, existing
                ));
            }
        }
        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate that consumer usernames and custom_ids are unique.
    ///
    /// In database mode the DB enforces this via UNIQUE constraints. In file
    /// mode there's no DB, so this catches duplicates at config load time
    /// and prevents the gateway from starting with ambiguous identity mappings
    /// that would cause incorrect OAuth2/JWT authentication.
    pub fn validate_unique_consumer_identities(&self) -> Result<(), Vec<String>> {
        let mut seen_usernames: HashMap<&str, &str> = HashMap::new();
        let mut seen_custom_ids: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for consumer in &self.consumers {
            if let Some(existing_id) = seen_usernames.insert(&consumer.username, &consumer.id) {
                duplicates.push(format!(
                    "Duplicate consumer username '{}' in consumer '{}' (conflicts with '{}')",
                    consumer.username, consumer.id, existing_id
                ));
            }
            if let Some(ref custom_id) = consumer.custom_id
                && let Some(existing_id) = seen_custom_ids.insert(custom_id, &consumer.id)
            {
                duplicates.push(format!(
                    "Duplicate consumer custom_id '{}' in consumer '{}' (conflicts with '{}')",
                    custom_id, consumer.id, existing_id
                ));
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Build a sorted list of listen_paths for longest prefix matching.
    #[allow(dead_code)]
    pub fn build_route_table(&self) -> Vec<(String, String)> {
        let mut routes: Vec<(String, String)> = self
            .proxies
            .iter()
            .map(|p| (p.listen_path.clone(), p.id.clone()))
            .collect();
        // Sort by path length descending for longest prefix match
        routes.sort_by(|a, b| b.0.len().cmp(&a.0.len()));
        routes
    }
}

fn default_true() -> bool {
    true
}

fn default_connect_timeout() -> u64 {
    5000
}

fn default_read_timeout() -> u64 {
    30000
}

fn default_write_timeout() -> u64 {
    30000
}
