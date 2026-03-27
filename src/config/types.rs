use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Maximum length for resource IDs.
const MAX_ID_LENGTH: usize = 254;

/// Regex pattern for valid resource IDs.
/// Must start with alphanumeric, followed by alphanumeric, dots, underscores, or hyphens.
static ID_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-zA-Z0-9][a-zA-Z0-9._-]*$").expect("invalid ID regex"));

/// Regex for valid exact hostnames: lowercase letters, digits, dots, hyphens.
static HOST_REGEX: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"^[a-z0-9]([a-z0-9.-]*[a-z0-9])?$").expect("invalid host regex"));

/// Regex for wildcard host patterns: *.domain.tld
static WILDCARD_HOST_REGEX: LazyLock<Regex> = LazyLock::new(|| {
    Regex::new(r"^\*\.[a-z0-9]([a-z0-9.-]*[a-z0-9])?$").expect("invalid wildcard host regex")
});

/// Validate a resource ID format.
///
/// Valid IDs must:
/// - Be non-empty and at most 254 characters
/// - Start with an alphanumeric character
/// - Contain only alphanumeric characters, dots, underscores, or hyphens
///
/// Returns `Ok(())` if valid, or `Err(message)` describing the violation.
pub fn validate_resource_id(id: &str) -> Result<(), String> {
    if id.is_empty() {
        return Err("ID must not be empty".to_string());
    }
    if id.len() > MAX_ID_LENGTH {
        return Err(format!(
            "ID must be at most {} characters, got {}",
            MAX_ID_LENGTH,
            id.len()
        ));
    }
    if !ID_REGEX.is_match(id) {
        return Err(format!(
            "ID '{}' is invalid: must start with an alphanumeric character and contain only \
             alphanumeric characters, dots, underscores, or hyphens",
            id
        ));
    }
    Ok(())
}

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

/// Health check probe type.
#[derive(Debug, Clone, Copy, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum HealthProbeType {
    /// HTTP GET probe (default). Sends a request to `http_path` and checks status code.
    #[default]
    Http,
    /// TCP probe. Attempts a TCP connection — success means healthy.
    Tcp,
    /// UDP probe. Sends `udp_probe_payload` and expects any response within timeout.
    Udp,
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
    /// Probe type: `http` (default), `tcp`, or `udp`.
    #[serde(default)]
    pub probe_type: HealthProbeType,
    /// Hex-encoded probe payload for UDP health checks.
    /// Sent to the target; any response within timeout means healthy.
    #[serde(default)]
    pub udp_probe_payload: Option<String>,
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
            probe_type: HealthProbeType::default(),
            udp_probe_payload: None,
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
    #[serde(default)]
    pub service_discovery: Option<ServiceDiscoveryConfig>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// Service discovery provider type.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SdProvider {
    /// DNS-based service discovery using SRV records.
    DnsSd,
    /// Kubernetes EndpointSlice-based service discovery.
    Kubernetes,
    /// HashiCorp Consul service discovery via HTTP API.
    Consul,
}

/// DNS-SD specific configuration (SRV record-based discovery).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSdConfig {
    /// The DNS name to query for SRV records (e.g., "_http._tcp.my-service.example.com").
    pub service_name: String,
    /// Poll interval in seconds for re-querying DNS records. Default: 30.
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

/// Kubernetes service discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct KubernetesConfig {
    /// Kubernetes namespace. Default: "default".
    #[serde(default = "default_k8s_namespace")]
    pub namespace: String,
    /// Service name in Kubernetes.
    pub service_name: String,
    /// Port name to select from EndpointSlice. If not set, uses the first port.
    #[serde(default)]
    pub port_name: Option<String>,
    /// Label selector for filtering EndpointSlices.
    #[serde(default)]
    pub label_selector: Option<String>,
    /// Poll interval in seconds. Default: 30.
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

/// Consul service discovery configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConsulConfig {
    /// Consul HTTP API address (e.g., "http://consul:8500").
    pub address: String,
    /// Service name registered in Consul.
    pub service_name: String,
    /// Datacenter filter. If not set, uses the local datacenter.
    #[serde(default)]
    pub datacenter: Option<String>,
    /// Service tag filter. If not set, no tag filtering.
    #[serde(default)]
    pub tag: Option<String>,
    /// Only return healthy services. Default: true.
    #[serde(default = "default_sd_healthy_only")]
    pub healthy_only: bool,
    /// Consul ACL token for authentication.
    #[serde(default)]
    pub token: Option<String>,
    /// Poll interval in seconds for blocking query long-poll. Default: 30.
    #[serde(default = "default_sd_poll_interval")]
    pub poll_interval_seconds: u64,
}

/// Service discovery configuration for an upstream.
///
/// Attaches a dynamic service discovery source to an upstream. Discovered
/// targets are merged with any statically configured targets and fed into
/// the load balancer. If the discovery source becomes unavailable, the
/// gateway continues serving with the last-known targets.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServiceDiscoveryConfig {
    /// The service discovery provider to use.
    pub provider: SdProvider,
    /// DNS-SD provider configuration. Required when `provider` is `dns_sd`.
    #[serde(default)]
    pub dns_sd: Option<DnsSdConfig>,
    /// Kubernetes provider configuration. Required when `provider` is `kubernetes`.
    #[serde(default)]
    pub kubernetes: Option<KubernetesConfig>,
    /// Consul provider configuration. Required when `provider` is `consul`.
    #[serde(default)]
    pub consul: Option<ConsulConfig>,
    /// Default weight assigned to discovered targets. Default: 1.
    #[serde(default = "default_weight")]
    pub default_weight: u32,
}

fn default_sd_poll_interval() -> u64 {
    30
}

fn default_k8s_namespace() -> String {
    "default".to_string()
}

fn default_sd_healthy_only() -> bool {
    true
}

/// Circuit breaker configuration for a proxy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    Tcp,
    #[serde(rename = "tcp_tls")]
    TcpTls,
    Udp,
    Dtls,
}

impl BackendProtocol {
    /// Returns true if this protocol is a raw stream proxy (TCP/UDP) rather than HTTP-based.
    pub fn is_stream_proxy(&self) -> bool {
        matches!(self, Self::Tcp | Self::TcpTls | Self::Udp | Self::Dtls)
    }

    /// Returns true if this protocol uses UDP transport.
    pub fn is_udp(&self) -> bool {
        matches!(self, Self::Udp | Self::Dtls)
    }

    /// Returns true if the backend connection uses TLS/DTLS.
    #[allow(dead_code)] // Used in Phase 2 (TCP/UDP proxy TLS origination)
    pub fn is_tls_backend(&self) -> bool {
        matches!(self, Self::TcpTls | Self::Dtls)
    }
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
            Self::Tcp => write!(f, "tcp"),
            Self::TcpTls => write!(f, "tcp_tls"),
            Self::Udp => write!(f, "udp"),
            Self::Dtls => write!(f, "dtls"),
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
    /// Optional list of hostnames this proxy matches on.
    /// Empty means match all hosts (backward compatible catch-all).
    /// Supports exact hostnames and single-level wildcard prefixes (e.g., "*.example.com").
    #[serde(default)]
    pub hosts: Vec<String>,
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
    // HTTP/2 flow control & performance tuning overrides
    #[serde(default)]
    pub pool_http2_initial_stream_window_size: Option<u32>,
    #[serde(default)]
    pub pool_http2_initial_connection_window_size: Option<u32>,
    #[serde(default)]
    pub pool_http2_adaptive_window: Option<bool>,
    #[serde(default)]
    pub pool_http2_max_frame_size: Option<u32>,
    #[serde(default)]
    pub pool_http2_max_concurrent_streams: Option<u32>,
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
    /// Port the gateway listens on for this TCP/UDP proxy.
    /// Required when backend_protocol is Tcp/TcpTls/Udp/Dtls.
    /// Not used for HTTP-based protocols.
    #[serde(default)]
    pub listen_port: Option<u16>,
    /// Whether to terminate TLS on the gateway side for incoming TCP connections.
    /// For TCP: uses the gateway's TLS certificate for TLS termination.
    /// For UDP: uses the DTLS certificate for DTLS termination (ECDSA P-256 or Ed25519).
    #[serde(default)]
    pub frontend_tls: bool,
    /// UDP session idle timeout in seconds. After this duration of inactivity,
    /// the UDP session mapping is removed. Default: 60 seconds.
    #[serde(default = "default_udp_idle_timeout")]
    pub udp_idle_timeout_seconds: u64,
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
    /// Validate that all proxy (host, listen_path) combinations are unique.
    ///
    /// Two proxies may share the same `listen_path` if their `hosts` sets are
    /// completely disjoint. A proxy with empty `hosts` (catch-all) conflicts
    /// with any other proxy that has the same `listen_path` and also has empty
    /// hosts. A specific host in one proxy's `hosts` conflicts if another proxy
    /// with the same `listen_path` lists the same host or is a catch-all.
    pub fn validate_unique_listen_paths(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for (i, proxy_a) in self.proxies.iter().enumerate() {
            for proxy_b in self.proxies.iter().skip(i + 1) {
                if proxy_a.listen_path != proxy_b.listen_path {
                    continue;
                }
                // Same listen_path — check if hosts overlap
                if hosts_overlap(&proxy_a.hosts, &proxy_b.hosts) {
                    if proxy_a.hosts.is_empty() && proxy_b.hosts.is_empty() {
                        errors.push(format!(
                            "Duplicate listen_path '{}' found in proxy '{}' (conflicts with '{}')",
                            proxy_a.listen_path, proxy_b.id, proxy_a.id
                        ));
                    } else {
                        errors.push(format!(
                            "Overlapping host+listen_path for '{}' in proxy '{}' (conflicts with '{}')",
                            proxy_a.listen_path, proxy_b.id, proxy_a.id
                        ));
                    }
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate host entries on all proxies.
    ///
    /// Each host must be either a valid lowercase hostname or a wildcard
    /// pattern `*.domain.tld`. No scheme, no port, no path component.
    pub fn validate_hosts(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for proxy in &self.proxies {
            for host in &proxy.hosts {
                if let Err(msg) = validate_host_entry(host) {
                    errors.push(format!("Proxy '{}': {}", proxy.id, msg));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that regex listen_paths compile correctly.
    ///
    /// Listen paths starting with `~` are treated as regex patterns. The `~`
    /// prefix is stripped and the remainder is compiled as a regex (auto-anchored
    /// with `^` if not already). Compilation errors are reported here at config
    /// load time rather than silently skipping routes at runtime.
    pub fn validate_regex_listen_paths(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for proxy in &self.proxies {
            if proxy.listen_path.starts_with('~') {
                let pattern = &proxy.listen_path[1..];
                if pattern.is_empty() {
                    errors.push(format!(
                        "Proxy '{}': regex listen_path '~' has empty pattern",
                        proxy.id
                    ));
                    continue;
                }
                let anchored = if pattern.starts_with('^') {
                    pattern.to_string()
                } else {
                    format!("^{}", pattern)
                };
                if let Err(e) = Regex::new(&anchored) {
                    errors.push(format!(
                        "Proxy '{}': invalid regex listen_path '{}': {}",
                        proxy.id, proxy.listen_path, e
                    ));
                }
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Normalize all proxy host entries to lowercase.
    pub fn normalize_hosts(&mut self) {
        for proxy in &mut self.proxies {
            for host in &mut proxy.hosts {
                *host = host.to_lowercase();
            }
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

    /// Validate that consumer keyauth API keys are unique across all consumers.
    ///
    /// If two consumers share the same API key, the ConsumerIndex silently
    /// overwrites one, causing the wrong consumer to be authenticated.
    pub fn validate_unique_consumer_credentials(&self) -> Result<(), Vec<String>> {
        let mut seen_keyauth: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for consumer in &self.consumers {
            if let Some(key_creds) = consumer.credentials.get("keyauth")
                && let Some(key) = key_creds.get("key").and_then(|s| s.as_str())
                && let Some(existing_id) = seen_keyauth.insert(key, &consumer.id)
            {
                // Do NOT include the API key value in the error message for security
                duplicates.push(format!(
                    "Duplicate keyauth API key in consumer '{}' (conflicts with consumer '{}')",
                    consumer.id, existing_id
                ));
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate that upstream names are unique when present.
    ///
    /// The `name` field is optional — multiple upstreams with `None` names
    /// are allowed. Only non-empty names must be unique.
    pub fn validate_unique_upstream_names(&self) -> Result<(), Vec<String>> {
        let mut seen: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for upstream in &self.upstreams {
            if let Some(ref name) = upstream.name
                && let Some(existing_id) = seen.insert(name.as_str(), &upstream.id)
            {
                duplicates.push(format!(
                    "Duplicate upstream name '{}' in upstream '{}' (conflicts with '{}')",
                    name, upstream.id, existing_id
                ));
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate that proxy names are unique when present.
    ///
    /// The `name` field is optional — multiple proxies with `None` names
    /// are allowed. Only non-empty names must be unique.
    pub fn validate_unique_proxy_names(&self) -> Result<(), Vec<String>> {
        let mut seen: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for proxy in &self.proxies {
            if let Some(ref name) = proxy.name
                && let Some(existing_id) = seen.insert(name.as_str(), &proxy.id)
            {
                duplicates.push(format!(
                    "Duplicate proxy name '{}' in proxy '{}' (conflicts with '{}')",
                    name, proxy.id, existing_id
                ));
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate that proxy upstream_id references point to existing upstreams.
    ///
    /// In database mode the DB enforces this via foreign key constraints.
    /// In file mode there's no DB, so this catches dangling references
    /// at config load time.
    pub fn validate_upstream_references(&self) -> Result<(), Vec<String>> {
        let upstream_ids: HashSet<&str> = self.upstreams.iter().map(|u| u.id.as_str()).collect();
        let mut errors = Vec::new();

        for proxy in &self.proxies {
            if let Some(ref uid) = proxy.upstream_id
                && !upstream_ids.contains(uid.as_str())
            {
                errors.push(format!(
                    "Proxy '{}' references non-existent upstream_id '{}'",
                    proxy.id, uid
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that each proxy has at most one plugin of each type.
    ///
    /// If a proxy has two plugin configs with the same `plugin_name`, the
    /// PluginCache silently uses last-one-wins. This validation catches
    /// that misconfiguration at load time.
    pub fn validate_unique_plugins_per_proxy(&self) -> Result<(), Vec<String>> {
        let plugin_name_by_id: HashMap<&str, &str> = self
            .plugin_configs
            .iter()
            .map(|pc| (pc.id.as_str(), pc.plugin_name.as_str()))
            .collect();

        let mut errors = Vec::new();

        for proxy in &self.proxies {
            let mut seen_names: HashMap<&str, &str> = HashMap::new();
            for assoc in &proxy.plugins {
                if let Some(&plugin_name) = plugin_name_by_id.get(assoc.plugin_config_id.as_str())
                    && let Some(existing_config_id) =
                        seen_names.insert(plugin_name, &assoc.plugin_config_id)
                {
                    errors.push(format!(
                        "Proxy '{}' has duplicate plugin '{}' (config IDs '{}' and '{}')",
                        proxy.id, plugin_name, existing_config_id, assoc.plugin_config_id
                    ));
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that all resource IDs are well-formed.
    ///
    /// Checks every proxy, consumer, plugin_config, and upstream ID against
    /// the `validate_resource_id` format rules.
    pub fn validate_resource_ids(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        for proxy in &self.proxies {
            if let Err(msg) = validate_resource_id(&proxy.id) {
                errors.push(format!("Proxy ID: {}", msg));
            }
        }
        for consumer in &self.consumers {
            if let Err(msg) = validate_resource_id(&consumer.id) {
                errors.push(format!("Consumer ID: {}", msg));
            }
        }
        for pc in &self.plugin_configs {
            if let Err(msg) = validate_resource_id(&pc.id) {
                errors.push(format!("PluginConfig ID: {}", msg));
            }
        }
        for upstream in &self.upstreams {
            if let Err(msg) = validate_resource_id(&upstream.id) {
                errors.push(format!("Upstream ID: {}", msg));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate that all resource IDs are unique within their type.
    ///
    /// In database mode the DB PRIMARY KEY constraint enforces this.
    /// In file mode there's no DB, so this catches duplicate IDs at
    /// config load time.
    pub fn validate_unique_resource_ids(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        let mut seen_proxy_ids: HashSet<&str> = HashSet::new();
        for proxy in &self.proxies {
            if !seen_proxy_ids.insert(&proxy.id) {
                errors.push(format!("Duplicate proxy ID '{}'", proxy.id));
            }
        }

        let mut seen_consumer_ids: HashSet<&str> = HashSet::new();
        for consumer in &self.consumers {
            if !seen_consumer_ids.insert(&consumer.id) {
                errors.push(format!("Duplicate consumer ID '{}'", consumer.id));
            }
        }

        let mut seen_plugin_ids: HashSet<&str> = HashSet::new();
        for pc in &self.plugin_configs {
            if !seen_plugin_ids.insert(&pc.id) {
                errors.push(format!("Duplicate plugin_config ID '{}'", pc.id));
            }
        }

        let mut seen_upstream_ids: HashSet<&str> = HashSet::new();
        for upstream in &self.upstreams {
            if !seen_upstream_ids.insert(&upstream.id) {
                errors.push(format!("Duplicate upstream ID '{}'", upstream.id));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate stream proxy (TCP/UDP) configuration.
    ///
    /// - Stream proxies must have a `listen_port` in range 1024-65535.
    /// - `listen_port` must be unique across all stream proxies.
    /// - HTTP proxies must not set `listen_port`.
    pub fn validate_stream_proxies(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let mut seen_ports: HashMap<u16, &str> = HashMap::new();

        for proxy in &self.proxies {
            if proxy.backend_protocol.is_stream_proxy() {
                match proxy.listen_port {
                    None => {
                        errors.push(format!(
                            "Stream proxy '{}' (protocol {}) must have a listen_port",
                            proxy.id, proxy.backend_protocol
                        ));
                    }
                    Some(port) if port < 1 => {
                        errors.push(format!(
                            "Stream proxy '{}' has invalid listen_port {} (must be >= 1)",
                            proxy.id, port
                        ));
                    }
                    Some(port) => {
                        if let Some(existing_id) = seen_ports.insert(port, &proxy.id) {
                            errors.push(format!(
                                "Duplicate listen_port {} in proxy '{}' (conflicts with '{}')",
                                port, proxy.id, existing_id
                            ));
                        }
                    }
                }
            } else if proxy.listen_port.is_some() {
                errors.push(format!(
                    "HTTP proxy '{}' (protocol {}) must not set listen_port",
                    proxy.id, proxy.backend_protocol
                ));
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Normalize stream proxy listen_paths to synthetic values.
    ///
    /// TCP/UDP proxies don't use URL path routing. This sets their `listen_path`
    /// to a synthetic value like `__tcp:5432` or `__udp:5353` so the existing
    /// UNIQUE constraint and config delta logic works unchanged.
    pub fn normalize_stream_proxy_paths(&mut self) {
        for proxy in &mut self.proxies {
            if proxy.backend_protocol.is_stream_proxy()
                && let Some(port) = proxy.listen_port
            {
                let prefix = if proxy.backend_protocol.is_udp() {
                    "__udp"
                } else {
                    "__tcp"
                };
                proxy.listen_path = format!("{}:{}", prefix, port);
            }
        }
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

fn default_udp_idle_timeout() -> u64 {
    60
}

/// Validate a single host entry.
///
/// Valid formats:
/// - Exact hostname: `api.example.com` (lowercase, no scheme/port/path)
/// - Wildcard: `*.example.com` (single-level wildcard prefix)
pub fn validate_host_entry(host: &str) -> Result<(), String> {
    if host.is_empty() {
        return Err("host entry must not be empty".to_string());
    }
    if host.contains("://") {
        return Err(format!(
            "host '{}' must not contain a scheme (e.g., 'http://')",
            host
        ));
    }
    if host.contains(':') && !host.starts_with('*') {
        return Err(format!("host '{}' must not contain a port number", host));
    }
    if host.contains('/') {
        return Err(format!("host '{}' must not contain a path", host));
    }
    if host != host.to_lowercase() {
        return Err(format!(
            "host '{}' must be lowercase (got mixed case)",
            host
        ));
    }
    if host.starts_with("*.") {
        if !WILDCARD_HOST_REGEX.is_match(host) {
            return Err(format!(
                "wildcard host '{}' is invalid: must be '*.domain.tld' format",
                host
            ));
        }
    } else if host.contains('*') {
        return Err(format!(
            "host '{}' has invalid wildcard: '*' is only allowed as prefix '*.domain'",
            host
        ));
    } else if !HOST_REGEX.is_match(host) {
        return Err(format!(
            "host '{}' is invalid: must be a valid hostname (lowercase letters, digits, dots, hyphens)",
            host
        ));
    }
    Ok(())
}

/// Check whether two host lists overlap.
///
/// Empty hosts means "match all" (catch-all), which overlaps with everything.
/// Otherwise, checks for any shared exact host or wildcard-to-exact match.
pub fn hosts_overlap(a: &[String], b: &[String]) -> bool {
    // Empty = catch-all, overlaps with everything
    if a.is_empty() || b.is_empty() {
        return true;
    }

    let a_set: HashSet<&str> = a.iter().map(|s| s.as_str()).collect();
    let b_set: HashSet<&str> = b.iter().map(|s| s.as_str()).collect();

    // Check exact overlaps
    if a_set.intersection(&b_set).next().is_some() {
        return true;
    }

    // Check wildcard-to-exact and wildcard-to-wildcard overlaps
    for host_a in a {
        for host_b in b {
            if wildcard_matches(host_a, host_b) || wildcard_matches(host_b, host_a) {
                return true;
            }
        }
    }

    false
}

/// Check if a wildcard pattern matches a hostname.
/// `*.example.com` matches `foo.example.com` but not `example.com` or `a.b.example.com`.
pub fn wildcard_matches(pattern: &str, hostname: &str) -> bool {
    if let Some(suffix) = pattern.strip_prefix("*.") {
        // Don't match the base domain itself
        if hostname == suffix {
            return false;
        }
        // Must end with .suffix and have exactly one label before it
        if let Some(prefix) = hostname.strip_suffix(suffix) {
            // prefix should be "something." with no additional dots
            if prefix.ends_with('.')
                && !prefix[..prefix.len() - 1].is_empty()
                && !prefix[..prefix.len() - 1].contains('.')
            {
                return true;
            }
        }
        false
    } else {
        pattern == hostname
    }
}
