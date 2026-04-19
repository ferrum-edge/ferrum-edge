//! Core domain model types and validation for the gateway configuration.
//!
//! Key design decisions:
//! - **Regex auto-anchoring**: `anchor_regex_pattern()` adds `^`/`$` to regex
//!   listen_paths for full-path matching, preventing accidental prefix matches.
//! - **Stream proxy routing**: TCP/UDP proxies are matched by `listen_port`,
//!   not `listen_path`, so path validation and router invalidation skip them.
//! - **Validation deduplication**: TLS cert/key paths are validated via a
//!   `validated_tls_paths` cache so each unique file is parsed only once.
//! - **Control character rejection**: Resource IDs, hostnames, and paths reject
//!   control characters to prevent log injection attacks.

use chrono::{DateTime, Utc};
use regex::Regex;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::sync::LazyLock;

/// Maximum length for resource IDs.
const MAX_ID_LENGTH: usize = 254;

// ---- Field length limits (aligned with DB schema VARCHAR widths) ----

/// Maximum length for name fields (proxy.name, upstream.name). Matches VARCHAR(255) in DB.
pub const MAX_NAME_LENGTH: usize = 255;
/// Maximum length for backend_host. Matches VARCHAR(255) in DB.
pub const MAX_BACKEND_HOST_LENGTH: usize = 255;
/// Maximum length for backend_path.
pub const MAX_BACKEND_PATH_LENGTH: usize = 2048;
/// Maximum length for listen_path (non-regex). Matches VARCHAR(500) in DB.
pub const MAX_LISTEN_PATH_LENGTH: usize = 500;
/// Maximum length for consumer username. Matches VARCHAR(255) in DB.
pub const MAX_USERNAME_LENGTH: usize = 255;
/// Maximum length for consumer custom_id. Matches VARCHAR(255) in DB.
pub const MAX_CUSTOM_ID_LENGTH: usize = 255;
/// Maximum length for individual hostname entries (DNS spec is 253).
pub const MAX_HOST_LENGTH: usize = 253;
/// Maximum number of host entries per proxy.
pub const MAX_HOSTS_PER_PROXY: usize = 100;
/// Maximum number of targets per upstream.
pub const MAX_TARGETS_PER_UPSTREAM: usize = 1000;
/// Maximum number of tags per upstream target.
pub const MAX_TAGS_PER_TARGET: usize = 50;
/// Maximum length for a tag key or value.
pub const MAX_TAG_LENGTH: usize = 255;
/// Maximum size of plugin config JSON in bytes.
pub const MAX_PLUGIN_CONFIG_SIZE: usize = 1_048_576; // 1 MiB
/// Maximum size of consumer credentials JSON in bytes.
pub const MAX_CREDENTIALS_SIZE: usize = 65_536; // 64 KiB
/// Maximum length for individual credential string values (API keys, secrets, identities).
pub const MAX_CREDENTIAL_VALUE_LENGTH: usize = 4096;
/// Minimum length for JWT secrets (admin API and consumer credentials).
pub const MIN_JWT_SECRET_LENGTH: usize = 32;
/// Default maximum number of credential entries per type (for zero-downtime rotation).
/// Overridable at runtime via `FERRUM_MAX_CREDENTIALS_PER_TYPE` env var / conf file.
pub const DEFAULT_MAX_CREDENTIALS_PER_TYPE: usize = 2;

/// Resolve the runtime max credentials per type from env var / conf file, falling
/// back to `DEFAULT_MAX_CREDENTIALS_PER_TYPE` if unset or unparsable.
pub fn max_credentials_per_type() -> usize {
    crate::config::conf_file::resolve_ferrum_var("FERRUM_MAX_CREDENTIALS_PER_TYPE")
        .and_then(|v| v.parse().ok())
        .unwrap_or(DEFAULT_MAX_CREDENTIALS_PER_TYPE)
}
/// Maximum number of ACL groups per consumer.
pub const MAX_ACL_GROUPS_PER_CONSUMER: usize = 500;
/// Maximum length for an ACL group name.
pub const MAX_ACL_GROUP_LENGTH: usize = 255;
/// Maximum length for hash_on field in upstream.
pub const MAX_HASH_ON_LENGTH: usize = 255;
/// Maximum number of status codes in circuit breaker / retry / health check lists.
pub const MAX_STATUS_CODES: usize = 50;
/// Maximum number of retryable methods.
pub const MAX_RETRYABLE_METHODS: usize = 9;
/// Maximum length for file path fields (TLS cert/key paths).
pub const MAX_FILE_PATH_LENGTH: usize = 4096;
/// Maximum length for service discovery optional string fields.
pub const MAX_SD_STRING_LENGTH: usize = 255;

// ---- Numeric range limits ----

/// Maximum timeout value in milliseconds (24 hours).
pub const MAX_TIMEOUT_MS: u64 = 86_400_000;
/// Maximum timeout value in seconds (24 hours).
pub const MAX_TIMEOUT_SECONDS: u64 = 86_400;
/// Maximum for threshold fields (circuit breaker, health checks).
pub const MAX_THRESHOLD: u32 = 10_000;
/// Maximum retry count.
pub const MAX_RETRIES: u32 = 100;
/// Maximum backoff delay in milliseconds (5 minutes).
pub const MAX_BACKOFF_MS: u64 = 300_000;
/// Maximum target weight.
pub const MAX_TARGET_WEIGHT: u32 = 65_535;
/// Maximum service discovery poll interval in seconds (1 hour).
pub const MAX_SD_POLL_INTERVAL: u64 = 3600;
/// Maximum health check interval in seconds (1 hour).
pub const MAX_HEALTH_CHECK_INTERVAL: u64 = 3600;
/// Maximum UDP idle timeout in seconds (1 hour).
pub const MAX_UDP_IDLE_TIMEOUT: u64 = 3600;
/// Maximum TCP idle timeout in seconds (24 hours).
pub const MAX_TCP_IDLE_TIMEOUT: u64 = 86_400;
/// Maximum pool idle timeout in seconds (1 hour).
pub const MAX_POOL_IDLE_TIMEOUT: u64 = 3600;
/// Maximum DNS cache TTL in seconds (24 hours).
pub const MAX_DNS_CACHE_TTL: u64 = 86_400;
/// Minimum HTTP/2 initial window size (RFC 9113 §6.9.2: 64 KiB default).
pub const MIN_HTTP2_WINDOW_SIZE: u32 = 65_535;
/// Maximum HTTP/2 initial window size (128 MiB practical operational limit).
pub const MAX_HTTP2_WINDOW_SIZE: u32 = 128 * 1024 * 1024;
/// Minimum HTTP/2 max frame size (RFC 9113 §6.5.2: 16 KiB).
pub const MIN_HTTP2_MAX_FRAME_SIZE: u32 = 16_384;
/// Maximum HTTP/2 max frame size (1 MiB practical operational limit).
pub const MAX_HTTP2_MAX_FRAME_SIZE: u32 = 1_048_576;
/// Maximum HTTP/3 connections per backend (reasonable operational limit).
pub const MAX_HTTP3_CONNECTIONS_PER_BACKEND: usize = 256;

/// Valid HTTP methods for allowed_methods and retryable_methods validation.
pub const VALID_HTTP_METHODS: &[&str] = &[
    "GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS", "TRACE", "CONNECT",
];

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
    LeastLatency,
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
    /// Optional path prefix that overrides the proxy's `backend_path` when this
    /// target is selected by the load balancer.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,
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
    /// gRPC health check using the standard grpc.health.v1.Health/Check RPC.
    Grpc,
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
    /// Service name for gRPC health check requests (grpc.health.v1.Health/Check).
    /// Empty string (default) checks overall server health.
    #[serde(default)]
    pub grpc_service_name: Option<String>,
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
            grpc_service_name: None,
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

/// Cookie configuration for `hash_on: "cookie:<name>"` sticky sessions.
///
/// When consistent hashing uses a cookie as the hash key and the cookie is not
/// present in the request, the gateway sets a `Set-Cookie` response header so
/// subsequent requests from the same client stick to the same backend target.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashOnCookieConfig {
    /// Cookie `Path` attribute. Default: `"/"`.
    #[serde(default = "default_cookie_path")]
    pub path: String,
    /// Cookie `Max-Age` in seconds. Default: 3600 (1 hour).
    #[serde(default = "default_cookie_ttl")]
    pub ttl_seconds: u64,
    /// Optional `Domain` attribute.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain: Option<String>,
    /// Set `HttpOnly` flag. Default: true.
    #[serde(default = "default_true")]
    pub http_only: bool,
    /// Set `Secure` flag. Default: false.
    #[serde(default)]
    pub secure: bool,
    /// `SameSite` attribute (`"Strict"`, `"Lax"`, or `"None"`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub same_site: Option<String>,
}

fn default_cookie_path() -> String {
    "/".to_string()
}

fn default_cookie_ttl() -> u64 {
    3600
}

impl Default for HashOnCookieConfig {
    fn default() -> Self {
        Self {
            path: default_cookie_path(),
            ttl_seconds: default_cookie_ttl(),
            domain: None,
            http_only: true,
            secure: false,
            same_site: None,
        }
    }
}

/// Maximum length for cookie config path field.
pub const MAX_COOKIE_PATH_LENGTH: usize = 2048;
/// Maximum length for cookie config domain field.
pub const MAX_COOKIE_DOMAIN_LENGTH: usize = 253;

/// Resolved backend TLS configuration.
///
/// At config load time, each proxy's effective TLS config is resolved:
/// - If the proxy references an upstream, the upstream's TLS fields are used.
/// - Otherwise, the proxy's own TLS fields are used (direct-backend proxies).
///
/// All runtime code (connection pools, health checks, proxy dispatch) reads
/// from this resolved config rather than raw proxy/upstream fields.
#[derive(Debug, Clone, Default)]
pub struct BackendTlsConfig {
    pub client_cert_path: Option<String>,
    pub client_key_path: Option<String>,
    pub server_ca_cert_path: Option<String>,
    pub verify_server_cert: bool,
}

impl BackendTlsConfig {
    /// Create a config with verification enabled and no client certs.
    pub fn default_verify() -> Self {
        Self {
            client_cert_path: None,
            client_key_path: None,
            server_ca_cert_path: None,
            verify_server_cert: true,
        }
    }
}

/// An upstream defines a group of backend targets with load balancing.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Upstream {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    #[serde(default = "default_namespace")]
    pub namespace: String,
    pub targets: Vec<UpstreamTarget>,
    #[serde(default)]
    pub algorithm: LoadBalancerAlgorithm,
    #[serde(default)]
    pub hash_on: Option<String>,
    /// Cookie attributes for `hash_on: "cookie:<name>"` sticky sessions.
    /// Ignored when `hash_on` is not cookie-based.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hash_on_cookie_config: Option<HashOnCookieConfig>,
    #[serde(default)]
    pub health_checks: Option<HealthCheckConfig>,
    #[serde(default)]
    pub service_discovery: Option<ServiceDiscoveryConfig>,
    /// Path to a PEM client certificate for mTLS with backend targets.
    #[serde(default)]
    pub backend_tls_client_cert_path: Option<String>,
    /// Path to a PEM private key for mTLS with backend targets.
    #[serde(default)]
    pub backend_tls_client_key_path: Option<String>,
    /// Whether to verify the backend server's TLS certificate.
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    /// Path to a PEM CA bundle for verifying backend server certificates.
    #[serde(default)]
    pub backend_tls_server_ca_cert_path: Option<String>,
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
    #[serde(default = "default_trip_on_connection_errors")]
    pub trip_on_connection_errors: bool,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: default_failure_threshold(),
            success_threshold: default_success_threshold(),
            timeout_seconds: default_circuit_timeout(),
            failure_status_codes: default_failure_status_codes(),
            half_open_max_requests: default_half_open_max(),
            trip_on_connection_errors: default_trip_on_connection_errors(),
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
fn default_trip_on_connection_errors() -> bool {
    true
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
    vec![]
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
    pub fn is_tls_backend(&self) -> bool {
        matches!(
            self,
            Self::Https | Self::Wss | Self::Grpcs | Self::H3 | Self::TcpTls | Self::Dtls
        )
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

/// Plugin scope (global, per-proxy, or proxy-group).
///
/// - **Global**: Plugin runs on ALL proxies (unless overridden by a proxy-scoped
///   or proxy-group-scoped plugin of the same name).
/// - **Proxy**: Plugin runs on exactly ONE proxy. Requires `proxy_id` to be set.
/// - **ProxyGroup**: Plugin runs on a SUBSET of proxies. The set of proxies is
///   determined by which proxies include this plugin in their `plugins` association
///   list. `proxy_id` must be `None`. A single `ProxyGroup` plugin instance is
///   shared across all associated proxies, so stateful plugins (e.g., rate_limiting)
///   share counters across the group.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum PluginScope {
    Global,
    Proxy,
    #[serde(rename = "proxy_group")]
    ProxyGroup,
}

/// A proxy resource defines a route to a backend.
///
/// HTTP-family proxies route on `hosts` + `listen_path`. At least one of the two
/// must be set; if both are empty/absent the config is rejected. Stream-family
/// proxies (`tcp`/`tcp_tls`/`udp`/`dtls`) route on `listen_port` and MUST NOT
/// set `listen_path`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Proxy {
    #[serde(default)]
    pub id: String,
    #[serde(default)]
    pub name: Option<String>,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    /// Used for multi-tenant resource isolation — each gateway instance
    /// loads only resources matching its configured namespace.
    #[serde(default = "default_namespace")]
    pub namespace: String,
    /// Optional list of hostnames this proxy matches on.
    /// Empty means match all hosts (catch-all).
    /// Supports exact hostnames and single-level wildcard prefixes (e.g., "*.example.com").
    /// For HTTP-family proxies, either `hosts` or `listen_path` must be set
    /// (both may be set together).
    #[serde(default)]
    pub hosts: Vec<String>,
    /// Path prefix or `~regex` this proxy matches.
    /// - HTTP-family proxies: required UNLESS `hosts` is non-empty. When both
    ///   `hosts` is empty and this is `None`, the config is rejected — that
    ///   would be "match literally everything" and collides with every
    ///   other catch-all route.
    /// - When `None` on an HTTP proxy, the proxy matches any path under the
    ///   specified hosts. `strip_listen_path` is a no-op; `backend_path`
    ///   (if set) prepends to the forwarded path.
    /// - Stream-family proxies: MUST be `None`. Stream proxies route on
    ///   `listen_port`.
    #[serde(default)]
    pub listen_path: Option<String>,
    pub backend_protocol: BackendProtocol,
    pub backend_host: String,
    pub backend_port: u16,
    #[serde(default)]
    pub backend_path: Option<String>,
    /// When true, strip the matched `listen_path` prefix from the forwarded
    /// request path. No-op when `listen_path` is `None` (host-only proxy) —
    /// there is no prefix to strip.
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
    /// Path to a PEM client certificate for mTLS with backend targets.
    /// Used only for direct-backend proxies (no `upstream_id`). When an upstream
    /// is referenced, the upstream's TLS config takes precedence.
    #[serde(default)]
    pub backend_tls_client_cert_path: Option<String>,
    /// Path to a PEM private key for mTLS with backend targets.
    /// Used only for direct-backend proxies (no `upstream_id`).
    #[serde(default)]
    pub backend_tls_client_key_path: Option<String>,
    /// Whether to verify the backend server's TLS certificate.
    /// Used only for direct-backend proxies (no `upstream_id`).
    #[serde(default = "default_true")]
    pub backend_tls_verify_server_cert: bool,
    /// Path to a PEM CA bundle for verifying backend server certificates.
    /// Used only for direct-backend proxies (no `upstream_id`).
    #[serde(default)]
    pub backend_tls_server_ca_cert_path: Option<String>,
    /// Resolved backend TLS config (populated at config load time).
    /// When the proxy references an upstream, this is the upstream's TLS config.
    /// For direct-backend proxies, this is the proxy's own TLS fields.
    /// Not serialized — derived from the upstream or proxy fields.
    #[serde(skip)]
    pub resolved_tls: BackendTlsConfig,
    #[serde(default)]
    pub dns_override: Option<String>,
    #[serde(default)]
    pub dns_cache_ttl_seconds: Option<u64>,
    #[serde(default)]
    pub auth_mode: AuthMode,
    #[serde(default)]
    pub plugins: Vec<PluginAssociation>,
    // Connection pooling settings (optional - override global defaults)
    // Note: pool_max_idle_per_host is intentionally global-only (FERRUM_POOL_MAX_IDLE_PER_HOST).
    // Per-proxy overrides were removed because they fragment the connection pool — different
    // values create separate reqwest::Client instances for the same backend, destroying
    // connection reuse and increasing P95 latency.
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
    /// Per-proxy override for HTTP/3 connections per backend.
    /// When set, overrides the global `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` default.
    #[serde(default)]
    pub pool_http3_connections_per_backend: Option<usize>,
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
    /// When true, forward encrypted client bytes directly to the backend without
    /// terminating TLS (TCP) or DTLS (UDP). The proxy peeks at the TLS/DTLS
    /// ClientHello to extract SNI for routing and logging but never decrypts
    /// application data. Only valid for stream proxies (tcp, tcp_tls, udp, dtls).
    /// Mutually exclusive with `frontend_tls`.
    #[serde(default)]
    pub passthrough: bool,
    /// UDP session idle timeout in seconds. After this duration of inactivity,
    /// the UDP session mapping is removed. Default: 60 seconds.
    #[serde(default = "default_udp_idle_timeout")]
    pub udp_idle_timeout_seconds: u64,
    /// Maximum allowed response amplification factor for UDP proxies.
    /// When set, backend→client datagrams are dropped if their size exceeds
    /// `last_request_size * factor`. Protects against UDP amplification attacks.
    /// `None` (default) = no limit.
    #[serde(default)]
    pub udp_max_response_amplification_factor: Option<f32>,
    /// TCP stream idle timeout in seconds. After this duration of no data
    /// transfer in either direction, the connection is closed.
    /// Per-proxy override; when `None`, uses the global `FERRUM_TCP_IDLE_TIMEOUT_SECONDS`
    /// (default: 300s / 5 min). Set to 0 to disable (rely on OS TCP timeouts only).
    #[serde(default)]
    pub tcp_idle_timeout_seconds: Option<u64>,
    /// Optional list of allowed HTTP methods (e.g., ["GET", "POST"]).
    /// When `None` (default), all methods are allowed. When `Some`, requests
    /// with methods not in the list receive 405 Method Not Allowed.
    #[serde(default)]
    pub allowed_methods: Option<Vec<String>>,
    /// Optional list of allowed WebSocket Origin values (e.g., ["https://example.com"]).
    /// When non-empty, WebSocket upgrade requests must include an Origin header
    /// matching one of these values (case-insensitive). Empty list (default) means
    /// no origin check — all origins are permitted. Protects against Cross-Site
    /// WebSocket Hijacking (CSWSH) per RFC 6455 §10.2.
    #[serde(default)]
    pub allowed_ws_origins: Vec<String>,
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
    #[serde(default)]
    pub id: String,
    pub username: String,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub custom_id: Option<String>,
    #[serde(default)]
    pub credentials: HashMap<String, serde_json::Value>,
    /// ACL group memberships. A consumer can belong to multiple groups, and the
    /// `access_control` plugin can allow/deny by group instead of (or in
    /// addition to) individual consumer usernames.
    #[serde(default)]
    pub acl_groups: Vec<String>,
    #[serde(default = "Utc::now")]
    pub created_at: DateTime<Utc>,
    #[serde(default = "Utc::now")]
    pub updated_at: DateTime<Utc>,
}

/// A plugin configuration resource.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PluginConfig {
    #[serde(default)]
    pub id: String,
    pub plugin_name: String,
    /// Namespace this resource belongs to. Defaults to "ferrum".
    #[serde(default = "default_namespace")]
    pub namespace: String,
    #[serde(default)]
    pub config: serde_json::Value,
    pub scope: PluginScope,
    #[serde(default)]
    pub proxy_id: Option<String>,
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Optional execution priority override. When set, replaces the plugin's
    /// built-in priority constant. Lower values execute first. Useful when
    /// multiple instances of the same plugin type are attached to a proxy
    /// (e.g., two `http_logging` instances for different log destinations)
    /// and you need to control their relative execution order.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub priority_override: Option<u16>,
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
    /// All distinct namespaces discovered at config load time (before namespace
    /// filtering). Populated by file mode so `GET /namespaces` can return all
    /// namespaces even though the in-memory config only holds one namespace's
    /// resources. DB-backed modes use `list_namespaces()` instead.
    #[serde(default)]
    pub known_namespaces: Vec<String>,
}

/// The current config schema version. Increment this when adding config migrations.
pub const CURRENT_CONFIG_VERSION: &str = "1";

fn default_config_version() -> String {
    "1".to_string()
}

/// The default namespace for all resources when `FERRUM_NAMESPACE` is unset.
pub const DEFAULT_NAMESPACE: &str = "ferrum";

/// Maximum length for namespace identifiers.
pub const MAX_NAMESPACE_LENGTH: usize = 254;

/// Default namespace value for serde deserialization.
pub fn default_namespace() -> String {
    DEFAULT_NAMESPACE.to_string()
}

/// Validate a namespace string. Same rules as resource IDs.
pub fn validate_namespace(ns: &str) -> Result<(), String> {
    if ns.is_empty() {
        return Err("namespace must not be empty".to_string());
    }
    if ns.len() > MAX_NAMESPACE_LENGTH {
        return Err(format!(
            "namespace must be at most {} characters, got {}",
            MAX_NAMESPACE_LENGTH,
            ns.len()
        ));
    }
    if !ID_REGEX.is_match(ns) {
        return Err(format!(
            "namespace '{}' is invalid: must start with alphanumeric and contain only alphanumeric, dots, underscores, or hyphens",
            ns
        ));
    }
    Ok(())
}

/// Auto-anchor a regex listen_path pattern for full-path matching.
///
/// Prepends `^` if not already present and appends `$` if not already present,
/// ensuring the pattern must match the entire request path rather than just a
/// prefix. Operators who need prefix-style matching can end their pattern with
/// `.*` to opt out of the end anchor.
pub fn anchor_regex_pattern(pattern: &str) -> String {
    let mut anchored = if pattern.starts_with('^') {
        pattern.to_string()
    } else {
        format!("^{}", pattern)
    };
    if !anchored.ends_with('$') {
        anchored.push('$');
    }
    anchored
}

impl GatewayConfig {
    /// Validate that all proxy (host, listen_path) combinations are unique.
    ///
    /// HTTP-family proxies can conflict in two ways:
    /// - Path-carrying proxies share a `listen_path` and have overlapping
    ///   `hosts` (or both use an empty/catch-all host list).
    /// - Host-only proxies (`listen_path.is_none()`) share any host with
    ///   another host-only proxy. Host-only proxies cannot have empty
    ///   `hosts` — that combination is rejected by `validate_fields_inner`.
    ///
    /// Stream proxies are skipped (they route on `listen_port`, not path).
    pub fn validate_unique_listen_paths(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Split proxies into two buckets: those with an explicit listen_path and
        // host-only proxies. Only proxies in the same bucket AND the same path
        // (for the path bucket) can conflict.
        let mut by_path: HashMap<&str, Vec<&Proxy>> = HashMap::new();
        let mut host_only: Vec<&Proxy> = Vec::new();
        for proxy in &self.proxies {
            if proxy.backend_protocol.is_stream_proxy() {
                continue;
            }
            match proxy.listen_path.as_deref() {
                Some(path) => by_path.entry(path).or_default().push(proxy),
                None => host_only.push(proxy),
            }
        }

        for (path, group) in &by_path {
            if group.len() < 2 {
                continue;
            }
            for (i, proxy_a) in group.iter().enumerate() {
                for proxy_b in group.iter().skip(i + 1) {
                    if hosts_overlap(&proxy_a.hosts, &proxy_b.hosts) {
                        if proxy_a.hosts.is_empty() && proxy_b.hosts.is_empty() {
                            errors.push(format!(
                                "Duplicate listen_path '{}' found in proxy '{}' (conflicts with '{}')",
                                path, proxy_b.id, proxy_a.id
                            ));
                        } else {
                            errors.push(format!(
                                "Overlapping host+listen_path for '{}' in proxy '{}' (conflicts with '{}')",
                                path, proxy_b.id, proxy_a.id
                            ));
                        }
                    }
                }
            }
        }

        for (i, proxy_a) in host_only.iter().enumerate() {
            for proxy_b in host_only.iter().skip(i + 1) {
                if hosts_overlap(&proxy_a.hosts, &proxy_b.hosts) {
                    errors.push(format!(
                        "Overlapping host-only proxies '{}' and '{}' — each host can route to at most one host-only proxy",
                        proxy_b.id, proxy_a.id
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
    /// with `^` and `$` if not already present for full-path matching).
    /// Compilation errors are reported here at config
    /// load time rather than silently skipping routes at runtime.
    pub fn validate_regex_listen_paths(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for proxy in &self.proxies {
            if proxy.backend_protocol.is_stream_proxy() {
                continue;
            }
            let Some(path) = proxy.listen_path.as_deref() else {
                continue;
            };
            if let Some(pattern) = path.strip_prefix('~') {
                if pattern.is_empty() {
                    errors.push(format!(
                        "Proxy '{}': regex listen_path '~' has empty pattern",
                        proxy.id
                    ));
                    continue;
                }
                let anchored = anchor_regex_pattern(pattern);
                if let Err(e) = Regex::new(&anchored) {
                    errors.push(format!(
                        "Proxy '{}': invalid regex listen_path '{}': {}",
                        proxy.id, path, e
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
            proxy.normalize_fields();
        }
    }

    /// Normalize all resource fields that have canonical in-memory forms.
    pub fn normalize_fields(&mut self) {
        self.normalize_hosts();
        for consumer in &mut self.consumers {
            consumer.normalize_fields();
        }
        for plugin_config in &mut self.plugin_configs {
            plugin_config.normalize_fields();
        }
        for upstream in &mut self.upstreams {
            upstream.normalize_fields();
        }
    }

    /// Resolve each proxy's `resolved_tls` from its upstream (if any) or its own fields.
    ///
    /// Must be called after loading/mutating config and before any proxy traffic flows.
    /// Called by `normalize_fields()` callers, `update_config()`, `apply_incremental()`,
    /// and admin API mutation handlers.
    pub fn resolve_upstream_tls(&mut self) {
        // Build a map of upstream_id → TLS config for O(1) lookups.
        let upstream_tls: HashMap<&str, BackendTlsConfig> = self
            .upstreams
            .iter()
            .map(|u| {
                (
                    u.id.as_str(),
                    BackendTlsConfig {
                        client_cert_path: u.backend_tls_client_cert_path.clone(),
                        client_key_path: u.backend_tls_client_key_path.clone(),
                        server_ca_cert_path: u.backend_tls_server_ca_cert_path.clone(),
                        verify_server_cert: u.backend_tls_verify_server_cert,
                    },
                )
            })
            .collect();

        for proxy in &mut self.proxies {
            proxy.resolved_tls = if let Some(ref uid) = proxy.upstream_id {
                upstream_tls
                    .get(uid.as_str())
                    .cloned()
                    .unwrap_or_else(BackendTlsConfig::default_verify)
            } else {
                BackendTlsConfig {
                    client_cert_path: proxy.backend_tls_client_cert_path.clone(),
                    client_key_path: proxy.backend_tls_client_key_path.clone(),
                    server_ca_cert_path: proxy.backend_tls_server_ca_cert_path.clone(),
                    verify_server_cert: proxy.backend_tls_verify_server_cert,
                }
            };
        }
    }

    /// Validate that consumer usernames and custom_ids are unique.
    ///
    /// In database mode the DB enforces this via UNIQUE constraints. In file
    /// mode there's no DB, so this catches duplicates at config load time
    /// and prevents the gateway from starting with ambiguous identity mappings
    /// that would cause incorrect JWKS/JWT authentication.
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

        // Cross-namespace collision: a custom_id that matches another consumer's
        // username or ID would silently overwrite in the identity index, causing
        // incorrect JWKS/JWT authentication.
        for consumer in &self.consumers {
            if let Some(ref custom_id) = consumer.custom_id
                && let Some(&owner_id) = seen_usernames.get(custom_id.as_str())
                && owner_id != consumer.id
            {
                duplicates.push(format!(
                    "Consumer '{}' custom_id '{}' collides with username of consumer '{}' \
                     — this will cause incorrect JWKS/JWT authentication",
                    consumer.id, custom_id, owner_id
                ));
            }
        }

        if duplicates.is_empty() {
            Ok(())
        } else {
            Err(duplicates)
        }
    }

    /// Validate that consumer credentials are unique across all consumers.
    ///
    /// Checks keyauth API keys, basicauth usernames, and mTLS identities.
    /// If two consumers share the same credential, the ConsumerIndex silently
    /// overwrites one, causing the wrong consumer to be authenticated.
    pub fn validate_unique_consumer_credentials(&self) -> Result<(), Vec<String>> {
        let mut seen_keyauth: HashMap<&str, &str> = HashMap::new();
        let mut seen_basicauth: HashMap<&str, &str> = HashMap::new();
        let mut seen_mtls: HashMap<&str, &str> = HashMap::new();
        let mut duplicates = Vec::new();

        for consumer in &self.consumers {
            // Check all keyauth entries (supports both single object and array)
            for entry in consumer.credential_entries("keyauth") {
                if let Some(key) = entry.get("key").and_then(|s| s.as_str())
                    && let Some(existing_id) = seen_keyauth.insert(key, &consumer.id)
                {
                    // Do NOT include the API key value in the error message for security
                    duplicates.push(format!(
                        "Duplicate keyauth API key in consumer '{}' (conflicts with consumer '{}')",
                        consumer.id, existing_id
                    ));
                }
            }

            // basicauth consumers are indexed by username — duplicates cause silent overwrite
            if consumer.has_credential("basicauth")
                && let Some(existing_id) = seen_basicauth.insert(&consumer.username, &consumer.id)
            {
                duplicates.push(format!(
                    "Duplicate basicauth username '{}' in consumer '{}' (conflicts with consumer '{}')",
                    consumer.username, consumer.id, existing_id
                ));
            }

            // Check all mTLS entries (supports both single object and array)
            for entry in consumer.credential_entries("mtls_auth") {
                if let Some(identity) = entry.get("identity").and_then(|s| s.as_str())
                    && let Some(existing_id) = seen_mtls.insert(identity, &consumer.id)
                {
                    duplicates.push(format!(
                        "Duplicate mtls_auth identity '{}' in consumer '{}' (conflicts with consumer '{}')",
                        identity, consumer.id, existing_id
                    ));
                }
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

    /// Validate plugin resource invariants and proxy/plugin associations.
    pub fn validate_plugin_references(&self) -> Result<(), Vec<String>> {
        let proxy_ids: HashSet<&str> = self.proxies.iter().map(|p| p.id.as_str()).collect();
        let plugin_by_id: HashMap<&str, &PluginConfig> = self
            .plugin_configs
            .iter()
            .map(|pc| (pc.id.as_str(), pc))
            .collect();
        let mut errors = Vec::new();

        for plugin in &self.plugin_configs {
            match plugin.scope {
                PluginScope::Global => {
                    if plugin.proxy_id.is_some() {
                        errors.push(format!(
                            "PluginConfig '{}' with scope 'global' must not have proxy_id",
                            plugin.id
                        ));
                    }
                }
                PluginScope::Proxy => match plugin.proxy_id.as_deref() {
                    Some(proxy_id) => {
                        if !proxy_ids.contains(proxy_id) {
                            errors.push(format!(
                                "PluginConfig '{}' references non-existent proxy_id '{}'",
                                plugin.id, proxy_id
                            ));
                        }
                    }
                    None => errors.push(format!(
                        "PluginConfig '{}' with scope 'proxy' must have proxy_id",
                        plugin.id
                    )),
                },
                PluginScope::ProxyGroup => {
                    if plugin.proxy_id.is_some() {
                        errors.push(format!(
                            "PluginConfig '{}' with scope 'proxy_group' must not have proxy_id (associations are managed via proxy.plugins)",
                            plugin.id
                        ));
                    }
                }
            }
        }

        for proxy in &self.proxies {
            let mut seen_assoc_ids: HashSet<&str> = HashSet::new();
            for assoc in &proxy.plugins {
                if !seen_assoc_ids.insert(assoc.plugin_config_id.as_str()) {
                    errors.push(format!(
                        "Proxy '{}' references plugin_config '{}' more than once",
                        proxy.id, assoc.plugin_config_id
                    ));
                }

                match plugin_by_id.get(assoc.plugin_config_id.as_str()) {
                    Some(plugin) => match plugin.scope {
                        PluginScope::Global => {
                            errors.push(format!(
                                "Proxy '{}' references plugin_config '{}' with scope 'global' — proxy associations may only reference proxy-scoped or proxy_group-scoped plugin configs",
                                proxy.id, plugin.id,
                            ));
                        }
                        PluginScope::Proxy => {
                            if plugin.proxy_id.as_deref() != Some(proxy.id.as_str()) {
                                errors.push(format!(
                                    "Proxy '{}' references plugin_config '{}' targeted to proxy '{}'",
                                    proxy.id,
                                    plugin.id,
                                    plugin.proxy_id.as_deref().unwrap_or("<none>")
                                ));
                            }
                        }
                        PluginScope::ProxyGroup => {
                            // ProxyGroup plugins have no proxy_id — any proxy can
                            // reference them via its plugins association list.
                        }
                    },
                    None => errors.push(format!(
                        "Proxy '{}' references non-existent plugin_config '{}'",
                        proxy.id, assoc.plugin_config_id
                    )),
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
    /// - `listen_port` must be unique across all stream proxies, **unless** all
    ///   proxies sharing the port have `passthrough: true` (SNI-based routing).
    /// - HTTP proxies must not set `listen_port`.
    /// - Passthrough proxies sharing a port must have non-overlapping `hosts`
    ///   and at most one may have empty `hosts` (catch-all/default).
    pub fn validate_stream_proxies(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        // Map port -> list of proxy IDs that use it
        let mut port_proxies: HashMap<u16, Vec<&str>> = HashMap::new();

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
                        port_proxies.entry(port).or_default().push(&proxy.id);
                    }
                }
            } else if proxy.listen_port.is_some() {
                errors.push(format!(
                    "HTTP proxy '{}' (protocol {}) must not set listen_port",
                    proxy.id, proxy.backend_protocol
                ));
            }
        }

        // Validate port sharing rules
        for (port, proxy_ids) in &port_proxies {
            if proxy_ids.len() <= 1 {
                continue; // No conflict for single-proxy ports
            }

            // All proxies sharing a port must have passthrough: true
            let proxies_on_port: Vec<&Proxy> = proxy_ids
                .iter()
                .filter_map(|id| self.proxies.iter().find(|p| p.id == *id))
                .collect();

            let all_passthrough = proxies_on_port.iter().all(|p| p.passthrough);
            if !all_passthrough {
                let non_pt: Vec<&str> = proxies_on_port
                    .iter()
                    .filter(|p| !p.passthrough)
                    .map(|p| p.id.as_str())
                    .collect();
                errors.push(format!(
                    "Duplicate listen_port {} — all proxies sharing a port must have passthrough: true, \
                     but {} do not",
                    port,
                    non_pt.join(", ")
                ));
                continue;
            }

            // At most one proxy per port may have empty hosts (catch-all)
            let catch_all_count = proxies_on_port
                .iter()
                .filter(|p| p.hosts.is_empty())
                .count();
            if catch_all_count > 1 {
                errors.push(format!(
                    "Passthrough port {} has {} proxies with empty hosts — at most one catch-all is allowed",
                    port, catch_all_count
                ));
            }

            // Check for host overlap between every pair
            for (i, a) in proxies_on_port.iter().enumerate() {
                for b in &proxies_on_port[i + 1..] {
                    if hosts_overlap(&a.hosts, &b.hosts) {
                        errors.push(format!(
                            "Passthrough proxies '{}' and '{}' on port {} have overlapping hosts — \
                             each SNI hostname must route to exactly one proxy",
                            a.id, b.id, port
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

    /// Validate that stream proxy ports do not conflict with gateway reserved ports.
    ///
    /// Reserved ports are the gateway's own listener ports (proxy HTTP/HTTPS,
    /// admin HTTP/HTTPS, CP gRPC). A stream proxy binding to one of these would
    /// shadow the gateway listener and cause startup failures or undefined behavior.
    pub fn validate_stream_proxy_port_conflicts(
        &self,
        reserved_ports: &std::collections::HashSet<u16>,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        for proxy in &self.proxies {
            if proxy.backend_protocol.is_stream_proxy()
                && let Some(port) = proxy.listen_port
                && reserved_ports.contains(&port)
            {
                errors.push(format!(
                    "Stream proxy '{}' listen_port {} conflicts with a gateway reserved port \
                     (proxy/admin/gRPC listener)",
                    proxy.id, port
                ));
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
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

// ---- Field-level validation ----

/// Check if a string contains ASCII control characters (excluding common whitespace).
/// Rejects null bytes, backspace, escape, etc. that could cause log injection.
/// Human-readable JSON value type name for error messages.
fn elem_type_name(v: &serde_json::Value) -> &'static str {
    match v {
        serde_json::Value::Null => "null",
        serde_json::Value::Bool(_) => "boolean",
        serde_json::Value::Number(_) => "number",
        serde_json::Value::String(_) => "string",
        serde_json::Value::Array(_) => "array",
        serde_json::Value::Object(_) => "object",
    }
}

fn contains_control_chars(s: &str) -> bool {
    s.bytes()
        .any(|b| b < 0x20 && b != b'\t' && b != b'\n' && b != b'\r')
}

/// Validate a string field length and reject control characters.
/// Returns `Err(message)` if the value exceeds `max_len` or contains control characters.
fn validate_string_field(field_name: &str, value: &str, max_len: usize) -> Result<(), String> {
    if value.len() > max_len {
        return Err(format!(
            "{} must not exceed {} characters (got {})",
            field_name,
            max_len,
            value.len()
        ));
    }
    if contains_control_chars(value) {
        return Err(format!(
            "{} must not contain control characters",
            field_name
        ));
    }
    Ok(())
}

/// Validate that a PEM certificate file exists, is readable, and contains at least one valid certificate.
pub fn validate_pem_cert_file(field_name: &str, path: &str) -> Result<(), String> {
    let file = std::fs::File::open(path).map_err(|e| {
        format!(
            "{}: failed to open certificate file '{}': {}",
            field_name, path, e
        )
    })?;
    let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(file))
        .filter_map(|r| r.ok())
        .collect();
    if certs.is_empty() {
        return Err(format!(
            "{}: no valid PEM certificates found in '{}'",
            field_name, path
        ));
    }
    Ok(())
}

/// Validate that a PEM private key file exists, is readable, and contains at least one valid PKCS8 private key.
pub fn validate_pem_key_file(field_name: &str, path: &str) -> Result<(), String> {
    let file = std::fs::File::open(path)
        .map_err(|e| format!("{}: failed to open key file '{}': {}", field_name, path, e))?;
    let keys: Vec<_> = rustls_pemfile::pkcs8_private_keys(&mut std::io::BufReader::new(file))
        .filter_map(|r| r.ok())
        .collect();
    if keys.is_empty() {
        return Err(format!(
            "{}: no valid PKCS8 private keys found in '{}'",
            field_name, path
        ));
    }
    Ok(())
}

/// Validate that a MaxMind `.mmdb` database file exists and is readable.
/// This mirrors the cert file validation pattern — per-mode callers decide
/// whether a failure is fatal (file mode), a warning (db mode), or a
/// config-rejection (dp mode).
pub fn validate_mmdb_file(field_name: &str, path: &str) -> Result<(), String> {
    let metadata = std::fs::metadata(path).map_err(|e| {
        format!(
            "{}: MaxMind database file '{}' not accessible: {}",
            field_name, path, e
        )
    })?;
    if !metadata.is_file() {
        return Err(format!(
            "{}: '{}' exists but is not a regular file",
            field_name, path
        ));
    }
    Ok(())
}

/// Validate a u64 field is within a range.
fn validate_u64_range(field_name: &str, value: u64, min: u64, max: u64) -> Result<(), String> {
    if value < min || value > max {
        return Err(format!(
            "{} must be between {} and {} (got {})",
            field_name, min, max, value
        ));
    }
    Ok(())
}

/// Validate a u32 field is within a range.
fn validate_u32_range(field_name: &str, value: u32, min: u32, max: u32) -> Result<(), String> {
    if value < min || value > max {
        return Err(format!(
            "{} must be between {} and {} (got {})",
            field_name, min, max, value
        ));
    }
    Ok(())
}

/// Validate a list of HTTP status codes.
fn validate_status_codes(field_name: &str, codes: &[u16]) -> Result<(), String> {
    if codes.len() > MAX_STATUS_CODES {
        return Err(format!(
            "{} must not have more than {} entries (got {})",
            field_name,
            MAX_STATUS_CODES,
            codes.len()
        ));
    }
    for &code in codes {
        if !(100..=599).contains(&code) {
            return Err(format!(
                "{} contains invalid HTTP status code {} (must be 100-599)",
                field_name, code
            ));
        }
    }
    Ok(())
}

impl Proxy {
    /// Normalize proxy fields to their canonical in-memory form.
    pub fn normalize_fields(&mut self) {
        for host in &mut self.hosts {
            *host = host.to_lowercase();
        }
        // RFC 1035: DNS names are case-insensitive. Normalize backend_host so
        // downstream consumers (DNS cache, connection pool keys) never create
        // duplicate entries for mixed-case variants of the same hostname.
        self.backend_host = self.backend_host.to_ascii_lowercase();
    }

    /// Validate all fields of a proxy for correctness and safe lengths.
    ///
    /// This validates field values only — uniqueness checks (listen_path conflicts,
    /// name uniqueness, upstream_id existence) are done separately in the admin handlers.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        self.validate_fields_inner(None, crate::tls::DEFAULT_CERT_EXPIRY_WARNING_DAYS)
    }

    /// Validate fields with a shared cache of already-validated TLS file paths.
    /// When multiple proxies reference the same cert/key/CA file, each path is
    /// opened and parsed only once — subsequent proxies skip the I/O.
    pub fn validate_fields_with_cache(
        &self,
        validated_tls_paths: &mut std::collections::HashSet<String>,
        cert_expiry_warning_days: u64,
    ) -> Result<(), Vec<String>> {
        self.validate_fields_inner(Some(validated_tls_paths), cert_expiry_warning_days)
    }

    fn validate_fields_inner(
        &self,
        mut validated_tls_paths: Option<&mut std::collections::HashSet<String>>,
        cert_expiry_warning_days: u64,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();
        let is_stream_proxy = self.backend_protocol.is_stream_proxy();

        // Passthrough mode validation
        if self.passthrough {
            if !is_stream_proxy {
                errors.push(
                    "passthrough is only supported for stream proxies (tcp, tcp_tls, udp, dtls)"
                        .to_string(),
                );
            }
            if self.frontend_tls {
                errors.push(
                    "passthrough and frontend_tls are mutually exclusive — passthrough forwards raw encrypted bytes without terminating TLS/DTLS".to_string(),
                );
            }
        }

        // Name
        if let Some(ref name) = self.name
            && let Err(e) = validate_string_field("name", name, MAX_NAME_LENGTH)
        {
            errors.push(e);
        }

        // Hosts
        if self.hosts.len() > MAX_HOSTS_PER_PROXY {
            errors.push(format!(
                "hosts must not have more than {} entries (got {})",
                MAX_HOSTS_PER_PROXY,
                self.hosts.len()
            ));
        }
        for host in &self.hosts {
            if host.len() > MAX_HOST_LENGTH {
                errors.push(format!(
                    "host entry '{}...' must not exceed {} characters",
                    &host[..40.min(host.len())],
                    MAX_HOST_LENGTH
                ));
            }
        }

        // listen_path
        //
        // Contract:
        // - Stream proxies MUST have `listen_path.is_none()`.
        // - HTTP-family proxies require `hosts.is_non_empty() || listen_path.is_some()`.
        // - `listen_path == Some("")` is invalid input (rejected here rather than
        //   silently normalized to None) — catches mis-written fixtures loudly.
        if is_stream_proxy {
            if self.listen_path.is_some() {
                errors.push(format!(
                    "Stream proxy '{}' (protocol {}) must not set listen_path — stream proxies route on listen_port",
                    self.id, self.backend_protocol
                ));
            }
        } else {
            match self.listen_path.as_deref() {
                None => {
                    if self.hosts.is_empty() {
                        errors.push(
                            "HTTP proxy requires at least one of `hosts` or `listen_path` — a proxy with neither is a catch-all for every request and collides with every other catch-all".to_string(),
                        );
                    }
                }
                Some(path) => {
                    if path.len() > MAX_LISTEN_PATH_LENGTH {
                        errors.push(format!(
                            "listen_path must not exceed {} characters (got {})",
                            MAX_LISTEN_PATH_LENGTH,
                            path.len()
                        ));
                    }
                    if contains_control_chars(path) {
                        errors.push("listen_path must not contain control characters".to_string());
                    }
                    if path.is_empty() {
                        errors.push(
                            "listen_path must not be an empty string — omit the field entirely for host-only routing"
                                .to_string(),
                        );
                    } else if let Some(pattern) = path.strip_prefix('~') {
                        if pattern.is_empty() {
                            errors.push("regex listen_path '~' has empty pattern".to_string());
                        }
                    } else if !path.starts_with('/') {
                        errors.push("listen_path must start with '/' or '~' (regex)".to_string());
                    }
                }
            }
        }

        // backend_host
        if let Err(e) =
            validate_string_field("backend_host", &self.backend_host, MAX_BACKEND_HOST_LENGTH)
        {
            errors.push(e);
        }
        if self.backend_host.contains("://") {
            errors.push("backend_host must not contain a scheme (e.g., 'http://')".to_string());
        }
        if self.upstream_id.is_none() && self.backend_host.is_empty() {
            errors.push("backend_host must be non-empty (or set upstream_id)".to_string());
        }
        if self.upstream_id.is_none() && self.backend_port == 0 {
            errors.push("backend_port must be greater than 0 (or set upstream_id)".to_string());
        }

        // backend_path
        if let Some(ref path) = self.backend_path
            && let Err(e) = validate_string_field("backend_path", path, MAX_BACKEND_PATH_LENGTH)
        {
            errors.push(e);
        }

        // Timeout ranges
        if let Err(e) = validate_u64_range(
            "backend_connect_timeout_ms",
            self.backend_connect_timeout_ms,
            1,
            MAX_TIMEOUT_MS,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u64_range(
            "backend_read_timeout_ms",
            self.backend_read_timeout_ms,
            1,
            MAX_TIMEOUT_MS,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u64_range(
            "backend_write_timeout_ms",
            self.backend_write_timeout_ms,
            1,
            MAX_TIMEOUT_MS,
        ) {
            errors.push(e);
        }

        // Pool timeout overrides
        if let Some(v) = self.pool_idle_timeout_seconds
            && let Err(e) =
                validate_u64_range("pool_idle_timeout_seconds", v, 1, MAX_POOL_IDLE_TIMEOUT)
        {
            errors.push(e);
        }
        if let Some(v) = self.pool_tcp_keepalive_seconds
            && let Err(e) =
                validate_u64_range("pool_tcp_keepalive_seconds", v, 1, MAX_TIMEOUT_SECONDS)
        {
            errors.push(e);
        }
        if let Some(v) = self.pool_http2_keep_alive_interval_seconds
            && let Err(e) = validate_u64_range(
                "pool_http2_keep_alive_interval_seconds",
                v,
                1,
                MAX_TIMEOUT_SECONDS,
            )
        {
            errors.push(e);
        }
        if let Some(v) = self.pool_http2_keep_alive_timeout_seconds
            && let Err(e) = validate_u64_range(
                "pool_http2_keep_alive_timeout_seconds",
                v,
                1,
                MAX_TIMEOUT_SECONDS,
            )
        {
            errors.push(e);
        }

        // DNS cache TTL
        if let Some(v) = self.dns_cache_ttl_seconds
            && let Err(e) = validate_u64_range("dns_cache_ttl_seconds", v, 1, MAX_DNS_CACHE_TTL)
        {
            errors.push(e);
        }

        // UDP idle timeout
        if let Err(e) = validate_u64_range(
            "udp_idle_timeout_seconds",
            self.udp_idle_timeout_seconds,
            1,
            MAX_UDP_IDLE_TIMEOUT,
        ) {
            errors.push(e);
        }

        // TCP idle timeout (0 means disabled, so only reject values above the max)
        if let Some(v) = self.tcp_idle_timeout_seconds
            && v > MAX_TCP_IDLE_TIMEOUT
        {
            errors.push(format!(
                "tcp_idle_timeout_seconds must be between 0 and {} (got {})",
                MAX_TCP_IDLE_TIMEOUT, v
            ));
        }

        // HTTP/2 flow control validation
        if let Some(v) = self.pool_http2_initial_stream_window_size
            && !(MIN_HTTP2_WINDOW_SIZE..=MAX_HTTP2_WINDOW_SIZE).contains(&v)
        {
            errors.push(format!(
                "pool_http2_initial_stream_window_size must be between {} and {} (got {})",
                MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE, v
            ));
        }
        if let Some(v) = self.pool_http2_initial_connection_window_size
            && !(MIN_HTTP2_WINDOW_SIZE..=MAX_HTTP2_WINDOW_SIZE).contains(&v)
        {
            errors.push(format!(
                "pool_http2_initial_connection_window_size must be between {} and {} (got {})",
                MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE, v
            ));
        }
        if let Some(v) = self.pool_http2_max_frame_size
            && !(MIN_HTTP2_MAX_FRAME_SIZE..=MAX_HTTP2_MAX_FRAME_SIZE).contains(&v)
        {
            errors.push(format!(
                "pool_http2_max_frame_size must be between {} and {} (got {})",
                MIN_HTTP2_MAX_FRAME_SIZE, MAX_HTTP2_MAX_FRAME_SIZE, v
            ));
        }
        if let Some(0) = self.pool_http2_max_concurrent_streams {
            errors.push("pool_http2_max_concurrent_streams must be at least 1 (got 0)".to_string());
        }

        // HTTP/3 connections per backend
        if let Some(v) = self.pool_http3_connections_per_backend
            && (v == 0 || v > MAX_HTTP3_CONNECTIONS_PER_BACKEND)
        {
            errors.push(format!(
                "pool_http3_connections_per_backend must be between 1 and {} (got {})",
                MAX_HTTP3_CONNECTIONS_PER_BACKEND, v
            ));
        }

        // Reject backend TLS fields on non-TLS protocols — cert configs are
        // meaningless for plaintext backends and would waste disk I/O and
        // fragment the connection pool.
        if !self.backend_protocol.is_tls_backend() {
            let protocol = &self.backend_protocol;
            if self.backend_tls_client_cert_path.is_some() {
                errors.push(format!(
                    "backend_tls_client_cert_path cannot be set when backend_protocol is '{protocol}' — TLS client certs are only used with TLS-enabled protocols (https, wss, grpcs, h3, tcp_tls, dtls)"
                ));
            }
            if self.backend_tls_client_key_path.is_some() {
                errors.push(format!(
                    "backend_tls_client_key_path cannot be set when backend_protocol is '{protocol}' — TLS client keys are only used with TLS-enabled protocols (https, wss, grpcs, h3, tcp_tls, dtls)"
                ));
            }
            if self.backend_tls_server_ca_cert_path.is_some() {
                errors.push(format!(
                    "backend_tls_server_ca_cert_path cannot be set when backend_protocol is '{protocol}' — CA certs are only used with TLS-enabled protocols (https, wss, grpcs, h3, tcp_tls, dtls)"
                ));
            }
            if !self.backend_tls_verify_server_cert {
                errors.push(format!(
                    "backend_tls_verify_server_cert cannot be set to false when backend_protocol is '{protocol}' — there is no TLS to verify on plaintext protocols"
                ));
            }
        }

        // Reject backend TLS fields in passthrough mode — the proxy does not
        // originate its own TLS to the backend; the client's encrypted stream
        // passes through directly.
        if self.passthrough {
            if self.backend_tls_client_cert_path.is_some() {
                errors.push(
                    "backend_tls_client_cert_path cannot be set when passthrough is true — the proxy does not originate backend TLS in passthrough mode".to_string(),
                );
            }
            if self.backend_tls_client_key_path.is_some() {
                errors.push(
                    "backend_tls_client_key_path cannot be set when passthrough is true — the proxy does not originate backend TLS in passthrough mode".to_string(),
                );
            }
            if self.backend_tls_server_ca_cert_path.is_some() {
                errors.push(
                    "backend_tls_server_ca_cert_path cannot be set when passthrough is true — the proxy does not originate backend TLS in passthrough mode".to_string(),
                );
            }
        }

        // TLS file path lengths
        if let Some(ref path) = self.backend_tls_client_cert_path
            && let Err(e) =
                validate_string_field("backend_tls_client_cert_path", path, MAX_FILE_PATH_LENGTH)
        {
            errors.push(e);
        }
        if let Some(ref path) = self.backend_tls_client_key_path
            && let Err(e) =
                validate_string_field("backend_tls_client_key_path", path, MAX_FILE_PATH_LENGTH)
        {
            errors.push(e);
        }
        if let Some(ref path) = self.backend_tls_server_ca_cert_path
            && let Err(e) = validate_string_field(
                "backend_tls_server_ca_cert_path",
                path,
                MAX_FILE_PATH_LENGTH,
            )
        {
            errors.push(e);
        }

        // TLS cert/key pairing: both must be set or neither
        match (
            &self.backend_tls_client_cert_path,
            &self.backend_tls_client_key_path,
        ) {
            (Some(_), None) => {
                errors.push(
                    "backend_tls_client_cert_path is set but backend_tls_client_key_path is missing — both must be configured together".to_string(),
                );
            }
            (None, Some(_)) => {
                errors.push(
                    "backend_tls_client_key_path is set but backend_tls_client_cert_path is missing — both must be configured together".to_string(),
                );
            }
            _ => {}
        }

        // TLS file content validation: open, read, and parse PEM files.
        // When a validated_tls_paths cache is provided (batch validation), paths
        // that were already validated by a prior proxy are skipped to avoid
        // redundant file I/O when many proxies share the same cert files.
        // Also checks certificate expiration: expired certs are rejected,
        // near-expiry certs emit a warning log.
        if let Some(ref path) = self.backend_tls_client_cert_path {
            let already_validated = validated_tls_paths
                .as_ref()
                .is_some_and(|s| s.contains(path.as_str()));
            if !already_validated {
                if let Err(e) = validate_pem_cert_file("backend_tls_client_cert_path", path) {
                    errors.push(e);
                } else if let Err(e) = crate::tls::check_cert_expiry_for_validation(
                    path,
                    "backend_tls_client_cert_path",
                    cert_expiry_warning_days,
                ) {
                    errors.push(e);
                } else if let Some(ref mut cache) = validated_tls_paths {
                    cache.insert(path.clone());
                }
            }
        }
        if let Some(ref path) = self.backend_tls_client_key_path {
            let already_validated = validated_tls_paths
                .as_ref()
                .is_some_and(|s| s.contains(path.as_str()));
            if !already_validated {
                if let Err(e) = validate_pem_key_file("backend_tls_client_key_path", path) {
                    errors.push(e);
                } else if let Some(ref mut cache) = validated_tls_paths {
                    cache.insert(path.clone());
                }
            }
        }
        if let Some(ref path) = self.backend_tls_server_ca_cert_path {
            let already_validated = validated_tls_paths
                .as_ref()
                .is_some_and(|s| s.contains(path.as_str()));
            if !already_validated {
                if let Err(e) = validate_pem_cert_file("backend_tls_server_ca_cert_path", path) {
                    errors.push(e);
                } else if let Err(e) = crate::tls::check_cert_expiry_for_validation(
                    path,
                    "backend_tls_server_ca_cert_path",
                    cert_expiry_warning_days,
                ) {
                    errors.push(e);
                } else if let Some(ref mut cache) = validated_tls_paths {
                    cache.insert(path.clone());
                }
            }
        }

        // Allowed methods validation
        if let Some(ref methods) = self.allowed_methods {
            if methods.is_empty() {
                errors.push(
                    "allowed_methods must be null (allow all) or a non-empty array".to_string(),
                );
            }
            for method in methods {
                let upper = method.trim().to_uppercase();
                if !VALID_HTTP_METHODS.contains(&upper.as_str()) {
                    errors.push(format!(
                        "allowed_methods contains invalid HTTP method: {}",
                        method
                    ));
                }
            }
        }

        // UDP amplification factor validation
        if let Some(factor) = self.udp_max_response_amplification_factor
            && factor <= 0.0
        {
            errors.push("udp_max_response_amplification_factor must be positive".to_string());
        }

        // Allowed WebSocket origins validation
        for (i, origin) in self.allowed_ws_origins.iter().enumerate() {
            if origin.trim().is_empty() {
                errors.push(format!("allowed_ws_origins[{}] must not be empty", i));
            }
        }

        // DNS override
        if let Some(ref dns) = self.dns_override
            && let Err(e) = validate_string_field("dns_override", dns, MAX_BACKEND_HOST_LENGTH)
        {
            errors.push(e);
        }

        // Circuit breaker config
        if let Some(ref cb) = self.circuit_breaker
            && let Err(cb_errors) = cb.validate_fields()
        {
            for e in cb_errors {
                errors.push(format!("circuit_breaker.{}", e));
            }
        }

        // Retry config
        if let Some(ref retry) = self.retry
            && let Err(retry_errors) = retry.validate_fields()
        {
            for e in retry_errors {
                errors.push(format!("retry.{}", e));
            }
        }

        if is_stream_proxy && self.response_body_mode != ResponseBodyMode::Stream {
            errors.push("Stream proxies (TCP/UDP) must use response_body_mode 'stream'".into());
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl Consumer {
    /// Returns all credential entries for a given type, normalizing both
    /// single-object and array-of-objects formats for backward compatibility.
    ///
    /// - `{"keyauth": {"key": "abc"}}` → `vec![&{"key": "abc"}]`
    /// - `{"keyauth": [{"key": "abc"}, {"key": "def"}]}` → `vec![&{"key": "abc"}, &{"key": "def"}]`
    ///
    /// Called on cold paths (index build) and semi-hot paths (after O(1) consumer
    /// lookup, iterating 1-2 entries). Non-object array elements are filtered out.
    pub fn credential_entries(&self, cred_type: &str) -> Vec<&serde_json::Value> {
        match self.credentials.get(cred_type) {
            Some(serde_json::Value::Array(arr)) => arr.iter().filter(|v| v.is_object()).collect(),
            Some(val) if val.is_object() => vec![val],
            _ => vec![],
        }
    }

    /// Returns true if the consumer has any credentials of the given type.
    pub fn has_credential(&self, cred_type: &str) -> bool {
        match self.credentials.get(cred_type) {
            Some(serde_json::Value::Array(arr)) => arr.iter().any(|v| v.is_object()),
            Some(val) => val.is_object(),
            None => false,
        }
    }

    /// Normalize consumer fields to their canonical in-memory form.
    pub fn normalize_fields(&mut self) {
        if self
            .custom_id
            .as_ref()
            .is_some_and(|custom_id| custom_id.trim().is_empty())
        {
            self.custom_id = None;
        }
    }

    /// Validate all fields of a consumer for correctness and safe lengths.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Username
        if self.username.trim().is_empty() {
            errors.push("username must not be empty".to_string());
        }
        if let Err(e) = validate_string_field("username", &self.username, MAX_USERNAME_LENGTH) {
            errors.push(e);
        }

        // Custom ID
        if let Some(ref cid) = self.custom_id
            && let Err(e) = validate_string_field("custom_id", cid, MAX_CUSTOM_ID_LENGTH)
        {
            errors.push(e);
        }

        // ACL groups
        if self.acl_groups.len() > MAX_ACL_GROUPS_PER_CONSUMER {
            errors.push(format!(
                "acl_groups must not have more than {} entries (got {})",
                MAX_ACL_GROUPS_PER_CONSUMER,
                self.acl_groups.len()
            ));
        }
        for (i, group) in self.acl_groups.iter().enumerate() {
            if group.trim().is_empty() {
                errors.push(format!("acl_groups[{}] must not be empty", i));
            }
            if let Err(e) = validate_string_field("acl_groups entry", group, MAX_ACL_GROUP_LENGTH) {
                errors.push(e);
            }
        }

        // Credentials total size
        let cred_json = serde_json::to_string(&self.credentials).unwrap_or_default();
        if cred_json.len() > MAX_CREDENTIALS_SIZE {
            errors.push(format!(
                "credentials JSON must not exceed {} bytes (got {})",
                MAX_CREDENTIALS_SIZE,
                cred_json.len()
            ));
        }

        // Validate individual credential values (supports both single object and array formats)
        for (cred_type, cred_value) in &self.credentials {
            if let Err(e) = validate_string_field("credential type", cred_type, 64) {
                errors.push(e);
            }
            // Collect objects to validate: either a single object or array elements.
            // Non-object elements in arrays are rejected — they would be silently
            // ignored at runtime by credential_entries(), leaving the consumer with
            // fewer usable credentials than the operator intended.
            let objects: Vec<&serde_json::Map<String, serde_json::Value>> =
                if let Some(arr) = cred_value.as_array() {
                    let limit = max_credentials_per_type();
                    if arr.len() > limit {
                        errors.push(format!(
                            "credentials.{} array must not exceed {} entries (got {})",
                            cred_type,
                            limit,
                            arr.len()
                        ));
                    }
                    if arr.is_empty() {
                        errors.push(format!(
                            "credentials.{} array must not be empty — remove the key instead",
                            cred_type
                        ));
                    }
                    for (i, elem) in arr.iter().enumerate() {
                        if !elem.is_object() {
                            errors.push(format!(
                                "credentials.{}[{}] must be a JSON object, got {}",
                                cred_type,
                                i,
                                elem_type_name(elem)
                            ));
                        }
                    }
                    arr.iter().filter_map(|v| v.as_object()).collect()
                } else if let Some(obj) = cred_value.as_object() {
                    vec![obj]
                } else {
                    errors.push(format!(
                        "credentials.{} must be a JSON object or array of objects",
                        cred_type
                    ));
                    vec![]
                };
            for (idx, obj) in objects.iter().enumerate() {
                let prefix = if cred_value.is_array() {
                    format!("credentials.{}[{}]", cred_type, idx)
                } else {
                    format!("credentials.{}", cred_type)
                };
                for (key, val) in *obj {
                    if let Some(s) = val.as_str() {
                        if s.len() > MAX_CREDENTIAL_VALUE_LENGTH {
                            errors.push(format!(
                                "{}.{} must not exceed {} characters (got {})",
                                prefix,
                                key,
                                MAX_CREDENTIAL_VALUE_LENGTH,
                                s.len()
                            ));
                        }
                        if contains_control_chars(s) {
                            errors.push(format!(
                                "{}.{} must not contain control characters",
                                prefix, key
                            ));
                        }
                        if cred_type == "jwt" && key == "secret" && s.len() < MIN_JWT_SECRET_LENGTH
                        {
                            errors.push(format!(
                                "{}.secret must be at least {} characters (got {})",
                                prefix,
                                MIN_JWT_SECRET_LENGTH,
                                s.len()
                            ));
                        }
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
}

impl Upstream {
    /// Normalize upstream fields to their canonical in-memory form.
    pub fn normalize_fields(&mut self) {
        // RFC 1035: DNS names are case-insensitive. Normalize target hosts so
        // downstream consumers (DNS cache, health check keys, LB keys) never
        // create duplicate entries for mixed-case variants of the same hostname.
        for target in &mut self.targets {
            target.host = target.host.to_ascii_lowercase();
        }
    }

    /// Validate all fields of an upstream for correctness and safe lengths.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.targets.is_empty() && self.service_discovery.is_none() {
            errors.push("must have at least one target or service_discovery".to_string());
        }

        // Name
        if let Some(ref name) = self.name
            && let Err(e) = validate_string_field("name", name, MAX_NAME_LENGTH)
        {
            errors.push(e);
        }

        // hash_on
        if let Some(ref hash_on) = self.hash_on
            && let Err(e) = validate_string_field("hash_on", hash_on, MAX_HASH_ON_LENGTH)
        {
            errors.push(e);
        }

        // Validate hash_on format: must be "ip", "header:<name>", or "cookie:<name>"
        if let Some(ref hash_on) = self.hash_on {
            let trimmed = hash_on.trim();
            if !trimmed.is_empty()
                && trimmed != "ip"
                && !trimmed.starts_with("header:")
                && !trimmed.starts_with("cookie:")
            {
                errors.push(format!(
                    "hash_on must be 'ip', 'header:<name>', or 'cookie:<name>' (got '{}')",
                    trimmed
                ));
            }
            // Validate that header/cookie name is non-empty
            if let Some(name) = trimmed.strip_prefix("header:")
                && name.trim().is_empty()
            {
                errors.push("hash_on 'header:' requires a non-empty header name".to_string());
            }
            if let Some(name) = trimmed.strip_prefix("cookie:")
                && name.trim().is_empty()
            {
                errors.push("hash_on 'cookie:' requires a non-empty cookie name".to_string());
            }
        }

        // hash_on_cookie_config
        if let Some(ref cc) = self.hash_on_cookie_config {
            if let Err(e) = validate_string_field(
                "hash_on_cookie_config.path",
                &cc.path,
                MAX_COOKIE_PATH_LENGTH,
            ) {
                errors.push(e);
            }
            if let Some(ref domain) = cc.domain
                && let Err(e) = validate_string_field(
                    "hash_on_cookie_config.domain",
                    domain,
                    MAX_COOKIE_DOMAIN_LENGTH,
                )
            {
                errors.push(e);
            }
            if let Some(ref same_site) = cc.same_site
                && !["Strict", "Lax", "None"].contains(&same_site.as_str())
            {
                errors.push(format!(
                    "hash_on_cookie_config.same_site must be 'Strict', 'Lax', or 'None' (got '{}')",
                    same_site
                ));
            }
            if cc.ttl_seconds > MAX_TIMEOUT_SECONDS {
                errors.push(format!(
                    "hash_on_cookie_config.ttl_seconds must not exceed {} (got {})",
                    MAX_TIMEOUT_SECONDS, cc.ttl_seconds
                ));
            }
        }

        // Target count limit
        if self.targets.len() > MAX_TARGETS_PER_UPSTREAM {
            errors.push(format!(
                "targets must not have more than {} entries (got {})",
                MAX_TARGETS_PER_UPSTREAM,
                self.targets.len()
            ));
        }

        // Validate individual targets
        for (i, target) in self.targets.iter().enumerate() {
            if let Err(e) = validate_string_field(
                &format!("targets[{}].host", i),
                &target.host,
                MAX_BACKEND_HOST_LENGTH,
            ) {
                errors.push(e);
            }
            if target.host.is_empty() {
                errors.push(format!("targets[{}].host must not be empty", i));
            }
            if target.port == 0 {
                errors.push(format!("targets[{}].port must be greater than 0", i));
            }
            if target.weight == 0 || target.weight > MAX_TARGET_WEIGHT {
                errors.push(format!(
                    "targets[{}].weight must be between 1 and {} (got {})",
                    i, MAX_TARGET_WEIGHT, target.weight
                ));
            }
            // Tag limits
            if target.tags.len() > MAX_TAGS_PER_TARGET {
                errors.push(format!(
                    "targets[{}].tags must not have more than {} entries (got {})",
                    i,
                    MAX_TAGS_PER_TARGET,
                    target.tags.len()
                ));
            }
            for (key, val) in &target.tags {
                if key.len() > MAX_TAG_LENGTH {
                    errors.push(format!(
                        "targets[{}].tags key must not exceed {} characters",
                        i, MAX_TAG_LENGTH
                    ));
                }
                if val.len() > MAX_TAG_LENGTH {
                    errors.push(format!(
                        "targets[{}].tags value must not exceed {} characters",
                        i, MAX_TAG_LENGTH
                    ));
                }
            }
            // Target path
            if let Some(ref path) = target.path
                && let Err(e) = validate_string_field(
                    &format!("targets[{}].path", i),
                    path,
                    MAX_BACKEND_PATH_LENGTH,
                )
            {
                errors.push(e);
            }
        }

        // Health check config
        if let Some(ref hc) = self.health_checks
            && let Err(hc_errors) = hc.validate_fields()
        {
            for e in hc_errors {
                errors.push(format!("health_checks.{}", e));
            }
        }

        // Service discovery config
        if let Some(ref sd) = self.service_discovery
            && let Err(sd_errors) = sd.validate_fields()
        {
            for e in sd_errors {
                errors.push(format!("service_discovery.{}", e));
            }
        }

        // Backend TLS file path lengths
        if let Some(ref path) = self.backend_tls_client_cert_path
            && let Err(e) =
                validate_string_field("backend_tls_client_cert_path", path, MAX_FILE_PATH_LENGTH)
        {
            errors.push(e);
        }
        if let Some(ref path) = self.backend_tls_client_key_path
            && let Err(e) =
                validate_string_field("backend_tls_client_key_path", path, MAX_FILE_PATH_LENGTH)
        {
            errors.push(e);
        }
        if let Some(ref path) = self.backend_tls_server_ca_cert_path
            && let Err(e) = validate_string_field(
                "backend_tls_server_ca_cert_path",
                path,
                MAX_FILE_PATH_LENGTH,
            )
        {
            errors.push(e);
        }

        // TLS cert/key pairing: both must be set or neither
        match (
            &self.backend_tls_client_cert_path,
            &self.backend_tls_client_key_path,
        ) {
            (Some(_), None) => {
                errors.push(
                    "backend_tls_client_cert_path is set but backend_tls_client_key_path is missing — both must be configured together".to_string(),
                );
            }
            (None, Some(_)) => {
                errors.push(
                    "backend_tls_client_key_path is set but backend_tls_client_cert_path is missing — both must be configured together".to_string(),
                );
            }
            _ => {}
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }

    /// Validate fields with a shared TLS path cache and cert expiry checking.
    pub fn validate_fields_with_cache(
        &self,
        validated_tls_paths: &mut HashSet<String>,
        cert_expiry_warning_days: u64,
    ) -> Result<(), Vec<String>> {
        let mut errors = match self.validate_fields() {
            Ok(()) => Vec::new(),
            Err(errs) => errs,
        };

        // TLS file content validation with deduplication.
        if let Some(ref path) = self.backend_tls_client_cert_path {
            let already_validated = validated_tls_paths.contains(path.as_str());
            if !already_validated {
                if let Err(e) = validate_pem_cert_file("backend_tls_client_cert_path", path) {
                    errors.push(e);
                } else if let Err(e) = crate::tls::check_cert_expiry_for_validation(
                    path,
                    "backend_tls_client_cert_path",
                    cert_expiry_warning_days,
                ) {
                    errors.push(e);
                } else {
                    validated_tls_paths.insert(path.clone());
                }
            }
        }
        if let Some(ref path) = self.backend_tls_client_key_path {
            let already_validated = validated_tls_paths.contains(path.as_str());
            if !already_validated {
                if let Err(e) = validate_pem_key_file("backend_tls_client_key_path", path) {
                    errors.push(e);
                } else {
                    validated_tls_paths.insert(path.clone());
                }
            }
        }
        if let Some(ref path) = self.backend_tls_server_ca_cert_path {
            let already_validated = validated_tls_paths.contains(path.as_str());
            if !already_validated {
                if let Err(e) = validate_pem_cert_file("backend_tls_server_ca_cert_path", path) {
                    errors.push(e);
                } else if let Err(e) = crate::tls::check_cert_expiry_for_validation(
                    path,
                    "backend_tls_server_ca_cert_path",
                    cert_expiry_warning_days,
                ) {
                    errors.push(e);
                } else {
                    validated_tls_paths.insert(path.clone());
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl PluginConfig {
    /// Normalize plugin config fields to their canonical in-memory form.
    pub fn normalize_fields(&mut self) {
        if self
            .proxy_id
            .as_ref()
            .is_some_and(|proxy_id| proxy_id.trim().is_empty())
        {
            self.proxy_id = None;
        }
    }

    /// Validate all fields of a plugin config for correctness and safe lengths.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Plugin name length (should already be validated against known plugins,
        // but enforce a length limit as defense-in-depth)
        if self.plugin_name.trim().is_empty() {
            errors.push("plugin_name must not be empty".to_string());
        }
        if let Err(e) = validate_string_field("plugin_name", &self.plugin_name, MAX_NAME_LENGTH) {
            errors.push(e);
        }

        match self.scope {
            PluginScope::Proxy => match self.proxy_id.as_deref() {
                Some(proxy_id) => {
                    if let Err(e) = validate_resource_id(proxy_id) {
                        errors.push(format!("proxy_id {}", e));
                    }
                }
                None => errors.push("scope 'proxy' requires proxy_id".to_string()),
            },
            PluginScope::Global => {
                if self.proxy_id.is_some() {
                    errors.push("scope 'global' must not have proxy_id".to_string());
                }
            }
            PluginScope::ProxyGroup => {
                if self.proxy_id.is_some() {
                    errors.push("scope 'proxy_group' must not have proxy_id (associations are managed via proxy.plugins)".to_string());
                }
            }
        }

        // Config JSON size
        let config_json = serde_json::to_string(&self.config).unwrap_or_default();
        if config_json.len() > MAX_PLUGIN_CONFIG_SIZE {
            errors.push(format!(
                "config JSON must not exceed {} bytes (got {})",
                MAX_PLUGIN_CONFIG_SIZE,
                config_json.len()
            ));
        }

        // Config JSON nesting depth
        if json_depth(&self.config) > 10 {
            errors.push("config JSON nesting depth must not exceed 10".to_string());
        }

        // Priority override range (0–10000 keeps plugins within sane ordering bands)
        if let Some(p) = self.priority_override
            && p > 10000
        {
            errors.push(format!(
                "priority_override must be between 0 and 10000 (got {})",
                p
            ));
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl CircuitBreakerConfig {
    /// Validate circuit breaker configuration fields.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if let Err(e) = validate_u32_range(
            "failure_threshold",
            self.failure_threshold,
            1,
            MAX_THRESHOLD,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u32_range(
            "success_threshold",
            self.success_threshold,
            1,
            MAX_THRESHOLD,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u64_range(
            "timeout_seconds",
            self.timeout_seconds,
            1,
            MAX_TIMEOUT_SECONDS,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_u32_range(
            "half_open_max_requests",
            self.half_open_max_requests,
            1,
            MAX_THRESHOLD,
        ) {
            errors.push(e);
        }
        if let Err(e) = validate_status_codes("failure_status_codes", &self.failure_status_codes) {
            errors.push(e);
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl RetryConfig {
    /// Validate retry configuration fields.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if let Err(e) = validate_u32_range("max_retries", self.max_retries, 0, MAX_RETRIES) {
            errors.push(e);
        }
        if let Err(e) =
            validate_status_codes("retryable_status_codes", &self.retryable_status_codes)
        {
            errors.push(e);
        }
        if self.retryable_methods.len() > MAX_RETRYABLE_METHODS {
            errors.push(format!(
                "retryable_methods must not have more than {} entries (got {})",
                MAX_RETRYABLE_METHODS,
                self.retryable_methods.len()
            ));
        }
        for method in &self.retryable_methods {
            let upper = method.to_uppercase();
            if !VALID_HTTP_METHODS.contains(&upper.as_str()) {
                errors.push(format!(
                    "retryable_methods contains invalid HTTP method: {}",
                    method
                ));
            }
        }

        // Validate backoff
        match &self.backoff {
            BackoffStrategy::Fixed { delay_ms } => {
                if *delay_ms > MAX_BACKOFF_MS {
                    errors.push(format!(
                        "backoff.delay_ms must not exceed {} (got {})",
                        MAX_BACKOFF_MS, delay_ms
                    ));
                }
            }
            BackoffStrategy::Exponential { base_ms, max_ms } => {
                if *base_ms > MAX_BACKOFF_MS {
                    errors.push(format!(
                        "backoff.base_ms must not exceed {} (got {})",
                        MAX_BACKOFF_MS, base_ms
                    ));
                }
                if *max_ms > MAX_BACKOFF_MS {
                    errors.push(format!(
                        "backoff.max_ms must not exceed {} (got {})",
                        MAX_BACKOFF_MS, max_ms
                    ));
                }
                if *base_ms > *max_ms {
                    errors.push(format!(
                        "backoff.base_ms ({}) must not exceed backoff.max_ms ({})",
                        base_ms, max_ms
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
}

impl HealthCheckConfig {
    /// Validate health check configuration fields.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if let Some(ref active) = self.active {
            if let Err(e) = validate_string_field(
                "active.http_path",
                &active.http_path,
                MAX_BACKEND_PATH_LENGTH,
            ) {
                errors.push(e);
            }
            if let Err(e) = validate_u64_range(
                "active.interval_seconds",
                active.interval_seconds,
                1,
                MAX_HEALTH_CHECK_INTERVAL,
            ) {
                errors.push(e);
            }
            if let Err(e) =
                validate_u64_range("active.timeout_ms", active.timeout_ms, 1, MAX_TIMEOUT_MS)
            {
                errors.push(e);
            }
            if let Err(e) = validate_u32_range(
                "active.healthy_threshold",
                active.healthy_threshold,
                1,
                MAX_THRESHOLD,
            ) {
                errors.push(e);
            }
            if let Err(e) = validate_u32_range(
                "active.unhealthy_threshold",
                active.unhealthy_threshold,
                1,
                MAX_THRESHOLD,
            ) {
                errors.push(e);
            }
            if let Err(e) =
                validate_status_codes("active.healthy_status_codes", &active.healthy_status_codes)
            {
                errors.push(e);
            }
            if let Some(ref payload) = active.udp_probe_payload
                && let Err(e) = validate_string_field("active.udp_probe_payload", payload, 2048)
            {
                errors.push(e);
            }
        }

        if let Some(ref passive) = self.passive {
            if let Err(e) = validate_status_codes(
                "passive.unhealthy_status_codes",
                &passive.unhealthy_status_codes,
            ) {
                errors.push(e);
            }
            if let Err(e) = validate_u32_range(
                "passive.unhealthy_threshold",
                passive.unhealthy_threshold,
                1,
                MAX_THRESHOLD,
            ) {
                errors.push(e);
            }
            if let Err(e) = validate_u64_range(
                "passive.unhealthy_window_seconds",
                passive.unhealthy_window_seconds,
                1,
                MAX_TIMEOUT_SECONDS,
            ) {
                errors.push(e);
            }
            // healthy_after_seconds can be 0 (disabled), so min is 0
            if let Err(e) = validate_u64_range(
                "passive.healthy_after_seconds",
                passive.healthy_after_seconds,
                0,
                MAX_TIMEOUT_SECONDS,
            ) {
                errors.push(e);
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl ServiceDiscoveryConfig {
    /// Validate service discovery configuration fields.
    pub fn validate_fields(&self) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        if self.default_weight == 0 || self.default_weight > MAX_TARGET_WEIGHT {
            errors.push(format!(
                "default_weight must be between 1 and {} (got {})",
                MAX_TARGET_WEIGHT, self.default_weight
            ));
        }

        match self.provider {
            SdProvider::DnsSd => {
                if let Some(ref dns_sd) = self.dns_sd {
                    if let Err(e) = validate_string_field(
                        "dns_sd.service_name",
                        &dns_sd.service_name,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if dns_sd.service_name.is_empty() {
                        errors.push("dns_sd.service_name must not be empty".to_string());
                    }
                    if let Err(e) = validate_u64_range(
                        "dns_sd.poll_interval_seconds",
                        dns_sd.poll_interval_seconds,
                        1,
                        MAX_SD_POLL_INTERVAL,
                    ) {
                        errors.push(e);
                    }
                } else {
                    errors.push("dns_sd config is required when provider is dns_sd".to_string());
                }
            }
            SdProvider::Kubernetes => {
                if let Some(ref k8s) = self.kubernetes {
                    if let Err(e) = validate_string_field(
                        "kubernetes.namespace",
                        &k8s.namespace,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if let Err(e) = validate_string_field(
                        "kubernetes.service_name",
                        &k8s.service_name,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if k8s.service_name.is_empty() {
                        errors.push("kubernetes.service_name must not be empty".to_string());
                    }
                    if let Some(ref port_name) = k8s.port_name
                        && let Err(e) = validate_string_field(
                            "kubernetes.port_name",
                            port_name,
                            MAX_SD_STRING_LENGTH,
                        )
                    {
                        errors.push(e);
                    }
                    if let Some(ref label_selector) = k8s.label_selector
                        && let Err(e) =
                            validate_string_field("kubernetes.label_selector", label_selector, 1024)
                    {
                        errors.push(e);
                    }
                    if let Err(e) = validate_u64_range(
                        "kubernetes.poll_interval_seconds",
                        k8s.poll_interval_seconds,
                        1,
                        MAX_SD_POLL_INTERVAL,
                    ) {
                        errors.push(e);
                    }
                } else {
                    errors.push(
                        "kubernetes config is required when provider is kubernetes".to_string(),
                    );
                }
            }
            SdProvider::Consul => {
                if let Some(ref consul) = self.consul {
                    if let Err(e) = validate_string_field(
                        "consul.address",
                        &consul.address,
                        MAX_BACKEND_PATH_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if consul.address.is_empty() {
                        errors.push("consul.address must not be empty".to_string());
                    }
                    if let Err(e) = validate_string_field(
                        "consul.service_name",
                        &consul.service_name,
                        MAX_NAME_LENGTH,
                    ) {
                        errors.push(e);
                    }
                    if consul.service_name.is_empty() {
                        errors.push("consul.service_name must not be empty".to_string());
                    }
                    if let Some(ref dc) = consul.datacenter
                        && let Err(e) =
                            validate_string_field("consul.datacenter", dc, MAX_SD_STRING_LENGTH)
                    {
                        errors.push(e);
                    }
                    if let Some(ref tag) = consul.tag
                        && let Err(e) =
                            validate_string_field("consul.tag", tag, MAX_SD_STRING_LENGTH)
                    {
                        errors.push(e);
                    }
                    if let Some(ref token) = consul.token
                        && let Err(e) = validate_string_field(
                            "consul.token",
                            token,
                            MAX_CREDENTIAL_VALUE_LENGTH,
                        )
                    {
                        errors.push(e);
                    }
                    if let Err(e) = validate_u64_range(
                        "consul.poll_interval_seconds",
                        consul.poll_interval_seconds,
                        1,
                        MAX_SD_POLL_INTERVAL,
                    ) {
                        errors.push(e);
                    }
                } else {
                    errors.push("consul config is required when provider is consul".to_string());
                }
            }
        }

        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

impl GatewayConfig {
    /// Validate all field-level constraints across every resource in the config.
    ///
    /// This validates individual field values (lengths, ranges, formats) — not
    /// cross-resource constraints like uniqueness or FK references, which are
    /// handled by the existing `validate_*` methods.
    ///
    /// `cert_expiry_warning_days` controls the near-expiry warning threshold
    /// for TLS certificate files. Expired certificates are always rejected.
    pub fn validate_all_fields(&self, cert_expiry_warning_days: u64) -> Result<(), Vec<String>> {
        self.validate_all_fields_with_ip_policy(
            cert_expiry_warning_days,
            &crate::config::BackendAllowIps::Both,
        )
    }

    /// Validate all fields with backend IP policy enforcement.
    pub fn validate_all_fields_with_ip_policy(
        &self,
        cert_expiry_warning_days: u64,
        backend_allow_ips: &crate::config::BackendAllowIps,
    ) -> Result<(), Vec<String>> {
        let mut errors = Vec::new();

        // Shared cache: when multiple proxies reference the same TLS file path,
        // each file is opened and parsed only once during batch validation.
        let mut validated_tls_paths = std::collections::HashSet::new();
        for proxy in &self.proxies {
            if let Err(errs) =
                proxy.validate_fields_with_cache(&mut validated_tls_paths, cert_expiry_warning_days)
            {
                for e in errs {
                    errors.push(format!("Proxy '{}': {}", proxy.id, e));
                }
            }
        }
        for consumer in &self.consumers {
            if let Err(errs) = consumer.validate_fields() {
                for e in errs {
                    errors.push(format!("Consumer '{}': {}", consumer.id, e));
                }
            }
        }
        for upstream in &self.upstreams {
            if let Err(errs) = upstream
                .validate_fields_with_cache(&mut validated_tls_paths, cert_expiry_warning_days)
            {
                for e in errs {
                    errors.push(format!("Upstream '{}': {}", upstream.id, e));
                }
            }
        }
        for pc in &self.plugin_configs {
            if let Err(errs) = pc.validate_fields() {
                for e in errs {
                    errors.push(format!("PluginConfig '{}': {}", pc.id, e));
                }
            }
        }

        // SSRF: validate literal IP backend_host / upstream target host values
        if !matches!(backend_allow_ips, crate::config::BackendAllowIps::Both) {
            for proxy in &self.proxies {
                if let Ok(ip) = proxy.backend_host.parse::<std::net::IpAddr>()
                    && !crate::config::check_backend_ip_allowed(&ip, backend_allow_ips)
                {
                    errors.push(format!(
                        "Proxy '{}': backend_host IP {} denied by FERRUM_BACKEND_ALLOW_IPS={} policy",
                        proxy.id, ip, backend_allow_ips
                    ));
                }
            }
            for upstream in &self.upstreams {
                for (i, target) in upstream.targets.iter().enumerate() {
                    if let Ok(ip) = target.host.parse::<std::net::IpAddr>()
                        && !crate::config::check_backend_ip_allowed(&ip, backend_allow_ips)
                    {
                        errors.push(format!(
                            "Upstream '{}': targets[{}].host IP {} denied by FERRUM_BACKEND_ALLOW_IPS={} policy",
                            upstream.id, i, ip, backend_allow_ips
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

    /// Validate file dependencies for plugins that reference external files
    /// (e.g., geo_restriction `.mmdb` databases).
    ///
    /// This is separate from `validate_all_fields_with_ip_policy()` so that
    /// each mode can handle missing files independently:
    /// - **File mode**: fatal (bail)
    /// - **DB mode**: warn (data already in DB)
    /// - **DP mode**: skip (plugin degrades gracefully with `reader: None`)
    ///
    /// Deduplicates paths so each file is checked at most once.
    pub fn validate_plugin_file_dependencies(&self) -> Vec<String> {
        let mut errors = Vec::new();
        let mut validated_paths = std::collections::HashSet::new();
        for pc in &self.plugin_configs {
            if !pc.enabled {
                continue;
            }
            if pc.plugin_name == "geo_restriction"
                && let Some(db_path) = pc.config.get("db_path").and_then(|v| v.as_str())
                && !db_path.is_empty()
                && validated_paths.insert(db_path.to_string())
                && let Err(e) = validate_mmdb_file("geo_restriction.db_path", db_path)
            {
                errors.push(format!("PluginConfig '{}': {}", pc.id, e));
            }
        }
        errors
    }
}

/// Compute the maximum nesting depth of a JSON value.
fn json_depth(value: &serde_json::Value) -> usize {
    match value {
        serde_json::Value::Array(arr) => 1 + arr.iter().map(json_depth).max().unwrap_or(0),
        serde_json::Value::Object(map) => 1 + map.values().map(json_depth).max().unwrap_or(0),
        _ => 0,
    }
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
