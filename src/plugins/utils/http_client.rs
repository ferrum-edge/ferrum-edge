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
//! - **HTTP/2 prior knowledge companion**: [`PluginHttpClient::get_http2`] for
//!   cleartext h2c / TLS ALPN-h2 destinations (native gRPC mirrors) without
//!   forcing ordinary plugin HTTP onto HTTP/2-only
//! - **Idle timeout**: Stale connections cleaned up automatically
//! - **DNS caching**: Uses the gateway's `DnsCache` for shared, warmed DNS
//! - **No ambient proxy discovery**: standard client builders ignore
//!   process-level proxy environment variables
//! - **No redirect following**: outbound calls reach only the configured
//!   endpoint; server-chosen 3xx targets (e.g. a cloud metadata IP) are never
//!   followed — SSRF defense-in-depth
//! - **No ambient proxies**: `HTTP_PROXY`, `HTTPS_PROXY`, and related process
//!   variables cannot redirect plugin traffic around gateway egress policy
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

use crate::config::{BackendEgressPolicy, PoolConfig};
use crate::dns::{DnsCache, DnsCacheResolver};
use crate::retry::{ErrorClass, classify_reqwest_error};
use crate::tls::CrlList;
use crate::tls::source::{CertSource, MaterialKind, load_material_blocking};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

/// Sanitized failure from a redacted plugin HTTP request.
///
/// `request_reached_wire` is false for request-construction failures and for
/// transport classes that prove no request bytes reached the destination. A
/// caller sending a non-idempotent request can use this boundary to avoid
/// replaying ambiguous outcomes.
#[derive(Debug, Clone, Copy)]
pub struct PluginHttpFailure {
    pub error_class: ErrorClass,
    pub request_reached_wire: bool,
}

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
    /// HTTP/2-only companion built with `http2_prior_knowledge()` so cleartext
    /// destinations speak h2c and TLS destinations negotiate ALPN `h2`. Shares
    /// the same DNS resolver, TLS posture, pool/keepalive tuning, redirect, and
    /// no-proxy invariants as [`Self::client`]. Used by native gRPC mirror
    /// traffic; ordinary plugin HTTP continues to use [`Self::client`].
    http2_client: Arc<reqwest::Client>,
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
    /// Certificate Revocation Lists for outbound TLS verification.
    /// Loaded once at startup from `FERRUM_TLS_CRL_FILE_PATH` and shared via Arc.
    /// Used by non-reqwest TLS sinks (tcp_logging, ws_logging, udp_logging DTLS)
    /// so that revoked backend certificates are rejected on log-shipping paths,
    /// matching the policy applied to the proxy backend / DTLS / frontend mTLS surfaces.
    /// Empty when `FERRUM_TLS_CRL_FILE_PATH` is unset.
    tls_crls: CrlList,
    /// Filesystem identity derived from the configured gateway CRL source.
    /// Plain paths and `file://` URIs are normalized here; inline material and
    /// provider-backed sources deliberately have no path because librdkafka
    /// cannot consume the parsed DER CRLs above directly.
    tls_crl_file_path: Option<String>,
    /// Whether any non-empty gateway CRL source was configured. This remains
    /// separate from `tls_crl_file_path` so non-file sources fail closed for
    /// sinks such as Kafka that require a filesystem path.
    tls_crl_source_configured: bool,
    /// The gateway's namespace (`FERRUM_NAMESPACE`). Used by plugins that store
    /// state in external systems (Redis, Prometheus, StatsD) to prevent key/metric
    /// collisions when multiple gateway instances with different namespaces share
    /// the same external backend.
    namespace: String,
    /// Effective authoritative client-IP header after env/conf precedence and
    /// normalization. Plugin construction uses this cold-path value to keep
    /// correlation writers from claiming gateway-owned attribution state.
    real_ip_header: Option<String>,
    /// Resolved backend IP policy (`FERRUM_BACKEND_ALLOW_IPS` after CLI/env/conf
    /// precedence). Used by plugins that validate outbound endpoints outside the
    /// proxy backend path.
    backend_allow_ips: BackendEgressPolicy,
    /// W3C `baggage` key prefixes stripped from outbound requests built by
    /// plugins (e.g., `request_mirror`'s mirror destination). Mirrors the
    /// proxy-path strip controlled by `FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS`
    /// — a plugin that reaches a non-mesh destination on its own should
    /// apply the same operator policy via
    /// [`Self::strip_egress_baggage_in_vec`] /
    /// [`Self::strip_egress_baggage_in_map`]. Empty by default.
    mesh_egress_strip_baggage_keys: Arc<Vec<String>>,
    /// Shared SOCK_OPS metrics state populated by the kernel ringbuf
    /// consumer. `Some(_)` only on mesh-mode node-waypoint topology where
    /// the gateway opens the pinned ringbuf from the node-agent; `None`
    /// in every other mode so the `__mesh_bpf_metrics` plugin (which
    /// reads this slot) falls back to a fresh unattached state and
    /// emits zero counters rather than panicking.
    bpf_metrics_state: Option<Arc<crate::ebpf::bpf_metrics::BpfMetricsState>>,
    /// Operator override for hot-path DashMap shard counts.
    pool_shard_amount: usize,
    /// Process-wide content-coding gates carried into compression plugin
    /// construction. Defaults keep both supported codecs enabled.
    compression_gzip_enabled: bool,
    compression_brotli_enabled: bool,
    /// Process-wide request body ceiling used to cross-check compression
    /// `max_decompressed_request_size`. `0` means unlimited at the wire layer;
    /// the compression hard maximum still applies.
    max_request_body_size_bytes: usize,
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
            .field("tls_crls_count", &self.tls_crls.len())
            .field("namespace", &self.namespace)
            .field("backend_allow_ips", &self.backend_allow_ips)
            .field("pool_shard_amount", &self.pool_shard_amount)
            .field("compression_gzip_enabled", &self.compression_gzip_enabled)
            .field(
                "compression_brotli_enabled",
                &self.compression_brotli_enabled,
            )
            .field(
                "max_request_body_size_bytes",
                &self.max_request_body_size_bytes,
            )
            .finish()
    }
}

#[derive(Clone)]
enum PluginTlsPosture {
    PlatformRoots,
    SkipVerification,
    CustomCaBundle(Vec<reqwest::Certificate>),
    FailClosedCaBundle { source_id: String, reason: String },
}

impl PluginTlsPosture {
    fn from_config(tls_no_verify: bool, tls_ca_bundle_path: Option<&str>) -> Self {
        if tls_no_verify {
            return Self::SkipVerification;
        }

        let Some(ca_path) = tls_ca_bundle_path else {
            return Self::PlatformRoots;
        };

        let source = CertSource::parse(ca_path, MaterialKind::CaBundle);
        let source_id = source.redacted_source_id();
        let ca_material = match load_material_blocking(&source, MaterialKind::CaBundle) {
            Ok(ca_material) => ca_material,
            Err(error) => {
                return Self::fail_closed(source_id, error.to_string());
            }
        };

        match reqwest::Certificate::from_pem_bundle(ca_material.bytes.expose_secret()) {
            Ok(certs) if !certs.is_empty() => Self::CustomCaBundle(certs),
            Ok(_) => Self::fail_closed(
                ca_material.display_source_id,
                "CA bundle did not contain any PEM certificates".to_string(),
            ),
            Err(error) => Self::fail_closed(ca_material.display_source_id, error.to_string()),
        }
    }

    fn fail_closed(source_id: String, reason: String) -> Self {
        tracing::error!(
            ca_bundle = %source_id,
            error = %reason,
            "Failed to load configured plugin HTTP CA bundle; failing closed with an empty trust store"
        );
        Self::FailClosedCaBundle { source_id, reason }
    }

    fn apply(&self, builder: reqwest::ClientBuilder) -> reqwest::ClientBuilder {
        match self {
            Self::PlatformRoots => builder,
            Self::SkipVerification => builder.danger_accept_invalid_certs(true),
            Self::CustomCaBundle(certs) => builder.tls_certs_only(certs.clone()),
            Self::FailClosedCaBundle { source_id, reason } => {
                tracing::debug!(
                    ca_bundle = %source_id,
                    error = %reason,
                    "Applying empty trust store for invalid plugin HTTP CA bundle"
                );
                builder.tls_certs_only(Vec::<reqwest::Certificate>::new())
            }
        }
    }
}

/// Build a minimal `reqwest::Client` that still uses the gateway's DNS cache
/// when available.
///
/// Used as a fallback when a fully-configured builder fails (e.g., due to
/// unsupported pool/keep-alive settings). Keeps the DNS cache attached so
/// plugin outbound calls do not silently fall through to system DNS — every
/// call would otherwise burn an ephemeral port through a fresh OS resolver,
/// which CLAUDE.md explicitly forbids ("DnsCacheResolver must be plugged into
/// every reqwest::Client in production").
///
/// TLS posture is already resolved by the startup-only caller and is applied
/// again here so falling back never widens trust from a configured custom CA
/// bundle to platform/webpki roots.
///
/// When `http2_prior_knowledge` is true, the fallback retains HTTP/2-only
/// negotiation (h2c / ALPN h2) so a degraded build path cannot silently
/// downgrade native gRPC mirror traffic to HTTP/1.1.
///
/// If even this minimal builder fails, build a no-DNS fallback that still keeps
/// redirects and ambient proxies disabled and applies the caller's TLS posture.
/// If that cannot be constructed either, drop custom TLS posture but retain
/// those two non-negotiable egress controls.
fn env_flag_default_true(key: &str) -> bool {
    match std::env::var(key) {
        Ok(value) => {
            let normalized = value.trim().to_ascii_lowercase();
            !matches!(normalized.as_str(), "0" | "false" | "no" | "off")
        }
        Err(_) => true,
    }
}

fn build_dns_cached_fallback_client(
    dns_cache: Option<DnsCache>,
    tls_posture: &PluginTlsPosture,
    http2_prior_knowledge: bool,
) -> reqwest::Client {
    // Never auto-follow redirects on a shared outbound client (SSRF posture,
    // matches src/connection_pool.rs and the configured clients above).
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none());
    if let Some(dns_cache) = dns_cache {
        let resolver = DnsCacheResolver::new(dns_cache);
        builder = builder.dns_resolver(Arc::new(resolver));
    }
    builder = tls_posture.apply(builder);
    if http2_prior_knowledge {
        builder = builder.http2_prior_knowledge();
    }
    builder.build().unwrap_or_else(|e| {
        tracing::error!(
            "Failed to build minimal DNS-cached fallback plugin client: {}. \
             Falling back to a no-redirect minimal plugin client with the same \
             TLS posture as a last resort.",
            e
        );
        let mut builder = tls_posture.apply(
            reqwest::Client::builder()
                .no_proxy()
                .redirect(reqwest::redirect::Policy::none()),
        );
        if http2_prior_knowledge {
            builder = builder.http2_prior_knowledge();
        }
        match builder.build() {
            Ok(client) => client,
            Err(e2) => {
                tracing::error!(
                    "Failed to build fallback plugin client with redirect and TLS policy set: {}. \
                     Retrying without custom TLS posture while keeping redirects disabled.",
                    e2
                );
                let mut builder = reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none());
                if http2_prior_knowledge {
                    builder = builder.http2_prior_knowledge();
                }
                builder.build().unwrap_or_else(|e3| {
                    // The production gateway builds this shared client
                    // before its initial plugin cache. Full and delta
                    // cache rebuilds clone that existing client and never
                    // re-enter this builder.
                    //
                    // Invariant: a bare reqwest builder with no custom
                    // resolver, TLS material, proxy, or redirect policy
                    // has no fallible operator input. If reqwest ever
                    // breaks that invariant, aborting client construction
                    // is safer than silently re-enabling ambient proxy
                    // routing.
                    panic!("Failed to build fail-closed minimal plugin HTTP client: {e3}")
                })
            }
        }
    })
}

/// Build a fully-configured plugin `reqwest::Client`, optionally forcing
/// HTTP/2 prior knowledge for native gRPC / h2c destinations.
fn build_configured_plugin_client(
    pool_config: &PoolConfig,
    dns_cache: Option<DnsCache>,
    tls_posture: &PluginTlsPosture,
    http2_prior_knowledge: bool,
) -> reqwest::Client {
    let mut builder = reqwest::Client::builder()
        .no_proxy()
        .pool_max_idle_per_host(pool_config.max_idle_per_host)
        .pool_idle_timeout(Duration::from_secs(pool_config.idle_timeout_seconds))
        .connect_timeout(Duration::from_secs(30))
        .timeout(Duration::from_secs(60))
        // Never auto-follow redirects on plugin outbound calls. A
        // compromised or spoofed upstream (e.g. an OIDC IdP whose JWKS or
        // discovery endpoint passes the first-hop same-host check in
        // jwks_auth's `validate_discovered_jwks_uri`) could otherwise
        // return a 3xx pointing at an attacker-chosen host such as the
        // cloud metadata endpoint (http://169.254.169.254/...), and reqwest
        // would follow it. Host/issuer pinning only validates the first
        // hop, and the `DnsCacheResolver` IP screen only rejects
        // private/loopback/link-local targets under a restrictive
        // `FERRUM_BACKEND_ALLOW_IPS` (not the default `Both`). Mirrors the
        // backend proxy client in `connection_pool.rs`.
        .redirect(reqwest::redirect::Policy::none());

    if let Some(dns_cache) = dns_cache.clone() {
        let resolver = DnsCacheResolver::new(dns_cache);
        builder = builder.dns_resolver(Arc::new(resolver));
    }

    // Trust resolution:
    //   - tls_no_verify=true   -> skip verification entirely
    //   - custom CA configured -> trust ONLY that parsed bundle
    //   - invalid custom CA    -> empty trust store (fail closed)
    //   - no CA configured     -> reqwest 0.13 defaults
    builder = tls_posture.apply(builder);

    if pool_config.enable_http_keep_alive {
        builder = builder.tcp_keepalive(Duration::from_secs(pool_config.tcp_keepalive_seconds));
    }

    // The companion is HTTP/2-only; the common block below applies identical
    // PING settings to both clients when `enable_http2` is on.
    if http2_prior_knowledge {
        builder = builder.http2_prior_knowledge();
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

    builder.build().unwrap_or_else(|e| {
        tracing::error!(
            http2_prior_knowledge,
            "Failed to build fully-configured plugin HTTP client: {e}. Retrying a \
             minimal builder that preserves the TLS trust posture (custom CA / \
             no-verify), DNS cache, and HTTP/2 preference, dropping only \
             pool/keepalive tuning — a custom CA configured for exclusivity must \
             not be silently widened to platform/webpki roots."
        );
        build_dns_cached_fallback_client(dns_cache, tls_posture, http2_prior_knowledge)
    })
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
    /// - An HTTP/2-prior-knowledge companion for native gRPC / h2c callers
    /// - Gateway DNS cache (shared TTL, stale-while-revalidate, background refresh)
    /// - Custom CA bundle from `FERRUM_TLS_CA_BUNDLE_PATH` (internal CAs)
    /// - `FERRUM_TLS_NO_VERIFY` support (skip TLS verification)
    /// - 30s connect timeout, 60s request timeout (generous for log sinks)
    /// - Redirect following disabled via `reqwest::redirect::Policy::none()`:
    ///   plugin egress reaches only the configured endpoint, never a
    ///   server-chosen 3xx target (SSRF defense-in-depth — mirrors the backend
    ///   proxy client in `connection_pool.rs`)
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        pool_config: &PoolConfig,
        dns_cache: DnsCache,
        slow_threshold_ms: u64,
        max_retries: u32,
        retry_delay_ms: u64,
        tls_no_verify: bool,
        tls_ca_bundle_path: Option<&str>,
        tls_crls: CrlList,
        namespace: &str,
        backend_allow_ips: BackendEgressPolicy,
        mesh_egress_strip_baggage_keys: Arc<Vec<String>>,
        pool_shard_amount: usize,
    ) -> Self {
        let dns_cache_clone = dns_cache.clone();
        let tls_posture = PluginTlsPosture::from_config(tls_no_verify, tls_ca_bundle_path);

        let client = build_configured_plugin_client(
            pool_config,
            Some(dns_cache.clone()),
            &tls_posture,
            false,
        );
        let http2_client =
            build_configured_plugin_client(pool_config, Some(dns_cache), &tls_posture, true);

        Self {
            client: Arc::new(client),
            http2_client: Arc::new(http2_client),
            slow_threshold: Duration::from_millis(slow_threshold_ms),
            max_retries,
            retry_delay: Duration::from_millis(retry_delay_ms),
            dns_cache: Some(dns_cache_clone),
            tls_no_verify,
            tls_ca_bundle_path: tls_ca_bundle_path.map(|s| s.to_string()),
            tls_crls,
            tls_crl_file_path: None,
            tls_crl_source_configured: false,
            namespace: namespace.to_string(),
            real_ip_header: None,
            backend_allow_ips,
            mesh_egress_strip_baggage_keys,
            bpf_metrics_state: None,
            pool_shard_amount,
            compression_gzip_enabled: true,
            compression_brotli_enabled: true,
            max_request_body_size_bytes: 0,
        }
    }

    /// Attach a shared SOCK_OPS metrics state so the
    /// `__mesh_bpf_metrics` plugin constructed via
    /// [`crate::plugins::create_plugin_with_http_client`] sees the same
    /// `Arc<BpfMetricsState>` the ringbuf consumer is updating.
    ///
    /// Builder method to keep call sites concise. `None` (default) leaves
    /// the plugin falling back to a fresh unattached state — safe in
    /// every non-mesh-node-waypoint deployment.
    pub fn with_bpf_metrics_state(
        mut self,
        state: Arc<crate::ebpf::bpf_metrics::BpfMetricsState>,
    ) -> Self {
        self.bpf_metrics_state = Some(state);
        self
    }

    /// Access the optional shared SOCK_OPS metrics state. Used by the
    /// `__mesh_bpf_metrics` plugin factory; `None` means "no consumer is
    /// updating real counters on this gateway — emit zeros".
    pub fn bpf_metrics_state(&self) -> Option<Arc<crate::ebpf::bpf_metrics::BpfMetricsState>> {
        self.bpf_metrics_state.clone()
    }

    /// Build a plugin HTTP client from pool config without a DNS cache.
    ///
    /// Uses reqwest's default DNS resolution. Prefer `new()` in production
    /// to share the gateway's DNS cache across all plugins.
    pub fn from_pool_config(config: &PoolConfig) -> Self {
        let tls_posture = PluginTlsPosture::PlatformRoots;
        let client = build_configured_plugin_client(config, None, &tls_posture, false);
        let http2_client = build_configured_plugin_client(config, None, &tls_posture, true);

        Self {
            client: Arc::new(client),
            http2_client: Arc::new(http2_client),
            slow_threshold: Duration::from_millis(1000),
            max_retries: 0,
            retry_delay: Duration::from_millis(100),
            dns_cache: None,
            tls_no_verify: false,
            tls_ca_bundle_path: None,
            tls_crls: Arc::new(Vec::new()),
            tls_crl_file_path: None,
            tls_crl_source_configured: false,
            namespace: crate::config::types::DEFAULT_NAMESPACE.to_string(),
            real_ip_header: None,
            backend_allow_ips: BackendEgressPolicy::unrestricted(),
            mesh_egress_strip_baggage_keys: Arc::new(Vec::new()),
            bpf_metrics_state: None,
            pool_shard_amount: 0,
            compression_gzip_enabled: true,
            compression_brotli_enabled: true,
            max_request_body_size_bytes: 0,
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

    /// Build a default-pool client carrying a specific backend IP egress policy.
    ///
    /// Used for admin plugin-config validation in modes that have no
    /// `ProxyState` (e.g. control plane), so a plugin's endpoint IP-policy
    /// check honors the gateway's configured `FERRUM_BACKEND_ALLOW_IPS` rather
    /// than defaulting open (`BackendEgressPolicy::unrestricted()`). Without this, a CP could
    /// accept a literal-IP backend endpoint that data planes later reject.
    pub fn default_with_backend_allow_ips(backend_allow_ips: BackendEgressPolicy) -> Self {
        // Route the validation client's reqwest stack through a DnsCacheResolver
        // carrying the same egress policy. Constructor side effects started
        // during config-load validation (e.g. jwks_auth / oidc_relying_party
        // background JWKS/discovery refresh) fetch hostname URLs; without the
        // resolver they would use the OS resolver, bypassing execute_request's
        // literal-only guard and letting a hostname that resolves — or rebinds —
        // to a denied IP (e.g. 169.254.169.254) be dialed before the real
        // runtime plugin is ever built. (jwks_auth construction is now pure;
        // other networked validators still need this protection.) The fresh
        // cache is cheap and short-lived (validation is a cold path), and
        // mirrors the runtime client's screen.
        let dns_cache = crate::dns::DnsCache::new(crate::dns::DnsConfig {
            backend_allow_ips: backend_allow_ips.clone(),
            ..Default::default()
        });
        Self::new(
            &PoolConfig::default(),
            dns_cache,
            1000, // slow_threshold_ms (from_pool_config default)
            0,    // max_retries
            100,  // retry_delay_ms (from_pool_config default)
            false,
            None,
            Arc::new(Vec::new()),
            crate::config::types::DEFAULT_NAMESPACE,
            backend_allow_ips,
            Arc::new(Vec::new()),
            0, // pool_shard_amount → auto
        )
    }

    /// Carry the already-resolved authoritative real-IP header into plugin
    /// construction and candidate admission. This remains cache-build state;
    /// request handling continues to use `EnvConfig` directly.
    pub(crate) fn with_real_ip_header(mut self, real_ip_header: Option<String>) -> Self {
        self.real_ip_header = real_ip_header;
        self
    }

    /// Carry the resolved process-wide compression codec gates into plugin
    /// cache construction. Per-plugin `algorithms` configuration is
    /// intersected with these values.
    pub(crate) fn with_compression_algorithms(
        mut self,
        gzip_enabled: bool,
        brotli_enabled: bool,
    ) -> Self {
        self.compression_gzip_enabled = gzip_enabled;
        self.compression_brotli_enabled = brotli_enabled;
        self
    }

    /// Carry the process-wide request body ceiling into compression plugin
    /// construction so `max_decompressed_request_size` cannot exceed the
    /// gateway's admitted upload bound.
    pub(crate) fn with_max_request_body_size_bytes(mut self, max_bytes: usize) -> Self {
        self.max_request_body_size_bytes = max_bytes;
        self
    }

    /// Apply process-wide compression codec gates and the gateway request-body
    /// ceiling from environment defaults.
    ///
    /// Admin/file/CP validation clients that do not inherit a live `ProxyState`
    /// plugin client must call this so compression admission matches the serving
    /// plugin cache (including `max_decompressed_request_size` cross-checks).
    pub(crate) fn with_process_compression_admission_policy(self) -> Self {
        let gzip_enabled = env_flag_default_true("FERRUM_COMPRESSION_GZIP_ENABLED");
        let brotli_enabled = env_flag_default_true("FERRUM_COMPRESSION_BROTLI_ENABLED");
        let max_request_body_size_bytes = std::env::var("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES")
            .ok()
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(10_485_760);
        self.with_compression_algorithms(gzip_enabled, brotli_enabled)
            .with_max_request_body_size_bytes(max_request_body_size_bytes)
    }

    pub(crate) fn compression_gzip_enabled(&self) -> bool {
        self.compression_gzip_enabled
    }

    pub(crate) fn compression_brotli_enabled(&self) -> bool {
        self.compression_brotli_enabled
    }

    pub(crate) fn max_request_body_size_bytes(&self) -> usize {
        self.max_request_body_size_bytes
    }

    /// Carry the configured gateway CRL source for non-rustls sinks. Only a
    /// plain path or `file://` URI has a librdkafka-compatible filesystem
    /// identity; other source kinds remain marked as configured so Kafka can
    /// reject verified TLS admission instead of silently omitting revocation.
    pub fn with_tls_crl_source(mut self, tls_crl_source: Option<String>) -> Self {
        let source = tls_crl_source
            .as_deref()
            .map(str::trim)
            .filter(|source| !source.is_empty());
        self.tls_crl_source_configured = source.is_some();
        self.tls_crl_file_path = source
            .and_then(|source| CertSource::parse(source, MaterialKind::Crl).as_file_path())
            .map(|path| path.to_string_lossy().into_owned());
        self
    }

    /// Effective authoritative real-IP header for cold-path plugin validation.
    pub(crate) fn real_ip_header(&self) -> Option<&str> {
        self.real_ip_header.as_deref()
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

    /// The gateway's loaded Certificate Revocation Lists (`FERRUM_TLS_CRL_FILE_PATH`).
    ///
    /// Empty when no CRL file is configured. Used by plugins that build their own
    /// `rustls::ClientConfig` (tcp_logging, ws_logging, udp_logging DTLS) so that
    /// revoked backend certificates are rejected on log-shipping paths, matching
    /// the policy applied to the proxy backend / DTLS / frontend mTLS surfaces.
    /// reqwest-based outbound calls are unaffected — reqwest does not expose CRL
    /// configuration.
    pub fn tls_crls(&self) -> &[rustls::pki_types::CertificateRevocationListDer<'static>] {
        &self.tls_crls
    }

    /// Filesystem path for `FERRUM_TLS_CRL_FILE_PATH` when a gateway CRL was
    /// loaded. Used by librdkafka (`ssl.crl.location`); rustls sinks consume
    /// [`Self::tls_crls`] instead.
    pub fn tls_crl_file_path(&self) -> Option<&str> {
        self.tls_crl_file_path.as_deref()
    }

    /// Whether a gateway CRL source was configured, including source kinds
    /// that cannot be represented as a filesystem path for librdkafka.
    pub(crate) fn tls_crl_source_configured(&self) -> bool {
        self.tls_crl_source_configured
    }

    /// The gateway's namespace (`FERRUM_NAMESPACE`).
    ///
    /// Used by plugins to namespace Redis keys and metric labels when multiple
    /// gateway instances share a single external backend.
    pub fn namespace(&self) -> &str {
        &self.namespace
    }

    /// Effective shard count for hot-path plugin DashMaps.
    pub fn pool_shard_amount(&self) -> usize {
        crate::util::sharding::pool_shard_amount(self.pool_shard_amount)
    }

    /// Resolved backend IP allowlist policy.
    ///
    /// This is the gateway-level `FERRUM_BACKEND_ALLOW_IPS` value after the
    /// normal CLI/env/conf/default precedence has been applied.
    pub fn backend_allow_ips(&self) -> &BackendEgressPolicy {
        &self.backend_allow_ips
    }

    /// Apply the gateway's egress baggage strip policy to a Vec of outbound
    /// headers. Plugins that build their own outbound HTTP requests
    /// (`request_mirror`, etc.) should call this before sending so the
    /// `FERRUM_MESH_EGRESS_STRIP_BAGGAGE_KEYS` policy applies uniformly to
    /// every egress destination — not just the proxy backend.
    pub fn strip_egress_baggage_in_vec(&self, headers: &mut Vec<(String, String)>) {
        crate::modes::mesh::hbone::strip_egress_baggage_in_vec(
            headers,
            &self.mesh_egress_strip_baggage_keys,
        );
    }

    /// Apply the gateway's egress baggage strip policy to a HashMap of
    /// outbound headers. Mirror of [`Self::strip_egress_baggage_in_vec`] for
    /// HashMap-shaped header collections.
    pub fn strip_egress_baggage_in_map(
        &self,
        headers: &mut std::collections::HashMap<String, String>,
    ) {
        crate::modes::mesh::hbone::strip_egress_baggage_in_map(
            headers,
            &self.mesh_egress_strip_baggage_keys,
        );
    }

    /// Get the underlying `reqwest::Client` for building requests.
    ///
    /// The returned client uses pooled connections - no per-call overhead.
    /// Prefer [`execute`] over calling `.send()` directly so that slow
    /// outbound calls are automatically logged with the destination URL.
    /// Use [`execute_redacted`] instead when the URL itself contains a secret
    /// token, such as incoming-webhook URLs.
    ///
    /// For native gRPC / cleartext HTTP/2 destinations, use [`get_http2`]
    /// instead so the request is built on the HTTP/2-prior-knowledge companion.
    pub fn get(&self) -> &reqwest::Client {
        &self.client
    }

    /// Get the HTTP/2-prior-knowledge companion client.
    ///
    /// Cleartext destinations use h2c; TLS destinations negotiate ALPN `h2`
    /// only. Shares DNS, TLS posture, pool/keepalive, redirect, and no-proxy
    /// invariants with [`get`]. Pass builders from this client through
    /// [`execute_http2_redacted`] so redaction and egress screening still run.
    /// The ordinary execute helpers deliberately remain pinned to the default
    /// shared client.
    pub fn get_http2(&self) -> &reqwest::Client {
        &self.http2_client
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
        self.execute_request(request, label, None, None).await
    }

    /// Send a pre-built request while logging only a caller-supplied redacted
    /// URL and returning a sanitized error string.
    ///
    /// This is for webhook-style endpoints whose path/query embeds credentials.
    /// The underlying request still uses the full URL, but slow-call and retry
    /// logs use `redacted_url`, and transport errors are reduced to
    /// `ErrorClass` so `reqwest::Error` cannot print the secret URL.
    pub async fn execute_redacted(
        &self,
        request: reqwest::RequestBuilder,
        label: &str,
        redacted_url: &str,
    ) -> Result<reqwest::Response, String> {
        let request = request.build().map_err(|e| {
            let error_class = classify_reqwest_error(&e);
            format!("{error_class} building request to {redacted_url}")
        })?;
        self.execute_request(request, label, None, Some(redacted_url))
            .await
            .map_err(|e| {
                let error_class = classify_reqwest_error(&e);
                format!("{error_class} calling {redacted_url}")
            })
    }

    /// Send a request through the trusted HTTP/2-prior-knowledge companion
    /// while logging only a caller-supplied redacted URL.
    ///
    /// This is intentionally separate from [`execute_redacted`]: ordinary
    /// plugin calls remain pinned to the default shared client, and callers
    /// cannot choose an arbitrary embedded `reqwest::Client` through their
    /// request builder.
    pub async fn execute_http2_redacted(
        &self,
        request: reqwest::RequestBuilder,
        label: &str,
        redacted_url: &str,
    ) -> Result<reqwest::Response, String> {
        let request = request.build().map_err(|e| {
            let error_class = classify_reqwest_error(&e);
            format!("{error_class} building request to {redacted_url}")
        })?;
        self.execute_request_with_client(
            &self.http2_client,
            request,
            label,
            None,
            Some(redacted_url),
        )
        .await
        .map_err(|e| {
            let error_class = classify_reqwest_error(&e);
            format!("{error_class} calling {redacted_url}")
        })
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
        self.execute_request(request, label, Some(accumulator), None)
            .await
    }

    /// Send a request with redacted logging AND elapsed-time accumulation.
    ///
    /// Combines [`execute_redacted`] (logs only `redacted_url`, returns a
    /// sanitized error string so the full secret-bearing URL never reaches
    /// logs) with [`execute_tracked`] (adds the round-trip time in nanoseconds
    /// to `accumulator`). Plugins that make external HTTP calls during the
    /// request lifecycle use this so the gateway can report
    /// `latency_plugin_external_io_ms` in transaction logs.
    pub async fn execute_redacted_tracked(
        &self,
        request: reqwest::RequestBuilder,
        label: &str,
        redacted_url: &str,
        accumulator: &AtomicU64,
    ) -> Result<reqwest::Response, String> {
        let request = request.build().map_err(|e| {
            let error_class = classify_reqwest_error(&e);
            format!("{error_class} building request to {redacted_url}")
        })?;
        self.execute_request(request, label, Some(accumulator), Some(redacted_url))
            .await
            .map_err(|e| {
                let error_class = classify_reqwest_error(&e);
                format!("{error_class} calling {redacted_url}")
            })
    }

    /// Send a redacted, latency-tracked request while retaining a replay-safety
    /// classification for non-idempotent callers.
    pub async fn execute_redacted_tracked_classified(
        &self,
        request: reqwest::RequestBuilder,
        label: &str,
        redacted_url: &str,
        accumulator: &AtomicU64,
    ) -> Result<reqwest::Response, PluginHttpFailure> {
        let request = request.build().map_err(|error| PluginHttpFailure {
            error_class: classify_reqwest_error(&error),
            request_reached_wire: false,
        })?;
        if let Some(reason) = self.denied_literal_ip_reason(&request) {
            tracing::warn!(
                plugin = label,
                url = %redacted_url,
                reason,
                "Plugin egress policy denied literal-IP endpoint; not dialing"
            );
            return Err(PluginHttpFailure {
                error_class: crate::retry::ErrorClass::DispatchPolicyRejected,
                request_reached_wire: false,
            });
        }
        self.execute_request(request, label, Some(accumulator), Some(redacted_url))
            .await
            .map_err(|error| {
                let error_class = classify_reqwest_error(&error);
                PluginHttpFailure {
                    error_class,
                    // `DispatchPolicyRejected` is intentionally treated as a
                    // post-wire class by the backend retry machinery so a
                    // terminal route policy rejection is never amplified.
                    // Here the caller needs the literal provider-I/O boundary:
                    // a DnsCacheResolver egress denial happens before any dial,
                    // so a non-idempotent provider request remains safe to send
                    // to a configured fallback.
                    request_reached_wire: error_class
                        != crate::retry::ErrorClass::DispatchPolicyRejected
                        && crate::retry::request_reached_wire(error_class),
                }
            })
    }

    async fn execute_request(
        &self,
        request: reqwest::Request,
        label: &str,
        accumulator: Option<&AtomicU64>,
        log_url_override: Option<&str>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        self.execute_request_with_client(
            &self.client,
            request,
            label,
            accumulator,
            log_url_override,
        )
        .await
    }

    async fn execute_request_with_client(
        &self,
        client: &reqwest::Client,
        request: reqwest::Request,
        label: &str,
        accumulator: Option<&AtomicU64>,
        log_url_override: Option<&str>,
    ) -> Result<reqwest::Response, reqwest::Error> {
        let url = request.url().to_string();
        let log_url = log_url_override.unwrap_or(&url).to_string();
        let method = request.method().clone();

        // reqwest skips the custom `DnsCacheResolver` for an IP-literal host
        // (there is nothing to resolve), so a denied literal endpoint
        // (`http://169.254.169.254/...`) would otherwise be dialed unscreened.
        // Enforce the backend egress policy here — the single runtime chokepoint
        // for every plugin that dials through the shared client. A denied
        // destination is surfaced to the plugin as a 502 (not dialed).
        if let Some(reason) = self.denied_literal_ip_reason(&request) {
            tracing::warn!(
                plugin = label,
                url = %log_url,
                reason,
                "Plugin egress policy denied literal-IP endpoint; not dialing"
            );
            let mut denied = http::Response::new(reqwest::Body::from(
                r#"{"error":"endpoint blocked by backend egress policy"}"#,
            ));
            *denied.status_mut() = http::StatusCode::BAD_GATEWAY;
            return Ok(reqwest::Response::from(denied));
        }

        let total_start = std::time::Instant::now();
        let retry_template = request.try_clone();
        let can_retry = self.max_retries > 0
            && matches!(method.as_str(), "GET" | "HEAD" | "OPTIONS")
            && retry_template.is_some();

        let mut current_request = request;
        let mut attempt = 0_u32;

        loop {
            let attempt_start = std::time::Instant::now();
            let result = client.execute(current_request).await;
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
                        url = %log_url,
                        attempt = attempt + 1,
                        max_retries = self.max_retries,
                        retry_delay_ms = self.retry_delay.as_millis() as u64,
                        error_class = %error_class,
                        "Retrying plugin HTTP call after transport failure"
                    );
                }

                tokio::time::sleep(self.retry_delay).await;

                let Some(template) = retry_template.as_ref() else {
                    return self.finish_request(result, label, &log_url, total_start);
                };
                let Some(next_request) = template.try_clone() else {
                    return self.finish_request(result, label, &log_url, total_start);
                };
                current_request = next_request;
                attempt += 1;
                continue;
            }

            return self.finish_request(result, label, &log_url, total_start);
        }
    }

    fn denied_literal_ip_reason(&self, request: &reqwest::Request) -> Option<&'static str> {
        let literal_ip = match request.url().host() {
            Some(url::Host::Ipv4(addr)) => Some(std::net::IpAddr::V4(addr)),
            Some(url::Host::Ipv6(addr)) => Some(std::net::IpAddr::V6(addr)),
            _ => None,
        };
        literal_ip.and_then(|ip| self.backend_allow_ips.deny_reason(&ip))
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

#[cfg(test)]
mod egress_strip_tests {
    //! Tests for `PluginHttpClient`'s egress baggage strip delegation. The
    //! helpers in `modes::mesh::hbone` are tested in isolation; these tests
    //! confirm `PluginHttpClient` plumbs the configured prefix list through
    //! correctly so plugins like `request_mirror` get the gateway's policy
    //! applied for free.
    use super::*;

    fn client_with_strip_prefixes(prefixes: Vec<String>) -> PluginHttpClient {
        PluginHttpClient {
            mesh_egress_strip_baggage_keys: Arc::new(prefixes),
            ..PluginHttpClient::default()
        }
    }

    #[test]
    fn strip_egress_baggage_in_vec_applies_configured_prefixes() {
        let client = client_with_strip_prefixes(vec!["source.".to_string()]);
        let mut headers = vec![
            ("host".to_string(), "example.com".to_string()),
            (
                "baggage".to_string(),
                "source.principal=spiffe://x,userid=alice".to_string(),
            ),
        ];
        client.strip_egress_baggage_in_vec(&mut headers);
        assert_eq!(headers[1].1, "userid=alice");
    }

    #[test]
    fn strip_egress_baggage_in_map_applies_configured_prefixes() {
        let client = client_with_strip_prefixes(vec!["source.".to_string()]);
        let mut headers = std::collections::HashMap::from([(
            "baggage".to_string(),
            "source.principal=spiffe://x".to_string(),
        )]);
        client.strip_egress_baggage_in_map(&mut headers);
        assert!(!headers.contains_key("baggage"));
    }

    #[test]
    fn strip_egress_baggage_in_vec_no_op_with_default_client() {
        let client = PluginHttpClient::default();
        let mut headers = vec![(
            "baggage".to_string(),
            "source.principal=spiffe://x".to_string(),
        )];
        client.strip_egress_baggage_in_vec(&mut headers);
        assert_eq!(headers[0].1, "source.principal=spiffe://x");
    }
}

#[cfg(test)]
mod bpf_metrics_slot_tests {
    //! GAP-3D: confirm `with_bpf_metrics_state` plumbs the shared Arc
    //! through to the `__mesh_bpf_metrics` plugin factory.
    use super::*;
    use crate::ebpf::bpf_metrics::BpfMetricsState;

    #[test]
    fn bpf_metrics_state_default_is_none() {
        let client = PluginHttpClient::default();
        assert!(client.bpf_metrics_state().is_none());
    }

    #[test]
    fn with_bpf_metrics_state_attaches_shared_arc() {
        let state = BpfMetricsState::new();
        state.record_connect();
        let client = PluginHttpClient::default().with_bpf_metrics_state(state.clone());

        let stored = client
            .bpf_metrics_state()
            .expect("state should be attached after with_bpf_metrics_state");
        assert_eq!(stored.snapshot().connect, 1);

        // Increment through the original handle; the stored clone observes
        // the change (i.e. it is the same Arc, not a copy of the values).
        state.record_connect();
        assert_eq!(stored.snapshot().connect, 2);
    }
}

#[cfg(test)]
mod fallback_tests {
    //! Tests for the DNS-cached fallback path used by `PluginHttpClient`
    //! when `reqwest::Client::builder().build()` fails (e.g., due to an
    //! internal TLS connector failure).
    //!
    //! Targets a private helper, so these tests live inline.
    use super::*;
    use crate::dns::DnsConfig;

    #[test]
    fn fallback_client_builds_with_dns_cache() {
        let dns_cache = DnsCache::new(DnsConfig::default());
        let _client = build_dns_cached_fallback_client(
            Some(dns_cache),
            &PluginTlsPosture::PlatformRoots,
            false,
        );
    }

    #[test]
    fn fallback_client_builds_without_dns_cache() {
        let _client =
            build_dns_cached_fallback_client(None, &PluginTlsPosture::PlatformRoots, false);
    }

    #[test]
    fn fallback_client_preserves_fail_closed_tls_posture() {
        let posture = PluginTlsPosture::FailClosedCaBundle {
            source_id: "invalid-ca.pem".to_string(),
            reason: "test invalid CA".to_string(),
        };
        let _client = build_dns_cached_fallback_client(None, &posture, false);
    }

    #[test]
    fn fallback_http2_prior_knowledge_companion_builds() {
        let _client =
            build_dns_cached_fallback_client(None, &PluginTlsPosture::PlatformRoots, true);
    }

    #[test]
    fn tls_posture_parses_configured_ca_bundle_once() {
        let cert_path =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/certs/server.crt");
        let posture = PluginTlsPosture::from_config(false, cert_path.to_str());

        match posture {
            PluginTlsPosture::CustomCaBundle(certs) => assert_eq!(certs.len(), 1),
            _ => panic!("expected configured CA bundle to parse"),
        }
    }

    #[test]
    fn tls_posture_fails_closed_for_invalid_ca_bundle() {
        let tempdir = tempfile::tempdir().expect("create tempdir");
        let ca_path = tempdir.path().join("invalid-ca.pem");
        std::fs::write(&ca_path, "not a pem certificate").expect("write invalid CA");

        let posture = PluginTlsPosture::from_config(false, ca_path.to_str());

        match posture {
            PluginTlsPosture::FailClosedCaBundle { source_id, reason } => {
                assert_eq!(source_id, ca_path.display().to_string());
                assert!(reason.contains("did not contain any PEM certificates"));
            }
            _ => panic!("expected invalid configured CA bundle to fail closed"),
        }
    }

    #[test]
    fn tls_no_verify_takes_precedence_over_ca_bundle() {
        let posture = PluginTlsPosture::from_config(true, Some("/does/not/exist.pem"));
        assert!(matches!(posture, PluginTlsPosture::SkipVerification));
    }

    #[tokio::test]
    async fn fallback_client_uses_dns_cache_resolver() {
        // Verify the fallback client routes DNS through the gateway cache.
        let dns_cache = DnsCache::new(DnsConfig::default());
        let initial_len = dns_cache.cache_len();
        let client = build_dns_cached_fallback_client(
            Some(dns_cache.clone()),
            &PluginTlsPosture::PlatformRoots,
            false,
        );

        let _ = client
            .get("http://localhost:1/")
            .timeout(Duration::from_millis(100))
            .send()
            .await;

        let after_len = dns_cache.cache_len();
        assert!(
            after_len > initial_len,
            "DNS cache should have populated via the cached resolver \
             (initial={}, after={}). If the fallback bypassed the resolver \
             via a default reqwest client, the cache would stay empty.",
            initial_len,
            after_len
        );
    }
}

#[cfg(test)]
mod redirect_tests {
    //! SSRF defense-in-depth: the shared plugin HTTP client must NOT follow
    //! 3xx redirects. A spoofed/compromised upstream (e.g. an OIDC IdP whose
    //! JWKS endpoint passes jwks_auth's first-hop same-host check) could
    //! otherwise redirect a plugin-initiated fetch to an attacker-chosen host
    //! such as the cloud metadata endpoint. These tests stand up a local
    //! listener that answers every request with a same-host 302 and assert the
    //! client surfaces the 302 verbatim — exactly one request, never chased.
    //!
    //! Inline (like `fallback_tests`) because they exercise client
    //! construction behavior — `new()` and `from_pool_config()` — directly.
    use super::*;
    use crate::dns::DnsConfig;
    use std::sync::atomic::AtomicUsize;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    /// Spawn a listener that answers every request with a same-host 302
    /// (`Location: http://<self>/chased`), counting how many requests it
    /// served. If the client followed the redirect it would loop back here and
    /// the counter would climb past 1 (and reqwest would ultimately error with
    /// "too many redirects"); with `Policy::none()` the client stops at the
    /// first 302.
    async fn spawn_redirecting_server() -> (String, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("local_addr");
        let count = Arc::new(AtomicUsize::new(0));
        let count_task = count.clone();
        tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                count_task.fetch_add(1, Ordering::SeqCst);
                // Read the request line/headers so the client's write side
                // drains; the contents are irrelevant to the assertion.
                let mut buf = [0u8; 1024];
                let _ = socket.read(&mut buf).await;
                let body = "redirected";
                let response = format!(
                    "HTTP/1.1 302 Found\r\nLocation: http://{addr}/chased\r\n\
                     Content-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = socket.write_all(response.as_bytes()).await;
                let _ = socket.flush().await;
            }
        });
        (format!("http://{addr}/"), count)
    }

    async fn assert_redirect_not_followed(client: &PluginHttpClient) {
        let (url, count) = spawn_redirecting_server().await;
        let resp = client
            .get()
            .get(&url)
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .expect("request should succeed and return the 302, not error");
        assert_eq!(
            resp.status().as_u16(),
            302,
            "client must surface the 3xx instead of following it; a followed \
             redirect would loop and change the status"
        );
        assert_eq!(
            count.load(Ordering::SeqCst),
            1,
            "exactly one request must reach the server; >1 means the redirect \
             was chased"
        );
    }

    #[tokio::test]
    async fn from_pool_config_does_not_follow_redirects() {
        // Exercises the cache-less constructor (also backs `Default`).
        let client = PluginHttpClient::default();
        assert_redirect_not_followed(&client).await;
    }

    #[tokio::test]
    async fn new_does_not_follow_redirects() {
        // Exercises the production constructor (DNS-cache path).
        let client = PluginHttpClient::new(
            &PoolConfig::default(),
            DnsCache::new(DnsConfig::default()),
            1000,
            0,
            100,
            false,
            None,
            Arc::new(Vec::new()),
            crate::config::types::DEFAULT_NAMESPACE,
            BackendEgressPolicy::unrestricted(),
            Arc::new(Vec::new()),
            0,
        );
        assert_redirect_not_followed(&client).await;
    }
}
