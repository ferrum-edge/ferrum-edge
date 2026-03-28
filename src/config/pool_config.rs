//! Global connection pool configuration
//! Provides environment variable defaults and proxy-level overrides

use std::env;

/// Minimum allowed value for `max_idle_per_host`.
///
/// Setting this too low causes excessive connection churn under load — each
/// request that cannot reuse an idle connection must open a new TCP connection
/// to the backend, dramatically increasing latency and error rates.
pub const MIN_IDLE_PER_HOST: usize = 4;

/// Maximum allowed value for `max_idle_per_host`.
///
/// Excessively high values waste memory (each idle connection holds a kernel
/// socket buffer) and file descriptors.  On most systems the practical ceiling
/// is the per-process file-descriptor limit (`ulimit -n`), but values above
/// 1024 rarely help because the backend itself becomes the bottleneck.
pub const MAX_IDLE_PER_HOST: usize = 1024;

/// Global connection pool configuration from environment variables
#[derive(Debug, Clone)]
pub struct PoolConfig {
    pub max_idle_per_host: usize,
    pub idle_timeout_seconds: u64,
    pub enable_http_keep_alive: bool,
    /// Controls HTTP/2 keep-alive PING frames on backend connections.
    /// When true, reqwest sends periodic PING frames to keep HTTP/2 connections alive.
    /// HTTP/2 itself is auto-negotiated via ALPN on HTTPS connections — this does NOT
    /// force h2c (cleartext HTTP/2) via http2_prior_knowledge().
    pub enable_http2: bool,
    /// Number of parallel backend HTTP/2 connections to keep per host.
    /// A small shard set reduces lock contention on a single multiplexed h2 sender
    /// under high concurrency while still preserving connection reuse.
    pub http2_connections_per_host: usize,
    pub tcp_keepalive_seconds: u64,
    pub http2_keep_alive_interval_seconds: u64,
    pub http2_keep_alive_timeout_seconds: u64,

    // ── HTTP/2 flow control & performance tuning ─────────────────────────
    //
    // The h2 spec defaults (64KB stream window, 16KB frame) were designed for
    // dial-up-era congestion safety.  On modern networks they throttle
    // throughput to ~8 Mbps at 100 ms RTT.  These settings let operators
    // (and per-proxy overrides) raise the limits to match their bandwidth.
    /// Initial per-stream flow-control window size in bytes.
    /// Larger values allow more data in flight per stream before the sender
    /// must wait for a WINDOW_UPDATE, directly improving single-stream throughput.
    /// Default: 8 MiB (8_388_608).  h2 spec minimum: 65_535, maximum: 2^31-1.
    pub http2_initial_stream_window_size: u32,

    /// Initial connection-level flow-control window size in bytes.
    /// This is the aggregate budget shared across all concurrent streams on
    /// one HTTP/2 connection.  Should be ≥ stream_window × expected_concurrency.
    /// Default: 32 MiB (33_554_432).
    pub http2_initial_connection_window_size: u32,

    /// Enable hyper's adaptive flow-control algorithm (BDP probing).
    /// When true, hyper dynamically adjusts the connection window based on
    /// measured bandwidth-delay product, scaling up automatically on fast
    /// links and staying conservative on slow ones.
    /// Default: false (use fixed windows for predictable performance).
    pub http2_adaptive_window: bool,

    /// Maximum HTTP/2 frame payload size in bytes.
    /// Larger frames reduce per-frame overhead but increase head-of-line
    /// blocking risk.  Must be between 16_384 (spec minimum) and 16_777_215.
    /// Default: 65_535.
    pub http2_max_frame_size: u32,

    /// Maximum number of concurrent HTTP/2 streams the gateway will open
    /// to a single backend connection.  `None` means unlimited (server decides).
    /// Useful for protecting backends that choke on high stream counts.
    /// Default: 1000.
    pub http2_max_concurrent_streams: Option<u32>,
}

impl Default for PoolConfig {
    fn default() -> Self {
        Self {
            max_idle_per_host: 64,
            idle_timeout_seconds: 90,
            enable_http_keep_alive: true,
            enable_http2: true,
            http2_connections_per_host: std::thread::available_parallelism()
                .map(|n| n.get().clamp(2, 8))
                .unwrap_or(4),
            tcp_keepalive_seconds: 60,
            http2_keep_alive_interval_seconds: 30,
            http2_keep_alive_timeout_seconds: 45, // More reasonable timeout comparable to HTTP read timeout
            http2_initial_stream_window_size: 8_388_608, // 8 MiB
            http2_initial_connection_window_size: 33_554_432, // 32 MiB
            http2_adaptive_window: false,
            http2_max_frame_size: 65_535,
            http2_max_concurrent_streams: Some(1000),
        }
    }
}

impl PoolConfig {
    /// Create pool configuration from environment variables with defaults
    pub fn from_env() -> Self {
        let mut config = Self::default();

        // Read from environment variables
        if let Ok(val) = env::var("FERRUM_POOL_MAX_IDLE_PER_HOST")
            && let Ok(parsed) = val.parse::<usize>()
        {
            config.max_idle_per_host = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_IDLE_TIMEOUT_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.idle_timeout_seconds = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE") {
            config.enable_http_keep_alive = val.parse::<bool>().unwrap_or(true);
        }

        if let Ok(val) = env::var("FERRUM_POOL_ENABLE_HTTP2") {
            config.enable_http2 = val.parse::<bool>().unwrap_or(true);
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST")
            && let Ok(parsed) = val.parse::<usize>()
        {
            config.http2_connections_per_host = parsed.max(1);
        }

        if let Ok(val) = env::var("FERRUM_POOL_TCP_KEEPALIVE_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.tcp_keepalive_seconds = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.http2_keep_alive_interval_seconds = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.http2_keep_alive_timeout_seconds = parsed;
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.http2_initial_stream_window_size = parsed.max(65_535);
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.http2_initial_connection_window_size = parsed.max(65_535);
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW") {
            config.http2_adaptive_window = val.parse::<bool>().unwrap_or(true);
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.http2_max_frame_size = parsed.clamp(16_384, 16_777_215);
        }

        if let Ok(val) = env::var("FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.http2_max_concurrent_streams = Some(parsed);
        }

        // Validate HTTP/2 timeout is reasonable compared to HTTP read timeout
        if config.http2_keep_alive_timeout_seconds < 10 {
            tracing::warn!(
                "HTTP/2 keep-alive timeout ({}s) is very low, consider increasing to 30-45s",
                config.http2_keep_alive_timeout_seconds
            );
        }

        // Validate and clamp max_idle_per_host
        config.max_idle_per_host =
            Self::validate_max_idle_per_host(config.max_idle_per_host, "global");

        config
    }

    /// Apply proxy-level overrides to this global configuration
    pub fn apply_proxy_overrides(&self, proxy: &crate::config::types::Proxy) -> PoolConfig {
        let mut config = self.clone();

        // Apply proxy-level overrides if present
        // Note: max_idle_per_host is intentionally global-only — per-proxy overrides
        // were removed because they fragment the connection pool (different values create
        // separate reqwest::Client instances for the same backend).

        if let Some(val) = proxy.pool_idle_timeout_seconds {
            config.idle_timeout_seconds = val;
        }

        if let Some(val) = proxy.pool_enable_http_keep_alive {
            config.enable_http_keep_alive = val;
        }

        if let Some(val) = proxy.pool_enable_http2 {
            config.enable_http2 = val;
        }

        if let Some(val) = proxy.pool_tcp_keepalive_seconds {
            config.tcp_keepalive_seconds = val;
        }

        if let Some(val) = proxy.pool_http2_keep_alive_interval_seconds {
            config.http2_keep_alive_interval_seconds = val;
        }

        if let Some(val) = proxy.pool_http2_keep_alive_timeout_seconds {
            config.http2_keep_alive_timeout_seconds = val;
        }

        if let Some(val) = proxy.pool_http2_initial_stream_window_size {
            config.http2_initial_stream_window_size = val.max(65_535);
        }

        if let Some(val) = proxy.pool_http2_initial_connection_window_size {
            config.http2_initial_connection_window_size = val.max(65_535);
        }

        if let Some(val) = proxy.pool_http2_adaptive_window {
            config.http2_adaptive_window = val;
        }

        if let Some(val) = proxy.pool_http2_max_frame_size {
            config.http2_max_frame_size = val.clamp(16_384, 16_777_215);
        }

        if let Some(val) = proxy.pool_http2_max_concurrent_streams {
            config.http2_max_concurrent_streams = Some(val);
        }

        config
    }

    /// Get configuration for a specific proxy (global defaults + proxy overrides)
    pub fn for_proxy(&self, proxy: &crate::config::types::Proxy) -> PoolConfig {
        self.apply_proxy_overrides(proxy)
    }

    /// Validate and clamp `max_idle_per_host` to the allowed range, logging
    /// a warning when the value is adjusted.
    pub fn validate_max_idle_per_host(value: usize, source: &str) -> usize {
        if value < MIN_IDLE_PER_HOST {
            tracing::warn!(
                "pool_max_idle_per_host={} for '{}' is below the minimum ({}). \
                 Values this low cause excessive connection churn under load, \
                 leading to high latency and errors. Clamping to {}.",
                value,
                source,
                MIN_IDLE_PER_HOST,
                MIN_IDLE_PER_HOST,
            );
            MIN_IDLE_PER_HOST
        } else if value > MAX_IDLE_PER_HOST {
            tracing::warn!(
                "pool_max_idle_per_host={} for '{}' exceeds the maximum ({}). \
                 Very high values waste file descriptors and memory without \
                 improving performance. Clamping to {}.",
                value,
                source,
                MAX_IDLE_PER_HOST,
                MAX_IDLE_PER_HOST,
            );
            MAX_IDLE_PER_HOST
        } else {
            value
        }
    }
}
