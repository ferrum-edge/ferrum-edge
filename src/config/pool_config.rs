//! Global connection pool configuration.
//! Provides env/ferrum.conf defaults and proxy-level overrides.

use super::conf_file::resolve_ferrum_var;
use super::types::{
    MAX_HTTP2_MAX_FRAME_SIZE, MAX_HTTP2_WINDOW_SIZE, MIN_HTTP2_MAX_FRAME_SIZE,
    MIN_HTTP2_WINDOW_SIZE,
};

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

/// Global connection pool configuration from environment variables or ferrum.conf.
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
    ///
    /// When enabled, adaptive windowing **overrides** the fixed
    /// [`Self::http2_initial_stream_window_size`] /
    /// [`Self::http2_initial_connection_window_size`] values at the HTTP/2
    /// builder (hyper/reqwest semantics). Default: `true`.
    ///
    /// Precedence is resolved at configuration load time: an explicit stream or
    /// connection window override from env/`ferrum.conf` or a per-proxy field
    /// auto-disables adaptive windowing when adaptive was not also set
    /// explicitly, so operator-tuned fixed windows take effect. An explicit
    /// adaptive choice remains authoritative.
    pub http2_adaptive_window: bool,

    /// Maximum HTTP/2 frame payload size in bytes.
    /// Larger frames reduce per-frame overhead but increase head-of-line
    /// blocking risk.  Must be between 16_384 (spec minimum) and 1_048_576 (1 MiB).
    /// Default: 1_048_576 (1 MiB).
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
            http2_adaptive_window: true,
            http2_max_frame_size: 1_048_576, // 1 MiB
            http2_max_concurrent_streams: Some(1000),
        }
    }
}

impl PoolConfig {
    /// Create pool configuration from environment variables/ferrum.conf with defaults.
    pub fn from_env() -> Self {
        let mut config = Self::default();
        // Track explicit operator intent separately from the shipped default so
        // we never treat "value happens to equal the default" as an override.
        let mut window_explicit = false;
        let mut adaptive_explicit = false;

        // Read through `resolve_ferrum_var()` so values in ferrum.conf are
        // honored anywhere the pool config is created outside EnvConfig.
        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_MAX_IDLE_PER_HOST")
            && let Ok(parsed) = val.parse::<usize>()
        {
            config.max_idle_per_host = parsed;
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_IDLE_TIMEOUT_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.idle_timeout_seconds = parsed;
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE") {
            config.enable_http_keep_alive = val.parse::<bool>().unwrap_or(true);
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_ENABLE_HTTP2") {
            config.enable_http2 = val.parse::<bool>().unwrap_or(true);
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_HTTP2_CONNECTIONS_PER_HOST")
            && let Ok(parsed) = val.parse::<usize>()
        {
            config.http2_connections_per_host = parsed.max(1);
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_TCP_KEEPALIVE_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.tcp_keepalive_seconds = parsed;
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.http2_keep_alive_interval_seconds = parsed;
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS")
            && let Ok(parsed) = val.parse::<u64>()
        {
            config.http2_keep_alive_timeout_seconds = parsed;
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.http2_initial_stream_window_size =
                parsed.clamp(MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE);
            window_explicit = true;
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.http2_initial_connection_window_size =
                parsed.clamp(MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE);
            window_explicit = true;
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW") {
            match val.parse::<bool>() {
                Ok(parsed) => {
                    config.http2_adaptive_window = parsed;
                    adaptive_explicit = true;
                }
                Err(_) => tracing::warn!(
                    value = %val,
                    "invalid FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW; expected true or false - \
                     keeping the resolved default"
                ),
            }
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_HTTP2_MAX_FRAME_SIZE")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.http2_max_frame_size =
                parsed.clamp(MIN_HTTP2_MAX_FRAME_SIZE, MAX_HTTP2_MAX_FRAME_SIZE);
        }

        if let Some(val) = resolve_ferrum_var("FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS")
            && let Ok(parsed) = val.parse::<u32>()
        {
            config.http2_max_concurrent_streams = Some(parsed.max(1));
        }

        config.apply_adaptive_window_precedence(
            window_explicit,
            adaptive_explicit,
            "global env/ferrum.conf",
            true,
        );

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

        // Apply proxy-level overrides if present.
        //
        // `max_idle_per_host` is intentionally global-only — per-proxy overrides
        // were removed because they fragment the connection pool (different values
        // create separate reqwest::Client instances for the same backend). That
        // deliberate tradeoff is documented; other client-baked settings *do*
        // enter the reqwest pool key via `append_reqwest_client_behavior_pool_key`
        // so divergent per-proxy values cannot silently first-creator-wins leak.

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

        let window_explicit = proxy.pool_http2_initial_stream_window_size.is_some()
            || proxy.pool_http2_initial_connection_window_size.is_some();
        let adaptive_explicit = proxy.pool_http2_adaptive_window.is_some();

        if let Some(val) = proxy.pool_http2_initial_stream_window_size {
            config.http2_initial_stream_window_size =
                val.clamp(MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE);
        }

        if let Some(val) = proxy.pool_http2_initial_connection_window_size {
            config.http2_initial_connection_window_size =
                val.clamp(MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE);
        }

        if let Some(val) = proxy.pool_http2_adaptive_window {
            config.http2_adaptive_window = val;
        }

        if let Some(val) = proxy.pool_http2_max_frame_size {
            config.http2_max_frame_size =
                val.clamp(MIN_HTTP2_MAX_FRAME_SIZE, MAX_HTTP2_MAX_FRAME_SIZE);
        }

        if let Some(val) = proxy.pool_http2_max_concurrent_streams {
            config.http2_max_concurrent_streams = Some(val.max(1));
        }

        // Resolve without an info log: `for_proxy` runs whenever a pool client /
        // H2 builder is constructed, so logging here would spam under connection
        // churn. Global env resolution logs once at startup; docs cover per-proxy.
        config.apply_adaptive_window_precedence(
            window_explicit,
            adaptive_explicit,
            proxy.id.as_str(),
            false,
        );

        config
    }

    /// Resolve adaptive-vs-fixed H2 window precedence for one configuration layer.
    ///
    /// Hyper/reqwest adaptive windowing overrides fixed initial window sizes.
    /// When an operator sets an explicit stream/connection window at this layer
    /// without also setting adaptive windowing explicitly, disable adaptive so
    /// the fixed windows are not silently inert. An explicit adaptive choice at
    /// the same layer remains authoritative.
    ///
    /// Explicitness is represented by the caller (env/`Option` presence), never
    /// inferred by comparing numeric values to shipped defaults. Resolution runs
    /// only at config load / proxy override time — never on the request path.
    fn apply_adaptive_window_precedence(
        &mut self,
        window_explicit: bool,
        adaptive_explicit: bool,
        source: &str,
        emit_info_log: bool,
    ) {
        if window_explicit && !adaptive_explicit && self.http2_adaptive_window {
            if emit_info_log {
                tracing::info!(
                    source = %source,
                    stream_window = self.http2_initial_stream_window_size,
                    connection_window = self.http2_initial_connection_window_size,
                    "Explicit HTTP/2 window size override present without an explicit \
                     adaptive_window setting; disabling http2_adaptive_window so fixed \
                     windows take effect (set FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW / \
                     pool_http2_adaptive_window to keep adaptive flow control)"
                );
            }
            self.http2_adaptive_window = false;
        }
    }

    /// Get configuration for a specific proxy (global defaults + proxy overrides)
    pub fn for_proxy(&self, proxy: &crate::config::types::Proxy) -> PoolConfig {
        self.apply_proxy_overrides(proxy)
    }

    /// Effective `enable_http2` after proxy overrides, without cloning `PoolConfig`.
    #[inline]
    pub fn effective_enable_http2(&self, proxy: &crate::config::types::Proxy) -> bool {
        proxy.pool_enable_http2.unwrap_or(self.enable_http2)
    }

    /// Append the reqwest client-level settings that `ConnectionPool::create_client`
    /// bakes into the shared `reqwest::Client`.
    ///
    /// These settings cannot be applied per-request, so they must partition the
    /// reqwest pool key. The encoding is deterministic and inspectable
    /// (`rcfg=…`) and writes directly into `buf` (no intermediate `String` /
    /// `PoolConfig` clone). Secrets never appear here.
    ///
    /// Included (mirrors `create_client`):
    /// - `idle_timeout_seconds` → `i`
    /// - effective TCP keepalive seconds (`0` when keep-alive is disabled) → `ka`
    /// - `enable_http2` → `h2=0|1`
    /// - when H2 enabled: keep-alive interval/timeout (`h2i`/`h2t`), adaptive
    ///   window (`aw`), max frame size (`mf`), and fixed stream/connection
    ///   windows (`sw`/`cw`) **only when adaptive window is off** (reqwest/
    ///   hyper adaptive mode overrides the fixed windows)
    ///
    /// Explicitly excluded:
    /// - `max_idle_per_host` — deliberate global-only fragmentation tradeoff
    /// - `backend_connect_timeout_ms` / `backend_read_timeout_ms` — request-only
    /// - `http2_max_concurrent_streams` — not consumed by reqwest `create_client`
    pub fn append_reqwest_client_behavior_pool_key(
        &self,
        proxy: &crate::config::types::Proxy,
        buf: &mut String,
    ) {
        use std::fmt::Write;

        let idle = proxy
            .pool_idle_timeout_seconds
            .unwrap_or(self.idle_timeout_seconds);
        let keep_alive_enabled = proxy
            .pool_enable_http_keep_alive
            .unwrap_or(self.enable_http_keep_alive);
        // Match `create_client`: TCP keepalive is only installed when enabled.
        let tcp_ka = if keep_alive_enabled {
            proxy
                .pool_tcp_keepalive_seconds
                .unwrap_or(self.tcp_keepalive_seconds)
        } else {
            0
        };
        let enable_http2 = self.effective_enable_http2(proxy);

        buf.push('|');
        let _ = write!(buf, "rcfg=i{idle};ka{tcp_ka}");
        if !enable_http2 {
            buf.push_str(";h2=0");
            return;
        }

        let h2i = proxy
            .pool_http2_keep_alive_interval_seconds
            .unwrap_or(self.http2_keep_alive_interval_seconds);
        let h2t = proxy
            .pool_http2_keep_alive_timeout_seconds
            .unwrap_or(self.http2_keep_alive_timeout_seconds);
        let adaptive = proxy
            .pool_http2_adaptive_window
            .unwrap_or(self.http2_adaptive_window);
        let max_frame = match proxy.pool_http2_max_frame_size {
            Some(val) => val.clamp(MIN_HTTP2_MAX_FRAME_SIZE, MAX_HTTP2_MAX_FRAME_SIZE),
            None => self.http2_max_frame_size,
        };

        let _ = write!(buf, ";h2=1;h2i{h2i};h2t{h2t};aw{}", u8::from(adaptive));
        // Adaptive window overrides fixed initial windows in reqwest/hyper, so
        // divergent `sw`/`cw` must not fragment when `aw=1`.
        if !adaptive {
            let stream_window = match proxy.pool_http2_initial_stream_window_size {
                Some(val) => val.clamp(MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE),
                None => self.http2_initial_stream_window_size,
            };
            let conn_window = match proxy.pool_http2_initial_connection_window_size {
                Some(val) => val.clamp(MIN_HTTP2_WINDOW_SIZE, MAX_HTTP2_WINDOW_SIZE),
                None => self.http2_initial_connection_window_size,
            };
            let _ = write!(buf, ";sw{stream_window};cw{conn_window}");
        }
        let _ = write!(buf, ";mf{max_frame}");
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
