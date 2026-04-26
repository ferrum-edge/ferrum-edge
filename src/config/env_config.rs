//! Environment variable parsing for the gateway's 90+ configuration options.
//!
//! **Three-tier resolution** (highest precedence first):
//! 1. Environment variable (`std::env::var`)
//! 2. Conf file value (`ferrum.conf`, parsed by `ConfFile`)
//! 3. Hardcoded default in this file
//!
//! The `resolve_var()` helper implements this precedence chain and logs an
//! info message when a conf file value is overridden by an env var, helping
//! operators debug "why isn't my conf file change taking effect?" issues.

use super::conf_file::ConfFile;
use std::collections::{HashMap, HashSet};
use std::env;

#[macro_use]
#[path = "env_config_macro.rs"]
mod env_config_macro;

/// The operating mode of the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatingMode {
    Database,
    File,
    ControlPlane,
    DataPlane,
    Migrate,
}

impl OperatingMode {
    #[allow(dead_code)] // Used by integration/unit tests via the lib crate
    pub fn from_env() -> Result<Self, String> {
        Self::resolve(&ConfFile::default())
    }

    fn resolve(conf: &ConfFile) -> Result<Self, String> {
        let raw = resolve_var(conf, "FERRUM_MODE").unwrap_or_default();
        match raw.to_lowercase().as_str() {
            "database" => Ok(Self::Database),
            "file" => Ok(Self::File),
            "cp" => Ok(Self::ControlPlane),
            "dp" => Ok(Self::DataPlane),
            "migrate" => Ok(Self::Migrate),
            other => Err(format!(
                "Invalid FERRUM_MODE '{}'. Expected: database, file, cp, dp, migrate",
                other
            )),
        }
    }
}

/// Backend IP allowlist policy for SSRF protection.
///
/// Controls which resolved backend IPs are permitted as proxy/upstream targets:
/// - `Private`: only private/reserved IPs (RFC 1918, loopback, link-local, CGNAT)
/// - `Public`: only public IPs (blocks internal/metadata endpoints)
/// - `Both`: all IPs allowed (default, no restriction)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BackendAllowIps {
    /// Only private/reserved IPs allowed as backends.
    Private,
    /// Only public (non-private) IPs allowed as backends.
    Public,
    /// All IPs allowed — no restriction (default).
    Both,
}

impl std::fmt::Display for BackendAllowIps {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Private => write!(f, "private"),
            Self::Public => write!(f, "public"),
            Self::Both => write!(f, "both"),
        }
    }
}

/// Check whether an IP address falls within private/reserved ranges.
///
/// Private/reserved ranges (denied in `Public` mode, allowed in `Private` mode):
/// - IPv4: 127.0.0.0/8, 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16,
///   169.254.0.0/16 (link-local / cloud metadata), 0.0.0.0/8, 100.64.0.0/10 (CGNAT)
/// - IPv6: ::1, ::, fe80::/10 (link-local), fd00::/8 (unique local)
pub fn is_private_ip(addr: &std::net::IpAddr) -> bool {
    match addr {
        std::net::IpAddr::V4(ip) => {
            ip.is_loopback()                // 127.0.0.0/8
            || ip.is_private()              // 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16
            || ip.is_link_local()           // 169.254.0.0/16
            || ip.is_unspecified()          // 0.0.0.0
            || ip.octets()[0] == 0          // 0.0.0.0/8 (full range)
            || (ip.octets()[0] == 100 && (ip.octets()[1] & 0xC0) == 64) // 100.64.0.0/10 (CGNAT)
        }
        std::net::IpAddr::V6(ip) => {
            ip.is_loopback()                                // ::1
            || ip.is_unspecified()                          // ::
            || (ip.segments()[0] & 0xffc0) == 0xfe80        // fe80::/10 (link-local)
            || (ip.segments()[0] & 0xff00) == 0xfd00 // fd00::/8 (unique local)
        }
    }
}

/// Check whether an IP is allowed under the given backend IP policy.
pub fn check_backend_ip_allowed(addr: &std::net::IpAddr, policy: &BackendAllowIps) -> bool {
    match policy {
        BackendAllowIps::Both => true,
        BackendAllowIps::Private => is_private_ip(addr),
        BackendAllowIps::Public => !is_private_ip(addr),
    }
}

/// Resolve a configuration value: env var takes precedence over conf file.
fn resolve_var(conf: &ConfFile, key: &str) -> Option<String> {
    if let Ok(env_val) = env::var(key) {
        if conf.get(key).is_some_and(|conf_val| conf_val != env_val) {
            tracing::info!("{key}: environment variable overrides ferrum.conf default");
        }
        return Some(env_val);
    }
    conf.get(key).map(|v| v.to_string())
}

/// Tri-state toggle: `auto` (detect at runtime), `true` (force on), `false` (force off).
///
/// Used for Linux-specific optimizations that can probe the kernel at startup.
/// When `auto`, the feature is enabled if the kernel supports it and disabled otherwise.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoBool {
    /// Detect support at runtime and enable if available.
    Auto,
    /// Force enabled (fail or warn if unsupported).
    True,
    /// Force disabled.
    False,
}

impl AutoBool {
    /// Resolve to a concrete bool using a runtime probe function.
    ///
    /// - `Auto` → call `probe()` and use its result
    /// - `True` → `true` (caller is responsible for handling unsupported case)
    /// - `False` → `false`
    pub fn resolve(self, probe: impl FnOnce() -> bool) -> bool {
        match self {
            Self::Auto => probe(),
            Self::True => true,
            Self::False => false,
        }
    }

    /// Returns `true` if the resolved value could POSSIBLY be `true` — i.e.
    /// every variant except `False`. Used by callers that must commit to a
    /// side-effect (e.g. setting `ServerConfig::enable_secret_extraction`)
    /// before the actual probe runs, and would rather over-enable than
    /// under-enable.
    pub fn could_be_enabled(self) -> bool {
        !matches!(self, Self::False)
    }
}

impl std::fmt::Display for AutoBool {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Auto => write!(f, "auto"),
            Self::True => write!(f, "true"),
            Self::False => write!(f, "false"),
        }
    }
}

/// All environment-driven configuration.
#[derive(Debug, Clone)]
#[allow(dead_code)] // Some fields are only used with optional features (e.g. mongodb)
pub struct EnvConfig {
    pub mode: OperatingMode,
    /// Namespace this gateway instance loads and manages. Resources from other
    /// namespaces are ignored. Default: "ferrum".
    pub namespace: String,
    pub log_level: String,
    /// Maximum number of buffered log lines in the non-blocking writer's channel.
    /// When the buffer is full, new log events are dropped (lossy mode) to avoid
    /// backpressure on request-processing threads. Larger values reduce the chance
    /// of log loss under extreme throughput but consume more memory. Default: 128000.
    /// Note: consumed in main() before EnvConfig is constructed (tracing must init
    /// first), but stored here for completeness alongside other FERRUM_* vars.
    #[allow(dead_code)]
    pub log_buffer_capacity: usize,
    /// When true, streaming responses are wrapped with a lightweight tracker
    /// that records the final transfer time via a deferred task. Adds one
    /// `Arc<StreamingMetrics>` + one `tokio::spawn` per streaming request.
    /// Default: false (maximum throughput).
    pub enable_streaming_latency_tracking: bool,

    // Proxy traffic
    pub proxy_http_port: u16,
    pub proxy_https_port: u16,
    pub frontend_tls_cert_path: Option<String>,
    pub frontend_tls_key_path: Option<String>,
    /// Bind address for proxy listeners (HTTP, HTTPS, HTTP/3).
    /// Default: "0.0.0.0" (IPv4 only). Set to "::" for dual-stack IPv4+IPv6.
    /// On most operating systems, binding to "::" accepts both IPv4 and IPv6
    /// connections via IPv4-mapped IPv6 addresses (dual-stack). This requires
    /// the OS to have dual-stack support enabled (the default on Linux, macOS,
    /// and Windows). If `net.ipv6.bindv6only=1` is set (Linux sysctl), binding
    /// to "::" will only accept IPv6 connections.
    pub proxy_bind_address: String,

    // Admin API
    pub admin_http_port: u16,
    pub admin_https_port: u16,
    pub admin_tls_cert_path: Option<String>,
    pub admin_tls_key_path: Option<String>,
    /// Bind address for Admin API listeners (HTTP, HTTPS).
    /// Default: "0.0.0.0" (IPv4 only). Set to "::" for dual-stack IPv4+IPv6.
    pub admin_bind_address: String,

    // Admin JWT
    pub admin_jwt_secret: Option<String>,
    /// JWT issuer claim (iss) for Admin API tokens. Tokens with a different issuer
    /// are rejected during verification. Default: "ferrum-edge".
    /// Note: Also resolved via `resolve_ferrum_var()` in `jwt_auth.rs` for use sites
    /// that don't have `EnvConfig` in scope (e.g., `create_jwt_manager_from_env()`).
    #[allow(dead_code)]
    pub admin_jwt_issuer: String,
    /// Maximum TTL in seconds for Admin API JWT tokens. Tokens requesting a longer
    /// lifetime via the /auth endpoint are capped to this value. Default: 3600.
    /// Note: Also resolved via `resolve_ferrum_var()` in `jwt_auth.rs`.
    #[allow(dead_code)]
    pub admin_jwt_max_ttl: u64,

    // Database
    pub db_type: Option<String>,
    pub db_url: Option<String>,
    pub db_poll_interval: u64,
    pub db_tls_enabled: bool,
    pub db_tls_ca_cert_path: Option<String>,
    pub db_tls_client_cert_path: Option<String>,
    pub db_tls_client_key_path: Option<String>,
    pub db_tls_insecure: bool,

    // Database TLS/SSL
    /// SSL mode for database connections (e.g., disable, prefer, require, verify-ca, verify-full)
    pub db_ssl_mode: Option<String>,
    /// Path to CA certificate for database server verification
    pub db_ssl_root_cert: Option<String>,
    /// Path to client certificate for database mTLS
    pub db_ssl_client_cert: Option<String>,
    /// Path to client private key for database mTLS
    pub db_ssl_client_key: Option<String>,

    // File mode
    pub file_config_path: Option<String>,

    /// Path to an externally provided backup config file (JSON). When set in
    /// database mode and the database is unreachable at startup, the gateway
    /// loads config from this file so pods can restart with stale config while
    /// the database recovers. The file is expected to be provisioned externally
    /// (e.g. via ConfigMap, PersistentVolume, or sidecar export).
    pub db_config_backup_path: Option<String>,

    /// Comma-separated list of failover database URLs. When the primary
    /// `FERRUM_DB_URL` is unreachable, the gateway tries each failover URL in
    /// order. All URLs must use the same `FERRUM_DB_TYPE` and share TLS settings.
    pub db_failover_urls: Vec<String>,

    /// Connection URL for a read replica database. When set, the polling loop
    /// reads config from this replica instead of the primary, reducing load on
    /// the primary. Writes (Admin API CRUD) always go to the primary. Falls
    /// back to primary if the replica is unreachable.
    pub db_read_replica_url: Option<String>,

    /// Threshold in milliseconds for logging slow database queries.
    /// When a database query exceeds this duration, a warning is logged with
    /// the operation name and elapsed time. Default: disabled (None).
    pub db_slow_query_threshold_ms: Option<u64>,

    // Database connection pool tuning
    /// Maximum number of connections in the database pool. Default: 10.
    /// Increase for CP mode with many DPs or high admin API concurrency.
    pub db_pool_max_connections: u32,
    /// Minimum number of idle connections maintained in the pool. Default: 1.
    /// Higher values reduce cold-start latency at the cost of holding open
    /// connections. Set to 0 to allow the pool to shrink to zero idle.
    pub db_pool_min_connections: u32,
    /// Maximum time (seconds) to wait for a connection from the pool before
    /// returning an error. Default: 30. Prevents unbounded waits when the
    /// pool is exhausted under load.
    pub db_pool_acquire_timeout_seconds: u64,
    /// Maximum time (seconds) a connection can sit idle before being closed.
    /// Default: 600 (10 minutes). Keeps the pool from holding stale connections.
    pub db_pool_idle_timeout_seconds: u64,
    /// Maximum lifetime (seconds) of a connection before it is closed and
    /// replaced. Default: 300 (5 minutes). Forces DNS re-resolution and
    /// prevents stale server-side state. Defence-in-depth alongside the
    /// explicit DnsCache-based reconnect.
    pub db_pool_max_lifetime_seconds: u64,
    /// Maximum time (seconds) to wait for a new TCP connection to the database.
    /// Default: 10. Separate from `acquire_timeout_seconds` (which covers
    /// waiting for a pool slot + connecting). 0 = disabled (falls back to OS
    /// TCP timeout, which can be 60–120s).
    pub db_pool_connect_timeout_seconds: u64,
    /// Maximum execution time (seconds) for any single SQL statement. Default:
    /// 30. Set via `SET statement_timeout` (PostgreSQL) or `SET SESSION
    /// max_execution_time` (MySQL) on every new connection. 0 = disabled.
    /// Ignored for SQLite (not supported).
    pub db_pool_statement_timeout_seconds: u64,

    // MongoDB-specific settings (when FERRUM_DB_TYPE=mongodb).
    // These fields are read by `mongo_store::MongoStore::connect()` when the
    // `mongodb` feature is enabled and `FERRUM_DB_TYPE=mongodb`.
    /// MongoDB database name to use. Default: "ferrum".
    pub mongo_database: String,
    /// MongoDB application name for server-side connection tracking.
    pub mongo_app_name: Option<String>,
    /// MongoDB replica set name. Required for change streams and transactions.
    pub mongo_replica_set: Option<String>,
    /// MongoDB auth mechanism override (e.g. "SCRAM-SHA-256", "MONGODB-X509").
    pub mongo_auth_mechanism: Option<String>,
    /// MongoDB server selection timeout in seconds. Default: 30.
    pub mongo_server_selection_timeout_seconds: u64,
    /// MongoDB connection timeout in seconds. Default: 10.
    pub mongo_connect_timeout_seconds: u64,

    // CP/DP
    pub cp_grpc_listen_addr: Option<String>,
    pub cp_dp_grpc_jwt_secret: Option<String>,
    pub dp_cp_grpc_url: Option<String>,
    /// Comma-separated, priority-ordered list of CP gRPC URLs for DP failover.
    /// When set, takes precedence over `dp_cp_grpc_url`. The DP connects to the
    /// first URL and fails over to subsequent URLs when unreachable.
    pub dp_cp_grpc_urls: Vec<String>,
    /// How often (in seconds) the DP retries the primary (first) CP URL while
    /// connected to a fallback CP. Default: 300 (5 minutes). 0 = disabled.
    pub dp_cp_failover_primary_retry_secs: u64,

    // CP gRPC TLS (server-side)
    /// Path to PEM certificate for the CP gRPC server. When set (with key),
    /// the gRPC listener uses TLS instead of plaintext.
    pub cp_grpc_tls_cert_path: Option<String>,
    /// Path to PEM private key for the CP gRPC server.
    pub cp_grpc_tls_key_path: Option<String>,
    /// Path to PEM CA bundle for verifying DP client certificates (mTLS).
    /// When set, the CP requires and verifies client certificates from DPs.
    pub cp_grpc_tls_client_ca_path: Option<String>,
    /// Capacity of the tokio broadcast channel used to fan out config deltas
    /// to subscribed Data Planes. When a DP lags behind by more than this many
    /// updates, it receives a full config snapshot instead of the missed deltas.
    /// Higher values trade memory for fewer full-snapshot recoveries under
    /// high config churn. Default: 128.
    pub cp_broadcast_channel_capacity: usize,

    // DP gRPC TLS (client-side)
    /// Path to PEM CA certificate for verifying the CP server certificate.
    /// When set, the DP verifies the CP server's identity.
    pub dp_grpc_tls_ca_cert_path: Option<String>,
    /// Path to PEM client certificate for DP-to-CP mTLS authentication.
    pub dp_grpc_tls_client_cert_path: Option<String>,
    /// Path to PEM client private key for DP-to-CP mTLS authentication.
    pub dp_grpc_tls_client_key_path: Option<String>,
    /// Skip TLS certificate verification for the DP gRPC client (testing only).
    pub dp_grpc_tls_no_verify: bool,

    // Request/Response limits
    pub max_header_size_bytes: usize,
    pub max_single_header_size_bytes: usize,
    /// Maximum number of request headers allowed. 0 = unlimited.
    pub max_header_count: usize,
    pub max_request_body_size_bytes: usize,
    pub max_response_body_size_bytes: usize,
    /// Cutoff (bytes) below which response bodies with a known Content-Length
    /// are eagerly buffered into a single allocation instead of streamed
    /// frame-by-frame. For small JSON API responses the single `bytes().await`
    /// allocation is cheaper than spinning up the async coalescing adapter.
    /// SSE (`text/event-stream`) responses always stream regardless of size.
    /// 0 = disabled (always stream). Default: 65536 (64 KiB).
    pub response_buffer_cutoff_bytes: usize,
    /// Target chunk size (bytes) for HTTP/2 response body coalescing.
    /// The `CoalescingH2Body` adapter accumulates small HTTP/2 DATA frames into
    /// chunks of at least this size before forwarding to the client, reducing
    /// per-frame overhead on gRPC and HTTP/2 direct pool paths.
    /// Default: 131072 (128 KiB). Minimum: 16384 (16 KiB). Maximum: 1048576 (1 MiB).
    pub h2_coalesce_target_bytes: usize,
    /// Maximum URL length in bytes (path + query string). 0 = unlimited.
    pub max_url_length_bytes: usize,
    /// Maximum number of query parameters allowed. 0 = unlimited.
    pub max_query_params: usize,
    /// Maximum total received gRPC payload size in bytes. For unary RPCs this is
    /// effectively a per-message limit (plus 5 bytes of gRPC framing). For streaming
    /// RPCs this caps the cumulative body size across all messages. 0 = unlimited.
    pub max_grpc_recv_size_bytes: usize,
    /// Maximum WebSocket frame size in bytes. Applied to both client and backend connections.
    pub max_websocket_frame_size_bytes: usize,
    /// WebSocket write buffer size in bytes. Controls how much data is buffered
    /// before flushing to the underlying transport. Larger values reduce syscalls
    /// for large WS frames but increase per-connection memory. The default (128 KB)
    /// is optimal for 10KB-100KB payloads. Increase to 4 MB+ for workloads with
    /// large WS frames (1 MB+). Only applies when frame-level plugins are active;
    /// tunnel mode uses raw copy_bidirectional which bypasses tungstenite entirely.
    pub websocket_write_buffer_size: usize,
    /// When true AND no frame-level plugins are configured on a proxy, bypass
    /// WebSocket frame parsing entirely and use raw TCP bidirectional copy after
    /// the upgrade handshake. This avoids per-frame header parsing, masking
    /// validation, and opcode dispatch — critical for large frames (9 MB+).
    ///
    /// Trade-offs when enabled:
    /// - `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` is NOT enforced (data streams
    ///   through a fixed-size copy buffer, so no large allocation risk)
    /// - Server-push protocols that send frames piggybacked with the HTTP 101
    ///   response may lose the first frame (rare in practice)
    ///
    /// Default: false (safe, frame-parsed path for all connections)
    pub websocket_tunnel_mode: bool,
    /// Maximum number of credential entries per type per consumer (for zero-downtime rotation).
    pub max_credentials_per_type: usize,
    /// HTTP/1.1 header read timeout in seconds. Protects against slowloris attacks
    /// by closing connections that take too long to send complete request headers.
    /// 0 = disabled (no timeout). Default: 10 seconds.
    pub http_header_read_timeout_seconds: u64,

    // DNS
    pub dns_overrides: HashMap<String, String>,
    /// Comma-separated nameserver addresses (ip[:port], IPv4 or IPv6).
    /// Default: parsed from /etc/resolv.conf
    pub dns_resolver_address: Option<String>,
    /// Path to hosts file. Default: /etc/hosts (system default)
    pub dns_resolver_hosts_file: Option<String>,
    /// Order of record types to query (comma-separated, case-insensitive).
    /// Valid values: CACHE, SRV, A, AAAA, CNAME. Default: "CACHE,SRV,A,CNAME"
    pub dns_order: Option<String>,
    /// Global TTL override (seconds) for positive DNS records. When set, ALL
    /// records use this TTL regardless of their native DNS TTL. Default: None
    /// (disabled — the cache respects each record's native TTL).
    pub dns_ttl_override: Option<u64>,
    /// Minimum TTL floor (seconds) for cached DNS records. Prevents 0-TTL or
    /// very short TTLs from causing excessive DNS queries. Default: 5
    pub dns_min_ttl: u64,
    /// Stale data usage time (seconds) during refresh. Default: 3600
    pub dns_stale_ttl: u64,
    /// TTL (seconds) for errors/empty responses. Default: 5
    pub dns_error_ttl: u64,
    /// Maximum number of entries in the DNS cache. Default: 10000
    pub dns_cache_max_size: usize,
    /// Maximum number of concurrent DNS warmup resolutions. Default: 500.
    pub dns_warmup_concurrency: usize,
    /// Threshold in milliseconds above which DNS resolutions are logged as slow. Default: disabled
    pub dns_slow_threshold_ms: Option<u64>,
    /// Percentage of TTL elapsed before background refresh triggers (1-99). Default: 90
    pub dns_refresh_threshold_percent: u8,
    /// Interval (seconds) for the background task that retries failed DNS lookups.
    /// Default: 10. Set to 0 to disable.
    pub dns_failed_retry_interval: u64,
    /// Retry DNS queries over TCP when UDP responses are truncated or fail. Default: true.
    pub dns_try_tcp_on_error: bool,
    /// Number of nameservers to query concurrently per lookup. Default: 3.
    pub dns_num_concurrent_reqs: usize,
    /// Maximum in-flight queries per multiplexed connection. Default: 512.
    pub dns_max_active_requests: usize,

    /// Path to a PEM file containing trusted CA certificates for outbound TLS verification.
    /// Used by backend proxy connections, service discovery, and plugin HTTP calls.
    pub tls_ca_bundle_path: Option<String>,
    /// Path to a PEM file containing the client certificate for backend TLS verification
    pub backend_tls_client_cert_path: Option<String>,
    /// Path to a PEM file containing the client key for backend TLS verification
    pub backend_tls_client_key_path: Option<String>,
    /// Path to a PEM file containing trusted CA certificates for client certificate verification
    pub frontend_tls_client_ca_bundle_path: Option<String>,

    /// Admin API TLS client CA bundle for mTLS verification
    pub admin_tls_client_ca_bundle_path: Option<String>,
    /// Disable outbound TLS certificate verification for all outbound connections
    /// (backend proxy, service discovery, plugin HTTP calls). For testing only.
    pub tls_no_verify: bool,
    /// Admin API read-only mode (default: false, always true in DP mode)
    pub admin_read_only: bool,
    /// Disable admin TLS certificate verification (for testing only)
    pub admin_tls_no_verify: bool,

    // HTTP/3 / QUIC
    /// Enable HTTP/3 listener (default: false)
    pub enable_http3: bool,
    /// HTTP/3 idle timeout in seconds (default: 30)
    pub http3_idle_timeout: u64,
    /// HTTP/3 max concurrent streams (default: 1000)
    pub http3_max_streams: u32,
    /// HTTP/3 per-stream receive window in bytes (default: 8 MiB).
    /// Controls how much data a peer can send on a single QUIC stream
    /// before the receiver must send a flow-control credit update.
    pub http3_stream_receive_window: u64,
    /// HTTP/3 connection-level receive window in bytes (default: 32 MiB).
    /// Aggregate budget shared across all concurrent streams on one QUIC connection.
    pub http3_receive_window: u64,
    /// HTTP/3 per-connection send window in bytes (default: 8 MiB).
    /// Controls how much data can be in flight (sent but unacknowledged)
    /// across all streams on a single QUIC connection.
    pub http3_send_window: u64,
    /// Number of QUIC connections to maintain per HTTP/3 backend (default: 4).
    /// Multiple connections distribute QUIC frame processing across driver tasks.
    pub http3_connections_per_backend: usize,
    /// HTTP/3 pool idle timeout in seconds (default: 120).
    /// Connections idle longer than this are evicted from the pool.
    pub http3_pool_idle_timeout_seconds: u64,
    /// Minimum bytes buffered before flushing a coalesced HTTP/3 DATA frame
    /// on the response streaming path (default: 32_768). Acts as the flush
    /// target — once the buffer reaches this size on chunk arrival, it is
    /// flushed. Clamped to `<= http3_coalesce_max_bytes` at parse time.
    /// Legal range: [1024, http3_coalesce_max_bytes].
    pub http3_coalesce_min_bytes: usize,
    /// Maximum bytes for the HTTP/3 response streaming coalesce buffer
    /// (default: 32_768). Used as the `BytesMut::with_capacity` initial
    /// allocation and as the upper bound that clamps `coalesce_min_bytes`
    /// at parse time. Higher values reduce reallocations for large-backend
    /// responses at the cost of per-stream memory. Legal range:
    /// [1024, 1_048_576].
    pub http3_coalesce_max_bytes: usize,
    /// Time-based flush interval on the HTTP/3 response streaming path in
    /// microseconds (default: 200). Floor: 50 µs to prevent "flush every
    /// poll" footguns. Legal range: [50, 100_000].
    pub http3_flush_interval_micros: u64,
    /// Bounded mpsc channel capacity for the H3→HTTP/HTTPS cross-protocol
    /// request-body bridge (default: 32). The bridge pushes H3 `recv_data`
    /// chunks into the channel; `reqwest::Body::wrap_stream` drains the
    /// receiver and feeds the backend TCP socket. This bounds in-flight
    /// request body memory to approximately `capacity × average_chunk_size`
    /// during a streaming cross-protocol upload (default ~32 × 16 KiB ≈
    /// 512 KiB per upload — enough pipeline depth to absorb backend jitter
    /// without starving throughput, while keeping 1 K concurrent uploads
    /// under ~500 MiB). Increase for high-bandwidth uploads where the
    /// client produces faster than the backend drains; decrease on
    /// memory-constrained hosts. Legal range: [1, 1024].
    pub http3_request_body_channel_capacity: usize,
    /// Milliseconds the HTTP/3 listener spends draining already-buffered
    /// request-body bytes before issuing STOP_SENDING when a
    /// small/successful response is emitted while the client is likely
    /// still uploading (default: 50). Small 2xx echo / idempotent
    /// uploads typically complete inside this window so the QUIC stream
    /// terminates via natural FIN rather than STOP_SENDING — avoiding
    /// the "stopped by peer" signal on happy-path traffic. Zero
    /// disables the drain and issues the halt immediately. Error
    /// responses (413, 502, plugin reject) always halt immediately —
    /// this setting only governs the fast-response path. Legal range:
    /// [0, 1000].
    pub h3_request_body_drain_ms: u64,
    /// Initial QUIC path MTU in bytes used to build `TransportConfig`
    /// (default: 1500). quinn's baseline of 1200 forces ~9 packets for a
    /// 10 KiB payload; 1500 is safe on modern networks and quinn backs off
    /// via black-hole detection if a smaller MTU is required. Legal range:
    /// [1200, 65527] (quinn's accepted bounds).
    pub http3_initial_mtu: u16,
    /// Milliseconds the gRPC backend pool waits on a saturated HTTP/2 sender
    /// for a free stream before opening a fresh connection (default: 1).
    /// Lower values reduce queueing for unary gRPC under load. Set to 0 to
    /// skip the wait and open a new backend connection immediately.
    pub grpc_pool_ready_wait_ms: u64,

    // Connection pool warmup
    /// Pre-establish backend connections at startup (default: true).
    /// Warms HTTP, gRPC, HTTP/2, and HTTP/3 pools after DNS warmup completes.
    /// Skipped for TCP/UDP stream proxies (no persistent connection pools).
    pub pool_warmup_enabled: bool,
    /// Maximum concurrent connection warmup attempts at startup (default: 500).
    pub pool_warmup_concurrency: usize,

    // Connection pool cleanup
    /// Interval in seconds between connection pool cleanup sweeps (default: 30).
    /// Applies to HTTP, gRPC, HTTP/2, and HTTP/3 connection pools.
    pub pool_cleanup_interval_seconds: u64,

    /// Interval in seconds between backend capability reprobes (default:
    /// 86400 = 24 hours). Startup classification runs before pool warmup;
    /// this interval controls the background refresh that re-checks HTTPS
    /// backends for HTTP/2 and HTTP/3 support and plaintext HTTP backends
    /// for h2c support outside the request hot path.
    pub backend_capability_refresh_interval_secs: u64,

    // Router cache
    /// Maximum entries in the router prefix/negative lookup cache (default: 0 = auto).
    /// When set to 0 (auto), the cache size is computed as `max(10_000, proxies × 3)`,
    /// scaling with proxy count to prevent eviction thrashing at high scale.
    /// Set an explicit value to cap memory usage on memory-constrained deployments.
    /// Minimum effective value: 1_000. Maximum: 10_000_000.
    pub router_cache_max_entries: usize,

    // TCP proxy
    /// Default TCP idle timeout in seconds (default: 300 / 5 min).
    /// Per-proxy `tcp_idle_timeout_seconds` overrides this. Set to 0 to disable.
    ///
    /// See [`Self::tcp_half_close_max_wait_seconds`] for how this interacts
    /// with the bidirectional-relay fast path.
    pub tcp_idle_timeout_seconds: u64,
    /// Hard cap on Phase 2 (half-close drain) of the TCP bidirectional relay.
    ///
    /// After one side of a TCP proxy stream finishes cleanly (EOF), the other
    /// direction is awaited so slow-response protocols (SMTP, IMAP,
    /// HTTP-over-TCP passthrough) are not truncated. Normally the session
    /// idle timeout bounds this wait, but `FERRUM_TCP_IDLE_TIMEOUT_SECONDS=0`
    /// disables idle entirely — in that case a stalled peer could wedge the
    /// Phase 2 future forever.
    ///
    /// This cap fires even when the idle timeout is disabled. Default 300
    /// (5 minutes). Set to `0` to disable.
    ///
    /// # Bidirectional-relay performance modes
    ///
    /// When **both** `tcp_idle_timeout_seconds` and
    /// `tcp_half_close_max_wait_seconds` are `0`, the relay selects a
    /// **fast path** that delegates to `tokio::io::copy_bidirectional_with_sizes`
    /// directly. Any other combination selects the **direction-tracking path**:
    ///
    /// | Mode | Trigger | Benefits | Downsides |
    /// |------|---------|----------|-----------|
    /// | Fast path | both vars == 0 | no `io::split`/BiLock, no Phase 1/2 loop, max TCP throughput, per-direction bytes preserved on clean completion | no idle watchdog (OS TCP timers only), no half-close hard cap, `disconnect_direction` reported as `unknown` on error |
    /// | Direction-tracking | either var != 0 (default) | idle timeout, half-close cap, per-direction byte counts, first-failure direction attribution in logs/metrics | one BiLock access per read/write, 2× `Vec<u8>` alloc per connection, Phase 1/2 scheduling overhead |
    ///
    /// Pick the fast path only when an external L4 load balancer already
    /// enforces per-connection timeouts and per-direction failure attribution
    /// is not consumed by your dashboards/alerts.
    pub tcp_half_close_max_wait_seconds: u64,

    // UDP proxy
    /// Maximum concurrent UDP sessions per proxy (default: 10000).
    pub udp_max_sessions: usize,
    /// UDP session cleanup interval in seconds (default: 10).
    pub udp_cleanup_interval_seconds: u64,
    /// Number of datagrams per `recvmmsg` syscall on Linux (default: 64).
    /// Controls how many datagrams are received in a single kernel crossing.
    /// Higher values reduce syscall overhead for high-throughput UDP proxies.
    /// Ignored on non-Linux platforms (falls back to individual `try_recv_from`).
    pub udp_recvmmsg_batch_size: usize,

    // Adaptive Buffer Sizing
    /// Enable adaptive buffer sizing for TCP/WebSocket tunnel copy buffers (default: true).
    pub adaptive_buffer_enabled: bool,
    /// Enable adaptive UDP batch limit per proxy (default: true).
    pub adaptive_batch_limit_enabled: bool,
    /// EWMA smoothing factor (1-999, fixed-point where 1000 = 1.0). Default: 300 (α = 0.3).
    pub adaptive_buffer_ewma_alpha: u64,
    /// Minimum buffer size in bytes (floor). Default: 8192 (8 KiB).
    pub adaptive_buffer_min_size: usize,
    /// Maximum buffer size in bytes (ceiling). Default: 262144 (256 KiB).
    pub adaptive_buffer_max_size: usize,
    /// Default buffer size when no data recorded yet. Default: 65536 (64 KiB).
    pub adaptive_buffer_default_size: usize,
    /// Default batch limit when no data recorded yet. Default: 6000.
    pub adaptive_batch_limit_default: usize,

    // TLS Hardening
    /// Minimum TLS version: "1.2" or "1.3" (default: "1.2")
    pub tls_min_version: String,
    /// Maximum TLS version: "1.2" or "1.3" (default: "1.3")
    pub tls_max_version: String,
    /// Comma-separated cipher suites (OpenSSL names). If empty, uses secure defaults.
    /// TLS 1.3: TLS_AES_256_GCM_SHA384, TLS_AES_128_GCM_SHA256, TLS_CHACHA20_POLY1305_SHA256
    /// TLS 1.2: ECDHE-ECDSA-AES256-GCM-SHA384, ECDHE-RSA-AES256-GCM-SHA384,
    ///          ECDHE-ECDSA-AES128-GCM-SHA256, ECDHE-RSA-AES128-GCM-SHA256,
    ///          ECDHE-ECDSA-CHACHA20-POLY1305, ECDHE-RSA-CHACHA20-POLY1305
    pub tls_cipher_suites: Option<String>,
    /// Prefer server cipher order for TLS 1.2 (default: true)
    pub tls_prefer_server_cipher_order: bool,
    /// Comma-separated ECDH curves/groups: X25519, secp256r1, secp384r1 (default: "X25519,secp256r1")
    pub tls_curves: Option<String>,
    /// TLS session resumption cache size for TLS 1.2 stateful session IDs.
    /// TLS 1.3 uses stateless tickets (unlimited). Applies to inbound listeners
    /// and outbound/backend client configs that opt into rustls session caching.
    /// (default: 4096)
    pub tls_session_cache_size: usize,
    /// Number of days before certificate expiration to emit a warning log.
    /// Expired certificates are rejected at startup/config-load time.
    /// Set to 0 to disable near-expiry warnings. (default: 30)
    pub tls_cert_expiry_warning_days: u64,
    /// Comma-separated HTTP methods allowed to be sent as TLS 1.3 0-RTT early data.
    /// When non-empty, the gateway advertises 0-RTT support on HTTPS and HTTP/3
    /// listeners and enforces that only the listed methods are accepted as early data.
    /// Default: empty (0-RTT disabled — `max_early_data_size=0`).
    /// Example: "GET" or "GET,HEAD,OPTIONS"
    pub tls_early_data_methods: HashSet<String>,

    // Stream proxy (TCP/UDP)
    /// Bind address for TCP/UDP stream proxy listeners (default: 0.0.0.0).
    #[allow(dead_code)] // Used in Phase 2 (stream listener startup)
    pub stream_proxy_bind_address: String,

    // DTLS frontend certificates (ECDSA P-256 or P-384 required)
    /// Path to DTLS server certificate (PEM) for frontend DTLS termination.
    /// If not set, a self-signed ECDSA P-256 certificate is generated at startup.
    pub dtls_cert_path: Option<String>,
    /// Path to DTLS server private key (PEM) for frontend DTLS termination.
    pub dtls_key_path: Option<String>,
    /// Path to CA certificate (PEM) for verifying DTLS client certificates (mTLS).
    /// When set, the gateway requires and verifies client certificates for frontend
    /// DTLS connections using this trust store. Separate from the TLS client CA used
    /// for TCP frontend mTLS (`FERRUM_TLS_CLIENT_CA_CERT_PATH`).
    pub dtls_client_ca_cert_path: Option<String>,
    /// Maximum plaintext payload bytes per DTLS record. Datagrams exceeding this are
    /// dropped with a warning. Default: 16384 (2^14, per RFC 9147 §4.1). Increase only
    /// if your UDP application sends datagrams larger than 16 KB over DTLS.
    pub dtls_max_plaintext_bytes: usize,
    /// DTLS record overhead bytes (header + auth tag). Default: 64. The output buffer
    /// per DTLS session is `dtls_max_plaintext_bytes + dtls_record_overhead_bytes`.
    pub dtls_record_overhead_bytes: usize,

    // Client IP resolution
    /// Comma-separated trusted proxy CIDRs/IPs for X-Forwarded-For resolution.
    /// When set, the gateway walks the XFF chain right-to-left, skipping trusted
    /// proxy IPs, to determine the real client IP. When unset, the TCP socket
    /// address is always used (secure default for edge deployments).
    /// Example: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1"
    pub trusted_proxies: String,
    /// Backend IP allowlist policy for SSRF protection.
    /// "private" = only private/reserved IPs, "public" = only public IPs, "both" = all (default).
    pub backend_allow_ips: BackendAllowIps,
    /// When true, add a Via header on both request and response paths per RFC 9110 §7.6.3.
    pub add_via_header: bool,
    /// Pseudonym used in the Via header. Defaults to "ferrum-edge".
    pub via_pseudonym: String,
    /// When true, add a Forwarded header (RFC 7239) alongside X-Forwarded-* headers.
    pub add_forwarded_header: bool,
    /// Header to use as the authoritative source of client IP. When set, this
    /// header is checked first (e.g., "CF-Connecting-IP" for Cloudflare, or
    /// "X-Real-IP" for nginx). If the header is absent or the direct connection
    /// is not from a trusted proxy, falls back to the X-Forwarded-For walk.
    pub real_ip_header: Option<String>,

    /// HMAC-SHA256 server secret for the basic_auth plugin. Password hashes
    /// prefixed with "hmac_sha256:" are verified using this key (~1μs vs ~100ms
    /// for bcrypt). Must be set to a unique, random value in production.
    /// If unset, an insecure default is used and a warning is logged at startup.
    /// Note: Also resolved via `resolve_ferrum_var()` in `basic_auth.rs` and
    /// `admin/mod.rs` for use sites that don't have `EnvConfig` in scope.
    #[allow(dead_code)]
    pub basic_auth_hmac_secret: Option<String>,

    /// Threshold in milliseconds for logging slow plugin outbound HTTP calls.
    /// When a plugin HTTP request (e.g. http_logging, JWKS fetch,
    /// OIDC discovery, OTLP export) exceeds this duration, a warning is logged.
    /// Default: 1000 (1 second).
    pub plugin_http_slow_threshold_ms: u64,
    /// Maximum retry attempts for safe/idempotent plugin outbound HTTP calls
    /// when the failure is transport-level (connection refused/reset/closed,
    /// connect timeout, DNS lookup failure). Default: 0 (disabled).
    pub plugin_http_max_retries: u32,
    /// Delay in milliseconds between automatic plugin outbound HTTP retries.
    /// Default: 100.
    pub plugin_http_retry_delay_ms: u64,

    /// Path to a PEM file containing Certificate Revocation Lists (CRLs).
    /// When set, all TLS/DTLS surfaces (frontend mTLS, backend verification, gRPC, WebSocket)
    /// will reject certificates listed in the CRL. Supports multiple CRLs in one file.
    /// Uses `-----BEGIN X509 CRL-----` PEM blocks.
    pub tls_crl_file_path: Option<String>,
    /// Comma-separated CIDRs/IPs allowed to connect to the admin API.
    /// When empty (default), all IPs are permitted. When set, connections from
    /// non-matching IPs are rejected at the TCP level before any request processing.
    /// Example: "10.0.100.0/24,10.0.200.5,::1"
    pub admin_allowed_cidrs: String,

    /// Max request body size in MiB for POST /restore (large config backups).
    /// Default: 100 MiB.
    pub admin_restore_max_body_size_mib: usize,

    /// Migration action: up, status, config (migrate mode only).
    /// Default: "up".
    pub migrate_action: String,

    /// When true, migration commands preview changes without applying.
    /// Default: false.
    pub migrate_dry_run: bool,

    // ── Runtime & listener tuning ────────────────────────────────────────
    /// Number of tokio worker threads. Default: number of CPU cores.
    pub worker_threads: Option<usize>,
    /// Maximum number of tokio blocking threads. Default: 512 (tokio default).
    pub blocking_threads: Option<usize>,
    /// Maximum concurrent connections the proxy will accept.
    /// Default: 100000. When the limit is reached, new connections queue
    /// until a slot frees up. Set to 0 to disable the limit entirely.
    pub max_connections: usize,
    /// Maximum concurrent in-flight requests (global, all protocols).
    /// Tracks HTTP/1.1 requests, HTTP/2 streams, HTTP/3 streams, and gRPC
    /// requests independently of the connection limit. Default: 0 (unlimited).
    /// When exceeded, new requests receive 503 Service Unavailable.
    pub max_requests: usize,
    /// Maximum concurrent proxy requests per resolved client IP.
    /// Uses the same client IP resolution as trusted proxy XFF walk.
    /// Default: 0 (disabled). When exceeded, returns 429 Too Many Requests.
    pub max_concurrent_requests_per_ip: u64,
    /// Interval in seconds between cleanup sweeps for per-IP request counters.
    /// Removes entries where the active request count has dropped to zero.
    /// Only relevant when `max_concurrent_requests_per_ip > 0`. Default: 60.
    pub per_ip_cleanup_interval_seconds: u64,
    /// Maximum entries in the circuit breaker cache. Entries are keyed by
    /// proxy_id::host:port. Stale entries from removed upstream targets are
    /// pruned during config reload. This cap prevents unbounded growth from
    /// target churn in dynamic environments (e.g., Kubernetes pod cycling).
    /// Default: 10000.
    pub circuit_breaker_cache_max_entries: usize,
    /// Maximum entries in the HTTP status code counters map. Common codes
    /// (200, 404, 500, etc.) are pre-populated at startup. Rare/exotic codes
    /// create entries on first occurrence up to this cap. Prevents unbounded
    /// growth from adversarial backends returning many distinct status codes.
    /// Default: 200.
    pub status_counts_max_entries: usize,
    /// TCP listen backlog size for proxy listeners. Default: 2048.
    /// Higher values absorb connection bursts without SYN drops.
    pub tcp_listen_backlog: u32,
    /// Number of parallel accept() loops per proxy listener port. Each loop binds
    /// its own socket to the same address via SO_REUSEPORT, giving the kernel
    /// separate accept queues to distribute SYN processing across — eliminating
    /// the single socket lock bottleneck at high connection rates (50K+ new
    /// conn/sec). This is orthogonal to `FERRUM_WORKER_THREADS` which controls
    /// the tokio runtime thread pool for all async work; `accept_threads`
    /// specifically parallelizes connection intake at the kernel level.
    /// Default: 0 (auto-detect = available CPU cores). Set to 1 to disable
    /// multi-listener. Only effective on Unix with SO_REUSEPORT (Linux 3.9+,
    /// macOS, BSDs).
    pub accept_threads: usize,
    /// Server-side HTTP/2 max concurrent streams per inbound connection.
    /// Limits how many requests a single HTTP/2 client can multiplex.
    /// Default: 1000 (nginx=128, envoy=100, unlimited by spec).
    pub server_http2_max_concurrent_streams: u32,
    /// Server-side HTTP/2 max pending accept-reset streams per connection.
    /// When exceeded, the server sends GOAWAY to mitigate rapid-reset abuse.
    /// Default: 64.
    pub server_http2_max_pending_accept_reset_streams: usize,
    /// Server-side HTTP/2 max locally reset streams per connection.
    /// When exceeded, the server sends GOAWAY to bound repeated local reset churn.
    /// Default: 256.
    pub server_http2_max_local_error_reset_streams: usize,
    /// Maximum concurrently upgraded WebSocket connections.
    /// Default: 20_000. Set to 0 to disable the dedicated WebSocket cap and
    /// rely only on the global connection limit.
    pub websocket_max_connections: usize,

    // ── Overload management ──────────────────────────────────────────────
    /// How often the overload monitor checks resource pressure in milliseconds.
    /// Default: 1000 (1 second).
    pub overload_check_interval_ms: u64,
    /// FD usage ratio above which keepalive is disabled. Default: 0.80 (80%).
    pub overload_fd_pressure_threshold: f64,
    /// FD usage ratio above which new connections are rejected. Default: 0.95 (95%).
    pub overload_fd_critical_threshold: f64,
    /// Connection semaphore usage ratio above which keepalive is disabled. Default: 0.85 (85%).
    pub overload_conn_pressure_threshold: f64,
    /// Connection semaphore usage ratio above which new connections are rejected. Default: 0.95 (95%).
    pub overload_conn_critical_threshold: f64,
    /// Request usage ratio above which keepalive is disabled. Default: 0.85 (85%).
    /// Only relevant when `max_requests > 0`.
    pub overload_req_pressure_threshold: f64,
    /// Request usage ratio above which new requests are rejected with 503. Default: 0.95 (95%).
    /// Only relevant when `max_requests > 0`.
    pub overload_req_critical_threshold: f64,
    /// Event loop latency in microseconds above which a warning is logged. Default: 10000 (10ms).
    pub overload_loop_warn_us: u64,
    /// Event loop latency in microseconds above which new connections are rejected. Default: 500000 (500ms).
    pub overload_loop_critical_us: u64,

    // ── Graceful shutdown ────────────────────────────────────────────────
    /// Seconds to wait for in-flight connections to drain on shutdown.
    /// During the drain period, the gateway stops accepting new connections,
    /// sets `Connection: close` on responses, and waits for existing requests
    /// to complete. Default: 30. Set to 0 to skip draining (immediate shutdown).
    pub shutdown_drain_seconds: u64,

    // ── Admin status metrics ─────────────────────────────────────────────
    /// Window size in seconds for computing per-second rate metrics on the
    /// admin `/status` endpoint.  A background task snapshots cumulative
    /// counters every N seconds and computes average rates.  Minimum: 1.
    pub status_metrics_window_seconds: u64,

    // ── TLS handshake offload ───────────────────────────────────────────
    /// Total dedicated threads for offloading TLS handshakes from the main
    /// event loop. 0 = disabled (handshakes run on tokio worker threads).
    /// When enabled, threads are organized into shards for TLS session cache
    /// affinity. Default: 0 (disabled).
    pub tls_offload_threads: usize,

    // ── TCP socket optimizations (Linux only) ────────────────────────────
    /// Enable TCP Fast Open on server (listening) and client (connecting) sockets.
    /// Saves 1 RTT on repeat connections by allowing data in the SYN packet.
    /// Requires Linux 4.11+ and `net.ipv4.tcp_fastopen` sysctl bit 0x1 (server)
    /// or 0x2 (client) enabled. No-op on non-Linux.
    /// Values: `auto` (check sysctl at startup), `true` (force on), `false` (force off).
    /// Default: `auto`.
    pub tcp_fastopen_enabled: AutoBool,
    /// TCP Fast Open server queue length — maximum pending TFO connections.
    /// Only used when `tcp_fastopen_enabled` is true. Default: 256.
    pub tcp_fastopen_queue_len: u16,

    // ── Stream proxy performance optimizations (Linux only) ─────────────
    /// Enable kTLS (kernel TLS) on TCP proxy TLS paths (Linux 4.13+ only).
    /// After the userspace TLS handshake, installs symmetric keys into the kernel
    /// so splice(2) can work on encrypted connections. Dramatically reduces latency
    /// and CPU for TLS TCP proxy paths.
    /// Values: `auto` (detect kernel support), `true` (force on), `false` (force off).
    /// Default: `auto` — probes full kTLS path (ULP install + dummy key install) on
    /// a loopback socket pair at startup. Only enables if the entire path succeeds.
    pub ktls_enabled: AutoBool,
    /// Enable io_uring-based splice for TCP proxy zero-copy relay (Linux 5.6+ only).
    /// Uses IORING_OP_SPLICE submission queue entries instead of direct libc splice
    /// syscalls. Falls back to libc splice if io_uring is unavailable.
    /// Values: `auto` (detect kernel support), `true` (force on), `false` (force off).
    /// Default: `auto`.
    pub io_uring_splice_enabled: AutoBool,
    /// Enable UDP GRO (Generic Receive Offload) on frontend UDP sockets (Linux 5.0+).
    /// Kernel coalesces multiple same-size UDP datagrams into a single large buffer,
    /// more efficient than recvmmsg.
    /// Values: `auto` (probe setsockopt on temp socket), `true`, `false`.
    /// Default: `auto`.
    pub udp_gro_enabled: AutoBool,
    /// Enable UDP GSO (Generic Segmentation Offload) for batched UDP sending (Linux 4.18+).
    /// Sends multiple datagrams in a single sendmsg() by specifying a segment size via
    /// ancillary data. The kernel splits them at the NIC level.
    /// Values: `auto` (probe sendmsg with UDP_SEGMENT on temp socket), `true`, `false`.
    /// Default: `auto`.
    pub udp_gso_enabled: AutoBool,
    /// Enable IP_PKTINFO / IPV6_PKTINFO on frontend UDP sockets (Linux only).
    /// Captures the per-datagram local destination address on recv and reuses
    /// it as the reply source on send, so the kernel skips the routing-table
    /// lookup. Complements UDP_SEGMENT (GSO) — both cmsgs ride in one sendmsg.
    /// Values: `auto` (probe setsockopt on temp socket), `true`, `false`.
    /// Default: `auto`.
    pub udp_pktinfo_enabled: AutoBool,
    /// SO_BUSY_POLL duration in microseconds for latency-sensitive UDP sockets (Linux 3.11+).
    /// When > 0, the kernel spins for this many microseconds waiting for incoming data
    /// before sleeping. Reduces receive latency at the cost of CPU. 0 = disabled. Default: 0.
    pub so_busy_poll_us: u32,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            mode: OperatingMode::File,
            namespace: "ferrum".into(),
            log_level: "error".into(),
            log_buffer_capacity: 128_000,
            enable_streaming_latency_tracking: false,
            proxy_http_port: 8000,
            proxy_https_port: 8443,
            frontend_tls_cert_path: None,
            frontend_tls_key_path: None,
            proxy_bind_address: "0.0.0.0".into(),
            admin_http_port: 9000,
            admin_https_port: 9443,
            admin_tls_cert_path: None,
            admin_tls_key_path: None,
            admin_bind_address: "0.0.0.0".into(),
            admin_jwt_secret: None,
            admin_jwt_issuer: "ferrum-edge".into(),
            admin_jwt_max_ttl: 3600,
            db_type: None,
            db_url: None,
            db_poll_interval: 30,
            db_tls_enabled: false,
            db_tls_ca_cert_path: None,
            db_tls_client_cert_path: None,
            db_tls_client_key_path: None,
            db_tls_insecure: false,
            db_ssl_mode: None,
            db_ssl_root_cert: None,
            db_ssl_client_cert: None,
            db_ssl_client_key: None,
            file_config_path: None,
            db_config_backup_path: None,
            db_failover_urls: Vec::new(),
            db_read_replica_url: None,
            db_slow_query_threshold_ms: None,
            db_pool_max_connections: 10,
            db_pool_min_connections: 1,
            db_pool_acquire_timeout_seconds: 30,
            db_pool_idle_timeout_seconds: 600,
            db_pool_max_lifetime_seconds: 300,
            db_pool_connect_timeout_seconds: 10,
            db_pool_statement_timeout_seconds: 30,
            mongo_database: "ferrum".to_string(),
            mongo_app_name: None,
            mongo_replica_set: None,
            mongo_auth_mechanism: None,
            mongo_server_selection_timeout_seconds: 30,
            mongo_connect_timeout_seconds: 10,
            cp_grpc_listen_addr: None,
            cp_dp_grpc_jwt_secret: None,
            dp_cp_grpc_url: None,
            dp_cp_grpc_urls: Vec::new(),
            dp_cp_failover_primary_retry_secs: 300,
            cp_grpc_tls_cert_path: None,
            cp_grpc_tls_key_path: None,
            cp_grpc_tls_client_ca_path: None,
            cp_broadcast_channel_capacity: 128,
            dp_grpc_tls_ca_cert_path: None,
            dp_grpc_tls_client_cert_path: None,
            dp_grpc_tls_client_key_path: None,
            dp_grpc_tls_no_verify: false,
            max_header_size_bytes: 32_768,
            max_single_header_size_bytes: 16_384,
            max_header_count: 100,
            max_request_body_size_bytes: 10_485_760,
            max_response_body_size_bytes: 10_485_760,
            response_buffer_cutoff_bytes: 65_536,
            h2_coalesce_target_bytes: 131_072,
            max_url_length_bytes: 8_192,
            max_query_params: 100,
            max_grpc_recv_size_bytes: 4_194_304,
            max_websocket_frame_size_bytes: 16_777_216,
            websocket_write_buffer_size: 131_072, // 128 KB
            websocket_tunnel_mode: false,
            max_credentials_per_type: 2,
            http_header_read_timeout_seconds: 10,
            dns_overrides: HashMap::new(),
            dns_resolver_address: None,
            dns_resolver_hosts_file: None,
            dns_order: None,
            dns_ttl_override: None,
            dns_min_ttl: 5,
            dns_stale_ttl: 3600,
            dns_error_ttl: 5,
            dns_cache_max_size: 10_000,
            dns_warmup_concurrency: 500,
            dns_slow_threshold_ms: None,
            dns_refresh_threshold_percent: 90,
            dns_failed_retry_interval: 10,
            dns_try_tcp_on_error: true,
            dns_num_concurrent_reqs: 3,
            dns_max_active_requests: 512,
            tls_ca_bundle_path: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            frontend_tls_client_ca_bundle_path: None,
            admin_tls_client_ca_bundle_path: None,
            tls_no_verify: false,
            admin_read_only: false,
            admin_tls_no_verify: false,
            stream_proxy_bind_address: "0.0.0.0".into(),
            dtls_cert_path: None,
            dtls_key_path: None,
            dtls_client_ca_cert_path: None,
            dtls_max_plaintext_bytes: 16_384,
            dtls_record_overhead_bytes: 64,
            enable_http3: false,
            http3_idle_timeout: 30,
            http3_max_streams: 1000,
            http3_stream_receive_window: 8_388_608, // 8 MiB
            http3_receive_window: 33_554_432,       // 32 MiB
            http3_send_window: 8_388_608,           // 8 MiB
            http3_connections_per_backend: 4,
            http3_pool_idle_timeout_seconds: 120,
            http3_coalesce_min_bytes: 32_768,
            http3_coalesce_max_bytes: 32_768,
            http3_flush_interval_micros: 200,
            http3_request_body_channel_capacity: 32,
            h3_request_body_drain_ms: 50,
            http3_initial_mtu: 1500,
            grpc_pool_ready_wait_ms: 1,
            pool_warmup_enabled: true,
            pool_warmup_concurrency: 500,
            pool_cleanup_interval_seconds: 30,
            backend_capability_refresh_interval_secs: 86_400,
            router_cache_max_entries: 0, // 0 = auto-scale based on proxy count
            tcp_idle_timeout_seconds: 300,
            tcp_half_close_max_wait_seconds: 300,
            udp_max_sessions: 10_000,
            udp_cleanup_interval_seconds: 10,
            udp_recvmmsg_batch_size: 64,
            adaptive_buffer_enabled: true,
            adaptive_batch_limit_enabled: true,
            adaptive_buffer_ewma_alpha: 300,
            adaptive_buffer_min_size: 8_192,
            adaptive_buffer_max_size: 262_144,
            adaptive_buffer_default_size: 65_536,
            adaptive_batch_limit_default: 6_000,
            tls_min_version: "1.2".into(),
            tls_max_version: "1.3".into(),
            tls_cipher_suites: None,
            tls_prefer_server_cipher_order: true,
            tls_curves: None,
            tls_session_cache_size: 4096,
            tls_cert_expiry_warning_days: 30,
            tls_early_data_methods: HashSet::new(),
            trusted_proxies: String::new(),
            backend_allow_ips: BackendAllowIps::Both,
            add_via_header: true,
            via_pseudonym: "ferrum-edge".into(),
            add_forwarded_header: false,
            real_ip_header: None,
            basic_auth_hmac_secret: None,
            plugin_http_slow_threshold_ms: 1000,
            plugin_http_max_retries: 0,
            plugin_http_retry_delay_ms: 100,
            tls_crl_file_path: None,
            admin_allowed_cidrs: String::new(),
            admin_restore_max_body_size_mib: 100,
            migrate_action: "up".into(),
            migrate_dry_run: false,
            worker_threads: None,
            blocking_threads: None,
            max_connections: 100_000,
            max_requests: 0,
            max_concurrent_requests_per_ip: 0,
            per_ip_cleanup_interval_seconds: 60,
            circuit_breaker_cache_max_entries: 10_000,
            status_counts_max_entries: 200,
            tcp_listen_backlog: 2048,
            accept_threads: 0,
            server_http2_max_concurrent_streams: 1000,
            server_http2_max_pending_accept_reset_streams: 64,
            server_http2_max_local_error_reset_streams: 256,
            websocket_max_connections: 20_000,
            overload_check_interval_ms: 1000,
            overload_fd_pressure_threshold: 0.80,
            overload_fd_critical_threshold: 0.95,
            overload_conn_pressure_threshold: 0.85,
            overload_conn_critical_threshold: 0.95,
            overload_req_pressure_threshold: 0.85,
            overload_req_critical_threshold: 0.95,
            overload_loop_warn_us: 10_000,
            overload_loop_critical_us: 500_000,
            shutdown_drain_seconds: 30,
            status_metrics_window_seconds: 30,
            tls_offload_threads: 0,
            tcp_fastopen_enabled: AutoBool::Auto,
            tcp_fastopen_queue_len: 256,
            ktls_enabled: AutoBool::Auto,
            io_uring_splice_enabled: AutoBool::Auto,
            udp_gro_enabled: AutoBool::Auto,
            udp_gso_enabled: AutoBool::Auto,
            udp_pktinfo_enabled: AutoBool::Auto,
            so_busy_poll_us: 0,
        }
    }
}

impl EnvConfig {
    /// Load configuration from environment variables and validate.
    ///
    /// When using external secret sources (`_FILE`, `_VAULT`, `_AWS`, `_GCP`,
    /// `_AZURE`), call `secrets::resolve_all_env_secrets()` before this method
    /// so that resolved values are available as plain env vars.
    pub fn from_env() -> Result<Self, String> {
        let conf = ConfFile::load()?;
        Self::from_env_with_conf(&conf)
    }

    /// Build config using values from the given conf file (takes precedence)
    /// with fallback to environment variables.
    pub fn from_env_with_conf(conf: &ConfFile) -> Result<Self, String> {
        let mode = OperatingMode::resolve(conf)?;

        // Mechanical env vars are declared in one place so parse/default semantics
        // stay consistent and malformed values fail loudly instead of silently
        // falling back to defaults.
        env_config! {
            conf = conf, mode = &mode;
            [core]
            dns_overrides: HashMap<String, String> = "FERRUM_DNS_OVERRIDES" => HashMap::new();
            namespace: String = "FERRUM_NAMESPACE" => "ferrum".to_string();
            log_level: String = "FERRUM_LOG_LEVEL" => "error".to_string();
            log_buffer_capacity: usize = "FERRUM_LOG_BUFFER_CAPACITY" => 128_000usize;
            enable_streaming_latency_tracking: bool = "FERRUM_ENABLE_STREAMING_LATENCY_TRACKING" => false;
        }

        env_config! {
            conf = conf, mode = &mode;
            [proxy]
            proxy_http_port: u16 = "FERRUM_PROXY_HTTP_PORT" => 8000u16;
            proxy_https_port: u16 = "FERRUM_PROXY_HTTPS_PORT" => 8443u16;
            frontend_tls_cert_path: Option<String> = "FERRUM_FRONTEND_TLS_CERT_PATH";
            frontend_tls_key_path: Option<String> = "FERRUM_FRONTEND_TLS_KEY_PATH";
            proxy_bind_address: String = "FERRUM_PROXY_BIND_ADDRESS" => "0.0.0.0".to_string();
        }

        env_config! {
            conf = conf, mode = &mode;
            [admin]
            admin_http_port: u16 = "FERRUM_ADMIN_HTTP_PORT" => 9000u16;
            admin_https_port: u16 = "FERRUM_ADMIN_HTTPS_PORT" => 9443u16;
            admin_tls_cert_path: Option<String> = "FERRUM_ADMIN_TLS_CERT_PATH";
            admin_tls_key_path: Option<String> = "FERRUM_ADMIN_TLS_KEY_PATH";
            admin_bind_address: String = "FERRUM_ADMIN_BIND_ADDRESS" => "0.0.0.0".to_string();
            admin_jwt_secret: Option<String> = "FERRUM_ADMIN_JWT_SECRET"
                => required_for(["database", "cp"]) min_len(crate::config::types::MIN_JWT_SECRET_LENGTH);
            admin_jwt_issuer: String = "FERRUM_ADMIN_JWT_ISSUER" => "ferrum-edge".to_string();
            admin_jwt_max_ttl: u64 = "FERRUM_ADMIN_JWT_MAX_TTL" => 3600u64;
        }

        env_config! {
            conf = conf, mode = &mode;
            [database]
            db_type: Option<String> = "FERRUM_DB_TYPE";
            db_url: Option<String> = "FERRUM_DB_URL";
            db_poll_interval: u64 = "FERRUM_DB_POLL_INTERVAL" => 30u64;
            db_tls_enabled: bool = "FERRUM_DB_TLS_ENABLED" => false;
            db_tls_ca_cert_path: Option<String> = "FERRUM_DB_TLS_CA_CERT_PATH";
            db_tls_client_cert_path: Option<String> = "FERRUM_DB_TLS_CLIENT_CERT_PATH";
            db_tls_client_key_path: Option<String> = "FERRUM_DB_TLS_CLIENT_KEY_PATH";
            db_tls_insecure: bool = "FERRUM_DB_TLS_INSECURE" => false;
            db_ssl_mode: Option<String> = "FERRUM_DB_SSL_MODE";
            db_ssl_root_cert: Option<String> = "FERRUM_DB_SSL_ROOT_CERT";
            db_ssl_client_cert: Option<String> = "FERRUM_DB_SSL_CLIENT_CERT";
            db_ssl_client_key: Option<String> = "FERRUM_DB_SSL_CLIENT_KEY";
            file_config_path: Option<String> = "FERRUM_FILE_CONFIG_PATH";
            db_config_backup_path: Option<String> = "FERRUM_DB_CONFIG_BACKUP_PATH";
            db_read_replica_url: Option<String> = "FERRUM_DB_READ_REPLICA_URL";
            db_slow_query_threshold_ms: Option<u64> = "FERRUM_DB_SLOW_QUERY_THRESHOLD_MS";
            db_pool_max_connections: u32 = "FERRUM_DB_POOL_MAX_CONNECTIONS" => 10u32, max(1u32);
            db_pool_min_connections: u32 = "FERRUM_DB_POOL_MIN_CONNECTIONS" => 1u32;
            db_pool_acquire_timeout_seconds: u64 = "FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS" => 30u64;
            db_pool_idle_timeout_seconds: u64 = "FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS" => 600u64;
            db_pool_max_lifetime_seconds: u64 = "FERRUM_DB_POOL_MAX_LIFETIME_SECONDS" => 300u64;
            db_pool_connect_timeout_seconds: u64 = "FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS" => 10u64;
            db_pool_statement_timeout_seconds: u64 = "FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS" => 30u64;
            mongo_database: String = "FERRUM_MONGO_DATABASE" => "ferrum".to_string();
            mongo_app_name: Option<String> = "FERRUM_MONGO_APP_NAME";
            mongo_replica_set: Option<String> = "FERRUM_MONGO_REPLICA_SET";
            mongo_auth_mechanism: Option<String> = "FERRUM_MONGO_AUTH_MECHANISM";
            mongo_server_selection_timeout_seconds: u64 = "FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS" => 30u64;
            mongo_connect_timeout_seconds: u64 = "FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS" => 10u64;
        }

        env_config! {
            conf = conf, mode = &mode;
            [cp_dp]
            cp_dp_grpc_jwt_secret: Option<String> = "FERRUM_CP_DP_GRPC_JWT_SECRET"
                => required_for(["cp", "dp"]) min_len(crate::config::types::MIN_JWT_SECRET_LENGTH);
            dp_cp_grpc_url: Option<String> = "FERRUM_DP_CP_GRPC_URL";
            dp_cp_grpc_urls: Vec<String> = "FERRUM_DP_CP_GRPC_URLS" => Vec::new();
            dp_cp_failover_primary_retry_secs: u64 = "FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS" => 300u64;
            cp_grpc_tls_cert_path: Option<String> = "FERRUM_CP_GRPC_TLS_CERT_PATH";
            cp_grpc_tls_key_path: Option<String> = "FERRUM_CP_GRPC_TLS_KEY_PATH";
            cp_grpc_tls_client_ca_path: Option<String> = "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH";
            cp_broadcast_channel_capacity: usize = "FERRUM_CP_BROADCAST_CHANNEL_CAPACITY" => 128usize;
            dp_grpc_tls_ca_cert_path: Option<String> = "FERRUM_DP_GRPC_TLS_CA_CERT_PATH";
            dp_grpc_tls_client_cert_path: Option<String> = "FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH";
            dp_grpc_tls_client_key_path: Option<String> = "FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH";
            dp_grpc_tls_no_verify: bool = "FERRUM_DP_GRPC_TLS_NO_VERIFY" => false;
        }

        env_config! {
            conf = conf, mode = &mode;
            [limits]
            max_header_size_bytes: usize = "FERRUM_MAX_HEADER_SIZE_BYTES" => 32_768usize;
            max_single_header_size_bytes: usize = "FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES" => 16_384usize;
            max_header_count: usize = "FERRUM_MAX_HEADER_COUNT" => 100usize;
            max_request_body_size_bytes: usize = "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES" => 10_485_760usize;
            max_response_body_size_bytes: usize = "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES" => 10_485_760usize;
            response_buffer_cutoff_bytes: usize = "FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES" => 65_536usize;
            h2_coalesce_target_bytes: usize = "FERRUM_H2_COALESCE_TARGET_BYTES" => 131_072usize, clamp(16_384usize, 1_048_576usize);
            max_url_length_bytes: usize = "FERRUM_MAX_URL_LENGTH_BYTES" => 8_192usize;
            max_query_params: usize = "FERRUM_MAX_QUERY_PARAMS" => 100usize;
            max_grpc_recv_size_bytes: usize = "FERRUM_MAX_GRPC_RECV_SIZE_BYTES" => 4_194_304usize;
            max_websocket_frame_size_bytes: usize = "FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES" => 16_777_216usize;
            websocket_write_buffer_size: usize = "FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE" => 131_072usize;
            websocket_tunnel_mode: bool = "FERRUM_WEBSOCKET_TUNNEL_MODE" => false;
            max_credentials_per_type: usize = "FERRUM_MAX_CREDENTIALS_PER_TYPE" => 2usize;
            http_header_read_timeout_seconds: u64 = "FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS" => 10u64;
        }

        env_config! {
            conf = conf, mode = &mode;
            [dns]
            dns_resolver_address: Option<String> = "FERRUM_DNS_RESOLVER_ADDRESS";
            dns_resolver_hosts_file: Option<String> = "FERRUM_DNS_RESOLVER_HOSTS_FILE";
            dns_order: Option<String> = "FERRUM_DNS_ORDER";
            dns_ttl_override: Option<u64> = "FERRUM_DNS_TTL_OVERRIDE_SECONDS";
            dns_min_ttl: u64 = "FERRUM_DNS_MIN_TTL_SECONDS" => 5u64;
            dns_stale_ttl: u64 = "FERRUM_DNS_STALE_TTL" => 3600u64;
            dns_error_ttl: u64 = "FERRUM_DNS_ERROR_TTL" => 5u64;
            dns_cache_max_size: usize = "FERRUM_DNS_CACHE_MAX_SIZE" => 10_000usize;
            dns_warmup_concurrency: usize = "FERRUM_DNS_WARMUP_CONCURRENCY" => 500usize, max(1usize);
            dns_slow_threshold_ms: Option<u64> = "FERRUM_DNS_SLOW_THRESHOLD_MS";
            dns_refresh_threshold_percent: u8 = "FERRUM_DNS_REFRESH_THRESHOLD_PERCENT" => 90u8, clamp(1u8, 99u8);
            dns_failed_retry_interval: u64 = "FERRUM_DNS_FAILED_RETRY_INTERVAL_SECONDS" => 10u64;
            dns_try_tcp_on_error: bool = "FERRUM_DNS_TRY_TCP_ON_ERROR" => true;
            dns_num_concurrent_reqs: usize = "FERRUM_DNS_NUM_CONCURRENT_REQS" => 3usize, clamp(1usize, 10usize);
            dns_max_active_requests: usize = "FERRUM_DNS_MAX_ACTIVE_REQUESTS" => 512usize, clamp(1usize, 4096usize);
        }

        env_config! {
            conf = conf, mode = &mode;
            [tls]
            tls_ca_bundle_path: Option<String> = "FERRUM_TLS_CA_BUNDLE_PATH";
            backend_tls_client_cert_path: Option<String> = "FERRUM_BACKEND_TLS_CLIENT_CERT_PATH";
            backend_tls_client_key_path: Option<String> = "FERRUM_BACKEND_TLS_CLIENT_KEY_PATH";
            frontend_tls_client_ca_bundle_path: Option<String> = "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH";
            admin_tls_client_ca_bundle_path: Option<String> = "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH";
            tls_no_verify: bool = "FERRUM_TLS_NO_VERIFY" => false;
            admin_tls_no_verify: bool = "FERRUM_ADMIN_TLS_NO_VERIFY" => false;
            admin_read_only: bool = "FERRUM_ADMIN_READ_ONLY" => false;
            stream_proxy_bind_address: String = "FERRUM_STREAM_PROXY_BIND_ADDRESS" => "0.0.0.0".to_string();
            dtls_cert_path: Option<String> = "FERRUM_DTLS_CERT_PATH";
            dtls_key_path: Option<String> = "FERRUM_DTLS_KEY_PATH";
            dtls_client_ca_cert_path: Option<String> = "FERRUM_DTLS_CLIENT_CA_CERT_PATH";
            dtls_max_plaintext_bytes: usize = "FERRUM_DTLS_MAX_PLAINTEXT_BYTES" => 16_384usize;
            dtls_record_overhead_bytes: usize = "FERRUM_DTLS_RECORD_OVERHEAD_BYTES" => 64usize;
            enable_http3: bool = "FERRUM_ENABLE_HTTP3" => false;
            http3_idle_timeout: u64 = "FERRUM_HTTP3_IDLE_TIMEOUT" => 30u64;
            http3_max_streams: u32 = "FERRUM_HTTP3_MAX_STREAMS" => 1000u32;
            http3_stream_receive_window: u64 = "FERRUM_HTTP3_STREAM_RECEIVE_WINDOW" => 8_388_608u64;
            http3_receive_window: u64 = "FERRUM_HTTP3_RECEIVE_WINDOW" => 33_554_432u64;
            http3_send_window: u64 = "FERRUM_HTTP3_SEND_WINDOW" => 8_388_608u64;
            http3_connections_per_backend: usize = "FERRUM_HTTP3_CONNECTIONS_PER_BACKEND" => 4usize, max(1usize);
            http3_pool_idle_timeout_seconds: u64 = "FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS" => 120u64;
            http3_coalesce_max_bytes: usize = "FERRUM_HTTP3_COALESCE_MAX_BYTES" => crate::http3::config::H3_COALESCE_MAX_DEFAULT, clamp(crate::http3::config::H3_COALESCE_MIN_FLOOR, crate::http3::config::H3_COALESCE_MAX_CAP);
            http3_flush_interval_micros: u64 = "FERRUM_HTTP3_FLUSH_INTERVAL_MICROS" => 200u64, clamp(crate::http3::config::H3_FLUSH_INTERVAL_MIN_MICROS, crate::http3::config::H3_FLUSH_INTERVAL_MAX_MICROS);
            http3_request_body_channel_capacity: usize = "FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY" => 32usize, clamp(1usize, 1024usize);
            h3_request_body_drain_ms: u64 = "FERRUM_H3_REQUEST_BODY_DRAIN_MS" => 50u64, clamp(0u64, 1000u64);
            http3_initial_mtu: u16 = "FERRUM_HTTP3_INITIAL_MTU" => 1500u16;
            grpc_pool_ready_wait_ms: u64 = "FERRUM_GRPC_POOL_READY_WAIT_MS" => 1u64;
            pool_warmup_enabled: bool = "FERRUM_POOL_WARMUP_ENABLED" => true;
            pool_warmup_concurrency: usize = "FERRUM_POOL_WARMUP_CONCURRENCY" => 500usize, max(1usize);
            pool_cleanup_interval_seconds: u64 = "FERRUM_POOL_CLEANUP_INTERVAL_SECONDS" => 30u64;
            backend_capability_refresh_interval_secs: u64 = "FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS" => 86_400u64;
            router_cache_max_entries: usize = "FERRUM_ROUTER_CACHE_MAX_ENTRIES" => 0usize;
            tcp_idle_timeout_seconds: u64 = "FERRUM_TCP_IDLE_TIMEOUT_SECONDS" => 300u64;
            tcp_half_close_max_wait_seconds: u64 = "FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS" => 300u64;
            udp_max_sessions: usize = "FERRUM_UDP_MAX_SESSIONS" => 10_000usize, max(1usize);
            udp_cleanup_interval_seconds: u64 = "FERRUM_UDP_CLEANUP_INTERVAL_SECONDS" => 10u64;
            udp_recvmmsg_batch_size: usize = "FERRUM_UDP_RECVMMSG_BATCH_SIZE" => 64usize, clamp(1usize, 1024usize);
            adaptive_buffer_enabled: bool = "FERRUM_ADAPTIVE_BUFFER_ENABLED" => true;
            adaptive_batch_limit_enabled: bool = "FERRUM_ADAPTIVE_BATCH_LIMIT_ENABLED" => true;
            adaptive_buffer_ewma_alpha: u64 = "FERRUM_ADAPTIVE_BUFFER_EWMA_ALPHA" => 300u64, clamp(1u64, 999u64);
            adaptive_buffer_min_size: usize = "FERRUM_ADAPTIVE_BUFFER_MIN_SIZE" => 8_192usize, clamp(1024usize, 1_048_576usize);
            adaptive_buffer_max_size: usize = "FERRUM_ADAPTIVE_BUFFER_MAX_SIZE" => 262_144usize, clamp(1024usize, 1_048_576usize);
            adaptive_buffer_default_size: usize = "FERRUM_ADAPTIVE_BUFFER_DEFAULT_SIZE" => 65_536usize, clamp(1024usize, 1_048_576usize);
            adaptive_batch_limit_default: usize = "FERRUM_ADAPTIVE_BATCH_LIMIT_DEFAULT" => 6_000usize, max(1usize);
            tls_min_version: String = "FERRUM_TLS_MIN_VERSION" => "1.2".to_string();
            tls_max_version: String = "FERRUM_TLS_MAX_VERSION" => "1.3".to_string();
            tls_cipher_suites: Option<String> = "FERRUM_TLS_CIPHER_SUITES";
            tls_prefer_server_cipher_order: bool = "FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER" => true;
            tls_curves: Option<String> = "FERRUM_TLS_CURVES";
            tls_session_cache_size: usize = "FERRUM_TLS_SESSION_CACHE_SIZE" => 4096usize;
            tls_cert_expiry_warning_days: u64 = "FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS" => 30u64;
        }

        env_config! {
            conf = conf, mode = &mode;
            [client_ip]
            trusted_proxies: String = "FERRUM_TRUSTED_PROXIES" => String::new();
            backend_allow_ips: BackendAllowIps = "FERRUM_BACKEND_ALLOW_IPS" => BackendAllowIps::Both;
            add_via_header: bool = "FERRUM_ADD_VIA_HEADER" => true;
            via_pseudonym: String = "FERRUM_VIA_PSEUDONYM" => "ferrum-edge".to_string();
            add_forwarded_header: bool = "FERRUM_ADD_FORWARDED_HEADER" => false;
            basic_auth_hmac_secret: Option<String> = "FERRUM_BASIC_AUTH_HMAC_SECRET";
            plugin_http_slow_threshold_ms: u64 = "FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS" => 1000u64;
            plugin_http_max_retries: u32 = "FERRUM_PLUGIN_HTTP_MAX_RETRIES" => 0u32;
            plugin_http_retry_delay_ms: u64 = "FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS" => 100u64;
            tls_crl_file_path: Option<String> = "FERRUM_TLS_CRL_FILE_PATH";
            admin_allowed_cidrs: String = "FERRUM_ADMIN_ALLOWED_CIDRS" => String::new();
            admin_restore_max_body_size_mib: usize = "FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB" => 100usize;
            migrate_action: String = "FERRUM_MIGRATE_ACTION" => "up".to_string(), lowercase();
            migrate_dry_run: bool = "FERRUM_MIGRATE_DRY_RUN" => false;
        }

        env_config! {
            conf = conf, mode = &mode;
            [runtime]
            max_connections: usize = "FERRUM_MAX_CONNECTIONS" => 100_000usize;
            max_requests: usize = "FERRUM_MAX_REQUESTS" => 0usize;
            max_concurrent_requests_per_ip: u64 = "FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP" => 0u64;
            per_ip_cleanup_interval_seconds: u64 = "FERRUM_PER_IP_CLEANUP_INTERVAL_SECONDS" => 60u64;
            circuit_breaker_cache_max_entries: usize = "FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES" => 10_000usize;
            status_counts_max_entries: usize = "FERRUM_STATUS_COUNTS_MAX_ENTRIES" => 200usize;
            tcp_listen_backlog: u32 = "FERRUM_TCP_LISTEN_BACKLOG" => 2048u32, max(128u32);
            server_http2_max_concurrent_streams: u32 = "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS" => 1000u32, max(1u32);
            server_http2_max_pending_accept_reset_streams: usize = "FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS" => 64usize, max(1usize);
            server_http2_max_local_error_reset_streams: usize = "FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS" => 256usize, max(1usize);
            websocket_max_connections: usize = "FERRUM_WEBSOCKET_MAX_CONNECTIONS" => 20_000usize;
            overload_check_interval_ms: u64 = "FERRUM_OVERLOAD_CHECK_INTERVAL_MS" => 1000u64, max(100u64);
            overload_fd_pressure_threshold: f64 = "FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD" => 0.80f64, clamp(0.0f64, 1.0f64);
            overload_fd_critical_threshold: f64 = "FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD" => 0.95f64, clamp(0.0f64, 1.0f64);
            overload_conn_pressure_threshold: f64 = "FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD" => 0.85f64, clamp(0.0f64, 1.0f64);
            overload_conn_critical_threshold: f64 = "FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD" => 0.95f64, clamp(0.0f64, 1.0f64);
            overload_req_pressure_threshold: f64 = "FERRUM_OVERLOAD_REQ_PRESSURE_THRESHOLD" => 0.85f64, clamp(0.0f64, 1.0f64);
            overload_req_critical_threshold: f64 = "FERRUM_OVERLOAD_REQ_CRITICAL_THRESHOLD" => 0.95f64, clamp(0.0f64, 1.0f64);
            overload_loop_warn_us: u64 = "FERRUM_OVERLOAD_LOOP_WARN_US" => 10_000u64;
            overload_loop_critical_us: u64 = "FERRUM_OVERLOAD_LOOP_CRITICAL_US" => 500_000u64;
            shutdown_drain_seconds: u64 = "FERRUM_SHUTDOWN_DRAIN_SECONDS" => 30u64;
            status_metrics_window_seconds: u64 = "FERRUM_STATUS_METRICS_WINDOW_SECONDS" => 30u64, max(1u64);
            tls_offload_threads: usize = "FERRUM_TLS_OFFLOAD_THREADS" => 0usize;
            tcp_fastopen_queue_len: u16 = "FERRUM_TCP_FASTOPEN_QUEUE_LEN" => 256u16;
            so_busy_poll_us: u32 = "FERRUM_SO_BUSY_POLL_US" => 0u32;
        }

        // Keep this hand-written: the CP gRPC listener inherits the admin bind
        // address when unset, so the default depends on another parsed field.
        let cp_grpc_listen_addr =
            match env_config_macro::resolve_optional::<String>(conf, "FERRUM_CP_GRPC_LISTEN_ADDR")?
            {
                Some(addr) => Some(addr),
                None if matches!(mode, OperatingMode::ControlPlane) => {
                    Some(format!("{}:50051", admin_bind_address))
                }
                None => None,
            };

        // Keep this hand-written: failover URLs are part of a broader
        // cross-variable validation path (TLS consistency vs. the primary).
        let db_failover_urls =
            env_config_macro::resolve_optional::<Vec<String>>(conf, "FERRUM_DB_FAILOVER_URLS")?
                .unwrap_or_default();

        // Keep this hand-written: 0-RTT methods emit startup warnings/info and
        // normalize each token to uppercase.
        let tls_early_data_methods: HashSet<String> = env_config_macro::resolve_optional::<
            Vec<String>,
        >(
            conf, "FERRUM_TLS_EARLY_DATA_METHODS"
        )?
        .unwrap_or_default()
        .into_iter()
        .map(|method| method.to_ascii_uppercase())
        .filter(|method| !method.is_empty())
        .collect();
        for method in &tls_early_data_methods {
            if method != "GET" {
                tracing::warn!(
                    "FERRUM_TLS_EARLY_DATA_METHODS includes non-GET method '{}' — \
                     0-RTT early data is replayable, which is dangerous for \
                     non-idempotent operations",
                    method
                );
            }
        }
        if !tls_early_data_methods.is_empty() {
            tracing::info!(
                "TLS 1.3 0-RTT early data enabled for methods: {:?}",
                tls_early_data_methods
            );
        }

        // Keep this hand-written: the value is pre-lowercased at load time so
        // request handling can avoid allocating on every lookup.
        let real_ip_header =
            env_config_macro::resolve_optional::<String>(conf, "FERRUM_REAL_IP_HEADER")?
                .map(|header| header.to_ascii_lowercase());

        // Keep these hand-written: optional runtime tunables clamp only when
        // set, and accept_threads has an `auto` runtime probe fallback.
        let worker_threads =
            env_config_macro::resolve_optional::<usize>(conf, "FERRUM_WORKER_THREADS")?
                .map(|threads| threads.max(1));
        let blocking_threads =
            env_config_macro::resolve_optional::<usize>(conf, "FERRUM_BLOCKING_THREADS")?
                .map(|threads| threads.max(1));
        let accept_threads_raw =
            env_config_macro::resolve_default::<usize, _>(conf, "FERRUM_ACCEPT_THREADS", || {
                0usize
            })?;
        let accept_threads = if accept_threads_raw == 0 {
            std::thread::available_parallelism()
                .map(|parallelism| parallelism.get())
                .unwrap_or(1)
        } else {
            accept_threads_raw
        };

        // Keep these hand-written: `auto` probe toggles deliberately stay out
        // of the macro escape hatch so their startup semantics remain obvious.
        let tcp_fastopen_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_TCP_FASTOPEN_ENABLED",
            || AutoBool::Auto,
        )?;
        let ktls_enabled =
            env_config_macro::resolve_default::<AutoBool, _>(conf, "FERRUM_KTLS_ENABLED", || {
                AutoBool::Auto
            })?;
        let io_uring_splice_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_IO_URING_SPLICE_ENABLED",
            || AutoBool::Auto,
        )?;
        let udp_gro_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_UDP_GRO_ENABLED",
            || AutoBool::Auto,
        )?;
        let udp_gso_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_UDP_GSO_ENABLED",
            || AutoBool::Auto,
        )?;
        let udp_pktinfo_enabled = env_config_macro::resolve_default::<AutoBool, _>(
            conf,
            "FERRUM_UDP_PKTINFO_ENABLED",
            || AutoBool::Auto,
        )?;

        // `http3_coalesce_min_bytes` depends on the runtime-parsed
        // `http3_coalesce_max_bytes`, so it lives outside the macro block.
        let http3_coalesce_min_bytes: usize = {
            let raw: usize =
                env_config_macro::resolve_default(conf, "FERRUM_HTTP3_COALESCE_MIN_BYTES", || {
                    crate::http3::config::H3_COALESCE_MAX_DEFAULT
                })?;
            let clamped = raw.clamp(
                crate::http3::config::H3_COALESCE_MIN_FLOOR,
                http3_coalesce_max_bytes,
            );
            if raw > http3_coalesce_max_bytes {
                tracing::warn!(
                    "FERRUM_HTTP3_COALESCE_MIN_BYTES={} exceeds FERRUM_HTTP3_COALESCE_MAX_BYTES={}; clamping MIN to MAX",
                    raw,
                    http3_coalesce_max_bytes,
                );
            }
            clamped
        };

        let config = Self {
            mode: mode.clone(),
            namespace,
            log_level,
            log_buffer_capacity,
            enable_streaming_latency_tracking,
            proxy_http_port,
            proxy_https_port,
            frontend_tls_cert_path,
            frontend_tls_key_path,
            proxy_bind_address,
            admin_http_port,
            admin_https_port,
            admin_tls_cert_path,
            admin_tls_key_path,
            admin_bind_address,
            admin_jwt_secret,
            admin_jwt_issuer,
            admin_jwt_max_ttl,
            db_type,
            db_url,
            db_poll_interval,
            db_tls_enabled,
            db_tls_ca_cert_path,
            db_tls_client_cert_path,
            db_tls_client_key_path,
            db_tls_insecure,
            db_ssl_mode,
            db_ssl_root_cert,
            db_ssl_client_cert,
            db_ssl_client_key,
            file_config_path,
            db_config_backup_path,
            db_failover_urls,
            db_read_replica_url,
            db_slow_query_threshold_ms,
            db_pool_max_connections,
            db_pool_min_connections,
            db_pool_acquire_timeout_seconds,
            db_pool_idle_timeout_seconds,
            db_pool_max_lifetime_seconds,
            db_pool_connect_timeout_seconds,
            db_pool_statement_timeout_seconds,
            mongo_database,
            mongo_app_name,
            mongo_replica_set,
            mongo_auth_mechanism,
            mongo_server_selection_timeout_seconds,
            mongo_connect_timeout_seconds,
            cp_grpc_listen_addr,
            cp_dp_grpc_jwt_secret,
            dp_cp_grpc_url,
            dp_cp_grpc_urls,
            dp_cp_failover_primary_retry_secs,
            cp_grpc_tls_cert_path,
            cp_grpc_tls_key_path,
            cp_grpc_tls_client_ca_path,
            cp_broadcast_channel_capacity,
            dp_grpc_tls_ca_cert_path,
            dp_grpc_tls_client_cert_path,
            dp_grpc_tls_client_key_path,
            dp_grpc_tls_no_verify,
            max_header_size_bytes,
            max_single_header_size_bytes,
            max_header_count,
            max_request_body_size_bytes,
            max_response_body_size_bytes,
            response_buffer_cutoff_bytes,
            h2_coalesce_target_bytes,
            max_url_length_bytes,
            max_query_params,
            max_grpc_recv_size_bytes,
            max_websocket_frame_size_bytes,
            websocket_write_buffer_size,
            websocket_tunnel_mode,
            max_credentials_per_type,
            http_header_read_timeout_seconds,
            dns_overrides,
            dns_resolver_address,
            dns_resolver_hosts_file,
            dns_order,
            dns_ttl_override,
            dns_min_ttl,
            dns_stale_ttl,
            dns_error_ttl,
            dns_cache_max_size,
            dns_warmup_concurrency,
            dns_slow_threshold_ms,
            dns_refresh_threshold_percent,
            dns_failed_retry_interval,
            dns_try_tcp_on_error,
            dns_num_concurrent_reqs,
            dns_max_active_requests,
            tls_ca_bundle_path,
            backend_tls_client_cert_path,
            backend_tls_client_key_path,
            frontend_tls_client_ca_bundle_path,
            admin_tls_client_ca_bundle_path,
            tls_no_verify,
            admin_read_only,
            admin_tls_no_verify,
            enable_http3,
            http3_idle_timeout,
            http3_max_streams,
            http3_stream_receive_window,
            http3_receive_window,
            http3_send_window,
            http3_connections_per_backend,
            http3_pool_idle_timeout_seconds,
            http3_coalesce_min_bytes,
            http3_coalesce_max_bytes,
            http3_flush_interval_micros,
            http3_request_body_channel_capacity,
            h3_request_body_drain_ms,
            http3_initial_mtu,
            grpc_pool_ready_wait_ms,
            pool_warmup_enabled,
            pool_warmup_concurrency,
            pool_cleanup_interval_seconds,
            backend_capability_refresh_interval_secs,
            router_cache_max_entries,
            tcp_idle_timeout_seconds,
            tcp_half_close_max_wait_seconds,
            udp_max_sessions,
            udp_cleanup_interval_seconds,
            udp_recvmmsg_batch_size,
            adaptive_buffer_enabled,
            adaptive_batch_limit_enabled,
            adaptive_buffer_ewma_alpha,
            adaptive_buffer_min_size,
            adaptive_buffer_max_size,
            adaptive_buffer_default_size,
            adaptive_batch_limit_default,
            tls_min_version,
            tls_max_version,
            tls_cipher_suites,
            tls_prefer_server_cipher_order,
            tls_curves,
            tls_session_cache_size,
            tls_cert_expiry_warning_days,
            tls_early_data_methods,
            stream_proxy_bind_address,
            dtls_cert_path,
            dtls_key_path,
            dtls_client_ca_cert_path,
            dtls_max_plaintext_bytes,
            dtls_record_overhead_bytes,
            trusted_proxies,
            backend_allow_ips,
            add_via_header,
            via_pseudonym,
            add_forwarded_header,
            real_ip_header,
            basic_auth_hmac_secret,
            plugin_http_slow_threshold_ms,
            plugin_http_max_retries,
            plugin_http_retry_delay_ms,
            tls_crl_file_path,
            admin_allowed_cidrs,
            admin_restore_max_body_size_mib,
            migrate_action,
            migrate_dry_run,
            worker_threads,
            blocking_threads,
            max_connections,
            max_requests,
            max_concurrent_requests_per_ip,
            per_ip_cleanup_interval_seconds,
            circuit_breaker_cache_max_entries,
            status_counts_max_entries,
            tcp_listen_backlog,
            accept_threads,
            server_http2_max_concurrent_streams,
            server_http2_max_pending_accept_reset_streams,
            server_http2_max_local_error_reset_streams,
            websocket_max_connections,
            overload_check_interval_ms,
            overload_fd_pressure_threshold,
            overload_fd_critical_threshold,
            overload_conn_pressure_threshold,
            overload_conn_critical_threshold,
            overload_req_pressure_threshold,
            overload_req_critical_threshold,
            overload_loop_warn_us,
            overload_loop_critical_us,
            shutdown_drain_seconds,
            status_metrics_window_seconds,
            tls_offload_threads,
            tcp_fastopen_enabled,
            tcp_fastopen_queue_len,
            ktls_enabled,
            io_uring_splice_enabled,
            udp_gro_enabled,
            udp_gso_enabled,
            udp_pktinfo_enabled,
            so_busy_poll_us,
        };

        config.validate()?;
        Ok(config)
    }

    /// Build a `SocketAddr` from the proxy bind address and the given port.
    /// The bind address is validated at config load time, so the parse is safe.
    /// Build an [`OverloadConfig`] from the parsed env vars.
    pub fn overload_config(&self) -> crate::overload::OverloadConfig {
        crate::overload::OverloadConfig {
            check_interval_ms: self.overload_check_interval_ms,
            fd_pressure_threshold: self.overload_fd_pressure_threshold,
            fd_critical_threshold: self.overload_fd_critical_threshold,
            conn_pressure_threshold: self.overload_conn_pressure_threshold,
            conn_critical_threshold: self.overload_conn_critical_threshold,
            req_pressure_threshold: self.overload_req_pressure_threshold,
            req_critical_threshold: self.overload_req_critical_threshold,
            loop_warn_us: self.overload_loop_warn_us,
            loop_critical_us: self.overload_loop_critical_us,
        }
    }

    pub fn proxy_socket_addr(&self, port: u16) -> std::net::SocketAddr {
        let ip: std::net::IpAddr = self
            .proxy_bind_address
            .parse()
            .expect("proxy_bind_address validated at config load");
        std::net::SocketAddr::new(ip, port)
    }

    /// Build a `SocketAddr` from the admin bind address and the given port.
    pub fn admin_socket_addr(&self, port: u16) -> std::net::SocketAddr {
        let ip: std::net::IpAddr = self
            .admin_bind_address
            .parse()
            .expect("admin_bind_address validated at config load");
        std::net::SocketAddr::new(ip, port)
    }

    /// Returns the resolved list of CP gRPC URLs for DP failover, priority-ordered.
    ///
    /// `FERRUM_DP_CP_GRPC_URLS` takes precedence. Falls back to
    /// `FERRUM_DP_CP_GRPC_URL` as a single-element list.
    pub fn resolved_dp_cp_grpc_urls(&self) -> Vec<String> {
        if !self.dp_cp_grpc_urls.is_empty() {
            self.dp_cp_grpc_urls.clone()
        } else if let Some(ref url) = self.dp_cp_grpc_url {
            vec![url.clone()]
        } else {
            Vec::new()
        }
    }

    /// Collect all ports reserved by the gateway's own listeners.
    ///
    /// Stream proxy `listen_port` values must not collide with these ports.
    /// Includes proxy HTTP/HTTPS, admin HTTP/HTTPS, and CP gRPC (when configured).
    pub fn reserved_gateway_ports(&self) -> std::collections::HashSet<u16> {
        let mut ports = std::collections::HashSet::new();
        // Port 0 means "disabled" — skip it so stream proxy validation
        // doesn't treat 0 as a reserved conflict.
        for &p in &[
            self.proxy_http_port,
            self.proxy_https_port,
            self.admin_http_port,
            self.admin_https_port,
        ] {
            if p != 0 {
                ports.insert(p);
            }
        }
        // CP gRPC listen address is "host:port" — extract the port if present.
        if let Some(ref addr) = self.cp_grpc_listen_addr
            && let Some(port_str) = addr.rsplit(':').next()
            && let Ok(port) = port_str.parse::<u16>()
        {
            ports.insert(port);
        }
        ports
    }

    /// Returns the database URL with TLS/SSL query parameters appended based on
    /// the `FERRUM_DB_SSL_*` environment variables. For PostgreSQL and MySQL, the
    /// SSL settings are translated into the appropriate connection string parameters.
    /// SQLite URLs are returned unchanged (no network TLS).
    pub fn effective_db_url(&self) -> Option<String> {
        let base_url = self.db_url.as_ref()?;
        let db_type = self.db_type.as_deref().unwrap_or("");

        // SQLite has no network TLS
        if db_type == "sqlite" {
            return Some(base_url.clone());
        }

        let has_ssl_params = self.db_ssl_mode.is_some()
            || self.db_ssl_root_cert.is_some()
            || self.db_ssl_client_cert.is_some()
            || self.db_ssl_client_key.is_some();

        if !has_ssl_params {
            return Some(base_url.clone());
        }

        let mut params: Vec<String> = Vec::new();

        match db_type {
            "postgres" => {
                if let Some(ref mode) = self.db_ssl_mode {
                    params.push(format!("sslmode={}", mode));
                }
                if let Some(ref cert) = self.db_ssl_root_cert {
                    params.push(format!("sslrootcert={}", cert));
                }
                if let Some(ref cert) = self.db_ssl_client_cert {
                    params.push(format!("sslcert={}", cert));
                }
                if let Some(ref key) = self.db_ssl_client_key {
                    params.push(format!("sslkey={}", key));
                }
            }
            "mysql" => {
                if let Some(ref mode) = self.db_ssl_mode {
                    // MySQL uses uppercase mode values
                    let mysql_mode = match mode.as_str() {
                        "disable" => "DISABLED",
                        "prefer" => "PREFERRED",
                        "require" => "REQUIRED",
                        "verify-ca" => "VERIFY_CA",
                        "verify-full" => "VERIFY_IDENTITY",
                        other => other,
                    };
                    params.push(format!("ssl-mode={}", mysql_mode));
                }
                if let Some(ref cert) = self.db_ssl_root_cert {
                    params.push(format!("ssl-ca={}", cert));
                }
                if let Some(ref cert) = self.db_ssl_client_cert {
                    params.push(format!("ssl-cert={}", cert));
                }
                if let Some(ref key) = self.db_ssl_client_key {
                    params.push(format!("ssl-key={}", key));
                }
            }
            _ => {
                return Some(base_url.clone());
            }
        }

        if params.is_empty() {
            return Some(base_url.clone());
        }

        let separator = if base_url.contains('?') { "&" } else { "?" };
        Some(format!("{}{}{}", base_url, separator, params.join("&")))
    }

    /// Returns the read replica URL with TLS/SSL query parameters appended,
    /// using the same logic as `effective_db_url()`.
    pub fn effective_db_read_replica_url(&self) -> Option<String> {
        let base_url = self.db_read_replica_url.as_ref()?;
        let db_type = self.db_type.as_deref().unwrap_or("");

        // SQLite has no network TLS
        if db_type == "sqlite" {
            return Some(base_url.clone());
        }

        let has_ssl_params = self.db_ssl_mode.is_some()
            || self.db_ssl_root_cert.is_some()
            || self.db_ssl_client_cert.is_some()
            || self.db_ssl_client_key.is_some();

        if !has_ssl_params {
            return Some(base_url.clone());
        }

        let mut params: Vec<String> = Vec::new();

        match db_type {
            "postgres" => {
                if let Some(ref mode) = self.db_ssl_mode {
                    params.push(format!("sslmode={}", mode));
                }
                if let Some(ref cert) = self.db_ssl_root_cert {
                    params.push(format!("sslrootcert={}", cert));
                }
                if let Some(ref cert) = self.db_ssl_client_cert {
                    params.push(format!("sslcert={}", cert));
                }
                if let Some(ref key) = self.db_ssl_client_key {
                    params.push(format!("sslkey={}", key));
                }
            }
            "mysql" => {
                if let Some(ref mode) = self.db_ssl_mode {
                    let mysql_mode = match mode.as_str() {
                        "disable" => "DISABLED",
                        "prefer" => "PREFERRED",
                        "require" => "REQUIRED",
                        "verify-ca" => "VERIFY_CA",
                        "verify-full" => "VERIFY_IDENTITY",
                        other => other,
                    };
                    params.push(format!("ssl-mode={}", mysql_mode));
                }
                if let Some(ref cert) = self.db_ssl_root_cert {
                    params.push(format!("ssl-ca={}", cert));
                }
                if let Some(ref cert) = self.db_ssl_client_cert {
                    params.push(format!("ssl-cert={}", cert));
                }
                if let Some(ref key) = self.db_ssl_client_key {
                    params.push(format!("ssl-key={}", key));
                }
            }
            _ => {
                return Some(base_url.clone());
            }
        }

        if params.is_empty() {
            return Some(base_url.clone());
        }

        let separator = if base_url.contains('?') { "&" } else { "?" };
        Some(format!("{}{}{}", base_url, separator, params.join("&")))
    }

    /// Returns the failover database URLs with TLS/SSL query parameters appended,
    /// using the same logic as `effective_db_url()`.
    pub fn effective_db_failover_urls(&self) -> Vec<String> {
        let db_type = self.db_type.as_deref().unwrap_or("");

        self.db_failover_urls
            .iter()
            .map(|base_url| {
                // SQLite has no network TLS
                if db_type == "sqlite" {
                    return base_url.clone();
                }

                let has_ssl_params = self.db_ssl_mode.is_some()
                    || self.db_ssl_root_cert.is_some()
                    || self.db_ssl_client_cert.is_some()
                    || self.db_ssl_client_key.is_some();

                if !has_ssl_params {
                    return base_url.clone();
                }

                let mut params: Vec<String> = Vec::new();

                match db_type {
                    "postgres" => {
                        if let Some(ref mode) = self.db_ssl_mode {
                            params.push(format!("sslmode={}", mode));
                        }
                        if let Some(ref cert) = self.db_ssl_root_cert {
                            params.push(format!("sslrootcert={}", cert));
                        }
                        if let Some(ref cert) = self.db_ssl_client_cert {
                            params.push(format!("sslcert={}", cert));
                        }
                        if let Some(ref key) = self.db_ssl_client_key {
                            params.push(format!("sslkey={}", key));
                        }
                    }
                    "mysql" => {
                        if let Some(ref mode) = self.db_ssl_mode {
                            let mysql_mode = match mode.as_str() {
                                "disable" => "DISABLED",
                                "prefer" => "PREFERRED",
                                "require" => "REQUIRED",
                                "verify-ca" => "VERIFY_CA",
                                "verify-full" => "VERIFY_IDENTITY",
                                other => other,
                            };
                            params.push(format!("ssl-mode={}", mysql_mode));
                        }
                        if let Some(ref cert) = self.db_ssl_root_cert {
                            params.push(format!("ssl-ca={}", cert));
                        }
                        if let Some(ref cert) = self.db_ssl_client_cert {
                            params.push(format!("ssl-cert={}", cert));
                        }
                        if let Some(ref key) = self.db_ssl_client_key {
                            params.push(format!("ssl-key={}", key));
                        }
                    }
                    _ => {
                        return base_url.clone();
                    }
                }

                if params.is_empty() {
                    return base_url.clone();
                }

                let separator = if base_url.contains('?') { "&" } else { "?" };
                format!("{}{}{}", base_url, separator, params.join("&"))
            })
            .collect()
    }

    fn validate(&self) -> Result<(), String> {
        match &self.mode {
            OperatingMode::Database | OperatingMode::ControlPlane => {
                if self.db_type.is_none() {
                    return Err("FERRUM_DB_TYPE is required in database/cp mode".into());
                }
                if self.db_url.is_none() {
                    return Err("FERRUM_DB_URL is required in database/cp mode".into());
                }
            }
            OperatingMode::File => {
                if self.file_config_path.is_none() {
                    return Err("FERRUM_FILE_CONFIG_PATH is required in file mode".into());
                }
            }
            OperatingMode::DataPlane => {
                if self.dp_cp_grpc_url.is_none() && self.dp_cp_grpc_urls.is_empty() {
                    return Err(
                        "FERRUM_DP_CP_GRPC_URL or FERRUM_DP_CP_GRPC_URLS is required in dp mode"
                            .into(),
                    );
                }
            }
            OperatingMode::Migrate => {
                // Migrate mode: validation depends on FERRUM_MIGRATE_ACTION.
                // For "config", FERRUM_FILE_CONFIG_PATH is required.
                // For "up" and "status", FERRUM_DB_TYPE and FERRUM_DB_URL are required.
                match self.migrate_action.as_str() {
                    "config" => {
                        if self.file_config_path.is_none() {
                            return Err(
                                "FERRUM_FILE_CONFIG_PATH is required for migrate config action"
                                    .into(),
                            );
                        }
                    }
                    "up" | "status" => {
                        if self.db_type.is_none() {
                            return Err(
                                "FERRUM_DB_TYPE is required for migrate up/status action".into()
                            );
                        }
                        if self.db_url.is_none() {
                            return Err(
                                "FERRUM_DB_URL is required for migrate up/status action".into()
                            );
                        }
                    }
                    other => {
                        return Err(format!(
                            "Invalid FERRUM_MIGRATE_ACTION '{}'. Expected: up, status, config",
                            other
                        ));
                    }
                }
            }
        }

        // Validate namespace
        crate::config::types::validate_namespace(&self.namespace)
            .map_err(|e| format!("Invalid FERRUM_NAMESPACE: {}", e))?;

        // Validate TLS version settings
        match self.tls_min_version.as_str() {
            "1.2" | "1.3" => {}
            other => {
                return Err(format!(
                    "Invalid FERRUM_TLS_MIN_VERSION '{}'. Expected: 1.2, 1.3",
                    other
                ));
            }
        }
        match self.tls_max_version.as_str() {
            "1.2" | "1.3" => {}
            other => {
                return Err(format!(
                    "Invalid FERRUM_TLS_MAX_VERSION '{}'. Expected: 1.2, 1.3",
                    other
                ));
            }
        }
        if self.tls_min_version == "1.3" && self.tls_max_version == "1.2" {
            return Err(
                "FERRUM_TLS_MIN_VERSION (1.3) cannot be greater than FERRUM_TLS_MAX_VERSION (1.2)"
                    .into(),
            );
        }

        if self.mode == OperatingMode::ControlPlane {
            assert!(
                self.cp_grpc_listen_addr.is_some(),
                "cp_grpc_listen_addr is populated during from_env_with_conf()"
            );
        }

        // Validate bind addresses are valid IP addresses
        if self.proxy_bind_address.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "Invalid FERRUM_PROXY_BIND_ADDRESS '{}'. Expected a valid IP address (e.g., 0.0.0.0 or ::)",
                self.proxy_bind_address
            ));
        }
        if self.admin_bind_address.parse::<std::net::IpAddr>().is_err() {
            return Err(format!(
                "Invalid FERRUM_ADMIN_BIND_ADDRESS '{}'. Expected a valid IP address (e.g., 0.0.0.0 or ::)",
                self.admin_bind_address
            ));
        }

        // Validate global backend TLS cert/key files exist and are parseable
        match (
            &self.backend_tls_client_cert_path,
            &self.backend_tls_client_key_path,
        ) {
            (Some(_), None) => {
                return Err(
                    "FERRUM_BACKEND_TLS_CLIENT_CERT_PATH is set but FERRUM_BACKEND_TLS_CLIENT_KEY_PATH is missing — both must be configured together".into(),
                );
            }
            (None, Some(_)) => {
                return Err(
                    "FERRUM_BACKEND_TLS_CLIENT_KEY_PATH is set but FERRUM_BACKEND_TLS_CLIENT_CERT_PATH is missing — both must be configured together".into(),
                );
            }
            _ => {}
        }
        if let Some(ref path) = self.backend_tls_client_cert_path {
            crate::config::types::validate_pem_cert_file(
                "FERRUM_BACKEND_TLS_CLIENT_CERT_PATH",
                path,
            )
            .map_err(|e| e.to_string())?;
        }
        if let Some(ref path) = self.backend_tls_client_key_path {
            crate::config::types::validate_pem_key_file("FERRUM_BACKEND_TLS_CLIENT_KEY_PATH", path)
                .map_err(|e| e.to_string())?;
        }
        if let Some(ref path) = self.tls_ca_bundle_path {
            crate::config::types::validate_pem_cert_file("FERRUM_TLS_CA_BUNDLE_PATH", path)
                .map_err(|e| e.to_string())?;
        }

        if self.http3_initial_mtu < crate::http3::config::QUIC_INITIAL_MTU_MIN
            || self.http3_initial_mtu > crate::http3::config::QUIC_INITIAL_MTU_MAX
        {
            return Err(format!(
                "FERRUM_HTTP3_INITIAL_MTU ({}) is outside quinn's legal range [{}, {}]",
                self.http3_initial_mtu,
                crate::http3::config::QUIC_INITIAL_MTU_MIN,
                crate::http3::config::QUIC_INITIAL_MTU_MAX,
            ));
        }

        // Non-fatal security warnings
        if self.tls_no_verify {
            eprintln!(
                "WARNING: FERRUM_TLS_NO_VERIFY=true — outbound TLS certificate verification is DISABLED. Do not use in production."
            );
        }
        if self.admin_tls_no_verify {
            eprintln!(
                "WARNING: FERRUM_ADMIN_TLS_NO_VERIFY=true — admin TLS certificate verification is DISABLED. Do not use in production."
            );
        }
        if self.dp_grpc_tls_no_verify {
            eprintln!(
                "WARNING: FERRUM_DP_GRPC_TLS_NO_VERIFY=true — gRPC TLS certificate verification is DISABLED. Do not use in production."
            );
        }

        Ok(())
    }
}
