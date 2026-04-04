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
use std::collections::HashMap;
use std::env;

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

/// Resolve a configuration value with a default fallback.
fn resolve_var_or(conf: &ConfFile, key: &str, default: &str) -> String {
    resolve_var(conf, key).unwrap_or_else(|| default.to_string())
}

/// Resolve a bool configuration value ("true" or "1").
fn resolve_bool(conf: &ConfFile, key: &str, default: bool) -> bool {
    resolve_var(conf, key)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(default)
}

/// All environment-driven configuration.
#[derive(Debug, Clone)]
pub struct EnvConfig {
    pub mode: OperatingMode,
    pub log_level: String,
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

    // CP/DP
    pub cp_grpc_listen_addr: Option<String>,
    pub cp_grpc_jwt_secret: Option<String>,
    pub dp_cp_grpc_url: Option<String>,
    pub dp_grpc_auth_token: Option<String>,

    // CP gRPC TLS (server-side)
    /// Path to PEM certificate for the CP gRPC server. When set (with key),
    /// the gRPC listener uses TLS instead of plaintext.
    pub cp_grpc_tls_cert_path: Option<String>,
    /// Path to PEM private key for the CP gRPC server.
    pub cp_grpc_tls_key_path: Option<String>,
    /// Path to PEM CA bundle for verifying DP client certificates (mTLS).
    /// When set, the CP requires and verifies client certificates from DPs.
    pub cp_grpc_tls_client_ca_path: Option<String>,

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
    /// Maximum URL length in bytes (path + query string). 0 = unlimited.
    pub max_url_length_bytes: usize,
    /// Maximum number of query parameters allowed. 0 = unlimited.
    pub max_query_params: usize,
    /// Maximum gRPC message size in bytes (applies to both send and receive). 0 = unlimited.
    pub max_grpc_message_size_bytes: usize,
    /// Maximum WebSocket frame size in bytes. Applied to both client and backend connections.
    pub max_websocket_frame_size_bytes: usize,

    // DNS
    pub dns_cache_ttl_seconds: u64,
    pub dns_overrides: HashMap<String, String>,
    /// Comma-separated nameserver addresses (ip[:port], IPv4 or IPv6).
    /// Default: parsed from /etc/resolv.conf
    pub dns_resolver_address: Option<String>,
    /// Path to hosts file. Default: /etc/hosts (system default)
    pub dns_resolver_hosts_file: Option<String>,
    /// Order of record types to query (comma-separated, case-insensitive).
    /// Valid values: CACHE, SRV, A, AAAA, CNAME. Default: "CACHE,SRV,A,CNAME"
    pub dns_order: Option<String>,
    /// Override TTL (seconds) for positive DNS records. Default: use response TTL
    pub dns_valid_ttl: Option<u64>,
    /// Stale data usage time (seconds) during refresh. Default: 3600
    pub dns_stale_ttl: u64,
    /// TTL (seconds) for errors/empty responses. Default: 1
    pub dns_error_ttl: u64,
    /// Maximum number of entries in the DNS cache. Default: 10000
    pub dns_cache_max_size: usize,
    /// Maximum number of concurrent DNS warmup resolutions. Default: 500.
    pub dns_warmup_concurrency: usize,
    /// Threshold in milliseconds above which DNS resolutions are logged as slow. Default: disabled
    pub dns_slow_threshold_ms: Option<u64>,

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
    /// Milliseconds the gRPC backend pool waits on a saturated HTTP/2 sender
    /// for a free stream before opening a fresh connection (default: 1).
    /// Lower values reduce queueing for unary gRPC under load. Set to 0 to
    /// skip the wait and open a new backend connection immediately.
    pub grpc_pool_ready_wait_ms: u64,

    // Connection pool cleanup
    /// Interval in seconds between connection pool cleanup sweeps (default: 30).
    /// Applies to HTTP, gRPC, HTTP/2, and HTTP/3 connection pools.
    pub pool_cleanup_interval_seconds: u64,

    // TCP proxy
    /// Default TCP idle timeout in seconds (default: 300 / 5 min).
    /// Per-proxy `tcp_idle_timeout_seconds` overrides this. Set to 0 to disable.
    pub tcp_idle_timeout_seconds: u64,

    // UDP proxy
    /// Maximum concurrent UDP sessions per proxy (default: 10000).
    pub udp_max_sessions: usize,
    /// UDP session cleanup interval in seconds (default: 10).
    pub udp_cleanup_interval_seconds: u64,

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
    /// TLS 1.3 uses stateless tickets (unlimited) so this only affects TLS 1.2 clients.
    /// (default: 4096)
    pub tls_session_cache_size: usize,
    /// Number of days before certificate expiration to emit a warning log.
    /// Expired certificates are rejected at startup/config-load time.
    /// Set to 0 to disable near-expiry warnings. (default: 30)
    pub tls_cert_expiry_warning_days: u64,

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

    // Client IP resolution
    /// Comma-separated trusted proxy CIDRs/IPs for X-Forwarded-For resolution.
    /// When set, the gateway walks the XFF chain right-to-left, skipping trusted
    /// proxy IPs, to determine the real client IP. When unset, the TCP socket
    /// address is always used (secure default for edge deployments).
    /// Example: "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,::1"
    pub trusted_proxies: String,
    /// Header to use as the authoritative source of client IP. When set, this
    /// header is checked first (e.g., "CF-Connecting-IP" for Cloudflare, or
    /// "X-Real-IP" for nginx). If the header is absent or the direct connection
    /// is not from a trusted proxy, falls back to the X-Forwarded-For walk.
    pub real_ip_header: Option<String>,

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
    /// TCP listen backlog size for proxy listeners. Default: 2048.
    /// Higher values absorb connection bursts without SYN drops.
    pub tcp_listen_backlog: u32,
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
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            mode: OperatingMode::File,
            log_level: "error".into(),
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
            cp_grpc_listen_addr: None,
            cp_grpc_jwt_secret: None,
            dp_cp_grpc_url: None,
            dp_grpc_auth_token: None,
            cp_grpc_tls_cert_path: None,
            cp_grpc_tls_key_path: None,
            cp_grpc_tls_client_ca_path: None,
            dp_grpc_tls_ca_cert_path: None,
            dp_grpc_tls_client_cert_path: None,
            dp_grpc_tls_client_key_path: None,
            dp_grpc_tls_no_verify: false,
            max_header_size_bytes: 32_768,
            max_single_header_size_bytes: 16_384,
            max_header_count: 100,
            max_request_body_size_bytes: 10_485_760,
            max_response_body_size_bytes: 10_485_760,
            max_url_length_bytes: 8_192,
            max_query_params: 100,
            max_grpc_message_size_bytes: 4_194_304,
            max_websocket_frame_size_bytes: 16_777_216,
            dns_cache_ttl_seconds: 300,
            dns_overrides: HashMap::new(),
            dns_resolver_address: None,
            dns_resolver_hosts_file: None,
            dns_order: None,
            dns_valid_ttl: None,
            dns_stale_ttl: 3600,
            dns_error_ttl: 5,
            dns_cache_max_size: 10_000,
            dns_warmup_concurrency: 500,
            dns_slow_threshold_ms: None,
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
            enable_http3: false,
            http3_idle_timeout: 30,
            http3_max_streams: 1000,
            http3_stream_receive_window: 8_388_608, // 8 MiB
            http3_receive_window: 33_554_432,       // 32 MiB
            http3_send_window: 8_388_608,           // 8 MiB
            http3_connections_per_backend: 4,
            http3_pool_idle_timeout_seconds: 120,
            grpc_pool_ready_wait_ms: 1,
            pool_cleanup_interval_seconds: 30,
            tcp_idle_timeout_seconds: 300,
            udp_max_sessions: 10_000,
            udp_cleanup_interval_seconds: 10,
            tls_min_version: "1.2".into(),
            tls_max_version: "1.3".into(),
            tls_cipher_suites: None,
            tls_prefer_server_cipher_order: true,
            tls_curves: None,
            tls_session_cache_size: 4096,
            tls_cert_expiry_warning_days: 30,
            trusted_proxies: String::new(),
            real_ip_header: None,
            plugin_http_slow_threshold_ms: 1000,
            plugin_http_max_retries: 0,
            plugin_http_retry_delay_ms: 100,
            admin_restore_max_body_size_mib: 100,
            migrate_action: "up".into(),
            migrate_dry_run: false,
            worker_threads: None,
            blocking_threads: None,
            max_connections: 100_000,
            tcp_listen_backlog: 2048,
            server_http2_max_concurrent_streams: 1000,
            server_http2_max_pending_accept_reset_streams: 64,
            server_http2_max_local_error_reset_streams: 256,
            websocket_max_connections: 20_000,
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

        let dns_overrides: HashMap<String, String> = resolve_var(conf, "FERRUM_DNS_OVERRIDES")
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let config = Self {
            mode: mode.clone(),
            log_level: resolve_var_or(conf, "FERRUM_LOG_LEVEL", "error"),
            enable_streaming_latency_tracking: resolve_bool(
                conf,
                "FERRUM_ENABLE_STREAMING_LATENCY_TRACKING",
                false,
            ),

            proxy_http_port: resolve_u16(conf, "FERRUM_PROXY_HTTP_PORT", 8000),
            proxy_https_port: resolve_u16(conf, "FERRUM_PROXY_HTTPS_PORT", 8443),
            frontend_tls_cert_path: resolve_var(conf, "FERRUM_FRONTEND_TLS_CERT_PATH"),
            frontend_tls_key_path: resolve_var(conf, "FERRUM_FRONTEND_TLS_KEY_PATH"),
            proxy_bind_address: resolve_var_or(conf, "FERRUM_PROXY_BIND_ADDRESS", "0.0.0.0"),

            admin_http_port: resolve_u16(conf, "FERRUM_ADMIN_HTTP_PORT", 9000),
            admin_https_port: resolve_u16(conf, "FERRUM_ADMIN_HTTPS_PORT", 9443),
            admin_tls_cert_path: resolve_var(conf, "FERRUM_ADMIN_TLS_CERT_PATH"),
            admin_tls_key_path: resolve_var(conf, "FERRUM_ADMIN_TLS_KEY_PATH"),
            admin_bind_address: resolve_var_or(conf, "FERRUM_ADMIN_BIND_ADDRESS", "0.0.0.0"),
            admin_jwt_secret: resolve_var(conf, "FERRUM_ADMIN_JWT_SECRET"),
            db_type: resolve_var(conf, "FERRUM_DB_TYPE"),
            db_url: resolve_var(conf, "FERRUM_DB_URL"),
            db_poll_interval: resolve_u64(conf, "FERRUM_DB_POLL_INTERVAL", 30),
            db_tls_enabled: resolve_bool(conf, "FERRUM_DB_TLS_ENABLED", false),
            db_tls_ca_cert_path: resolve_var(conf, "FERRUM_DB_TLS_CA_CERT_PATH"),
            db_tls_client_cert_path: resolve_var(conf, "FERRUM_DB_TLS_CLIENT_CERT_PATH"),
            db_tls_client_key_path: resolve_var(conf, "FERRUM_DB_TLS_CLIENT_KEY_PATH"),
            db_tls_insecure: resolve_bool(conf, "FERRUM_DB_TLS_INSECURE", false),

            // Database TLS/SSL
            db_ssl_mode: resolve_var(conf, "FERRUM_DB_SSL_MODE"),
            db_ssl_root_cert: resolve_var(conf, "FERRUM_DB_SSL_ROOT_CERT"),
            db_ssl_client_cert: resolve_var(conf, "FERRUM_DB_SSL_CLIENT_CERT"),
            db_ssl_client_key: resolve_var(conf, "FERRUM_DB_SSL_CLIENT_KEY"),

            file_config_path: resolve_var(conf, "FERRUM_FILE_CONFIG_PATH"),
            db_config_backup_path: resolve_var(conf, "FERRUM_DB_CONFIG_BACKUP_PATH"),
            db_failover_urls: resolve_var(conf, "FERRUM_DB_FAILOVER_URLS")
                .map(|s| {
                    s.split(',')
                        .map(|u| u.trim().to_string())
                        .filter(|u| !u.is_empty())
                        .collect()
                })
                .unwrap_or_default(),
            db_read_replica_url: resolve_var(conf, "FERRUM_DB_READ_REPLICA_URL"),

            db_slow_query_threshold_ms: resolve_var(conf, "FERRUM_DB_SLOW_QUERY_THRESHOLD_MS")
                .and_then(|v| v.parse().ok()),

            // Database connection pool tuning
            db_pool_max_connections: resolve_var(conf, "FERRUM_DB_POOL_MAX_CONNECTIONS")
                .and_then(|v| v.parse().ok())
                .map(|v: u32| v.max(1))
                .unwrap_or(10),
            db_pool_min_connections: resolve_var(conf, "FERRUM_DB_POOL_MIN_CONNECTIONS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1),
            db_pool_acquire_timeout_seconds: resolve_u64(
                conf,
                "FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS",
                30,
            ),
            db_pool_idle_timeout_seconds: resolve_u64(
                conf,
                "FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS",
                600,
            ),
            db_pool_max_lifetime_seconds: resolve_u64(
                conf,
                "FERRUM_DB_POOL_MAX_LIFETIME_SECONDS",
                300,
            ),

            cp_grpc_listen_addr: resolve_var(conf, "FERRUM_CP_GRPC_LISTEN_ADDR"),
            cp_grpc_jwt_secret: resolve_var(conf, "FERRUM_CP_GRPC_JWT_SECRET"),
            dp_cp_grpc_url: resolve_var(conf, "FERRUM_DP_CP_GRPC_URL"),
            dp_grpc_auth_token: resolve_var(conf, "FERRUM_DP_GRPC_AUTH_TOKEN"),

            // CP gRPC TLS
            cp_grpc_tls_cert_path: resolve_var(conf, "FERRUM_CP_GRPC_TLS_CERT_PATH"),
            cp_grpc_tls_key_path: resolve_var(conf, "FERRUM_CP_GRPC_TLS_KEY_PATH"),
            cp_grpc_tls_client_ca_path: resolve_var(conf, "FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH"),

            // DP gRPC TLS
            dp_grpc_tls_ca_cert_path: resolve_var(conf, "FERRUM_DP_GRPC_TLS_CA_CERT_PATH"),
            dp_grpc_tls_client_cert_path: resolve_var(conf, "FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH"),
            dp_grpc_tls_client_key_path: resolve_var(conf, "FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH"),
            dp_grpc_tls_no_verify: resolve_bool(conf, "FERRUM_DP_GRPC_TLS_NO_VERIFY", false),

            max_header_size_bytes: resolve_usize(conf, "FERRUM_MAX_HEADER_SIZE_BYTES", 32_768),
            max_single_header_size_bytes: resolve_usize(
                conf,
                "FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES",
                16_384,
            ),
            max_header_count: resolve_usize(conf, "FERRUM_MAX_HEADER_COUNT", 100),
            max_request_body_size_bytes: resolve_usize(
                conf,
                "FERRUM_MAX_REQUEST_BODY_SIZE_BYTES",
                10_485_760,
            ),
            max_response_body_size_bytes: resolve_usize(
                conf,
                "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES",
                10_485_760,
            ),
            max_url_length_bytes: resolve_usize(conf, "FERRUM_MAX_URL_LENGTH_BYTES", 8_192),
            max_query_params: resolve_usize(conf, "FERRUM_MAX_QUERY_PARAMS", 100),
            max_grpc_message_size_bytes: resolve_usize(
                conf,
                "FERRUM_MAX_GRPC_MESSAGE_SIZE_BYTES",
                4_194_304,
            ),
            max_websocket_frame_size_bytes: resolve_usize(
                conf,
                "FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES",
                16_777_216,
            ),

            dns_cache_ttl_seconds: resolve_u64(conf, "FERRUM_DNS_CACHE_TTL_SECONDS", 300),
            dns_overrides,
            dns_resolver_address: resolve_var(conf, "FERRUM_DNS_RESOLVER_ADDRESS"),
            dns_resolver_hosts_file: resolve_var(conf, "FERRUM_DNS_RESOLVER_HOSTS_FILE"),
            dns_order: resolve_var(conf, "FERRUM_DNS_ORDER"),
            dns_valid_ttl: resolve_var(conf, "FERRUM_DNS_VALID_TTL").and_then(|v| v.parse().ok()),
            dns_stale_ttl: resolve_u64(conf, "FERRUM_DNS_STALE_TTL", 3600),
            dns_error_ttl: resolve_u64(conf, "FERRUM_DNS_ERROR_TTL", 5),
            dns_cache_max_size: resolve_var(conf, "FERRUM_DNS_CACHE_MAX_SIZE")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000),
            dns_warmup_concurrency: resolve_var(conf, "FERRUM_DNS_WARMUP_CONCURRENCY")
                .and_then(|v| v.parse().ok())
                .unwrap_or(500)
                .max(1),
            dns_slow_threshold_ms: resolve_var(conf, "FERRUM_DNS_SLOW_THRESHOLD_MS")
                .and_then(|v| v.parse().ok()),

            // Global TLS trust store and mTLS
            tls_ca_bundle_path: resolve_var(conf, "FERRUM_TLS_CA_BUNDLE_PATH"),
            backend_tls_client_cert_path: resolve_var(conf, "FERRUM_BACKEND_TLS_CLIENT_CERT_PATH"),
            backend_tls_client_key_path: resolve_var(conf, "FERRUM_BACKEND_TLS_CLIENT_KEY_PATH"),

            // Global Frontend mTLS (client certificate verification)
            frontend_tls_client_ca_bundle_path: resolve_var(
                conf,
                "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH",
            ),

            // Admin API TLS enhancements
            admin_tls_client_ca_bundle_path: resolve_var(
                conf,
                "FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH",
            ),
            tls_no_verify: resolve_bool(conf, "FERRUM_TLS_NO_VERIFY", false),
            admin_tls_no_verify: resolve_bool(conf, "FERRUM_ADMIN_TLS_NO_VERIFY", false),
            admin_read_only: resolve_bool(conf, "FERRUM_ADMIN_READ_ONLY", false),
            stream_proxy_bind_address: resolve_var_or(
                conf,
                "FERRUM_STREAM_PROXY_BIND_ADDRESS",
                "0.0.0.0",
            ),
            dtls_cert_path: resolve_var(conf, "FERRUM_DTLS_CERT_PATH"),
            dtls_key_path: resolve_var(conf, "FERRUM_DTLS_KEY_PATH"),
            dtls_client_ca_cert_path: resolve_var(conf, "FERRUM_DTLS_CLIENT_CA_CERT_PATH"),

            // HTTP/3 / QUIC
            enable_http3: resolve_bool(conf, "FERRUM_ENABLE_HTTP3", false),
            http3_idle_timeout: resolve_u64(conf, "FERRUM_HTTP3_IDLE_TIMEOUT", 30),
            http3_max_streams: resolve_var(conf, "FERRUM_HTTP3_MAX_STREAMS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(1000),
            http3_stream_receive_window: resolve_u64(
                conf,
                "FERRUM_HTTP3_STREAM_RECEIVE_WINDOW",
                8_388_608,
            ),
            http3_receive_window: resolve_u64(conf, "FERRUM_HTTP3_RECEIVE_WINDOW", 33_554_432),
            http3_send_window: resolve_u64(conf, "FERRUM_HTTP3_SEND_WINDOW", 8_388_608),
            http3_connections_per_backend: resolve_var(
                conf,
                "FERRUM_HTTP3_CONNECTIONS_PER_BACKEND",
            )
            .and_then(|v| v.parse().ok())
            .unwrap_or(4)
            .max(1),
            http3_pool_idle_timeout_seconds: resolve_u64(
                conf,
                "FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS",
                120,
            ),
            grpc_pool_ready_wait_ms: resolve_u64(conf, "FERRUM_GRPC_POOL_READY_WAIT_MS", 1),

            // Connection pool cleanup
            pool_cleanup_interval_seconds: resolve_u64(
                conf,
                "FERRUM_POOL_CLEANUP_INTERVAL_SECONDS",
                30,
            ),

            // TCP proxy
            tcp_idle_timeout_seconds: resolve_u64(conf, "FERRUM_TCP_IDLE_TIMEOUT_SECONDS", 300),

            // UDP proxy
            udp_max_sessions: resolve_var(conf, "FERRUM_UDP_MAX_SESSIONS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000)
                .max(1),
            udp_cleanup_interval_seconds: resolve_u64(
                conf,
                "FERRUM_UDP_CLEANUP_INTERVAL_SECONDS",
                10,
            ),

            // TLS Hardening
            tls_min_version: resolve_var_or(conf, "FERRUM_TLS_MIN_VERSION", "1.2"),
            tls_max_version: resolve_var_or(conf, "FERRUM_TLS_MAX_VERSION", "1.3"),
            tls_cipher_suites: resolve_var(conf, "FERRUM_TLS_CIPHER_SUITES"),
            tls_prefer_server_cipher_order: resolve_var(
                conf,
                "FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER",
            )
            .map(|v| v == "true")
            .unwrap_or(true),
            tls_curves: resolve_var(conf, "FERRUM_TLS_CURVES"),
            tls_session_cache_size: resolve_usize(conf, "FERRUM_TLS_SESSION_CACHE_SIZE", 4096),
            tls_cert_expiry_warning_days: resolve_u64(
                conf,
                "FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS",
                30,
            ),

            // Client IP resolution
            trusted_proxies: resolve_var_or(conf, "FERRUM_TRUSTED_PROXIES", ""),
            // Pre-lowercase at load time so the hot path avoids per-request
            // to_lowercase() allocation when looking up this header in ctx.headers
            // (which stores hyper's already-lowercased header names).
            real_ip_header: resolve_var(conf, "FERRUM_REAL_IP_HEADER").map(|h| h.to_lowercase()),

            plugin_http_slow_threshold_ms: resolve_u64(
                conf,
                "FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS",
                1000,
            ),
            plugin_http_max_retries: resolve_var(conf, "FERRUM_PLUGIN_HTTP_MAX_RETRIES")
                .and_then(|v| v.parse::<u32>().ok())
                .unwrap_or(0),
            plugin_http_retry_delay_ms: resolve_u64(conf, "FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS", 100),

            admin_restore_max_body_size_mib: resolve_usize(
                conf,
                "FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB",
                100,
            ),
            migrate_action: resolve_var_or(conf, "FERRUM_MIGRATE_ACTION", "up").to_lowercase(),
            migrate_dry_run: resolve_bool(conf, "FERRUM_MIGRATE_DRY_RUN", false),
            worker_threads: resolve_var(conf, "FERRUM_WORKER_THREADS")
                .and_then(|v| v.parse().ok())
                .map(|v: usize| v.max(1)),
            blocking_threads: resolve_var(conf, "FERRUM_BLOCKING_THREADS")
                .and_then(|v| v.parse().ok())
                .map(|v: usize| v.max(1)),
            max_connections: resolve_var(conf, "FERRUM_MAX_CONNECTIONS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(100_000),
            tcp_listen_backlog: resolve_var(conf, "FERRUM_TCP_LISTEN_BACKLOG")
                .and_then(|v| v.parse().ok())
                .map(|v: u32| v.max(128))
                .unwrap_or(2048),
            server_http2_max_concurrent_streams: resolve_var(
                conf,
                "FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS",
            )
            .and_then(|v| v.parse().ok())
            .map(|v: u32| v.max(1))
            .unwrap_or(1000),
            server_http2_max_pending_accept_reset_streams: resolve_var(
                conf,
                "FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS",
            )
            .and_then(|v| v.parse().ok())
            .map(|v: usize| v.max(1))
            .unwrap_or(64),
            server_http2_max_local_error_reset_streams: resolve_var(
                conf,
                "FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS",
            )
            .and_then(|v| v.parse().ok())
            .map(|v: usize| v.max(1))
            .unwrap_or(256),
            websocket_max_connections: resolve_var(conf, "FERRUM_WEBSOCKET_MAX_CONNECTIONS")
                .and_then(|v| v.parse().ok())
                .unwrap_or(20_000),
        };

        config.validate()?;
        Ok(config)
    }

    /// Build a `SocketAddr` from the proxy bind address and the given port.
    /// The bind address is validated at config load time, so the parse is safe.
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

    /// Collect all ports reserved by the gateway's own listeners.
    ///
    /// Stream proxy `listen_port` values must not collide with these ports.
    /// Includes proxy HTTP/HTTPS, admin HTTP/HTTPS, and CP gRPC (when configured).
    pub fn reserved_gateway_ports(&self) -> std::collections::HashSet<u16> {
        let mut ports = std::collections::HashSet::new();
        ports.insert(self.proxy_http_port);
        ports.insert(self.proxy_https_port);
        ports.insert(self.admin_http_port);
        ports.insert(self.admin_https_port);
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
                if self.admin_jwt_secret.is_none() {
                    return Err("FERRUM_ADMIN_JWT_SECRET is required in database/cp mode".into());
                }
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
                if self.dp_cp_grpc_url.is_none() {
                    return Err("FERRUM_DP_CP_GRPC_URL is required in dp mode".into());
                }
                if self.dp_grpc_auth_token.is_none() {
                    return Err("FERRUM_DP_GRPC_AUTH_TOKEN is required in dp mode".into());
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
            if self.cp_grpc_listen_addr.is_none() {
                return Err("FERRUM_CP_GRPC_LISTEN_ADDR is required in cp mode".into());
            }
            if self.cp_grpc_jwt_secret.is_none() {
                return Err("FERRUM_CP_GRPC_JWT_SECRET is required in cp mode".into());
            }
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

fn resolve_u16(conf: &ConfFile, key: &str, default: u16) -> u16 {
    resolve_var(conf, key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn resolve_u64(conf: &ConfFile, key: &str, default: u64) -> u64 {
    resolve_var(conf, key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn resolve_usize(conf: &ConfFile, key: &str, default: usize) -> usize {
    resolve_var(conf, key)
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
