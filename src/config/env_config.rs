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
    pub fn from_env() -> Result<Self, String> {
        match env::var("FERRUM_MODE")
            .unwrap_or_default()
            .to_lowercase()
            .as_str()
        {
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

    // Proxy traffic ports
    pub proxy_http_port: u16,
    pub proxy_https_port: u16,
    pub proxy_tls_cert_path: Option<String>,
    pub proxy_tls_key_path: Option<String>,

    // Admin API ports
    pub admin_http_port: u16,
    pub admin_https_port: u16,
    pub admin_tls_cert_path: Option<String>,
    pub admin_tls_key_path: Option<String>,

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

    // CP/DP
    pub cp_grpc_listen_addr: Option<String>,
    pub cp_grpc_jwt_secret: Option<String>,
    pub dp_cp_grpc_url: Option<String>,
    pub dp_grpc_auth_token: Option<String>,

    // Request/Response limits
    pub max_header_size_bytes: usize,
    pub max_single_header_size_bytes: usize,
    pub max_body_size_bytes: usize,
    pub max_response_body_size_bytes: usize,

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
    /// Threshold in milliseconds above which DNS resolutions are logged as slow. Default: disabled
    pub dns_slow_threshold_ms: Option<u64>,

    /// Path to a PEM file containing trusted CA certificates for backend TLS verification
    pub backend_tls_ca_bundle_path: Option<String>,
    /// Path to a PEM file containing the client certificate for backend TLS verification
    pub backend_tls_client_cert_path: Option<String>,
    /// Path to a PEM file containing the client key for backend TLS verification
    pub backend_tls_client_key_path: Option<String>,
    /// Path to a PEM file containing trusted CA certificates for client certificate verification
    pub frontend_tls_client_ca_bundle_path: Option<String>,

    /// Admin API TLS client CA bundle for mTLS verification
    pub admin_tls_client_ca_bundle_path: Option<String>,
    /// Disable backend TLS certificate verification (for testing only)
    pub backend_tls_no_verify: bool,
    /// Admin API read-only mode (default: false, always true in DP mode)
    pub admin_read_only: bool,
    /// Disable admin TLS certificate verification (for testing only)
    pub admin_tls_no_verify: bool,

    // HTTP/3 / QUIC
    /// Enable HTTP/3 listener (default: false)
    pub enable_http3: bool,
    /// HTTP/3 idle timeout in seconds (default: 30)
    pub http3_idle_timeout: u64,
    /// HTTP/3 max concurrent streams (default: 100)
    pub http3_max_streams: u32,

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

    // Stream proxy (TCP/UDP)
    /// Bind address for TCP/UDP stream proxy listeners (default: 0.0.0.0).
    #[allow(dead_code)] // Used in Phase 2 (stream listener startup)
    pub stream_proxy_bind_address: String,

    // DTLS frontend certificates (ECDSA P-256 or Ed25519 required)
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
    /// When a plugin HTTP request (e.g. http_logging, oauth2 introspection,
    /// JWKS fetch, OTLP export) exceeds this duration, a warning is logged.
    /// Default: 1000 (1 second).
    pub plugin_http_slow_threshold_ms: u64,
}

impl Default for EnvConfig {
    fn default() -> Self {
        Self {
            mode: OperatingMode::File,
            log_level: "error".into(),
            enable_streaming_latency_tracking: false,
            proxy_http_port: 8000,
            proxy_https_port: 8443,
            proxy_tls_cert_path: None,
            proxy_tls_key_path: None,
            admin_http_port: 9000,
            admin_https_port: 9443,
            admin_tls_cert_path: None,
            admin_tls_key_path: None,
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
            cp_grpc_listen_addr: None,
            cp_grpc_jwt_secret: None,
            dp_cp_grpc_url: None,
            dp_grpc_auth_token: None,
            max_header_size_bytes: 32_768,
            max_single_header_size_bytes: 16_384,
            max_body_size_bytes: 10_485_760,
            max_response_body_size_bytes: 10_485_760,
            dns_cache_ttl_seconds: 300,
            dns_overrides: HashMap::new(),
            dns_resolver_address: None,
            dns_resolver_hosts_file: None,
            dns_order: None,
            dns_valid_ttl: None,
            dns_stale_ttl: 3600,
            dns_error_ttl: 1,
            dns_cache_max_size: 10_000,
            dns_slow_threshold_ms: None,
            backend_tls_ca_bundle_path: None,
            backend_tls_client_cert_path: None,
            backend_tls_client_key_path: None,
            frontend_tls_client_ca_bundle_path: None,
            admin_tls_client_ca_bundle_path: None,
            backend_tls_no_verify: false,
            admin_read_only: false,
            admin_tls_no_verify: false,
            stream_proxy_bind_address: "0.0.0.0".into(),
            dtls_cert_path: None,
            dtls_key_path: None,
            dtls_client_ca_cert_path: None,
            enable_http3: false,
            http3_idle_timeout: 30,
            http3_max_streams: 100,
            tls_min_version: "1.2".into(),
            tls_max_version: "1.3".into(),
            tls_cipher_suites: None,
            tls_prefer_server_cipher_order: true,
            tls_curves: None,
            trusted_proxies: String::new(),
            real_ip_header: None,
            plugin_http_slow_threshold_ms: 1000,
        }
    }
}

impl EnvConfig {
    pub fn from_env() -> Result<Self, String> {
        let mode = OperatingMode::from_env()?;

        let dns_overrides: HashMap<String, String> = env::var("FERRUM_DNS_OVERRIDES")
            .ok()
            .and_then(|s| serde_json::from_str(&s).ok())
            .unwrap_or_default();

        let config = Self {
            mode: mode.clone(),
            log_level: env::var("FERRUM_LOG_LEVEL").unwrap_or_else(|_| "error".into()),
            enable_streaming_latency_tracking: env::var("FERRUM_ENABLE_STREAMING_LATENCY_TRACKING")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),

            proxy_http_port: parse_env_u16("FERRUM_PROXY_HTTP_PORT", 8000),
            proxy_https_port: parse_env_u16("FERRUM_PROXY_HTTPS_PORT", 8443),
            proxy_tls_cert_path: env::var("FERRUM_PROXY_TLS_CERT_PATH").ok(),
            proxy_tls_key_path: env::var("FERRUM_PROXY_TLS_KEY_PATH").ok(),

            admin_http_port: parse_env_u16("FERRUM_ADMIN_HTTP_PORT", 9000),
            admin_https_port: parse_env_u16("FERRUM_ADMIN_HTTPS_PORT", 9443),
            admin_tls_cert_path: env::var("FERRUM_ADMIN_TLS_CERT_PATH").ok(),
            admin_tls_key_path: env::var("FERRUM_ADMIN_TLS_KEY_PATH").ok(),
            admin_jwt_secret: env::var("FERRUM_ADMIN_JWT_SECRET").ok(),
            db_type: env::var("FERRUM_DB_TYPE").ok(),
            db_url: env::var("FERRUM_DB_URL").ok(),
            db_poll_interval: parse_env_u64("FERRUM_DB_POLL_INTERVAL", 30),
            db_tls_enabled: env::var("FERRUM_DB_TLS_ENABLED").unwrap_or_default() == "true",
            db_tls_ca_cert_path: env::var("FERRUM_DB_TLS_CA_CERT_PATH").ok(),
            db_tls_client_cert_path: env::var("FERRUM_DB_TLS_CLIENT_CERT_PATH").ok(),
            db_tls_client_key_path: env::var("FERRUM_DB_TLS_CLIENT_KEY_PATH").ok(),
            db_tls_insecure: env::var("FERRUM_DB_TLS_INSECURE").unwrap_or_default() == "true",

            // Database TLS/SSL
            db_ssl_mode: env::var("FERRUM_DB_SSL_MODE").ok(),
            db_ssl_root_cert: env::var("FERRUM_DB_SSL_ROOT_CERT").ok(),
            db_ssl_client_cert: env::var("FERRUM_DB_SSL_CLIENT_CERT").ok(),
            db_ssl_client_key: env::var("FERRUM_DB_SSL_CLIENT_KEY").ok(),

            file_config_path: env::var("FERRUM_FILE_CONFIG_PATH").ok(),
            db_config_backup_path: env::var("FERRUM_DB_CONFIG_BACKUP_PATH").ok(),

            cp_grpc_listen_addr: env::var("FERRUM_CP_GRPC_LISTEN_ADDR").ok(),
            cp_grpc_jwt_secret: env::var("FERRUM_CP_GRPC_JWT_SECRET").ok(),
            dp_cp_grpc_url: env::var("FERRUM_DP_CP_GRPC_URL").ok(),
            dp_grpc_auth_token: env::var("FERRUM_DP_GRPC_AUTH_TOKEN").ok(),

            max_header_size_bytes: parse_env_usize("FERRUM_MAX_HEADER_SIZE_BYTES", 32_768),
            max_single_header_size_bytes: parse_env_usize(
                "FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES",
                16_384,
            ),
            max_body_size_bytes: parse_env_usize("FERRUM_MAX_BODY_SIZE_BYTES", 10_485_760),
            max_response_body_size_bytes: parse_env_usize(
                "FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES",
                10_485_760,
            ),

            dns_cache_ttl_seconds: parse_env_u64("FERRUM_DNS_CACHE_TTL_SECONDS", 300),
            dns_overrides,
            dns_resolver_address: env::var("FERRUM_DNS_RESOLVER_ADDRESS").ok(),
            dns_resolver_hosts_file: env::var("FERRUM_DNS_RESOLVER_HOSTS_FILE").ok(),
            dns_order: env::var("FERRUM_DNS_ORDER").ok(),
            dns_valid_ttl: env::var("FERRUM_DNS_VALID_TTL")
                .ok()
                .and_then(|v| v.parse().ok()),
            dns_stale_ttl: parse_env_u64("FERRUM_DNS_STALE_TTL", 3600),
            dns_error_ttl: parse_env_u64("FERRUM_DNS_ERROR_TTL", 1),
            dns_cache_max_size: env::var("FERRUM_DNS_CACHE_MAX_SIZE")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(10_000),
            dns_slow_threshold_ms: env::var("FERRUM_DNS_SLOW_THRESHOLD_MS")
                .ok()
                .and_then(|v| v.parse().ok()),

            // Global Backend mTLS
            backend_tls_ca_bundle_path: env::var("FERRUM_BACKEND_TLS_CA_BUNDLE_PATH").ok(),
            backend_tls_client_cert_path: env::var("FERRUM_BACKEND_TLS_CLIENT_CERT_PATH").ok(),
            backend_tls_client_key_path: env::var("FERRUM_BACKEND_TLS_CLIENT_KEY_PATH").ok(),

            // Global Frontend mTLS (client certificate verification)
            frontend_tls_client_ca_bundle_path: env::var(
                "FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH",
            )
            .ok(),

            // Admin API TLS enhancements
            admin_tls_client_ca_bundle_path: env::var("FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH")
                .ok(),
            backend_tls_no_verify: env::var("FERRUM_BACKEND_TLS_NO_VERIFY").unwrap_or_default()
                == "true",
            admin_tls_no_verify: env::var("FERRUM_ADMIN_TLS_NO_VERIFY").unwrap_or_default()
                == "true",
            admin_read_only: env::var("FERRUM_ADMIN_READ_ONLY").unwrap_or_default() == "true",
            stream_proxy_bind_address: env::var("FERRUM_STREAM_PROXY_BIND_ADDRESS")
                .unwrap_or_else(|_| "0.0.0.0".into()),
            dtls_cert_path: env::var("FERRUM_DTLS_CERT_PATH").ok(),
            dtls_key_path: env::var("FERRUM_DTLS_KEY_PATH").ok(),
            dtls_client_ca_cert_path: env::var("FERRUM_DTLS_CLIENT_CA_CERT_PATH").ok(),

            // HTTP/3 / QUIC
            enable_http3: env::var("FERRUM_ENABLE_HTTP3").unwrap_or_default() == "true",
            http3_idle_timeout: parse_env_u64("FERRUM_HTTP3_IDLE_TIMEOUT", 30),
            http3_max_streams: env::var("FERRUM_HTTP3_MAX_STREAMS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),

            // TLS Hardening
            tls_min_version: env::var("FERRUM_TLS_MIN_VERSION").unwrap_or_else(|_| "1.2".into()),
            tls_max_version: env::var("FERRUM_TLS_MAX_VERSION").unwrap_or_else(|_| "1.3".into()),
            tls_cipher_suites: env::var("FERRUM_TLS_CIPHER_SUITES").ok(),
            tls_prefer_server_cipher_order: env::var("FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER")
                .map(|v| v == "true")
                .unwrap_or(true),
            tls_curves: env::var("FERRUM_TLS_CURVES").ok(),

            // Client IP resolution
            trusted_proxies: env::var("FERRUM_TRUSTED_PROXIES").unwrap_or_default(),
            // Pre-lowercase at load time so the hot path avoids per-request
            // to_lowercase() allocation when looking up this header in ctx.headers
            // (which stores hyper's already-lowercased header names).
            real_ip_header: env::var("FERRUM_REAL_IP_HEADER")
                .ok()
                .map(|h| h.to_lowercase()),

            plugin_http_slow_threshold_ms: parse_env_u64(
                "FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS",
                1000,
            ),
        };

        config.validate()?;
        Ok(config)
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
                let action = std::env::var("FERRUM_MIGRATE_ACTION")
                    .unwrap_or_else(|_| "up".into())
                    .to_lowercase();
                match action.as_str() {
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

        Ok(())
    }
}

fn parse_env_u16(key: &str, default: u16) -> u16 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn parse_env_usize(key: &str, default: usize) -> usize {
    env::var(key)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}
