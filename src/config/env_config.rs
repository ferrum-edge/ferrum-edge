use std::collections::HashMap;
use std::env;

/// The operating mode of the gateway.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OperatingMode {
    Database,
    File,
    ControlPlane,
    DataPlane,
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
            other => Err(format!(
                "Invalid FERRUM_MODE '{}'. Expected: database, file, cp, dp",
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
    pub db_poll_check_interval: u64,
    pub db_incremental_polling: bool,

    // File mode
    pub file_config_path: Option<String>,

    // CP/DP
    pub cp_grpc_listen_addr: Option<String>,
    pub cp_grpc_jwt_secret: Option<String>,
    pub dp_cp_grpc_url: Option<String>,
    pub dp_grpc_auth_token: Option<String>,

    // Request limits
    pub max_header_size_bytes: usize,
    pub max_body_size_bytes: usize,

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
            log_level: env::var("FERRUM_LOG_LEVEL").unwrap_or_else(|_| "info".into()),

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
            db_poll_check_interval: parse_env_u64("FERRUM_DB_POLL_CHECK_INTERVAL", 5),
            db_incremental_polling: env::var("FERRUM_DB_INCREMENTAL_POLLING")
                .map(|v| v != "false")
                .unwrap_or(true),

            file_config_path: env::var("FERRUM_FILE_CONFIG_PATH").ok(),

            cp_grpc_listen_addr: env::var("FERRUM_CP_GRPC_LISTEN_ADDR").ok(),
            cp_grpc_jwt_secret: env::var("FERRUM_CP_GRPC_JWT_SECRET").ok(),
            dp_cp_grpc_url: env::var("FERRUM_DP_CP_GRPC_URL").ok(),
            dp_grpc_auth_token: env::var("FERRUM_DP_GRPC_AUTH_TOKEN").ok(),

            max_header_size_bytes: parse_env_usize("FERRUM_MAX_HEADER_SIZE_BYTES", 16384),
            max_body_size_bytes: parse_env_usize("FERRUM_MAX_BODY_SIZE_BYTES", 10_485_760),

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

            // Global Backend mTLS
            backend_tls_ca_bundle_path: env::var("FERRUM_BACKEND_TLS_CA_BUNDLE_PATH").ok(),
            backend_tls_client_cert_path: env::var("FERRUM_BACKEND_TLS_CLIENT_CERT_PATH").ok(),
            backend_tls_client_key_path: env::var("FERRUM_BACKEND_TLS_CLIENT_KEY_PATH").ok(),
            
            // Global Frontend mTLS (client certificate verification)
            frontend_tls_client_ca_bundle_path: env::var("FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH").ok(),
            
            // Admin API TLS enhancements
            admin_tls_client_ca_bundle_path: env::var("FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH").ok(),
            backend_tls_no_verify: env::var("FERRUM_BACKEND_TLS_NO_VERIFY").unwrap_or_default() == "true",
            admin_tls_no_verify: env::var("FERRUM_ADMIN_TLS_NO_VERIFY").unwrap_or_default() == "true",
            admin_read_only: env::var("FERRUM_ADMIN_READ_ONLY").unwrap_or_default() == "true",

            // HTTP/3 / QUIC
            enable_http3: env::var("FERRUM_ENABLE_HTTP3").unwrap_or_default() == "true",
            http3_idle_timeout: parse_env_u64("FERRUM_HTTP3_IDLE_TIMEOUT", 30),
            http3_max_streams: env::var("FERRUM_HTTP3_MAX_STREAMS")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(100),
        };

        config.validate()?;
        Ok(config)
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
