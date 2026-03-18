//! Tests for environment configuration loading and validation.
//!
//! These tests mutate process-global environment variables, so they MUST run serially.
//! We use `serial_test` via a simple mutex to enforce this.

use ferrum_gateway::config::{EnvConfig, OperatingMode};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper to set env vars, run a closure, then clean them up.
/// Holds a mutex to prevent concurrent env var mutations.
fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    for (k, v) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe { std::env::set_var(k, v); }
    }
    f();
    for (k, _) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe { std::env::remove_var(k); }
    }
}

/// Helper to remove an env var (must be called inside with_env_vars or while holding ENV_LOCK).
fn remove_var(key: &str) {
    // SAFETY: Called within with_env_vars which holds ENV_LOCK.
    unsafe { std::env::remove_var(key); }
}

#[test]
fn test_operating_mode_database() {
    with_env_vars(&[("FERRUM_MODE", "database")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::Database);
    });
}

#[test]
fn test_operating_mode_file() {
    with_env_vars(&[("FERRUM_MODE", "file")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::File);
    });
}

#[test]
fn test_operating_mode_cp() {
    with_env_vars(&[("FERRUM_MODE", "cp")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::ControlPlane);
    });
}

#[test]
fn test_operating_mode_dp() {
    with_env_vars(&[("FERRUM_MODE", "dp")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::DataPlane);
    });
}

#[test]
fn test_operating_mode_invalid() {
    with_env_vars(&[("FERRUM_MODE", "invalid")], || {
        let result = OperatingMode::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("Invalid FERRUM_MODE"));
    });
}

#[test]
fn test_operating_mode_case_insensitive() {
    with_env_vars(&[("FERRUM_MODE", "DATABASE")], || {
        let mode = OperatingMode::from_env().unwrap();
        assert_eq!(mode, OperatingMode::Database);
    });
}

#[test]
fn test_env_config_file_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/to/config.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::File);
            assert_eq!(config.file_config_path, Some("/path/to/config.yaml".to_string()));
        },
    );
}

#[test]
fn test_env_config_file_mode_missing_path() {
    with_env_vars(&[("FERRUM_MODE", "file")], || {
        remove_var("FERRUM_FILE_CONFIG_PATH");
        let result = EnvConfig::from_env();
        assert!(result.is_err());
        assert!(result.unwrap_err().contains("FERRUM_FILE_CONFIG_PATH"));
    });
}

#[test]
fn test_env_config_database_mode_missing_jwt() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
        ],
        || {
            remove_var("FERRUM_ADMIN_JWT_SECRET");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_ADMIN_JWT_SECRET"));
        },
    );
}

#[test]
fn test_env_config_database_mode_missing_db_type() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_ADMIN_JWT_SECRET", "secret"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
        ],
        || {
            remove_var("FERRUM_DB_TYPE");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_DB_TYPE"));
        },
    );
}

#[test]
fn test_env_config_database_mode_missing_db_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_ADMIN_JWT_SECRET", "secret"),
            ("FERRUM_DB_TYPE", "sqlite"),
        ],
        || {
            remove_var("FERRUM_DB_URL");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_DB_URL"));
        },
    );
}

#[test]
fn test_env_config_dp_mode_missing_grpc_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_GRPC_AUTH_TOKEN", "token"),
        ],
        || {
            remove_var("FERRUM_DP_CP_GRPC_URL");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_DP_CP_GRPC_URL"));
        },
    );
}

#[test]
fn test_env_config_dp_mode_missing_auth_token() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
        ],
        || {
            remove_var("FERRUM_DP_GRPC_AUTH_TOKEN");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_DP_GRPC_AUTH_TOKEN"));
        },
    );
}

#[test]
fn test_env_config_cp_mode_missing_grpc_listen() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            ("FERRUM_ADMIN_JWT_SECRET", "secret"),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
            ("FERRUM_CP_GRPC_JWT_SECRET", "grpc-secret"),
        ],
        || {
            remove_var("FERRUM_CP_GRPC_LISTEN_ADDR");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_CP_GRPC_LISTEN_ADDR"));
        },
    );
}

#[test]
fn test_env_config_cp_mode_missing_grpc_jwt_secret() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            ("FERRUM_ADMIN_JWT_SECRET", "secret"),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
        ],
        || {
            remove_var("FERRUM_CP_GRPC_JWT_SECRET");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_CP_GRPC_JWT_SECRET"));
        },
    );
}

#[test]
fn test_env_config_default_ports() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_PROXY_HTTP_PORT");
            remove_var("FERRUM_PROXY_HTTPS_PORT");
            remove_var("FERRUM_ADMIN_HTTP_PORT");
            remove_var("FERRUM_ADMIN_HTTPS_PORT");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.proxy_http_port, 8000);
            assert_eq!(config.proxy_https_port, 8443);
            assert_eq!(config.admin_http_port, 9000);
            assert_eq!(config.admin_https_port, 9443);
        },
    );
}

#[test]
fn test_env_config_custom_ports() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PROXY_HTTP_PORT", "3000"),
            ("FERRUM_ADMIN_HTTP_PORT", "4000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.proxy_http_port, 3000);
            assert_eq!(config.admin_http_port, 4000);
        },
    );
}

#[test]
fn test_env_config_default_log_level() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_LOG_LEVEL");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.log_level, "info");
        },
    );
}

#[test]
fn test_env_config_http3_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_ENABLE_HTTP3");
            remove_var("FERRUM_HTTP3_IDLE_TIMEOUT");
            remove_var("FERRUM_HTTP3_MAX_STREAMS");

            let config = EnvConfig::from_env().unwrap();
            assert!(!config.enable_http3);
            assert_eq!(config.http3_idle_timeout, 30);
            assert_eq!(config.http3_max_streams, 100);
        },
    );
}

#[test]
fn test_env_config_dns_overrides_parsing() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_OVERRIDES", r#"{"myhost.local":"10.0.0.1","other.local":"10.0.0.2"}"#),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_overrides.len(), 2);
            assert_eq!(config.dns_overrides.get("myhost.local").unwrap(), "10.0.0.1");
            assert_eq!(config.dns_overrides.get("other.local").unwrap(), "10.0.0.2");
        },
    );
}

#[test]
fn test_env_config_dns_overrides_empty() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_OVERRIDES");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.dns_overrides.is_empty());
        },
    );
}

#[test]
fn test_env_config_tls_flags() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_TLS_NO_VERIFY", "true"),
            ("FERRUM_ADMIN_TLS_NO_VERIFY", "true"),
            ("FERRUM_ADMIN_READ_ONLY", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.backend_tls_no_verify);
            assert!(config.admin_tls_no_verify);
            assert!(config.admin_read_only);
        },
    );
}

#[test]
fn test_env_config_tls_flags_default_false() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_BACKEND_TLS_NO_VERIFY");
            remove_var("FERRUM_ADMIN_TLS_NO_VERIFY");
            remove_var("FERRUM_ADMIN_READ_ONLY");

            let config = EnvConfig::from_env().unwrap();
            assert!(!config.backend_tls_no_verify);
            assert!(!config.admin_tls_no_verify);
            assert!(!config.admin_read_only);
        },
    );
}

#[test]
fn test_env_config_request_limits_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_HEADER_SIZE_BYTES");
            remove_var("FERRUM_MAX_BODY_SIZE_BYTES");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_header_size_bytes, 16384);
            assert_eq!(config.max_body_size_bytes, 10_485_760);
        },
    );
}

#[test]
fn test_env_config_database_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_ADMIN_JWT_SECRET", "my-secret"),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::Database);
            assert_eq!(config.db_type, Some("sqlite".to_string()));
            assert_eq!(config.db_url, Some("sqlite::memory:".to_string()));
            assert_eq!(config.admin_jwt_secret, Some("my-secret".to_string()));
        },
    );
}

#[test]
fn test_env_config_dp_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URL", "http://control-plane:50051"),
            ("FERRUM_DP_GRPC_AUTH_TOKEN", "my-token"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::DataPlane);
            assert_eq!(config.dp_cp_grpc_url, Some("http://control-plane:50051".to_string()));
            assert_eq!(config.dp_grpc_auth_token, Some("my-token".to_string()));
        },
    );
}

#[test]
fn test_env_config_cp_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            ("FERRUM_ADMIN_JWT_SECRET", "admin-secret"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
            ("FERRUM_CP_GRPC_JWT_SECRET", "grpc-secret"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::ControlPlane);
            assert_eq!(config.cp_grpc_listen_addr, Some("0.0.0.0:50051".to_string()));
            assert_eq!(config.cp_grpc_jwt_secret, Some("grpc-secret".to_string()));
        },
    );
}

// ============================================================================
// DNS Enhanced Configuration Tests
// ============================================================================

#[test]
fn test_env_config_dns_resolver_address() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_RESOLVER_ADDRESS", "1.1.1.1,8.8.8.8"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_resolver_address, Some("1.1.1.1,8.8.8.8".to_string()));
        },
    );
}

#[test]
fn test_env_config_dns_resolver_address_not_set() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_RESOLVER_ADDRESS");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.dns_resolver_address.is_none());
        },
    );
}

#[test]
fn test_env_config_dns_resolver_hosts_file() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_RESOLVER_HOSTS_FILE", "/custom/hosts"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_resolver_hosts_file, Some("/custom/hosts".to_string()));
        },
    );
}

#[test]
fn test_env_config_dns_order() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_ORDER", "A,AAAA,SRV"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_order, Some("A,AAAA,SRV".to_string()));
        },
    );
}

#[test]
fn test_env_config_dns_valid_ttl() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_VALID_TTL", "120"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_valid_ttl, Some(120));
        },
    );
}

#[test]
fn test_env_config_dns_valid_ttl_not_set() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_VALID_TTL");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.dns_valid_ttl.is_none(), "dns_valid_ttl should be None when not set");
        },
    );
}

#[test]
fn test_env_config_dns_stale_ttl_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_STALE_TTL");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_stale_ttl, 3600, "dns_stale_ttl should default to 3600");
        },
    );
}

#[test]
fn test_env_config_dns_stale_ttl_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_STALE_TTL", "7200"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_stale_ttl, 7200);
        },
    );
}

#[test]
fn test_env_config_dns_error_ttl_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_ERROR_TTL");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_error_ttl, 1, "dns_error_ttl should default to 1");
        },
    );
}

#[test]
fn test_env_config_dns_error_ttl_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_ERROR_TTL", "5"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_error_ttl, 5);
        },
    );
}
