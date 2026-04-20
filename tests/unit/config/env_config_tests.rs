//! Tests for environment configuration loading and validation.
//!
//! These tests mutate process-global environment variables, so they MUST run serially.
//! We use `serial_test` via a simple mutex to enforce this.

use ferrum_edge::config::{EnvConfig, OperatingMode};
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper to set env vars, run a closure, then clean them up.
/// Holds a mutex to prevent concurrent env var mutations.
fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    for (k, v) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::set_var(k, v);
        }
    }
    f();
    for (k, _) in vars {
        // SAFETY: We hold a mutex preventing concurrent access.
        unsafe {
            std::env::remove_var(k);
        }
    }
}

/// Helper to remove an env var (must be called inside with_env_vars or while holding ENV_LOCK).
fn remove_var(key: &str) {
    // SAFETY: Called within with_env_vars which holds ENV_LOCK.
    unsafe {
        std::env::remove_var(key);
    }
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
            assert_eq!(
                config.file_config_path,
                Some("/path/to/config.yaml".to_string())
            );
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
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
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
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
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
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
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
fn test_env_config_dp_mode_missing_jwt_secret() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
        ],
        || {
            remove_var("FERRUM_CP_DP_GRPC_JWT_SECRET");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_CP_DP_GRPC_JWT_SECRET"));
        },
    );
}

#[test]
fn test_env_config_cp_mode_missing_grpc_listen() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "grpc-secret-padding-32-char-min!",
            ),
        ],
        || {
            remove_var("FERRUM_CP_GRPC_LISTEN_ADDR");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.cp_grpc_listen_addr,
                Some("0.0.0.0:50051".to_string())
            );
        },
    );
}

#[test]
fn test_env_config_cp_mode_missing_grpc_jwt_secret() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
        ],
        || {
            remove_var("FERRUM_CP_DP_GRPC_JWT_SECRET");
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(result.unwrap_err().contains("FERRUM_CP_DP_GRPC_JWT_SECRET"));
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
            assert_eq!(config.log_level, "error");
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
            assert_eq!(config.http3_max_streams, 1000);
            assert_eq!(config.server_http2_max_pending_accept_reset_streams, 64);
            assert_eq!(config.server_http2_max_local_error_reset_streams, 256);
            assert_eq!(config.websocket_max_connections, 20_000);
        },
    );
}

#[test]
fn test_http3_coalesce_min_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_COALESCE_MIN_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_min_bytes, 32_768);
        },
    );
}

#[test]
fn test_http3_coalesce_min_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "16384"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_min_bytes, 16_384);
        },
    );
}

#[test]
fn test_http3_coalesce_min_clamped_above_max() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "65536"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_min_bytes, 32_768);
        },
    );
}

#[test]
fn test_http3_coalesce_min_clamped_below_floor() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "512"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_min_bytes, 1024);
        },
    );
}

#[test]
fn test_http3_coalesce_max_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_COALESCE_MAX_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 32_768);
        },
    );
}

#[test]
fn test_http3_coalesce_max_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "131072"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 131_072);
        },
    );
}

#[test]
fn test_http3_coalesce_max_clamped_above_cap() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "2097152"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 1_048_576);
        },
    );
}

#[test]
fn test_http3_coalesce_max_clamped_below_floor() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "512"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 1024);
        },
    );
}

#[test]
fn test_http3_coalesce_min_clamped_to_runtime_max() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "16384"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "65536"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 16_384);
            assert_eq!(config.http3_coalesce_min_bytes, 16_384);
        },
    );
}

#[test]
fn test_http3_coalesce_min_allows_large_value_when_max_raised() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MAX_BYTES", "262144"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "131072"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_coalesce_max_bytes, 262_144);
            assert_eq!(config.http3_coalesce_min_bytes, 131_072);
        },
    );
}

#[test]
fn test_http3_coalesce_min_non_numeric_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_COALESCE_MIN_BYTES", "abc"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_COALESCE_MIN_BYTES"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_flush_interval_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_FLUSH_INTERVAL_MICROS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_flush_interval_micros, 200);
        },
    );
}

#[test]
fn test_http3_flush_interval_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_FLUSH_INTERVAL_MICROS", "500"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_flush_interval_micros, 500);
        },
    );
}

#[test]
fn test_http3_flush_interval_floor() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_FLUSH_INTERVAL_MICROS", "10"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_flush_interval_micros, 50);
        },
    );
}

#[test]
fn test_http3_flush_interval_ceiling() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_FLUSH_INTERVAL_MICROS", "200000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_flush_interval_micros, 100_000);
        },
    );
}

#[test]
fn test_http3_initial_mtu_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP3_INITIAL_MTU");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_initial_mtu, 1500);
        },
    );
}

#[test]
fn test_http3_initial_mtu_from_env() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "1350"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http3_initial_mtu, 1350);
        },
    );
}

#[test]
fn test_http3_initial_mtu_below_min_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "1199"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_INITIAL_MTU"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_initial_mtu_above_max_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "65528"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_INITIAL_MTU"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_initial_mtu_u16_overflow_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "70000"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_INITIAL_MTU"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_http3_initial_mtu_non_numeric_rejected() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP3_INITIAL_MTU", "abc"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.err().unwrap();
            assert!(
                err.contains("FERRUM_HTTP3_INITIAL_MTU"),
                "unexpected error: {err}"
            );
        },
    );
}

#[test]
fn test_env_config_http2_reset_and_websocket_limits_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS", "96"),
            ("FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS", "384"),
            ("FERRUM_WEBSOCKET_MAX_CONNECTIONS", "4000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.server_http2_max_pending_accept_reset_streams, 96);
            assert_eq!(config.server_http2_max_local_error_reset_streams, 384);
            assert_eq!(config.websocket_max_connections, 4000);
        },
    );
}

#[test]
fn test_env_config_dns_overrides_parsing() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            (
                "FERRUM_DNS_OVERRIDES",
                r#"{"myhost.local":"10.0.0.1","other.local":"10.0.0.2"}"#,
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_overrides.len(), 2);
            assert_eq!(
                config.dns_overrides.get("myhost.local").unwrap(),
                "10.0.0.1"
            );
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
            ("FERRUM_TLS_NO_VERIFY", "true"),
            ("FERRUM_ADMIN_TLS_NO_VERIFY", "true"),
            ("FERRUM_ADMIN_READ_ONLY", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.tls_no_verify);
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
            remove_var("FERRUM_TLS_NO_VERIFY");
            remove_var("FERRUM_ADMIN_TLS_NO_VERIFY");
            remove_var("FERRUM_ADMIN_READ_ONLY");

            let config = EnvConfig::from_env().unwrap();
            assert!(!config.tls_no_verify);
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
            remove_var("FERRUM_MAX_REQUEST_BODY_SIZE_BYTES");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_header_size_bytes, 32768);
            assert_eq!(config.max_single_header_size_bytes, 16384);
            assert_eq!(config.max_request_body_size_bytes, 10_485_760);
            assert_eq!(config.max_response_body_size_bytes, 10_485_760);
            assert_eq!(config.max_header_count, 100);
            assert_eq!(config.max_url_length_bytes, 8_192);
            assert_eq!(config.max_query_params, 100);
            assert_eq!(config.max_grpc_recv_size_bytes, 4_194_304);
            assert_eq!(config.max_websocket_frame_size_bytes, 16_777_216);
            assert_eq!(config.http_header_read_timeout_seconds, 10);
            assert!(config.add_via_header);
            assert_eq!(config.via_pseudonym, "ferrum-edge");
            assert!(!config.add_forwarded_header);
        },
    );
}

#[test]
fn test_env_config_database_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "my-secret-padding-for-32-chars!!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite::memory:"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::Database);
            assert_eq!(config.db_type, Some("sqlite".to_string()));
            assert_eq!(config.db_url, Some("sqlite::memory:".to_string()));
            assert_eq!(
                config.admin_jwt_secret,
                Some("my-secret-padding-for-32-chars!!!".to_string())
            );
        },
    );
}

#[test]
fn test_env_config_dp_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URL", "http://control-plane:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "my-secret-padding-for-32-char-min!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::DataPlane);
            assert_eq!(
                config.dp_cp_grpc_url,
                Some("http://control-plane:50051".to_string())
            );
            assert_eq!(
                config.cp_dp_grpc_jwt_secret,
                Some("my-secret-padding-for-32-char-min!".to_string())
            );
        },
    );
}

#[test]
fn test_env_config_cp_mode_valid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "cp"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "admin-secret-padding-32-chars!!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "grpc-secret-padding-32-char-min!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mode, OperatingMode::ControlPlane);
            assert_eq!(
                config.cp_grpc_listen_addr,
                Some("0.0.0.0:50051".to_string())
            );
            assert_eq!(
                config.cp_dp_grpc_jwt_secret,
                Some("grpc-secret-padding-32-char-min!".to_string())
            );
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
            assert_eq!(
                config.dns_resolver_address,
                Some("1.1.1.1,8.8.8.8".to_string())
            );
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
            assert_eq!(
                config.dns_resolver_hosts_file,
                Some("/custom/hosts".to_string())
            );
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
fn test_env_config_dns_ttl_override() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_TTL_OVERRIDE_SECONDS", "120"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_ttl_override, Some(120));
        },
    );
}

#[test]
fn test_env_config_dns_ttl_override_not_set() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_TTL_OVERRIDE_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert!(
                config.dns_ttl_override.is_none(),
                "dns_ttl_override should be None when not set"
            );
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
            assert_eq!(
                config.dns_stale_ttl, 3600,
                "dns_stale_ttl should default to 3600"
            );
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
            assert_eq!(config.dns_error_ttl, 5, "dns_error_ttl should default to 5");
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

#[test]
fn test_env_config_dns_warmup_concurrency_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DNS_WARMUP_CONCURRENCY");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_warmup_concurrency, 500);
        },
    );
}

#[test]
fn test_env_config_dns_warmup_concurrency_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_WARMUP_CONCURRENCY", "128"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_warmup_concurrency, 128);
        },
    );
}

#[test]
fn test_env_config_dns_warmup_concurrency_clamps_zero() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DNS_WARMUP_CONCURRENCY", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dns_warmup_concurrency, 1);
        },
    );
}

// --- Pool Warmup Tests ---

#[test]
fn test_env_config_pool_warmup_enabled_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_POOL_WARMUP_ENABLED");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.pool_warmup_enabled);
        },
    );
}

#[test]
fn test_env_config_pool_warmup_enabled_false() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_POOL_WARMUP_ENABLED", "false"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(!config.pool_warmup_enabled);
        },
    );
}

#[test]
fn test_env_config_pool_warmup_concurrency_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_POOL_WARMUP_CONCURRENCY");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.pool_warmup_concurrency, 500);
        },
    );
}

#[test]
fn test_env_config_pool_warmup_concurrency_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_POOL_WARMUP_CONCURRENCY", "128"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.pool_warmup_concurrency, 128);
        },
    );
}

#[test]
fn test_env_config_pool_warmup_concurrency_clamps_zero() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_POOL_WARMUP_CONCURRENCY", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.pool_warmup_concurrency, 1);
        },
    );
}

// --- Size Limit Tests ---

#[test]
fn test_env_config_max_single_header_size_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_single_header_size_bytes, 16384,
                "max_single_header_size_bytes should default to 16384"
            );
        },
    );
}

#[test]
fn test_env_config_max_single_header_size_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES", "4096"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_single_header_size_bytes, 4096);
        },
    );
}

#[test]
fn test_env_config_max_response_body_size_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_response_body_size_bytes, 10_485_760,
                "max_response_body_size_bytes should default to 10MB"
            );
        },
    );
}

#[test]
fn test_env_config_max_response_body_size_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES", "52428800"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_response_body_size_bytes, 52_428_800);
        },
    );
}

#[test]
fn test_env_config_max_header_size_updated_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_HEADER_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_header_size_bytes, 32768,
                "max_header_size_bytes should default to 32KB"
            );
        },
    );
}

#[test]
fn test_env_config_max_header_count_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_HEADER_COUNT");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_header_count, 100,
                "max_header_count should default to 100"
            );
        },
    );
}

#[test]
fn test_env_config_max_header_count_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_HEADER_COUNT", "200"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_header_count, 200);
        },
    );
}

#[test]
fn test_env_config_max_url_length_bytes_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_URL_LENGTH_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_url_length_bytes, 8_192,
                "max_url_length_bytes should default to 8KB"
            );
        },
    );
}

#[test]
fn test_env_config_max_url_length_bytes_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_URL_LENGTH_BYTES", "16384"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_url_length_bytes, 16_384);
        },
    );
}

#[test]
fn test_env_config_max_query_params_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_QUERY_PARAMS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_query_params, 100,
                "max_query_params should default to 100"
            );
        },
    );
}

#[test]
fn test_env_config_max_query_params_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_QUERY_PARAMS", "50"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_query_params, 50);
        },
    );
}

#[test]
fn test_env_config_max_grpc_recv_size_bytes_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_GRPC_RECV_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_grpc_recv_size_bytes, 4_194_304,
                "max_grpc_recv_size_bytes should default to 4MB"
            );
        },
    );
}

#[test]
fn test_env_config_max_grpc_recv_size_bytes_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_GRPC_RECV_SIZE_BYTES", "8388608"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_grpc_recv_size_bytes, 8_388_608);
        },
    );
}

#[test]
fn test_env_config_max_websocket_frame_size_bytes_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_websocket_frame_size_bytes, 16_777_216,
                "max_websocket_frame_size_bytes should default to 16MB"
            );
        },
    );
}

#[test]
fn test_env_config_max_websocket_frame_size_bytes_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES", "33554432"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_websocket_frame_size_bytes, 33_554_432);
        },
    );
}

// ============================================================================
// HTTP Header Read Timeout Tests
// ============================================================================

#[test]
fn test_env_config_http_header_read_timeout_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.http_header_read_timeout_seconds, 10,
                "http_header_read_timeout_seconds should default to 10"
            );
        },
    );
}

#[test]
fn test_env_config_http_header_read_timeout_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", "60"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.http_header_read_timeout_seconds, 60);
        },
    );
}

#[test]
fn test_env_config_http_header_read_timeout_disabled() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.http_header_read_timeout_seconds, 0,
                "0 should disable the header read timeout"
            );
        },
    );
}

// ============================================================================
// Per-IP Concurrent Request Limit Tests
// ============================================================================

#[test]
fn test_env_config_max_concurrent_requests_per_ip_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.max_concurrent_requests_per_ip, 0,
                "max_concurrent_requests_per_ip should default to 0 (disabled)"
            );
        },
    );
}

#[test]
fn test_env_config_max_concurrent_requests_per_ip_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP", "100"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.max_concurrent_requests_per_ip, 100);
        },
    );
}

// ============================================================================
// Admin Allowed CIDRs Tests
// ============================================================================

#[test]
fn test_env_config_admin_allowed_cidrs_default_empty() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_ADMIN_ALLOWED_CIDRS");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.admin_allowed_cidrs.is_empty());
        },
    );
}

#[test]
fn test_env_config_admin_allowed_cidrs_set() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_ADMIN_ALLOWED_CIDRS", "10.0.100.0/24,127.0.0.1,::1"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.admin_allowed_cidrs, "10.0.100.0/24,127.0.0.1,::1");
        },
    );
}

// ============================================================================
// Via / Forwarded Header Tests
// ============================================================================

#[test]
fn test_env_config_add_via_header_enabled() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_ADD_VIA_HEADER", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.add_via_header);
        },
    );
}

#[test]
fn test_env_config_via_pseudonym_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_VIA_PSEUDONYM", "my-gateway"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.via_pseudonym, "my-gateway");
        },
    );
}

#[test]
fn test_env_config_add_forwarded_header_enabled() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_ADD_FORWARDED_HEADER", "true"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.add_forwarded_header);
        },
    );
}

// ============================================================================
// Backend Allow IPs (SSRF Protection) Tests
// ============================================================================

#[test]
fn test_env_config_backend_allow_ips_default_both() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_BACKEND_ALLOW_IPS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.backend_allow_ips, BackendAllowIps::Both);
        },
    );
}

#[test]
fn test_env_config_backend_allow_ips_private() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_ALLOW_IPS", "private"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.backend_allow_ips, BackendAllowIps::Private);
        },
    );
}

#[test]
fn test_env_config_backend_allow_ips_public() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_ALLOW_IPS", "public"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.backend_allow_ips, BackendAllowIps::Public);
        },
    );
}

#[test]
fn test_env_config_backend_allow_ips_case_insensitive() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_ALLOW_IPS", "PRIVATE"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.backend_allow_ips, BackendAllowIps::Private);
        },
    );
}

#[test]
fn test_env_config_backend_allow_ips_invalid() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_BACKEND_ALLOW_IPS", "invalid"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("Invalid FERRUM_BACKEND_ALLOW_IPS")
            );
        },
    );
}

// ============================================================================
// is_private_ip / check_backend_ip_allowed Tests
// ============================================================================

use ferrum_edge::config::{BackendAllowIps, check_backend_ip_allowed, is_private_ip};

#[test]
fn test_is_private_ip_loopback_v4() {
    assert!(is_private_ip(&"127.0.0.1".parse().unwrap()));
    assert!(is_private_ip(&"127.255.255.255".parse().unwrap()));
}

#[test]
fn test_is_private_ip_rfc1918() {
    assert!(is_private_ip(&"10.0.0.1".parse().unwrap()));
    assert!(is_private_ip(&"10.255.255.255".parse().unwrap()));
    assert!(is_private_ip(&"172.16.0.1".parse().unwrap()));
    assert!(is_private_ip(&"172.31.255.255".parse().unwrap()));
    assert!(is_private_ip(&"192.168.0.1".parse().unwrap()));
    assert!(is_private_ip(&"192.168.255.255".parse().unwrap()));
}

#[test]
fn test_is_private_ip_link_local_v4() {
    assert!(is_private_ip(&"169.254.0.1".parse().unwrap()));
    assert!(is_private_ip(&"169.254.169.254".parse().unwrap()));
}

#[test]
fn test_is_private_ip_unspecified_v4() {
    assert!(is_private_ip(&"0.0.0.0".parse().unwrap()));
    assert!(is_private_ip(&"0.1.2.3".parse().unwrap()));
}

#[test]
fn test_is_private_ip_cgnat() {
    assert!(is_private_ip(&"100.64.0.1".parse().unwrap()));
    assert!(is_private_ip(&"100.127.255.255".parse().unwrap()));
    // 100.128.x.x is NOT CGNAT
    assert!(!is_private_ip(&"100.128.0.1".parse().unwrap()));
}

#[test]
fn test_is_private_ip_public_v4() {
    assert!(!is_private_ip(&"8.8.8.8".parse().unwrap()));
    assert!(!is_private_ip(&"1.1.1.1".parse().unwrap()));
    assert!(!is_private_ip(&"203.0.113.5".parse().unwrap()));
}

#[test]
fn test_is_private_ip_ipv6() {
    assert!(is_private_ip(&"::1".parse().unwrap()));
    assert!(is_private_ip(&"::".parse().unwrap()));
    assert!(is_private_ip(&"fe80::1".parse().unwrap()));
    assert!(is_private_ip(&"fd00::1".parse().unwrap()));
    // Public IPv6
    assert!(!is_private_ip(&"2001:db8::1".parse().unwrap()));
    assert!(!is_private_ip(&"2607:f8b0:4004:800::200e".parse().unwrap()));
}

#[test]
fn test_check_backend_ip_allowed_both_allows_all() {
    let policy = BackendAllowIps::Both;
    assert!(check_backend_ip_allowed(
        &"10.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"8.8.8.8".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"169.254.169.254".parse().unwrap(),
        &policy
    ));
}

#[test]
fn test_check_backend_ip_allowed_public_denies_private() {
    let policy = BackendAllowIps::Public;
    assert!(!check_backend_ip_allowed(
        &"10.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"127.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"169.254.169.254".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"100.64.0.1".parse().unwrap(),
        &policy
    ));
    // Public allowed
    assert!(check_backend_ip_allowed(
        &"8.8.8.8".parse().unwrap(),
        &policy
    ));
}

#[test]
fn test_check_backend_ip_allowed_private_denies_public() {
    let policy = BackendAllowIps::Private;
    assert!(!check_backend_ip_allowed(
        &"8.8.8.8".parse().unwrap(),
        &policy
    ));
    assert!(!check_backend_ip_allowed(
        &"1.1.1.1".parse().unwrap(),
        &policy
    ));
    // Private allowed
    assert!(check_backend_ip_allowed(
        &"10.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"127.0.0.1".parse().unwrap(),
        &policy
    ));
    assert!(check_backend_ip_allowed(
        &"169.254.169.254".parse().unwrap(),
        &policy
    ));
}

// ============================================================================
// Database TLS/SSL Configuration Tests
// ============================================================================

#[test]
fn test_env_config_db_ssl_defaults_none() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_SSL_MODE");
            remove_var("FERRUM_DB_SSL_ROOT_CERT");
            remove_var("FERRUM_DB_SSL_CLIENT_CERT");
            remove_var("FERRUM_DB_SSL_CLIENT_KEY");

            let config = EnvConfig::from_env().unwrap();
            assert!(config.db_ssl_mode.is_none());
            assert!(config.db_ssl_root_cert.is_none());
            assert!(config.db_ssl_client_cert.is_none());
            assert!(config.db_ssl_client_key.is_none());
        },
    );
}

#[test]
fn test_env_config_db_ssl_mode_parsed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_SSL_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_ssl_mode, Some("require".to_string()));
        },
    );
}

#[test]
fn test_effective_db_url_no_ssl_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
        ],
        || {
            remove_var("FERRUM_DB_SSL_MODE");
            remove_var("FERRUM_DB_SSL_ROOT_CERT");
            remove_var("FERRUM_DB_SSL_CLIENT_CERT");
            remove_var("FERRUM_DB_SSL_CLIENT_KEY");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "postgres://localhost/ferrum"
            );
        },
    );
}

#[test]
fn test_effective_db_url_postgres_ssl_mode() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_SSL_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "postgres://localhost/ferrum?sslmode=require"
            );
        },
    );
}

#[test]
fn test_effective_db_url_postgres_all_ssl_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            (
                "FERRUM_DB_URL",
                "postgres://user:pass@db.example.com/ferrum",
            ),
            ("FERRUM_DB_SSL_MODE", "verify-full"),
            ("FERRUM_DB_SSL_ROOT_CERT", "/certs/ca.pem"),
            ("FERRUM_DB_SSL_CLIENT_CERT", "/certs/client.pem"),
            ("FERRUM_DB_SSL_CLIENT_KEY", "/certs/client-key.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "postgres://user:pass@db.example.com/ferrum?sslmode=verify-full&sslrootcert=/certs/ca.pem&sslcert=/certs/client.pem&sslkey=/certs/client-key.pem"
            );
        },
    );
}

#[test]
fn test_effective_db_url_postgres_existing_query_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            (
                "FERRUM_DB_URL",
                "postgres://localhost/ferrum?connect_timeout=10",
            ),
            ("FERRUM_DB_SSL_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "postgres://localhost/ferrum?connect_timeout=10&sslmode=require"
            );
        },
    );
}

#[test]
fn test_effective_db_url_mysql_ssl_mode_mapping() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://localhost/ferrum"),
            ("FERRUM_DB_SSL_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "mysql://localhost/ferrum?ssl-mode=REQUIRED"
            );
        },
    );
}

#[test]
fn test_effective_db_url_mysql_verify_ca() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://localhost/ferrum"),
            ("FERRUM_DB_SSL_MODE", "verify-ca"),
            ("FERRUM_DB_SSL_ROOT_CERT", "/certs/ca.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "mysql://localhost/ferrum?ssl-mode=VERIFY_CA&ssl-ca=/certs/ca.pem"
            );
        },
    );
}

#[test]
fn test_effective_db_url_mysql_all_ssl_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://user:pass@db.example.com/ferrum"),
            ("FERRUM_DB_SSL_MODE", "verify-full"),
            ("FERRUM_DB_SSL_ROOT_CERT", "/certs/ca.pem"),
            ("FERRUM_DB_SSL_CLIENT_CERT", "/certs/client.pem"),
            ("FERRUM_DB_SSL_CLIENT_KEY", "/certs/client-key.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "mysql://user:pass@db.example.com/ferrum?ssl-mode=VERIFY_IDENTITY&ssl-ca=/certs/ca.pem&ssl-cert=/certs/client.pem&ssl-key=/certs/client-key.pem"
            );
        },
    );
}

#[test]
fn test_effective_db_url_sqlite_ignores_ssl() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite://ferrum.db?mode=rwc"),
            ("FERRUM_DB_SSL_MODE", "require"),
            ("FERRUM_DB_SSL_ROOT_CERT", "/certs/ca.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "sqlite://ferrum.db?mode=rwc"
            );
        },
    );
}

#[test]
fn test_effective_db_url_root_cert_only() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_SSL_ROOT_CERT", "/certs/ca.pem"),
        ],
        || {
            remove_var("FERRUM_DB_SSL_MODE");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.effective_db_url().unwrap(),
                "postgres://localhost/ferrum?sslrootcert=/certs/ca.pem"
            );
        },
    );
}

#[test]
fn test_plugin_http_slow_threshold_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_slow_threshold_ms, 1000);
        },
    );
}

#[test]
fn test_plugin_http_slow_threshold_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS", "5000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_slow_threshold_ms, 5000);
        },
    );
}

#[test]
fn test_plugin_http_slow_threshold_zero() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_slow_threshold_ms, 0);
        },
    );
}

#[test]
fn test_plugin_http_slow_threshold_invalid_errors() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS", "not_a_number"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS")
            );
        },
    );
}

#[test]
fn test_plugin_http_retries_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_PLUGIN_HTTP_MAX_RETRIES");
            remove_var("FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_max_retries, 0);
            assert_eq!(config.plugin_http_retry_delay_ms, 100);
        },
    );
}

#[test]
fn test_plugin_http_retries_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_MAX_RETRIES", "4"),
            ("FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS", "250"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.plugin_http_max_retries, 4);
            assert_eq!(config.plugin_http_retry_delay_ms, 250);
        },
    );
}

#[test]
fn test_plugin_http_retries_invalid_error() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_PLUGIN_HTTP_MAX_RETRIES", "not_a_number"),
            ("FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS", "also_bad"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_PLUGIN_HTTP_MAX_RETRIES")
            );
        },
    );
}

#[test]
fn test_effective_db_url_none_when_no_db_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_URL");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.effective_db_url().is_none());
        },
    );
}

// ============================================================================
// Database Failover URL Tests
// ============================================================================

#[test]
fn test_db_failover_urls_empty_by_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.db_failover_urls.is_empty());
            assert!(config.effective_db_failover_urls().is_empty());
        },
    );
}

#[test]
fn test_db_failover_urls_parsed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            (
                "FERRUM_DB_FAILOVER_URLS",
                "postgres://secondary1/ferrum, postgres://secondary2/ferrum",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_failover_urls.len(), 2);
            assert_eq!(config.db_failover_urls[0], "postgres://secondary1/ferrum");
            assert_eq!(config.db_failover_urls[1], "postgres://secondary2/ferrum");
        },
    );
}

#[test]
fn test_db_failover_urls_filters_empty_entries() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_FAILOVER_URLS", "postgres://secondary/ferrum,,, "),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_failover_urls.len(), 1);
            assert_eq!(config.db_failover_urls[0], "postgres://secondary/ferrum");
        },
    );
}

#[test]
fn test_db_failover_urls_with_ssl_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_FAILOVER_URLS", "postgres://secondary/ferrum"),
            ("FERRUM_DB_SSL_MODE", "verify-full"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let effective = config.effective_db_failover_urls();
            assert_eq!(effective.len(), 1);
            assert!(effective[0].contains("sslmode=verify-full"));
        },
    );
}

// ============================================================================
// Database Read Replica URL Tests
// ============================================================================

#[test]
fn test_db_read_replica_url_none_by_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.db_read_replica_url.is_none());
            assert!(config.effective_db_read_replica_url().is_none());
        },
    );
}

#[test]
fn test_db_read_replica_url_parsed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_READ_REPLICA_URL", "postgres://replica/ferrum"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_read_replica_url.as_deref(),
                Some("postgres://replica/ferrum")
            );
            assert_eq!(
                config.effective_db_read_replica_url().as_deref(),
                Some("postgres://replica/ferrum")
            );
        },
    );
}

#[test]
fn test_db_read_replica_url_with_ssl_params() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_READ_REPLICA_URL", "postgres://replica/ferrum"),
            ("FERRUM_DB_SSL_MODE", "require"),
            ("FERRUM_DB_SSL_ROOT_CERT", "/path/to/ca.pem"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let effective = config.effective_db_read_replica_url().unwrap();
            assert!(effective.contains("sslmode=require"));
            assert!(effective.contains("sslrootcert=/path/to/ca.pem"));
        },
    );
}

#[test]
fn test_db_read_replica_url_mysql_ssl_mode_translation() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "mysql"),
            ("FERRUM_DB_URL", "mysql://primary/ferrum"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_READ_REPLICA_URL", "mysql://replica/ferrum"),
            ("FERRUM_DB_SSL_MODE", "verify-full"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let effective = config.effective_db_read_replica_url().unwrap();
            assert!(effective.contains("ssl-mode=VERIFY_IDENTITY"));
        },
    );
}

#[test]
fn test_db_read_replica_url_sqlite_no_ssl() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            ("FERRUM_DB_TYPE", "sqlite"),
            ("FERRUM_DB_URL", "sqlite://ferrum.db"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "test-secret-padding-for-32-chars!",
            ),
            ("FERRUM_DB_READ_REPLICA_URL", "sqlite://replica.db"),
            ("FERRUM_DB_SSL_MODE", "require"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let effective = config.effective_db_read_replica_url().unwrap();
            // SQLite should not get SSL params
            assert_eq!(effective, "sqlite://replica.db");
        },
    );
}

#[test]
fn test_env_config_tcp_idle_timeout_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_TCP_IDLE_TIMEOUT_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tcp_idle_timeout_seconds, 300);
        },
    );
}

#[test]
fn test_env_config_tcp_idle_timeout_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_TCP_IDLE_TIMEOUT_SECONDS", "600"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tcp_idle_timeout_seconds, 600);
        },
    );
}

#[test]
fn test_env_config_tcp_idle_timeout_zero_disables() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_TCP_IDLE_TIMEOUT_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tcp_idle_timeout_seconds, 0);
        },
    );
}

// ============================================================================
// Database Connection Pool Configuration Tests
// ============================================================================

#[test]
fn test_env_config_db_pool_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_POOL_MAX_CONNECTIONS");
            remove_var("FERRUM_DB_POOL_MIN_CONNECTIONS");
            remove_var("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS");
            remove_var("FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS");
            remove_var("FERRUM_DB_POOL_MAX_LIFETIME_SECONDS");
            remove_var("FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS");
            remove_var("FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS");

            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_pool_max_connections, 10);
            assert_eq!(config.db_pool_min_connections, 1);
            assert_eq!(config.db_pool_acquire_timeout_seconds, 30);
            assert_eq!(config.db_pool_idle_timeout_seconds, 600);
            assert_eq!(config.db_pool_max_lifetime_seconds, 300);
            assert_eq!(config.db_pool_connect_timeout_seconds, 10);
            assert_eq!(config.db_pool_statement_timeout_seconds, 30);
        },
    );
}

#[test]
fn test_env_config_db_pool_custom_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "database"),
            (
                "FERRUM_ADMIN_JWT_SECRET",
                "secret-padding-for-32-characters!!",
            ),
            ("FERRUM_DB_TYPE", "postgres"),
            ("FERRUM_DB_URL", "postgres://localhost/ferrum"),
            ("FERRUM_DB_POOL_MAX_CONNECTIONS", "50"),
            ("FERRUM_DB_POOL_MIN_CONNECTIONS", "5"),
            ("FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS", "60"),
            ("FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS", "1200"),
            ("FERRUM_DB_POOL_MAX_LIFETIME_SECONDS", "600"),
            ("FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS", "15"),
            ("FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS", "60"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_pool_max_connections, 50);
            assert_eq!(config.db_pool_min_connections, 5);
            assert_eq!(config.db_pool_acquire_timeout_seconds, 60);
            assert_eq!(config.db_pool_idle_timeout_seconds, 1200);
            assert_eq!(config.db_pool_max_lifetime_seconds, 600);
            assert_eq!(config.db_pool_connect_timeout_seconds, 15);
            assert_eq!(config.db_pool_statement_timeout_seconds, 60);
        },
    );
}

#[test]
fn test_env_config_grpc_pool_ready_wait_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_GRPC_POOL_READY_WAIT_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.grpc_pool_ready_wait_ms, 1);
        },
    );
}

#[test]
fn test_env_config_grpc_pool_ready_wait_custom_value() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_GRPC_POOL_READY_WAIT_MS", "7"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.grpc_pool_ready_wait_ms, 7);
        },
    );
}

#[test]
fn test_env_config_db_pool_max_connections_minimum_clamped() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_MAX_CONNECTIONS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_pool_max_connections, 1,
                "max_connections should be clamped to at least 1"
            );
        },
    );
}

#[test]
fn test_env_config_db_pool_min_connections_zero_allowed() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_MIN_CONNECTIONS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.db_pool_min_connections, 0,
                "min_connections=0 should be allowed (no eager warming)"
            );
        },
    );
}

#[test]
fn test_env_config_db_pool_invalid_values_error() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_POOL_MAX_CONNECTIONS", "not_a_number"),
            ("FERRUM_DB_POOL_MIN_CONNECTIONS", "abc"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_DB_POOL_MAX_CONNECTIONS")
            );
        },
    );
}

// --- reserved_gateway_ports tests ---

#[test]
fn test_reserved_gateway_ports_defaults() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/test.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let ports = config.reserved_gateway_ports();
            assert!(
                ports.contains(&8000),
                "should contain default proxy HTTP port"
            );
            assert!(
                ports.contains(&8443),
                "should contain default proxy HTTPS port"
            );
            assert!(
                ports.contains(&9000),
                "should contain default admin HTTP port"
            );
            assert!(
                ports.contains(&9443),
                "should contain default admin HTTPS port"
            );
        },
    );
}

#[test]
fn test_reserved_gateway_ports_custom_ports() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/test.yaml"),
            ("FERRUM_PROXY_HTTP_PORT", "3000"),
            ("FERRUM_ADMIN_HTTP_PORT", "4000"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let ports = config.reserved_gateway_ports();
            assert!(ports.contains(&3000));
            assert!(ports.contains(&4000));
        },
    );
}

#[test]
fn test_reserved_gateway_ports_includes_grpc() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/test.yaml"),
            ("FERRUM_CP_GRPC_LISTEN_ADDR", "0.0.0.0:50051"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let ports = config.reserved_gateway_ports();
            assert!(ports.contains(&50051), "should contain CP gRPC port");
        },
    );
}

#[test]
fn test_db_slow_query_threshold_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_slow_query_threshold_ms, None);
        },
    );
}

#[test]
fn test_db_slow_query_threshold_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS", "500"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.db_slow_query_threshold_ms, Some(500));
        },
    );
}

#[test]
fn test_db_slow_query_threshold_invalid_errors() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS", "not_a_number"),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            assert!(
                result
                    .unwrap_err()
                    .contains("FERRUM_DB_SLOW_QUERY_THRESHOLD_MS")
            );
        },
    );
}

// ---------------------------------------------------------------------------
// MongoDB configuration tests
// ---------------------------------------------------------------------------

#[test]
fn test_mongo_database_defaults_to_ferrum() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_database, "ferrum");
        },
    );
}

#[test]
fn test_mongo_database_custom_value() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MONGO_DATABASE", "my_gateway"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_database, "my_gateway");
        },
    );
}

#[test]
fn test_mongo_app_name_optional() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MONGO_APP_NAME", "my-edge-proxy"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_app_name, Some("my-edge-proxy".to_string()));
        },
    );
}

#[test]
fn test_mongo_replica_set_optional() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MONGO_REPLICA_SET", "rs0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_replica_set, Some("rs0".to_string()));
        },
    );
}

#[test]
fn test_mongo_timeouts_custom_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS", "60"),
            ("FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS", "5"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_server_selection_timeout_seconds, 60);
            assert_eq!(config.mongo_connect_timeout_seconds, 5);
        },
    );
}

#[test]
fn test_mongo_timeouts_default_values() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.mongo_server_selection_timeout_seconds, 30);
            assert_eq!(config.mongo_connect_timeout_seconds, 10);
        },
    );
}

// ============================================================================
// Circuit Breaker Cache Max Entries Tests
// ============================================================================

#[test]
fn test_env_config_circuit_breaker_cache_max_entries_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.circuit_breaker_cache_max_entries, 10_000,
                "circuit_breaker_cache_max_entries should default to 10000"
            );
        },
    );
}

#[test]
fn test_env_config_circuit_breaker_cache_max_entries_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_CIRCUIT_BREAKER_CACHE_MAX_ENTRIES", "500"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.circuit_breaker_cache_max_entries, 500);
        },
    );
}

// ============================================================================
// Status Counts Max Entries Tests
// ============================================================================

#[test]
fn test_env_config_status_counts_max_entries_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_STATUS_COUNTS_MAX_ENTRIES");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.status_counts_max_entries, 200,
                "status_counts_max_entries should default to 200"
            );
        },
    );
}

#[test]
fn test_env_config_status_counts_max_entries_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_STATUS_COUNTS_MAX_ENTRIES", "50"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.status_counts_max_entries, 50);
        },
    );
}

// ============================================================================
// Status Metrics Window Seconds Tests
// ============================================================================

#[test]
fn test_env_config_status_metrics_window_seconds_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
        ],
        || {
            remove_var("FERRUM_STATUS_METRICS_WINDOW_SECONDS");
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.status_metrics_window_seconds, 30,
                "status_metrics_window_seconds should default to 30"
            );
        },
    );
}

#[test]
fn test_env_config_status_metrics_window_seconds_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_STATUS_METRICS_WINDOW_SECONDS", "60"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.status_metrics_window_seconds, 60);
        },
    );
}

#[test]
fn test_env_config_status_metrics_window_seconds_minimum_clamped() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/path/config.yaml"),
            ("FERRUM_STATUS_METRICS_WINDOW_SECONDS", "0"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.status_metrics_window_seconds, 1,
                "status_metrics_window_seconds should be clamped to minimum of 1"
            );
        },
    );
}

// --- DP CP failover URL tests ---

#[test]
fn test_resolved_dp_cp_grpc_urls_single_url_only() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URL", "http://cp1:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let urls = config.resolved_dp_cp_grpc_urls();
            assert_eq!(urls, vec!["http://cp1:50051"]);
        },
    );
}

#[test]
fn test_resolved_dp_cp_grpc_urls_multi_urls_only() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_DP_CP_GRPC_URLS",
                "https://cp1:50051,https://cp2:50051,https://cp3:50051",
            ),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let urls = config.resolved_dp_cp_grpc_urls();
            assert_eq!(
                urls,
                vec![
                    "https://cp1:50051",
                    "https://cp2:50051",
                    "https://cp3:50051",
                ]
            );
        },
    );
}

#[test]
fn test_resolved_dp_cp_grpc_urls_multi_takes_precedence() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URL", "http://single:50051"),
            (
                "FERRUM_DP_CP_GRPC_URLS",
                "https://cp1:50051,https://cp2:50051",
            ),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            let urls = config.resolved_dp_cp_grpc_urls();
            assert_eq!(urls, vec!["https://cp1:50051", "https://cp2:50051"]);
        },
    );
}

#[test]
fn test_resolved_dp_cp_grpc_urls_trims_whitespace() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_DP_CP_GRPC_URLS",
                " https://cp1:50051 , https://cp2:50051 ",
            ),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.dp_cp_grpc_urls,
                vec!["https://cp1:50051", "https://cp2:50051"]
            );
        },
    );
}

#[test]
fn test_resolved_dp_cp_grpc_urls_filters_empty() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_DP_CP_GRPC_URLS",
                "https://cp1:50051,,https://cp2:50051,",
            ),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(
                config.dp_cp_grpc_urls,
                vec!["https://cp1:50051", "https://cp2:50051"]
            );
        },
    );
}

#[test]
fn test_dp_mode_validation_accepts_urls_without_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URLS", "https://cp1:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert!(config.dp_cp_grpc_url.is_none());
            assert_eq!(config.resolved_dp_cp_grpc_urls(), vec!["https://cp1:50051"]);
        },
    );
}

#[test]
fn test_dp_mode_validation_rejects_no_url() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let result = EnvConfig::from_env();
            assert!(result.is_err());
            let err = result.unwrap_err();
            assert!(
                err.contains("FERRUM_DP_CP_GRPC_URL or FERRUM_DP_CP_GRPC_URLS"),
                "Error should mention both env vars: {}",
                err
            );
        },
    );
}

#[test]
fn test_dp_cp_failover_primary_retry_secs_default() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dp_cp_failover_primary_retry_secs, 300);
        },
    );
}

#[test]
fn test_dp_cp_failover_primary_retry_secs_custom() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "dp"),
            ("FERRUM_DP_CP_GRPC_URL", "http://cp:50051"),
            (
                "FERRUM_CP_DP_GRPC_JWT_SECRET",
                "secret-padding-for-32-char-min!!",
            ),
            ("FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS", "60"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.dp_cp_failover_primary_retry_secs, 60);
        },
    );
}

// ============================================================================
// TLS 1.3 0-RTT early data methods
// ============================================================================

#[test]
fn test_tls_early_data_methods_default_empty() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
        ],
        || {
            remove_var("FERRUM_TLS_EARLY_DATA_METHODS");
            let config = EnvConfig::from_env().unwrap();
            assert!(config.tls_early_data_methods.is_empty());
        },
    );
}

#[test]
fn test_tls_early_data_methods_single() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
            ("FERRUM_TLS_EARLY_DATA_METHODS", "GET"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tls_early_data_methods.len(), 1);
            assert!(config.tls_early_data_methods.contains("GET"));
        },
    );
}

#[test]
fn test_tls_early_data_methods_multiple_comma_separated() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
            ("FERRUM_TLS_EARLY_DATA_METHODS", "GET, HEAD, OPTIONS"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tls_early_data_methods.len(), 3);
            assert!(config.tls_early_data_methods.contains("GET"));
            assert!(config.tls_early_data_methods.contains("HEAD"));
            assert!(config.tls_early_data_methods.contains("OPTIONS"));
        },
    );
}

#[test]
fn test_tls_early_data_methods_uppercased() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
            ("FERRUM_TLS_EARLY_DATA_METHODS", "get,head"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tls_early_data_methods.len(), 2);
            assert!(config.tls_early_data_methods.contains("GET"));
            assert!(config.tls_early_data_methods.contains("HEAD"));
        },
    );
}

#[test]
fn test_tls_early_data_methods_empty_entries_filtered() {
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/tmp/r.yaml"),
            ("FERRUM_TLS_EARLY_DATA_METHODS", "GET,,HEAD,"),
        ],
        || {
            let config = EnvConfig::from_env().unwrap();
            assert_eq!(config.tls_early_data_methods.len(), 2);
            assert!(config.tls_early_data_methods.contains("GET"));
            assert!(config.tls_early_data_methods.contains("HEAD"));
        },
    );
}
