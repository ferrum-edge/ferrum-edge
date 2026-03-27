//! Tests for the ferrum.conf configuration file parser and integration
//! with EnvConfig.

use ferrum_gateway::config::EnvConfig;
use ferrum_gateway::config::conf_file::ConfFile;
use std::sync::Mutex;

static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper to set env vars, run a closure, then clean them up.
fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
    for (k, v) in vars {
        unsafe {
            std::env::set_var(k, v);
        }
    }
    f();
    for (k, _) in vars {
        unsafe {
            std::env::remove_var(k);
        }
    }
}

#[test]
fn test_conf_file_overrides_env_vars() {
    let conf_contents = "\
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /from/conf
FERRUM_LOG_LEVEL = debug
FERRUM_PROXY_HTTP_PORT = 9999
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    // Set env vars that should be overridden by conf file
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/from/env"),
            ("FERRUM_LOG_LEVEL", "error"),
            ("FERRUM_PROXY_HTTP_PORT", "1111"),
        ],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            // Conf file values take precedence
            assert_eq!(config.file_config_path.as_deref(), Some("/from/conf"));
            assert_eq!(config.log_level, "debug");
            assert_eq!(config.proxy_http_port, 9999);
        },
    );
}

#[test]
fn test_conf_file_falls_back_to_env_when_not_set() {
    // Conf file only sets mode and file path, everything else from env
    let conf_contents = "\
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /some/path
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/env/path"),
            ("FERRUM_LOG_LEVEL", "warn"),
            ("FERRUM_PROXY_HTTP_PORT", "7777"),
        ],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            // Conf file overrides these
            assert_eq!(config.file_config_path.as_deref(), Some("/some/path"));
            // Env var used for fields not in conf file
            assert_eq!(config.log_level, "warn");
            assert_eq!(config.proxy_http_port, 7777);
        },
    );
}

#[test]
fn test_empty_conf_file_uses_env_vars() {
    let conf = ConfFile::parse("").unwrap();
    assert!(conf.is_empty());

    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/env/path"),
            ("FERRUM_LOG_LEVEL", "info"),
        ],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            assert_eq!(config.file_config_path.as_deref(), Some("/env/path"));
            assert_eq!(config.log_level, "info");
        },
    );
}

#[test]
fn test_conf_file_bool_values() {
    let conf_contents = "\
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /path
FERRUM_ENABLE_HTTP3 = true
FERRUM_BACKEND_TLS_NO_VERIFY = 1
FERRUM_ADMIN_READ_ONLY = false
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    with_env_vars(
        &[("FERRUM_MODE", "file"), ("FERRUM_FILE_CONFIG_PATH", "/p")],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            assert!(config.enable_http3);
            assert!(config.backend_tls_no_verify);
            assert!(!config.admin_read_only);
        },
    );
}

#[test]
fn test_conf_file_numeric_values() {
    let conf_contents = "\
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /path
FERRUM_PROXY_HTTP_PORT = 3000
FERRUM_PROXY_HTTPS_PORT = 3443
FERRUM_ADMIN_HTTP_PORT = 4000
FERRUM_MAX_BODY_SIZE_BYTES = 5242880
FERRUM_DNS_CACHE_TTL_SECONDS = 600
FERRUM_HTTP3_MAX_STREAMS = 200
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    with_env_vars(
        &[("FERRUM_MODE", "file"), ("FERRUM_FILE_CONFIG_PATH", "/p")],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            assert_eq!(config.proxy_http_port, 3000);
            assert_eq!(config.proxy_https_port, 3443);
            assert_eq!(config.admin_http_port, 4000);
            assert_eq!(config.max_body_size_bytes, 5_242_880);
            assert_eq!(config.dns_cache_ttl_seconds, 600);
            assert_eq!(config.http3_max_streams, 200);
        },
    );
}

#[test]
fn test_conf_file_optional_string_values() {
    let conf_contents = "\
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /path
FERRUM_TRUSTED_PROXIES = 10.0.0.0/8,172.16.0.0/12
FERRUM_REAL_IP_HEADER = X-Real-IP
FERRUM_TLS_CIPHER_SUITES = TLS_AES_256_GCM_SHA384
FERRUM_STREAM_PROXY_BIND_ADDRESS = 127.0.0.1
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    with_env_vars(
        &[("FERRUM_MODE", "file"), ("FERRUM_FILE_CONFIG_PATH", "/p")],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            assert_eq!(config.trusted_proxies, "10.0.0.0/8,172.16.0.0/12");
            // real_ip_header is lowercased at load time
            assert_eq!(config.real_ip_header.as_deref(), Some("x-real-ip"));
            assert_eq!(
                config.tls_cipher_suites.as_deref(),
                Some("TLS_AES_256_GCM_SHA384")
            );
            assert_eq!(config.stream_proxy_bind_address, "127.0.0.1");
        },
    );
}

#[test]
fn test_conf_file_parse_error_on_invalid_syntax() {
    let result = ConfFile::parse("this has no equals sign");
    assert!(result.is_err());
    assert!(result.unwrap_err().contains("missing '='"));
}

#[test]
fn test_conf_file_quoted_values_in_config() {
    let conf_contents = r#"
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = "/path/with spaces/config.yml"
FERRUM_ADMIN_JWT_SECRET = "my-secret-key"
"#;
    let conf = ConfFile::parse(conf_contents).unwrap();
    assert_eq!(
        conf.get("FERRUM_FILE_CONFIG_PATH"),
        Some("/path/with spaces/config.yml")
    );
    assert_eq!(conf.get("FERRUM_ADMIN_JWT_SECRET"), Some("my-secret-key"));
}

#[test]
fn test_conf_file_inline_comments() {
    let conf_contents = "\
FERRUM_MODE = file # operating mode
FERRUM_FILE_CONFIG_PATH = /path # config path
";
    let conf = ConfFile::parse(conf_contents).unwrap();
    assert_eq!(conf.get("FERRUM_MODE"), Some("file"));
    assert_eq!(conf.get("FERRUM_FILE_CONFIG_PATH"), Some("/path"));
}

#[test]
fn test_conf_file_database_mode() {
    let conf_contents = "\
FERRUM_MODE = database
FERRUM_DB_TYPE = postgres
FERRUM_DB_URL = postgres://localhost/ferrum
FERRUM_ADMIN_JWT_SECRET = secret123
FERRUM_DB_POLL_INTERVAL = 60
FERRUM_DB_SSL_MODE = verify-full
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    with_env_vars(&[("FERRUM_MODE", "database")], || {
        let config = EnvConfig::from_env_with_conf(&conf).unwrap();
        assert_eq!(config.db_type.as_deref(), Some("postgres"));
        assert_eq!(
            config.db_url.as_deref(),
            Some("postgres://localhost/ferrum")
        );
        assert_eq!(config.admin_jwt_secret.as_deref(), Some("secret123"));
        assert_eq!(config.db_poll_interval, 60);
        assert_eq!(config.db_ssl_mode.as_deref(), Some("verify-full"));
    });
}
