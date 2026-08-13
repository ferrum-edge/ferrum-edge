//! Tests for the ferrum.conf configuration file parser and integration
//! with EnvConfig.

use crate::unit::env_lock::ENV_LOCK;
use ferrum_edge::config::conf_file::ConfFile;
use ferrum_edge::config::{DbTlsMode, EnvConfig};

/// Helper to set env vars, run a closure, then clean them up.
fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
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
fn test_env_vars_override_conf_file() {
    let conf_contents = "\
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /from/conf
FERRUM_LOG_LEVEL = debug
FERRUM_PROXY_HTTP_PORT = 9999
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    // Env vars take precedence over conf file values
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/from/env"),
            ("FERRUM_LOG_LEVEL", "error"),
            ("FERRUM_PROXY_HTTP_PORT", "1111"),
        ],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            // Env var values take precedence
            assert_eq!(config.file_config_path.as_deref(), Some("/from/env"));
            assert_eq!(config.log_level, "error");
            assert_eq!(config.proxy_http_port, 1111);
        },
    );
}

#[test]
fn test_conf_file_provides_defaults_when_env_not_set() {
    // Conf file sets defaults; env vars override where present
    let conf_contents = "\
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /from/conf
FERRUM_LOG_LEVEL = debug
FERRUM_PROXY_HTTP_PORT = 9999
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    // Only set mode and file_config_path as env vars, leave others to conf defaults
    with_env_vars(
        &[
            ("FERRUM_MODE", "file"),
            ("FERRUM_FILE_CONFIG_PATH", "/from/env"),
        ],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            // Env var overrides conf file
            assert_eq!(config.file_config_path.as_deref(), Some("/from/env"));
            // Conf file provides defaults for fields not set via env
            assert_eq!(config.log_level, "debug");
            assert_eq!(config.proxy_http_port, 9999);
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
FERRUM_TLS_NO_VERIFY = 1
FERRUM_ADMIN_READ_ONLY = false
FERRUM_ADMIN_AUDIT_ENABLED = true
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    with_env_vars(
        &[("FERRUM_MODE", "file"), ("FERRUM_FILE_CONFIG_PATH", "/p")],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            assert!(config.enable_http3);
            assert!(config.tls_no_verify);
            assert!(!config.admin_read_only);
            assert!(config.admin_audit_enabled);
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
FERRUM_MAX_REQUEST_BODY_SIZE_BYTES = 5242880
FERRUM_DNS_TTL_OVERRIDE_SECONDS = 600
FERRUM_HTTP3_MAX_STREAMS = 200
FERRUM_GRPC_POOL_READY_WAIT_MS = 3
FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS = 80
FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS = 320
FERRUM_WEBSOCKET_MAX_CONNECTIONS = 1234
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    with_env_vars(
        &[("FERRUM_MODE", "file"), ("FERRUM_FILE_CONFIG_PATH", "/p")],
        || {
            let config = EnvConfig::from_env_with_conf(&conf).unwrap();
            assert_eq!(config.proxy_http_port, 3000);
            assert_eq!(config.proxy_https_port, 3443);
            assert_eq!(config.admin_http_port, 4000);
            assert_eq!(config.max_request_body_size_bytes, 5_242_880);
            assert_eq!(config.dns_ttl_override, Some(600));
            assert_eq!(config.http3_max_streams, 200);
            assert_eq!(config.grpc_pool_ready_wait_ms, 3);
            assert_eq!(config.server_http2_max_pending_accept_reset_streams, 80);
            assert_eq!(config.server_http2_max_local_error_reset_streams, 320);
            assert_eq!(config.websocket_max_connections, 1234);
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
FERRUM_ADMIN_JWT_SECRET = secret123-padding-for-32-chars!!
FERRUM_DB_POLL_INTERVAL = 60
FERRUM_DB_TLS_MODE = verify-full
";
    let conf = ConfFile::parse(conf_contents).unwrap();

    with_env_vars(&[("FERRUM_MODE", "database")], || {
        let config = EnvConfig::from_env_with_conf(&conf).unwrap();
        assert_eq!(config.db_type.as_deref(), Some("postgres"));
        assert_eq!(
            config.db_url.as_deref(),
            Some("postgres://localhost/ferrum")
        );
        assert_eq!(
            config.admin_jwt_secret.as_deref(),
            Some("secret123-padding-for-32-chars!!")
        );
        assert_eq!(config.db_poll_interval, 60);
        assert_eq!(config.db_tls_mode, Some(DbTlsMode::VerifyFull));
    });
}

// ── Parser unit tests (moved from src/config/conf_file.rs) ──────────────────

#[test]
fn test_parse_basic() {
    let conf = ConfFile::parse("FERRUM_MODE = file\nFERRUM_LOG_LEVEL = debug\n").unwrap();
    assert_eq!(conf.get("FERRUM_MODE"), Some("file"));
    assert_eq!(conf.get("FERRUM_LOG_LEVEL"), Some("debug"));
}

#[test]
fn test_parse_comments_and_empty_lines() {
    let input = "# This is a comment\n\nFERRUM_MODE = file\n  # Another comment\n";
    let conf = ConfFile::parse(input).unwrap();
    assert_eq!(conf.get("FERRUM_MODE"), Some("file"));
    // Only the one non-comment, non-empty line should be parsed
    assert!(conf.get("# This is a comment").is_none());
    assert!(conf.get("# Another comment").is_none());
}

#[test]
fn test_parse_quoted_values() {
    let input = "KEY1 = \"hello world\"\nKEY2 = 'single quoted'\n";
    let conf = ConfFile::parse(input).unwrap();
    assert_eq!(conf.get("KEY1"), Some("hello world"));
    assert_eq!(conf.get("KEY2"), Some("single quoted"));
}

#[test]
fn test_parse_no_spaces() {
    let conf = ConfFile::parse("KEY=value").unwrap();
    assert_eq!(conf.get("KEY"), Some("value"));
}

#[test]
fn test_parse_inline_comments() {
    let conf = ConfFile::parse("KEY = value # this is a comment").unwrap();
    assert_eq!(conf.get("KEY"), Some("value"));
}

#[test]
fn test_parse_empty_value() {
    let conf = ConfFile::parse("KEY =").unwrap();
    assert_eq!(conf.get("KEY"), Some(""));
}

#[test]
fn test_parse_invalid_line() {
    let result = ConfFile::parse("no_equals_sign");
    assert!(result.is_err());
}

#[test]
fn conf_file_missing_equals_error_omits_secret_bearing_line() {
    let secret_line = "FERRUM_ADMIN_JWT_SECRET_super_secret_value_do_not_leak";
    let err = ConfFile::parse(secret_line).expect_err("missing '='");
    assert!(
        err.contains("missing '='"),
        "expected missing-'=' reason, got: {err}"
    );
    assert!(err.contains("line 1"), "expected line number, got: {err}");
    assert!(
        !err.contains(secret_line),
        "malformed-line diagnostic must not echo the secret-bearing line: {err}"
    );
    assert!(
        !err.contains("super_secret_value_do_not_leak"),
        "malformed-line diagnostic must not echo secret material: {err}"
    );
}

#[test]
fn test_empty_file() {
    let conf = ConfFile::parse("").unwrap();
    assert!(conf.is_empty());
}

#[test]
fn test_comments_only() {
    let conf = ConfFile::parse("# just comments\n# nothing else\n").unwrap();
    assert!(conf.is_empty());
}

// ── Stable-file load contract (issue #3776) ─────────────────────────────────

#[test]
fn absent_default_conf_path_yields_empty_defaults() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("does-not-exist.conf");
    let conf = ConfFile::load_from_path(&missing, true).expect("absent default is empty");
    assert!(conf.is_empty());
}

#[test]
fn explicit_missing_conf_path_fails_closed() {
    let dir = tempfile::tempdir().unwrap();
    let missing = dir.path().join("missing-explicit.conf");
    let err = ConfFile::load_from_path(&missing, false).expect_err("explicit missing");
    assert!(
        err.contains("not found") || err.contains("Failed to read"),
        "expected missing-path diagnostic, got: {err}"
    );
}

#[test]
fn conf_file_exact_limit_loads_and_limit_plus_one_refuses() {
    use ferrum_edge::config::stable_file::MAX_FERRUM_CONF_BYTES;

    let dir = tempfile::tempdir().unwrap();
    let exact = dir.path().join("exact.conf");
    // Fill with valid KEY=VALUE lines under the ceiling.
    let mut body = String::new();
    let mut n = 0u32;
    while (body.len() as u64) + 32 < MAX_FERRUM_CONF_BYTES {
        body.push_str(&format!("FERRUM_CUSTOM_{n} = v\n"));
        n += 1;
    }
    let pad = (MAX_FERRUM_CONF_BYTES as usize).saturating_sub(body.len());
    if pad > 1 {
        body.push('#');
        body.push_str(&"x".repeat(pad - 1));
    }
    assert_eq!(body.len() as u64, MAX_FERRUM_CONF_BYTES);
    std::fs::write(&exact, &body).unwrap();
    ConfFile::load_from_path(&exact, false).expect("exact ferrum.conf ceiling must load");

    let over = dir.path().join("over.conf");
    std::fs::write(&over, format!("{body}y")).unwrap();
    let err = ConfFile::load_from_path(&over, false).expect_err("limit+1");
    assert!(
        err.contains("maximum supported size"),
        "expected size diagnostic, got: {err}"
    );
}

#[test]
fn conf_file_malformed_syntax_fails_without_inventing_empty_cache_via_load_from_path() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("bad.conf");
    std::fs::write(&path, "NOT_A_VALID_LINE\n").unwrap();
    let err = ConfFile::load_from_path(&path, false).expect_err("malformed");
    assert!(
        err.contains("missing '='") || err.contains("Invalid conf"),
        "got: {err}"
    );
}

#[test]
fn conf_lookup_fails_closed_on_a_sticky_load_failure() {
    // Behavioral replacement for the old source-string pin: the conf-file half
    // of `resolve_ferrum_var` must resolve to `None` on a cached load failure,
    // never to an invented empty defaults map. `resolve_ferrum_var` itself
    // memoizes into a process-wide `OnceLock`, so the shared decision function
    // is exercised directly against both cached outcomes.
    let failed: Result<ConfFile, String> =
        Err("Failed to read ferrum.conf /etc/ferrum.conf: path not found".to_string());
    assert_eq!(
        ferrum_edge::config::conf_file::conf_value_from_cached(&failed, "FERRUM_MODE"),
        None,
        "a sticky load failure must not resolve conf-backed values"
    );
    assert_eq!(
        ferrum_edge::config::conf_file::conf_value_from_cached(&failed, "FERRUM_LOG_LEVEL"),
        None
    );

    let loaded: Result<ConfFile, String> = ConfFile::parse("FERRUM_LOG_LEVEL = debug\n");
    assert_eq!(
        ferrum_edge::config::conf_file::conf_value_from_cached(&loaded, "FERRUM_LOG_LEVEL")
            .as_deref(),
        Some("debug"),
        "an accepted snapshot still resolves its values"
    );
    assert_eq!(
        ferrum_edge::config::conf_file::conf_value_from_cached(&loaded, "FERRUM_MODE"),
        None,
        "an absent key is None, which is what the failure case must be indistinguishable from"
    );
}

#[test]
fn empty_or_whitespace_conf_path_is_treated_as_unset() {
    use ferrum_edge::config::conf_file::conf_path_selection;
    use std::path::PathBuf;

    let default_path = PathBuf::from("./ferrum.conf");

    // Unset: default path, absence tolerated (historical behavior).
    assert_eq!(conf_path_selection(None), (default_path.clone(), true));

    // Exported-but-blank configures nothing, so it must behave as unset rather
    // than failing startup on a blank path.
    assert_eq!(conf_path_selection(Some("")), (default_path.clone(), true));
    assert_eq!(
        conf_path_selection(Some("   \t ")),
        (default_path.clone(), true)
    );

    // An explicit non-empty path stays fail-closed.
    assert_eq!(
        conf_path_selection(Some("/etc/ferrum/ferrum.conf")),
        (PathBuf::from("/etc/ferrum/ferrum.conf"), false)
    );
}

#[test]
fn a_blank_conf_path_falls_back_to_absent_ok_default_loading() {
    // End-to-end through the load path the selection feeds: the default path is
    // tolerated when absent, so a blank FERRUM_CONF_PATH cannot turn into a
    // blank-path startup failure.
    use ferrum_edge::config::conf_file::conf_path_selection;

    let (path, absent_ok) = conf_path_selection(Some(" "));
    assert!(absent_ok);
    if !path.exists() {
        let conf = ConfFile::load_from_path(&path, absent_ok)
            .expect("a blank configured path must fall back to tolerated defaults");
        assert!(conf.is_empty());
    }
}

#[cfg(unix)]
#[test]
fn conf_file_fifo_is_rejected_promptly() {
    let dir = tempfile::tempdir().unwrap();
    let fifo = dir.path().join("ferrum.conf");
    let status = std::process::Command::new("mkfifo")
        .arg(&fifo)
        .status()
        .expect("mkfifo");
    assert!(status.success());
    let started = std::time::Instant::now();
    let err = ConfFile::load_from_path(&fifo, false).expect_err("fifo");
    assert!(started.elapsed() < std::time::Duration::from_secs(2));
    assert!(
        err.contains("not a regular file") || err.contains("Failed to read"),
        "got: {err}"
    );
}
