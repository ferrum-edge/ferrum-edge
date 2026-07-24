//! Unit tests for CLI argument parsing, path resolution, and subcommand behavior.

use clap::Parser;
use ferrum_edge::cli::{
    Cli, Command, HealthArgs, ReloadArgs, RunArgs, ValidateArgs, VersionArgs, execute_health,
    resolve_settings_path, resolve_spec_path,
};
use std::path::Path;
use tempfile::TempDir;

/// Serialize env-var-mutating tests against *every* other env-touching test in
/// the `unit_tests` binary, not just the ones in this file. A file-private
/// mutex only orders this module against itself, which is not what
/// `std::env::set_var`'s Rust 2024 safety contract requires: it is a data race
/// against any concurrent `getenv` anywhere in the process, and the secrets and
/// config suites read the same `FERRUM_*` variables these tests write.
use crate::unit::env_lock::ENV_LOCK;

/// Helper to set env vars, run a closure, then clean them up.
fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    // Poison-tolerant: the lock now spans the whole binary, so one panicking
    // env test elsewhere must not cascade into unrelated failures here. It
    // guards no invariant of its own — only mutual exclusion.
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    for (k, v) in vars {
        unsafe { std::env::set_var(k, v) };
    }
    f();
    for (k, _) in vars {
        unsafe { std::env::remove_var(k) };
    }
}

/// Helper to temporarily unset env vars, run a closure, then restore.
fn without_env_vars<F: FnOnce()>(vars: &[&str], f: F) {
    // Poison-tolerant: the lock now spans the whole binary, so one panicking
    // env test elsewhere must not cascade into unrelated failures here. It
    // guards no invariant of its own — only mutual exclusion.
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let saved: Vec<(&str, Option<String>)> =
        vars.iter().map(|k| (*k, std::env::var(k).ok())).collect();
    for k in vars {
        unsafe { std::env::remove_var(k) };
    }
    f();
    for (k, v) in &saved {
        match v {
            Some(val) => unsafe { std::env::set_var(k, val) },
            None => unsafe { std::env::remove_var(k) },
        }
    }
}

// ── Clap parsing tests ──────────────────────────────────────────────────────

#[test]
fn test_parse_no_args() {
    let cli = Cli::try_parse_from(["ferrum-edge"]).unwrap();
    assert!(cli.command.is_none());
}

#[test]
fn test_parse_version_subcommand() {
    let cli = Cli::try_parse_from(["ferrum-edge", "version"]).unwrap();
    assert!(matches!(
        cli.command,
        Some(Command::Version(VersionArgs { json: false }))
    ));
}

#[test]
fn test_parse_version_json() {
    let cli = Cli::try_parse_from(["ferrum-edge", "version", "--json"]).unwrap();
    match cli.command {
        Some(Command::Version(args)) => assert!(args.json),
        _ => panic!("Expected Version command"),
    }
}

#[test]
fn test_parse_run_no_options() {
    let cli = Cli::try_parse_from(["ferrum-edge", "run"]).unwrap();
    match cli.command {
        Some(Command::Run(args)) => {
            assert!(args.settings.is_none());
            assert!(args.spec.is_none());
            assert!(args.mode.is_none());
            assert_eq!(args.verbose, 0);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_parse_run_all_options() {
    let cli = Cli::try_parse_from([
        "ferrum-edge",
        "run",
        "--settings",
        "/etc/ferrum.conf",
        "--spec",
        "/etc/resources.yaml",
        "--mode",
        "file",
        "-vvv",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Run(args)) => {
            assert_eq!(args.settings.unwrap().to_str().unwrap(), "/etc/ferrum.conf");
            assert_eq!(args.spec.unwrap().to_str().unwrap(), "/etc/resources.yaml");
            assert_eq!(args.mode.as_deref(), Some("file"));
            assert_eq!(args.verbose, 3);
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_parse_run_short_flags() {
    let cli = Cli::try_parse_from([
        "ferrum-edge",
        "run",
        "-s",
        "f.conf",
        "-c",
        "r.yaml",
        "-m",
        "cp",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Run(args)) => {
            assert_eq!(args.settings.unwrap().to_str().unwrap(), "f.conf");
            assert_eq!(args.spec.unwrap().to_str().unwrap(), "r.yaml");
            assert_eq!(args.mode.as_deref(), Some("cp"));
        }
        _ => panic!("Expected Run command"),
    }
}

#[test]
fn test_parse_run_verbose_levels() {
    for (flags, expected) in [
        (vec!["ferrum-edge", "run", "-v"], 1),
        (vec!["ferrum-edge", "run", "-vv"], 2),
        (vec!["ferrum-edge", "run", "-vvv"], 3),
        (vec!["ferrum-edge", "run", "--verbose", "--verbose"], 2),
    ] {
        let cli = Cli::try_parse_from(flags).unwrap();
        match cli.command {
            Some(Command::Run(args)) => assert_eq!(args.verbose, expected),
            _ => panic!("Expected Run command"),
        }
    }
}

#[test]
fn test_parse_validate_with_spec() {
    let cli =
        Cli::try_parse_from(["ferrum-edge", "validate", "--spec", "/path/to/config.yaml"]).unwrap();
    match cli.command {
        Some(Command::Validate(args)) => {
            assert_eq!(args.spec.unwrap().to_str().unwrap(), "/path/to/config.yaml");
            assert!(args.settings.is_none());
        }
        _ => panic!("Expected Validate command"),
    }
}

#[test]
fn test_parse_reload_with_pid() {
    let cli = Cli::try_parse_from(["ferrum-edge", "reload", "--pid", "42195"]).unwrap();
    match cli.command {
        Some(Command::Reload(args)) => assert_eq!(args.pid, Some(42195)),
        _ => panic!("Expected Reload command"),
    }
}

#[test]
fn test_parse_reload_no_pid() {
    let cli = Cli::try_parse_from(["ferrum-edge", "reload"]).unwrap();
    match cli.command {
        Some(Command::Reload(args)) => assert!(args.pid.is_none()),
        _ => panic!("Expected Reload command"),
    }
}

#[test]
fn test_parse_unknown_subcommand_fails() {
    let result = Cli::try_parse_from(["ferrum-edge", "start"]);
    assert!(result.is_err());
}

// ── health --live parsing ───────────────────────────────────────────────────

#[test]
fn test_parse_health_defaults_to_readiness() {
    let cli = Cli::try_parse_from(["ferrum-edge", "health"]).unwrap();
    match cli.command {
        Some(Command::Health(args)) => {
            assert!(!args.live, "health without --live must probe readiness");
            assert!(!args.tls);
            assert!(args.port.is_none());
        }
        _ => panic!("Expected Health command"),
    }
}

#[test]
fn test_parse_health_live_flag() {
    let cli = Cli::try_parse_from(["ferrum-edge", "health", "--live"]).unwrap();
    match cli.command {
        Some(Command::Health(args)) => assert!(args.live, "--live must select liveness probe"),
        _ => panic!("Expected Health command"),
    }
}

#[test]
fn test_parse_health_live_with_port_and_host() {
    let cli = Cli::try_parse_from([
        "ferrum-edge",
        "health",
        "--live",
        "-p",
        "9001",
        "--host",
        "127.0.0.1",
    ])
    .unwrap();
    match cli.command {
        Some(Command::Health(args)) => {
            assert!(args.live);
            assert_eq!(args.port, Some(9001));
            assert_eq!(args.host, "127.0.0.1");
        }
        _ => panic!("Expected Health command"),
    }
}

// ── Smart path resolution tests ─────────────────────────────────────────────

#[test]
fn test_resolve_settings_explicit_absolute_path() {
    let result = resolve_settings_path(Some(Path::new("/explicit/ferrum.conf")));
    assert_eq!(result.unwrap().to_str().unwrap(), "/explicit/ferrum.conf");
}

#[test]
fn test_resolve_settings_explicit_relative_path() {
    let result = resolve_settings_path(Some(Path::new("relative/ferrum.conf")));
    let resolved = result.unwrap();
    // Should be resolved against CWD
    assert!(resolved.is_absolute());
    assert!(resolved.to_str().unwrap().ends_with("relative/ferrum.conf"));
}

#[test]
fn test_resolve_settings_respects_env_var() {
    // When FERRUM_CONF_PATH is set, smart defaults should not override it.
    with_env_vars(&[("FERRUM_CONF_PATH", "/env/ferrum.conf")], || {
        let result = resolve_settings_path(None);
        assert!(result.is_none());
    });
}

#[test]
fn test_resolve_settings_finds_local_file() {
    without_env_vars(&["FERRUM_CONF_PATH"], || {
        // The repo has a ./ferrum.conf in the project root, so this should find it.
        let result = resolve_settings_path(None);
        if Path::new("./ferrum.conf").exists() {
            assert!(result.is_some());
        }
    });
}

#[test]
fn test_resolve_spec_explicit_absolute_path() {
    let result = resolve_spec_path(Some(Path::new("/etc/ferrum/resources.yaml")));
    assert_eq!(
        result.unwrap().to_str().unwrap(),
        "/etc/ferrum/resources.yaml"
    );
}

#[test]
fn test_resolve_spec_respects_env_var() {
    with_env_vars(&[("FERRUM_FILE_CONFIG_PATH", "/env/config.yaml")], || {
        let result = resolve_spec_path(None);
        assert!(result.is_none());
    });
}

#[test]
fn test_resolve_spec_searches_candidates() {
    // Create a temp dir with a resources.yaml file and run from there.
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("resources.yaml");
    std::fs::write(
        &spec_path,
        "proxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    without_env_vars(&["FERRUM_FILE_CONFIG_PATH"], || {
        // The CWD won't have resources.yaml (unless the repo does), but this verifies
        // the function doesn't panic and returns None when no candidates exist.
        let result = resolve_spec_path(None);
        // We can't guarantee what the test CWD contains, just that it doesn't crash.
        let _ = result;
    });
}

#[test]
fn test_resolve_spec_no_candidates_returns_none() {
    without_env_vars(&["FERRUM_FILE_CONFIG_PATH"], || {
        // With no env var and likely no ./resources.yaml etc., should return None
        // (unless the repo happens to have one, in which case it returns Some).
        let result = resolve_spec_path(None);
        // Either way, no panic
        let _ = result;
    });
}

// ── apply_run_overrides tests ───────────────────────────────────────────────

#[test]
fn test_apply_run_overrides_sets_mode() {
    without_env_vars(
        &[
            "FERRUM_MODE",
            "FERRUM_LOG_LEVEL",
            "FERRUM_CONF_PATH",
            "FERRUM_FILE_CONFIG_PATH",
        ],
        || {
            let args = RunArgs {
                settings: None,
                spec: None,
                mode: Some("database".to_string()),
                verbose: 0,
            };
            ferrum_edge::cli::apply_run_overrides(&args);
            assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "database");
            // Cleanup
            unsafe { std::env::remove_var("FERRUM_MODE") };
        },
    );
}

#[test]
fn test_apply_run_overrides_verbose_levels() {
    without_env_vars(
        &[
            "FERRUM_MODE",
            "FERRUM_LOG_LEVEL",
            "FERRUM_CONF_PATH",
            "FERRUM_FILE_CONFIG_PATH",
        ],
        || {
            for (level, expected) in [(1, "info"), (2, "debug"), (3, "trace"), (4, "trace")] {
                let args = RunArgs {
                    settings: None,
                    spec: None,
                    mode: Some("file".to_string()),
                    verbose: level,
                };
                ferrum_edge::cli::apply_run_overrides(&args);
                assert_eq!(std::env::var("FERRUM_LOG_LEVEL").unwrap(), expected);
                unsafe {
                    std::env::remove_var("FERRUM_LOG_LEVEL");
                    std::env::remove_var("FERRUM_MODE");
                };
            }
        },
    );
}

#[test]
fn test_apply_run_overrides_no_verbose_does_not_set_log_level() {
    without_env_vars(
        &[
            "FERRUM_MODE",
            "FERRUM_LOG_LEVEL",
            "FERRUM_CONF_PATH",
            "FERRUM_FILE_CONFIG_PATH",
        ],
        || {
            let args = RunArgs {
                settings: None,
                spec: None,
                mode: Some("file".to_string()),
                verbose: 0,
            };
            ferrum_edge::cli::apply_run_overrides(&args);
            assert!(std::env::var("FERRUM_LOG_LEVEL").is_err());
            unsafe { std::env::remove_var("FERRUM_MODE") };
        },
    );
}

/// Point `FERRUM_CONF_PATH` at a path that does not exist, so `ConfFile::load()`
/// inside `infer_file_mode()` yields an empty settings file.
///
/// Without this the inference tests would consult whatever `./ferrum.conf` the
/// test process happens to sit next to, which is the repository's own operator
/// template — a file that could start declaring `FERRUM_MODE` at any time.
fn pin_absent_conf_file(temp_dir: &TempDir) {
    let missing = temp_dir.path().join("no-such-ferrum.conf");
    assert!(!missing.exists());
    unsafe { std::env::set_var("FERRUM_CONF_PATH", &missing) };
}

fn write_non_file_conf(path: &Path, mode: &str) {
    std::fs::write(
        path,
        format!(
            "FERRUM_MODE = {mode}\n\
             FERRUM_DB_TYPE = sqlite\n\
             FERRUM_DB_URL = sqlite::memory:\n\
             FERRUM_ADMIN_JWT_SECRET = fixture-admin-jwt-secret-not-a-real-credential\n"
        ),
    )
    .unwrap();
}

fn write_empty_resources(path: &Path) {
    std::fs::write(
        path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();
}

/// Mode inference is no longer part of `apply_*_overrides`; it is a separate,
/// explicitly-ordered step that `main()` runs *after* startup secret
/// resolution. See `cli::infer_file_mode`.
#[test]
fn test_infer_file_mode_from_spec_path() {
    without_env_vars(
        &[
            "FERRUM_MODE",
            "FERRUM_LOG_LEVEL",
            "FERRUM_CONF_PATH",
            "FERRUM_FILE_CONFIG_PATH",
        ],
        || {
            let temp_dir = TempDir::new().unwrap();
            pin_absent_conf_file(&temp_dir);
            let args = RunArgs {
                settings: None,
                spec: Some("/tmp/some-spec.yaml".into()),
                mode: None,
                verbose: 0,
            };
            ferrum_edge::cli::apply_run_overrides(&args);
            assert_eq!(
                std::env::var("FERRUM_FILE_CONFIG_PATH").unwrap(),
                "/tmp/some-spec.yaml"
            );
            // Applying overrides alone must NOT materialize a mode: doing so
            // before secret resolution is what created a synthetic second
            // source for a `FERRUM_MODE_*` deployment.
            assert!(
                std::env::var("FERRUM_MODE").is_err(),
                "overrides must not synthesize a mode before secret resolution"
            );

            ferrum_edge::cli::infer_file_mode();
            assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "file");
        },
    );
}

#[test]
fn test_apply_run_overrides_explicit_mode_not_overridden_by_spec() {
    without_env_vars(
        &[
            "FERRUM_MODE",
            "FERRUM_LOG_LEVEL",
            "FERRUM_CONF_PATH",
            "FERRUM_FILE_CONFIG_PATH",
        ],
        || {
            let temp_dir = TempDir::new().unwrap();
            pin_absent_conf_file(&temp_dir);
            let args = RunArgs {
                settings: None,
                spec: Some("/tmp/spec.yaml".into()),
                mode: Some("database".to_string()),
                verbose: 0,
            };
            ferrum_edge::cli::apply_run_overrides(&args);
            ferrum_edge::cli::infer_file_mode();
            // Mode should remain "database", not inferred to "file"
            assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "database");
        },
    );
}

/// A mode already present in the environment — which is where startup secret
/// resolution materializes `FERRUM_MODE_FILE`/`_VAULT`/`_AWS`/`_AZURE`/`_GCP`
/// before this runs — is an explicit env source and outranks the smart default,
/// even with a spec path configured.
#[test]
fn test_infer_file_mode_yields_to_resolved_mode_env_var() {
    without_env_vars(
        &["FERRUM_MODE", "FERRUM_CONF_PATH", "FERRUM_FILE_CONFIG_PATH"],
        || {
            let temp_dir = TempDir::new().unwrap();
            pin_absent_conf_file(&temp_dir);
            unsafe {
                std::env::set_var("FERRUM_MODE", "database");
                std::env::set_var("FERRUM_FILE_CONFIG_PATH", "/tmp/spec.yaml");
            }

            ferrum_edge::cli::infer_file_mode();

            assert_eq!(
                std::env::var("FERRUM_MODE").unwrap(),
                "database",
                "an externally resolved FERRUM_MODE must not be downgraded to the smart default"
            );
        },
    );
}

/// `ferrum.conf` sits above smart defaults in `CLI > env > conf file > smart
/// defaults > hardcoded`. Materializing `FERRUM_MODE=file` as an env var would
/// invert that, because `EnvConfig` gives the environment precedence over the
/// settings file.
#[test]
fn test_infer_file_mode_yields_to_conf_file_mode() {
    without_env_vars(
        &["FERRUM_MODE", "FERRUM_CONF_PATH", "FERRUM_FILE_CONFIG_PATH"],
        || {
            let temp_dir = TempDir::new().unwrap();
            let conf_path = temp_dir.path().join("ferrum.conf");
            std::fs::write(&conf_path, "FERRUM_MODE = database\n").unwrap();
            unsafe {
                std::env::set_var("FERRUM_CONF_PATH", &conf_path);
                std::env::set_var("FERRUM_FILE_CONFIG_PATH", "/tmp/spec.yaml");
            }

            ferrum_edge::cli::infer_file_mode();

            assert!(
                std::env::var("FERRUM_MODE").is_err(),
                "a configured conf-file mode must not be overridden by the file-mode smart default"
            );
        },
    );
}

/// A blank `FERRUM_MODE` in the settings file is not a configured mode, so the
/// smart default still applies rather than falling through to a parse error.
#[test]
fn test_infer_file_mode_treats_blank_conf_mode_as_unset() {
    without_env_vars(
        &["FERRUM_MODE", "FERRUM_CONF_PATH", "FERRUM_FILE_CONFIG_PATH"],
        || {
            let temp_dir = TempDir::new().unwrap();
            let conf_path = temp_dir.path().join("ferrum.conf");
            std::fs::write(&conf_path, "FERRUM_MODE = \"\"\n").unwrap();
            unsafe {
                std::env::set_var("FERRUM_CONF_PATH", &conf_path);
                std::env::set_var("FERRUM_FILE_CONFIG_PATH", "/tmp/spec.yaml");
            }

            ferrum_edge::cli::infer_file_mode();

            assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "file");
        },
    );
}

/// Explicit `--spec` installs the resources path but must not promote file mode
/// over a non-file `FERRUM_MODE` in the selected settings file (`run` path).
#[test]
fn test_run_explicit_spec_does_not_override_conf_file_mode() {
    without_env_vars(
        &["FERRUM_MODE", "FERRUM_CONF_PATH", "FERRUM_FILE_CONFIG_PATH"],
        || {
            let temp_dir = TempDir::new().unwrap();
            let conf_path = temp_dir.path().join("ferrum.conf");
            let spec_path = temp_dir.path().join("resources.yaml");
            write_non_file_conf(&conf_path, "database");
            write_empty_resources(&spec_path);

            let args = RunArgs {
                settings: Some(conf_path.clone()),
                spec: Some(spec_path.clone()),
                mode: None,
                verbose: 0,
            };
            ferrum_edge::cli::apply_run_overrides(&args);
            assert!(
                std::env::var("FERRUM_FILE_CONFIG_PATH")
                    .unwrap()
                    .ends_with("resources.yaml"),
                "explicit --spec must install FERRUM_FILE_CONFIG_PATH"
            );
            assert!(
                std::env::var("FERRUM_MODE").is_err(),
                "overrides must not synthesize a mode before inference"
            );

            ferrum_edge::cli::infer_file_mode();

            assert!(
                std::env::var("FERRUM_MODE").is_err(),
                "explicit --spec must not promote file mode over ferrum.conf FERRUM_MODE=database"
            );
        },
    );
}

/// Same `--spec` / conf-mode contract on the `validate` override path.
#[test]
fn test_validate_explicit_spec_does_not_override_conf_file_mode() {
    without_env_vars(
        &["FERRUM_MODE", "FERRUM_CONF_PATH", "FERRUM_FILE_CONFIG_PATH"],
        || {
            let temp_dir = TempDir::new().unwrap();
            let conf_path = temp_dir.path().join("ferrum.conf");
            let spec_path = temp_dir.path().join("resources.yaml");
            write_non_file_conf(&conf_path, "cp");
            write_empty_resources(&spec_path);

            let args = ValidateArgs {
                settings: Some(conf_path),
                spec: Some(spec_path),
            };
            ferrum_edge::cli::apply_validate_overrides(&args);
            ferrum_edge::cli::infer_file_mode();

            assert!(
                std::env::var("FERRUM_MODE").is_err(),
                "explicit --spec must not promote file mode over ferrum.conf FERRUM_MODE=cp"
            );
            assert!(
                std::env::var("FERRUM_FILE_CONFIG_PATH")
                    .unwrap()
                    .ends_with("resources.yaml"),
                "explicit --spec must still install the resources path"
            );
        },
    );
}

// ── apply_validate_overrides tests ──────────────────────────────────────────

#[test]
fn test_apply_validate_overrides_sets_spec_path() {
    without_env_vars(
        &["FERRUM_MODE", "FERRUM_CONF_PATH", "FERRUM_FILE_CONFIG_PATH"],
        || {
            let temp_dir = TempDir::new().unwrap();
            pin_absent_conf_file(&temp_dir);
            let args = ValidateArgs {
                settings: None,
                spec: Some("/etc/ferrum/config.yaml".into()),
            };
            ferrum_edge::cli::apply_validate_overrides(&args);
            assert_eq!(
                std::env::var("FERRUM_FILE_CONFIG_PATH").unwrap(),
                "/etc/ferrum/config.yaml"
            );
            ferrum_edge::cli::infer_file_mode();
            assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "file");
        },
    );
}

// ── execute_version tests ───────────────────────────────────────────────────

#[test]
fn test_execute_version_does_not_panic() {
    // Just verify it doesn't panic — output goes to stdout which we can't easily capture
    // in a unit test without additional infrastructure.
    ferrum_edge::cli::execute_version(&VersionArgs { json: false });
    ferrum_edge::cli::execute_version(&VersionArgs { json: true });
}

// ── execute_reload tests ────────────────────────────────────────────────────

#[test]
fn test_execute_reload_invalid_pid() {
    let result = ferrum_edge::cli::execute_reload(&ReloadArgs {
        pid: Some(999_999_999),
    });
    assert!(result.is_err());
}

#[cfg(unix)]
#[test]
fn test_execute_reload_no_pid_when_no_process_running() {
    // With no ferrum-edge process running, auto-detect should fail gracefully.
    let result = ferrum_edge::cli::execute_reload(&ReloadArgs { pid: None });
    // This may succeed if a ferrum-edge process happens to be running, but
    // in CI/test environments it should typically fail. Either way, no panic.
    let _ = result;
}

// ── execute_health path selection ───────────────────────────────────────────

/// Spawn a one-shot plaintext server on loopback, run `execute_health`, and
/// return the CLI result plus the captured request line.
fn run_health_against_plain_server<F>(live: bool, serve: F) -> (Result<(), String>, String)
where
    F: FnOnce(&mut std::net::TcpStream) + Send + 'static,
{
    use std::io::Read;
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("loopback should be available for CLI health tests");
    let port = listener.local_addr().unwrap().port();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut buf = [0u8; 1024];
        let n = stream.read(&mut buf).unwrap();
        let request = String::from_utf8_lossy(&buf[..n]).into_owned();
        serve(&mut stream);
        request.lines().next().unwrap_or("").to_string()
    });

    let args = HealthArgs {
        port: Some(port),
        host: "127.0.0.1".to_string(),
        tls: false,
        tls_no_verify: false,
        live,
    };
    let result = execute_health(&args);
    let request_line = server.join().unwrap();
    (result, request_line)
}

/// Spawn a one-shot plaintext server that replies with `response`.
fn run_health_against_response(live: bool, response: &[u8]) -> (Result<(), String>, String) {
    use std::io::Write;

    let response = response.to_vec();
    run_health_against_plain_server(live, move |stream| {
        stream.write_all(&response).unwrap();
    })
}

/// Spawn a one-shot TLS server that replies with `response` and run the health
/// command with certificate verification disabled.
fn run_health_against_tls_response(response: &[u8]) -> Result<(), String> {
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};
    use std::sync::Arc;

    let key_pair =
        rcgen::KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).expect("generate TLS key");
    let params =
        rcgen::CertificateParams::new(vec!["localhost".to_string()]).expect("certificate params");
    let certificate = params
        .self_signed(&key_pair)
        .expect("self-sign certificate");

    let certificate_pem = certificate.pem();
    let mut certificate_reader = certificate_pem.as_bytes();
    let certificate_chain: Vec<_> = rustls_pemfile::certs(&mut certificate_reader)
        .collect::<Result<_, _>>()
        .expect("parse certificate");
    let key_pem = key_pair.serialize_pem();
    let mut key_reader = key_pem.as_bytes();
    let private_key = rustls_pemfile::private_key(&mut key_reader)
        .expect("parse private key")
        .expect("private key present");
    let server_config = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("default protocol versions")
    .with_no_client_auth()
    .with_single_cert(certificate_chain, private_key)
    .expect("configure TLS server certificate");

    let listener = TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .expect("loopback should be available for CLI health TLS tests");
    let port = listener.local_addr().unwrap().port();
    let response = response.to_vec();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let connection =
            rustls::ServerConnection::new(Arc::new(server_config)).expect("TLS server connection");
        let mut tls_stream = rustls::StreamOwned::new(connection, stream);
        let mut request = [0u8; 1024];
        let read = tls_stream.read(&mut request).expect("read TLS request");
        assert!(read > 0, "TLS health request must not be empty");
        tls_stream.write_all(&response).expect("write TLS response");
        tls_stream.flush().expect("flush TLS response");
    });

    let result = execute_health(&HealthArgs {
        port: Some(port),
        host: "127.0.0.1".to_string(),
        tls: true,
        tls_no_verify: true,
        live: false,
    });
    server.join().unwrap();
    result
}

/// Spawn a one-shot HTTP server on loopback that captures the request line,
/// run `execute_health`, and return the request line the CLI sent.
fn capture_health_request_line(live: bool) -> String {
    let (result, request_line) =
        run_health_against_response(live, b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok");
    result.expect("health check against a 200 server should succeed");
    request_line
}

#[test]
fn test_execute_health_default_targets_health_endpoint() {
    let request_line = capture_health_request_line(false);
    assert!(
        request_line.starts_with("GET /health "),
        "default health check must probe readiness /health, got: {request_line}"
    );
}

#[test]
fn test_execute_health_live_targets_live_endpoint() {
    let request_line = capture_health_request_line(true);
    assert!(
        request_line.starts_with("GET /live "),
        "--live must probe liveness /live, got: {request_line}"
    );
}

// ── execute_health status-line parsing ──────────────────────────────────────

#[test]
fn test_execute_health_http10_200_succeeds() {
    let (result, _) =
        run_health_against_response(false, b"HTTP/1.0 200 OK\r\nContent-Length: 2\r\n\r\nok");
    assert!(result.is_ok(), "HTTP/1.0 200 must be healthy: {result:?}");
}

#[test]
fn test_execute_health_http11_200_without_reason_phrase_succeeds() {
    let (result, _) = run_health_against_response(false, b"HTTP/1.1 200\r\n\r\n");
    assert!(
        result.is_ok(),
        "HTTP/1.1 200 without a reason phrase must be healthy: {result:?}"
    );
}

#[test]
fn test_execute_health_rejects_503_with_200_ok_body() {
    let (result, _) = run_health_against_response(
        false,
        b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 6\r\n\r\n200 OK",
    );
    let err = result.expect_err("503 with '200 OK' body must be unhealthy");
    assert!(
        err.contains("503"),
        "error should report the real status line, got: {err}"
    );
}

#[test]
fn test_execute_health_rejects_503_with_200_ok_header() {
    let (result, _) = run_health_against_response(
        false,
        b"HTTP/1.1 503 Service Unavailable\r\nX-Status: 200 OK\r\nContent-Length: 2\r\n\r\nok",
    );
    assert!(
        result.is_err(),
        "503 with '200 OK' header value must be unhealthy"
    );
}

#[test]
fn test_execute_health_rejects_non200_status() {
    let (result, _) = run_health_against_response(
        false,
        b"HTTP/1.1 404 Not Found\r\nContent-Length: 2\r\n\r\nok",
    );
    assert!(result.is_err(), "404 must be unhealthy");
}

#[test]
fn test_execute_health_rejects_malformed_status_line() {
    let (result, _) = run_health_against_response(false, b"200 OK\r\nContent-Length: 2\r\n\r\nok");
    let err = result.expect_err("a status line missing the HTTP version must be rejected");
    assert!(
        err.contains("malformed HTTP status line"),
        "error should describe the malformed status line, got: {err}"
    );
}

#[test]
fn test_execute_health_rejects_empty_response() {
    let (result, _) = run_health_against_response(false, b"");
    assert!(result.is_err(), "an empty response must be unhealthy");
}

#[test]
fn test_execute_health_consumes_multiple_informational_responses() {
    let (result, _) = run_health_against_response(
        false,
        b"HTTP/1.1 103 Early Hints\r\nLink: </style.css>\r\n\r\n\
          HTTP/1.1 100 Continue\r\n\r\n\
          HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
    );
    assert!(
        result.is_ok(),
        "a final 200 after complete informational responses must be healthy: {result:?}"
    );
}

#[test]
fn test_execute_health_uses_final_non200_after_informational_response() {
    let (result, _) = run_health_against_response(
        false,
        b"HTTP/1.1 103 Early Hints\r\n\r\n\
          HTTP/1.1 503 Service Unavailable\r\nContent-Length: 6\r\n\r\n200 OK",
    );
    let error = result.expect_err("the final 503 must be unhealthy");
    assert!(error.contains("503 Service Unavailable"), "{error}");
}

#[test]
fn test_execute_health_treats_101_as_final_unhealthy_response() {
    let (result, _) = run_health_against_response(
        false,
        b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n\r\n\
          HTTP/1.1 200 OK\r\n\r\n",
    );
    let error = result.expect_err("101 must not be skipped in search of a later 200");
    assert!(error.contains("101 Switching Protocols"), "{error}");
}

#[test]
fn test_execute_health_bounds_informational_response_sections() {
    let mut response = b"HTTP/1.1 103 Early Hints\r\n\r\n".repeat(9);
    response.extend_from_slice(b"HTTP/1.1 200 OK\r\n\r\n");
    let (result, _) = run_health_against_response(false, &response);
    let error = result.expect_err("too many informational responses must be rejected");
    assert!(error.contains("8 informational sections"), "{error}");
}

#[test]
fn test_execute_health_rejects_invalid_http_versions() {
    for status_line in ["HTTP/", "HTTP/garbage", "HTTP/1.1junk"] {
        let response = format!("{status_line} 200 OK\r\n\r\n");
        let (result, _) = run_health_against_response(false, response.as_bytes());
        assert!(result.is_err(), "{status_line:?} must be rejected");
    }
}

#[test]
fn test_execute_health_rejects_missing_or_malformed_status_codes() {
    for status_line in ["HTTP/1.1", "HTTP/1.1 OK", "HTTP/1.1 20", "HTTP/1.1 2000"] {
        let response = format!("{status_line}\r\n\r\n");
        let (result, _) = run_health_against_response(false, response.as_bytes());
        assert!(result.is_err(), "{status_line:?} must be rejected");
    }
}

#[test]
fn test_execute_health_requires_crlf_terminated_status_and_head() {
    for response in [
        b"HTTP/1.1 200".as_slice(),
        b"HTTP/1.1 200\r\n".as_slice(),
        b"HTTP/1.1 200\n\n".as_slice(),
    ] {
        let (result, _) = run_health_against_response(false, response);
        assert!(result.is_err(), "incomplete or LF-only framing must fail");
    }
}

#[test]
fn test_execute_health_rejects_leading_empty_status_line() {
    for response in [
        b"\r\nHTTP/1.1 200 OK\r\n\r\n".as_slice(),
        b"\r\n\r\nHTTP/1.1 200 OK\r\n\r\n".as_slice(),
    ] {
        let (result, _) = run_health_against_response(false, response);
        assert!(result.is_err(), "a leading empty status line must fail");
    }
}

#[test]
fn test_execute_health_rejects_malformed_header_syntax() {
    for response in [
        b"HTTP/1.1 200 OK\r\nMissing-Colon\r\n\r\n".as_slice(),
        b"HTTP/1.1 200 OK\r\nBad Header: value\r\n\r\n".as_slice(),
    ] {
        let (result, _) = run_health_against_response(false, response);
        assert!(result.is_err(), "malformed header syntax must fail");
    }
}

#[test]
fn test_execute_health_rejects_invalid_utf8_response_head() {
    let (result, _) =
        run_health_against_response(false, b"HTTP/1.1 200 OK\r\nX-Invalid: \xff\r\n\r\n");
    let error = result.expect_err("invalid UTF-8 in a response head must fail");
    assert!(error.contains("not valid UTF-8"), "{error}");
}

#[test]
fn test_execute_health_escapes_untrusted_status_text() {
    let (result, _) =
        run_health_against_response(false, b"HTTP/1.1 503 unsafe\x1b[31mreason\r\n\r\n");
    let error = result.expect_err("status controls must fail closed");
    assert!(
        !error.contains('\x1b'),
        "raw escape reached error text: {error:?}"
    );
    assert!(
        error.contains("\\u{1b}"),
        "escape was not rendered safely: {error}"
    );
}

#[test]
fn test_execute_health_escapes_non200_reason_text() {
    let response = "HTTP/1.1 503 unsafe\u{85}reason\r\n\r\n";
    let (result, _) = run_health_against_response(false, response.as_bytes());
    let error = result.expect_err("503 must be unhealthy");
    assert!(
        !error.contains('\u{85}'),
        "raw control reached error text: {error:?}"
    );
    assert!(
        error.contains("\\u{85}"),
        "reason was not rendered safely: {error}"
    );
}

#[test]
fn test_execute_health_bounds_total_response_head_bytes() {
    let response = format!(
        "HTTP/1.1 103 Early Hints\r\nX-Fill: {}\r\n\r\nHTTP/1.1 200 OK\r\n\r\n",
        "a".repeat(17 * 1024)
    );
    let (result, _) = run_health_against_response(false, response.as_bytes());
    let error = result.expect_err("oversized response heads must fail");
    assert!(error.contains("16384-byte limit"), "{error}");
}

#[test]
fn test_execute_health_enforces_one_overall_response_deadline() {
    use std::io::Write;
    use std::time::{Duration, Instant};

    let started = Instant::now();
    let (result, _) = run_health_against_plain_server(false, |stream| {
        for _ in 0..40 {
            if stream.write_all(b"H").is_err() {
                break;
            }
            std::thread::sleep(Duration::from_millis(250));
        }
    });
    let elapsed = started.elapsed();
    let error = result.expect_err("a trickling peer must hit the overall deadline");
    assert!(error.contains("Timed out reading plaintext"), "{error}");
    assert!(
        elapsed < Duration::from_secs(7),
        "per-read timeout was reset by trickled bytes: {elapsed:?}"
    );
}

#[test]
fn test_execute_health_tls_uses_shared_interim_response_parser() {
    let result =
        run_health_against_tls_response(b"HTTP/1.1 103 Early Hints\r\n\r\nHTTP/1.1 200\r\n\r\n");
    assert!(
        result.is_ok(),
        "TLS must accept the same bounded interim/final framing: {result:?}"
    );
}

// ============================================================================
// validate env TLS/security surface parity (issue #2976 / #2977)
// ============================================================================

fn file_mode_env() -> ferrum_edge::config::EnvConfig {
    let mut env = ferrum_edge::config::EnvConfig::default();
    env.mode = ferrum_edge::config::OperatingMode::File;
    env.admin_https_port = 0; // skip admin TLS unless tests set paths + nonzero port
    env
}

#[test]
fn test_validate_env_security_rejects_missing_frontend_tls_cert() {
    ensure_rustls_provider();
    let mut env = file_mode_env();
    env.frontend_tls_cert_path = Some("/nonexistent/frontend.crt".into());
    env.frontend_tls_key_path = Some("/nonexistent/frontend.key".into());

    let err = ferrum_edge::cli::validate_env_security_surfaces(&env)
        .expect_err("missing frontend TLS material must fail validate");
    assert!(
        err.contains("frontend TLS") || err.to_lowercase().contains("cert"),
        "expected frontend TLS diagnostic, got: {err}"
    );
}

#[test]
fn test_validate_env_security_rejects_invalid_admin_cidrs() {
    let mut env = file_mode_env();
    env.admin_allowed_cidrs = "not-a-cidr".into();

    let err = ferrum_edge::cli::validate_env_security_surfaces(&env)
        .expect_err("malformed admin CIDRs must fail validate");
    assert!(
        err.contains("FERRUM_ADMIN_ALLOWED_CIDRS"),
        "expected CIDR diagnostic, got: {err}"
    );
}

#[test]
fn test_validate_env_security_rejects_invalid_metrics_cidrs() {
    let mut env = file_mode_env();
    env.metrics_allowed_cidrs = "1.2.3.4/99".into();

    let err = ferrum_edge::cli::validate_env_security_surfaces(&env)
        .expect_err("malformed metrics CIDRs must fail validate");
    assert!(
        err.contains("FERRUM_METRICS_ALLOWED_CIDRS"),
        "expected metrics CIDR diagnostic, got: {err}"
    );
}

#[test]
fn test_validate_env_security_rejects_unparseable_crl() {
    ensure_rustls_provider();
    let dir = tempfile::tempdir().unwrap();
    let crl_path = dir.path().join("bad.crl");
    std::fs::write(&crl_path, b"not-a-crl").unwrap();

    let mut env = file_mode_env();
    env.tls_crl_file_path = Some(crl_path.to_string_lossy().into_owned());

    let err = ferrum_edge::cli::validate_env_security_surfaces(&env)
        .expect_err("unparseable CRL must fail validate");
    assert!(
        err.to_lowercase().contains("crl"),
        "expected CRL diagnostic, got: {err}"
    );
}

#[test]
fn test_validate_env_security_file_mode_accepts_unset_jwt_secret() {
    without_env_vars(
        &[
            "FERRUM_ADMIN_JWT_SECRET",
            "FERRUM_ADMIN_JWT_MAX_TTL",
            "FERRUM_ADMIN_JWT_ISSUER",
            "FERRUM_ADMIN_JWT_AUDIENCE",
        ],
        || {
            let env = file_mode_env();
            ferrum_edge::cli::validate_env_security_surfaces(&env)
                .expect("file mode must allow unset JWT secret (random at runtime)");
        },
    );
}

#[test]
fn test_validate_env_security_file_mode_rejects_short_jwt_secret() {
    let _guard = ENV_LOCK
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let keys = [
        "FERRUM_ADMIN_JWT_SECRET",
        "FERRUM_ADMIN_JWT_MAX_TTL",
        "FERRUM_ADMIN_JWT_ISSUER",
        "FERRUM_ADMIN_JWT_AUDIENCE",
    ];
    let saved: Vec<_> = keys
        .iter()
        .map(|&k| (k, std::env::var_os(k)))
        .collect();
    unsafe {
        std::env::set_var("FERRUM_ADMIN_JWT_SECRET", "short-secret-20chars!");
        std::env::remove_var("FERRUM_ADMIN_JWT_MAX_TTL");
        std::env::remove_var("FERRUM_ADMIN_JWT_ISSUER");
        std::env::remove_var("FERRUM_ADMIN_JWT_AUDIENCE");
    }
    let env = file_mode_env();
    let err = ferrum_edge::cli::validate_env_security_surfaces(&env)
        .expect_err("file mode must fail validate on short JWT secret");
    for (k, v) in saved {
        unsafe {
            match v {
                Some(val) => std::env::set_var(k, val),
                None => std::env::remove_var(k),
            }
        }
    }
    assert!(
        err.contains("JWT") || err.contains("secret") || err.contains("at least"),
        "expected JWT invalid-config diagnostic, got: {err}"
    );
}

#[test]
fn test_validate_env_security_rejects_expired_frontend_cert() {
    ensure_rustls_provider();
    use rcgen::{CertificateParams, KeyPair};
    use time::{Duration, OffsetDateTime};

    let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
    let mut params = CertificateParams::new(vec!["localhost".to_string()]).unwrap();
    params.not_before = OffsetDateTime::now_utc() - Duration::days(2);
    params.not_after = OffsetDateTime::now_utc() - Duration::days(1);
    let cert = params.self_signed(&key_pair).unwrap();

    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("expired.crt");
    let key_path = dir.path().join("expired.key");
    std::fs::write(&cert_path, cert.pem()).unwrap();
    std::fs::write(&key_path, key_pair.serialize_pem()).unwrap();

    let mut env = file_mode_env();
    env.frontend_tls_cert_path = Some(cert_path.to_string_lossy().into_owned());
    env.frontend_tls_key_path = Some(key_path.to_string_lossy().into_owned());

    let err = ferrum_edge::cli::validate_env_security_surfaces(&env)
        .expect_err("expired frontend cert must fail validate");
    assert!(
        err.to_lowercase().contains("expir") || err.to_lowercase().contains("tls"),
        "expected expiry/TLS diagnostic, got: {err}"
    );
}


#[test]
fn test_validate_env_security_rejects_missing_admin_tls_cert() {
    ensure_rustls_provider();
    let mut env = file_mode_env();
    env.admin_https_port = 9443;
    env.admin_tls_cert_path = Some("/nonexistent/admin.crt".into());
    env.admin_tls_key_path = Some("/nonexistent/admin.key".into());

    let err = ferrum_edge::cli::validate_env_security_surfaces(&env)
        .expect_err("missing admin TLS material must fail validate");
    assert!(
        err.contains("admin TLS") || err.to_lowercase().contains("cert"),
        "expected admin TLS diagnostic, got: {err}"
    );
}

#[test]
fn test_validate_env_security_rejects_missing_dtls_cert() {
    ensure_rustls_provider();
    let mut env = file_mode_env();
    env.dtls_cert_path = Some("/nonexistent/dtls.crt".into());
    env.dtls_key_path = Some("/nonexistent/dtls.key".into());

    let err = ferrum_edge::cli::validate_env_security_surfaces(&env)
        .expect_err("missing DTLS cert must fail validate");
    assert!(
        err.contains("DTLS") || err.to_lowercase().contains("cert"),
        "expected DTLS diagnostic, got: {err}"
    );
}

fn ensure_rustls_provider() {
    use std::sync::Once;
    static INIT: Once = Once::new();
    INIT.call_once(|| {
        let _ = rustls::crypto::ring::default_provider().install_default();
    });
}
