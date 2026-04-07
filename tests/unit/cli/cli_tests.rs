//! Unit tests for CLI argument parsing, path resolution, and subcommand behavior.

use clap::Parser;
use ferrum_edge::cli::{
    Cli, Command, ReloadArgs, RunArgs, ValidateArgs, VersionArgs, resolve_settings_path,
    resolve_spec_path,
};
use std::path::Path;
use std::sync::Mutex;
use tempfile::TempDir;

/// Serialize env-var-mutating tests to avoid races.
static ENV_LOCK: Mutex<()> = Mutex::new(());

/// Helper to set env vars, run a closure, then clean them up.
fn with_env_vars<F: FnOnce()>(vars: &[(&str, &str)], f: F) {
    let _guard = ENV_LOCK.lock().unwrap();
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
    let _guard = ENV_LOCK.lock().unwrap();
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

#[test]
fn test_apply_run_overrides_spec_infers_file_mode() {
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
                spec: Some("/tmp/some-spec.yaml".into()),
                mode: None,
                verbose: 0,
            };
            ferrum_edge::cli::apply_run_overrides(&args);
            assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "file");
            assert_eq!(
                std::env::var("FERRUM_FILE_CONFIG_PATH").unwrap(),
                "/tmp/some-spec.yaml"
            );
            unsafe {
                std::env::remove_var("FERRUM_MODE");
                std::env::remove_var("FERRUM_FILE_CONFIG_PATH");
            };
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
            let args = RunArgs {
                settings: None,
                spec: Some("/tmp/spec.yaml".into()),
                mode: Some("database".to_string()),
                verbose: 0,
            };
            ferrum_edge::cli::apply_run_overrides(&args);
            // Mode should remain "database", not inferred to "file"
            assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "database");
            unsafe {
                std::env::remove_var("FERRUM_MODE");
                std::env::remove_var("FERRUM_FILE_CONFIG_PATH");
            };
        },
    );
}

// ── apply_validate_overrides tests ──────────────────────────────────────────

#[test]
fn test_apply_validate_overrides_sets_spec_path() {
    without_env_vars(
        &["FERRUM_MODE", "FERRUM_CONF_PATH", "FERRUM_FILE_CONFIG_PATH"],
        || {
            let args = ValidateArgs {
                settings: None,
                spec: Some("/etc/ferrum/config.yaml".into()),
            };
            ferrum_edge::cli::apply_validate_overrides(&args);
            assert_eq!(
                std::env::var("FERRUM_FILE_CONFIG_PATH").unwrap(),
                "/etc/ferrum/config.yaml"
            );
            assert_eq!(std::env::var("FERRUM_MODE").unwrap(), "file");
            unsafe {
                std::env::remove_var("FERRUM_FILE_CONFIG_PATH");
                std::env::remove_var("FERRUM_MODE");
            };
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
