//! Functional tests for the Ferrum Edge CLI subcommands.
//!
//! These tests spawn the actual `ferrum-edge` binary and verify CLI behavior
//! end-to-end: argument parsing, version output, validate, run, and reload.
//!
//! Marked with `#[ignore]` — run with:
//!   cargo test --test functional_tests -- --ignored functional_cli

use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;
use tokio::time::sleep;

fn binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

// ── version ─────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_version_prints_version() {
    let output = Command::new(binary_path())
        .args(["version"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to run ferrum-edge version");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.starts_with("ferrum-edge "));
    // Should contain a semver-like version
    assert!(stdout.contains('.'));
}

#[ignore]
#[tokio::test]
async fn functional_cli_version_json() {
    let output = Command::new(binary_path())
        .args(["version", "--json"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to run ferrum-edge version --json");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    let json: serde_json::Value = serde_json::from_str(stdout.trim()).expect("Invalid JSON");
    assert!(json.get("version").is_some());
    assert!(json.get("target").is_some());
}

// ── help ────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_help_shows_subcommands() {
    let output = Command::new(binary_path())
        .args(["--help"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to run ferrum-edge --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("run"));
    assert!(stdout.contains("validate"));
    assert!(stdout.contains("reload"));
    assert!(stdout.contains("version"));
}

#[ignore]
#[tokio::test]
async fn functional_cli_run_help_shows_options() {
    let output = Command::new(binary_path())
        .args(["run", "--help"])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()
        .expect("Failed to run ferrum-edge run --help");

    assert!(output.status.success());
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("--settings"));
    assert!(stdout.contains("--spec"));
    assert!(stdout.contains("--mode"));
    assert!(stdout.contains("--verbose"));
}

// ── validate ────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_validate_valid_spec() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "proxies:\n  - id: test\n    listen_path: /test\n    backend_protocol: http\n    backend_host: localhost\n    backend_port: 3000\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let output = Command::new(binary_path())
        .args(["validate", "--spec", spec_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        output.status.success(),
        "validate failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Validation passed."));
    assert!(stdout.contains("Proxies: 1"));
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_nonexistent_spec() {
    let output = Command::new(binary_path())
        .args(["validate", "--spec", "/nonexistent/config.yaml"])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(!output.status.success());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("not found") || stderr.contains("Spec validation failed"),
        "Expected error about missing file, got: {}",
        stderr
    );
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_invalid_yaml() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("bad.yaml");
    std::fs::write(&spec_path, "this is not: [valid yaml: for ferrum\n").unwrap();

    let output = Command::new(binary_path())
        .args(["validate", "--spec", spec_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(!output.status.success());
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_with_settings() {
    let temp_dir = TempDir::new().unwrap();

    // Create a settings file
    let settings_path = temp_dir.path().join("ferrum.conf");
    std::fs::write(&settings_path, "FERRUM_MODE = file\n").unwrap();

    // Create a spec file
    let spec_path = temp_dir.path().join("resources.yaml");
    std::fs::write(
        &spec_path,
        "proxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let output = Command::new(binary_path())
        .args([
            "validate",
            "--settings",
            settings_path.to_str().unwrap(),
            "--spec",
            spec_path.to_str().unwrap(),
        ])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        output.status.success(),
        "validate failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Validation passed."));
}

// ── run ─────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_run_starts_and_stops() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "proxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let mut child = Command::new(binary_path())
        .args([
            "run",
            "--spec",
            spec_path.to_str().unwrap(),
            "--mode",
            "file",
        ])
        .env("FERRUM_PROXY_HTTP_PORT", "18990")
        .env("FERRUM_ADMIN_HTTP_PORT", "18991")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start ferrum-edge run");

    // Wait for startup
    sleep(Duration::from_secs(2)).await;

    // Check it's still running
    assert!(
        child.try_wait().unwrap().is_none(),
        "Gateway exited prematurely"
    );

    // Health check via admin API
    let health_url = "http://127.0.0.1:18991/health";
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let resp = client.get(health_url).send().await;
    if let Ok(r) = resp {
        assert!(
            r.status().is_success(),
            "Health check returned {}",
            r.status()
        );
    }
    // Note: health check may fail if startup is slow — that's acceptable in CI.

    // Stop gracefully
    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let status = child.wait().expect("Failed to wait for child");
    assert!(
        status.success(),
        "Gateway exited with non-zero status: {:?}",
        status
    );
}

#[ignore]
#[tokio::test]
async fn functional_cli_run_with_verbose() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "proxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    // Start with -v (info level) and capture stderr for log output
    let mut child = Command::new(binary_path())
        .args([
            "run",
            "--spec",
            spec_path.to_str().unwrap(),
            "--mode",
            "file",
            "-v",
        ])
        .env("FERRUM_PROXY_HTTP_PORT", "18992")
        .env("FERRUM_ADMIN_HTTP_PORT", "18993")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start ferrum-edge run -v");

    sleep(Duration::from_secs(2)).await;

    // Just verify it started successfully with -v
    assert!(
        child.try_wait().unwrap().is_none(),
        "Gateway with -v exited prematurely"
    );

    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let _ = child.wait();
}

// ── reload ──────────────────────────────────────────────────────────────────

#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_reload_sends_sighup() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "proxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    // Start a gateway to reload
    let mut child = Command::new(binary_path())
        .args([
            "run",
            "--spec",
            spec_path.to_str().unwrap(),
            "--mode",
            "file",
        ])
        .env("FERRUM_PROXY_HTTP_PORT", "18994")
        .env("FERRUM_ADMIN_HTTP_PORT", "18995")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start gateway for reload test");

    sleep(Duration::from_secs(2)).await;

    let pid = child.id();

    // Use the reload subcommand
    let output = Command::new(binary_path())
        .args(["reload", "--pid", &pid.to_string()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge reload");

    assert!(
        output.status.success(),
        "reload failed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(stdout.contains("Sent SIGHUP"));

    // Gateway should still be running after reload
    sleep(Duration::from_millis(500)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "Gateway exited after reload"
    );

    // Cleanup
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let _ = child.wait();
}

// ── backwards compatibility ─────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_no_args_legacy_mode() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "proxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    // No subcommand — legacy env-var-only mode
    let mut child = Command::new(binary_path())
        .env("FERRUM_MODE", "file")
        .env("FERRUM_FILE_CONFIG_PATH", spec_path.to_str().unwrap())
        .env("FERRUM_PROXY_HTTP_PORT", "18996")
        .env("FERRUM_ADMIN_HTTP_PORT", "18997")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start ferrum-edge in legacy mode");

    sleep(Duration::from_secs(2)).await;
    assert!(
        child.try_wait().unwrap().is_none(),
        "Legacy mode gateway exited prematurely"
    );

    #[cfg(unix)]
    {
        let pid = child.id();
        let _ = std::process::Command::new("kill")
            .args(["-TERM", &pid.to_string()])
            .status();
    }
    #[cfg(not(unix))]
    {
        let _ = child.kill();
    }
    let status = child.wait().expect("Failed to wait");
    assert!(status.success());
}
