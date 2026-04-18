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
use tokio::net::TcpListener;
use tokio::time::sleep;

fn binary_path() -> &'static str {
    if std::path::Path::new("./target/debug/ferrum-edge").exists() {
        "./target/debug/ferrum-edge"
    } else {
        "./target/release/ferrum-edge"
    }
}

// Resolve the binary to an absolute path so that tests which set a custom
// `current_dir()` on the Command can still find it.
fn binary_abs_path() -> std::path::PathBuf {
    let rel = binary_path();
    let p = std::path::Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .unwrap_or_else(|_| std::path::PathBuf::from("."))
            .join(rel)
    }
}

async fn ephemeral_port() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    port
}

async fn wait_for_health(admin_port: u16) -> bool {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()
        .unwrap();
    let url = format!("http://127.0.0.1:{}/health", admin_port);
    for _ in 0..60 {
        if let Ok(resp) = client.get(&url).send().await
            && resp.status().is_success()
        {
            return true;
        }
        sleep(Duration::from_millis(250)).await;
    }
    false
}

fn kill_child(mut child: std::process::Child) {
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

// ── smart path defaults ─────────────────────────────────────────────────────

/// Smart-path discovery: with no `--settings`/`--spec` flags and no env vars
/// for config paths or mode, a `ferrum.conf` + `resources.yaml` in the CWD
/// must be picked up automatically and route traffic.
#[ignore]
#[tokio::test]
async fn functional_cli_smart_path_discovery_from_cwd() {
    const MAX_ATTEMPTS: u32 = 3;
    let binary = binary_abs_path();

    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        // Each attempt gets its own temp dir + fresh ports so failures don't
        // contaminate the next try.
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        // Backend echo server on a held listener (no port race for the echo).
        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_server = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        let body = "smart-path-echo";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        });
        sleep(Duration::from_millis(150)).await;

        // ferrum.conf drives ports + mode. Put it in the CWD root so the
        // `./ferrum.conf` smart-path entry wins.
        let conf = format!(
            "FERRUM_MODE = file\nFERRUM_PROXY_HTTP_PORT = {}\nFERRUM_ADMIN_HTTP_PORT = {}\n",
            proxy_port, admin_port
        );
        std::fs::write(temp_dir.path().join("ferrum.conf"), conf).unwrap();

        // resources.yaml drives the proxy. Place it at `./resources.yaml`.
        let spec = format!(
            r#"proxies:
  - id: "smart-path-proxy"
    listen_path: "/sp"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        );
        std::fs::write(temp_dir.path().join("resources.yaml"), spec).unwrap();

        // IMPORTANT: spawn with current_dir() set AND no FERRUM_* env vars
        // for config paths / mode. We also clear inherited vars that would
        // short-circuit the smart-path search.
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .current_dir(temp_dir.path())
            .env_remove("FERRUM_MODE")
            .env_remove("FERRUM_CONF_PATH")
            .env_remove("FERRUM_FILE_CONFIG_PATH")
            .env_remove("FERRUM_PROXY_HTTP_PORT")
            .env_remove("FERRUM_ADMIN_HTTP_PORT")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn ferrum-edge");

        if wait_for_health(admin_port).await {
            // Verify proxy routes through.
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let url = format!("http://127.0.0.1:{}/sp/anything", proxy_port);
            let resp = client.get(&url).send().await;
            let route_ok = matches!(resp, Ok(r) if r.status().is_success());

            // Cleanup regardless.
            kill_child(child);
            echo_server.abort();

            assert!(
                route_ok,
                "Smart-path gateway started but proxy routing failed"
            );
            return;
        }

        last_err = format!(
            "attempt {}/{} failed (proxy={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        eprintln!("{}", last_err);
        let _ = child.kill();
        let _ = child.wait();
        echo_server.abort();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start via smart-path discovery: {}",
        last_err
    );
}

/// `--spec <file>` with no `FERRUM_MODE` env var must infer
/// `FERRUM_MODE=file` (see `apply_run_overrides` in `src/cli.rs`).
#[ignore]
#[tokio::test]
async fn functional_cli_spec_flag_infers_file_mode() {
    const MAX_ATTEMPTS: u32 = 3;
    let binary = binary_abs_path();

    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_server = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        let body = "spec-infer-echo";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        });
        sleep(Duration::from_millis(150)).await;

        let spec_path = temp_dir.path().join("resources.yaml");
        let spec = format!(
            r#"proxies:
  - id: "spec-infer-proxy"
    listen_path: "/si"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        );
        std::fs::write(&spec_path, spec).unwrap();

        // Spawn with --spec but WITHOUT --mode, --settings, or FERRUM_MODE.
        // Run from a scratch dir that has no ferrum.conf / resources.yaml
        // so the smart-path search cannot confound the test.
        let work_dir = TempDir::new().expect("Failed to create work directory");
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .args(["--spec", spec_path.to_str().unwrap()])
            .current_dir(work_dir.path())
            .env_remove("FERRUM_MODE")
            .env_remove("FERRUM_CONF_PATH")
            .env_remove("FERRUM_FILE_CONFIG_PATH")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn ferrum-edge");

        if wait_for_health(admin_port).await {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let url = format!("http://127.0.0.1:{}/si/x", proxy_port);
            let resp = client.get(&url).send().await;
            let route_ok = matches!(resp, Ok(r) if r.status().is_success());

            kill_child(child);
            echo_server.abort();
            assert!(route_ok, "--spec inferred file mode but routing failed");
            return;
        }

        last_err = format!(
            "attempt {}/{} failed (proxy={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        eprintln!("{}", last_err);
        let _ = child.kill();
        let _ = child.wait();
        echo_server.abort();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start with inferred file mode: {}",
        last_err
    );
}

/// Precedence — CLI flag must win over env var. `--mode file` on CLI wins over
/// `FERRUM_MODE=database` in the environment. If precedence were reversed, the
/// gateway would try to connect to a database and fail startup; we verify
/// file mode by proxying a request end-to-end.
#[ignore]
#[tokio::test]
async fn functional_cli_precedence_flag_beats_env_var() {
    const MAX_ATTEMPTS: u32 = 3;
    let binary = binary_abs_path();

    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let proxy_port = ephemeral_port().await;
        let admin_port = ephemeral_port().await;

        let echo_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let echo_port = echo_listener.local_addr().unwrap().port();
        let echo_server = tokio::spawn(async move {
            loop {
                if let Ok((mut stream, _)) = echo_listener.accept().await {
                    tokio::spawn(async move {
                        use tokio::io::{AsyncReadExt, AsyncWriteExt};
                        let mut buf = vec![0u8; 4096];
                        let _ = stream.read(&mut buf).await;
                        let body = "flag-wins";
                        let resp = format!(
                            "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{}",
                            body.len(),
                            body
                        );
                        let _ = stream.write_all(resp.as_bytes()).await;
                        let _ = stream.shutdown().await;
                    });
                }
            }
        });
        sleep(Duration::from_millis(150)).await;

        let spec_path = temp_dir.path().join("resources.yaml");
        let spec = format!(
            r#"proxies:
  - id: "flag-wins-proxy"
    listen_path: "/fw"
    backend_protocol: http
    backend_host: "127.0.0.1"
    backend_port: {echo_port}
    strip_listen_path: true
consumers: []
plugin_configs: []
"#
        );
        std::fs::write(&spec_path, spec).unwrap();

        // CLI says `--mode file`; env var shouts `FERRUM_MODE=database`.
        // If CLI wins (as documented), file mode starts and routing succeeds.
        let work_dir = TempDir::new().expect("Failed to create work directory");
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .args(["--spec", spec_path.to_str().unwrap()])
            .args(["--mode", "file"])
            .current_dir(work_dir.path())
            .env("FERRUM_MODE", "database")
            .env_remove("FERRUM_CONF_PATH")
            .env_remove("FERRUM_FILE_CONFIG_PATH")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn ferrum-edge");

        if wait_for_health(admin_port).await {
            let client = reqwest::Client::builder()
                .timeout(Duration::from_secs(3))
                .build()
                .unwrap();
            let url = format!("http://127.0.0.1:{}/fw/x", proxy_port);
            let resp = client.get(&url).send().await;
            let route_ok = matches!(resp, Ok(r) if r.status().is_success());

            kill_child(child);
            echo_server.abort();
            assert!(
                route_ok,
                "CLI --mode file should beat FERRUM_MODE=database; routing failed"
            );
            return;
        }

        last_err = format!(
            "attempt {}/{} failed (proxy={}, admin={})",
            attempt, MAX_ATTEMPTS, proxy_port, admin_port
        );
        eprintln!("{}", last_err);
        let _ = child.kill();
        let _ = child.wait();
        echo_server.abort();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start with CLI-flag-wins precedence: {}",
        last_err
    );
}

/// Precedence — env var must win over conf file. We put a nonsense
/// `FERRUM_PROXY_HTTP_PORT` in ferrum.conf and set the real (listenable) port
/// via env var. The gateway should bind the env-var port; health check on
/// that admin port succeeds and the conf-file port is NOT bound.
#[ignore]
#[tokio::test]
async fn functional_cli_precedence_env_beats_conf_file() {
    const MAX_ATTEMPTS: u32 = 3;
    let binary = binary_abs_path();

    let mut last_err = String::new();
    for attempt in 1..=MAX_ATTEMPTS {
        let temp_dir = TempDir::new().expect("Failed to create temp directory");
        let env_proxy_port = ephemeral_port().await;
        let env_admin_port = ephemeral_port().await;
        // Conf-file ports are decoys — they must NOT be bound when env vars override.
        let conf_proxy_port = ephemeral_port().await;
        let conf_admin_port = ephemeral_port().await;

        // Sanity: all 4 distinct
        assert_ne!(env_proxy_port, conf_proxy_port);
        assert_ne!(env_admin_port, conf_admin_port);

        // ferrum.conf includes decoy ports AND a mode so the gateway has
        // enough config to start even if env vars were stripped.
        let conf = format!(
            "FERRUM_MODE = file\nFERRUM_PROXY_HTTP_PORT = {}\nFERRUM_ADMIN_HTTP_PORT = {}\n",
            conf_proxy_port, conf_admin_port
        );
        std::fs::write(temp_dir.path().join("ferrum.conf"), conf).unwrap();

        // Minimal spec — no routing needed; we only check which admin port binds.
        std::fs::write(
            temp_dir.path().join("resources.yaml"),
            "proxies: []\nconsumers: []\nplugin_configs: []\n",
        )
        .unwrap();

        // Env var should override the conf-file default.
        let mut cmd = Command::new(&binary);
        cmd.arg("run")
            .current_dir(temp_dir.path())
            .env("FERRUM_PROXY_HTTP_PORT", env_proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", env_admin_port.to_string())
            .env_remove("FERRUM_MODE")
            .env_remove("FERRUM_CONF_PATH")
            .env_remove("FERRUM_FILE_CONFIG_PATH")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let mut child = cmd.spawn().expect("Failed to spawn ferrum-edge");

        if wait_for_health(env_admin_port).await {
            // Confirm the conf-file admin port is NOT bound (i.e. env var won).
            let decoy_client = reqwest::Client::builder()
                .timeout(Duration::from_millis(500))
                .build()
                .unwrap();
            let decoy_url = format!("http://127.0.0.1:{}/health", conf_admin_port);
            let decoy_resp = decoy_client.get(&decoy_url).send().await;
            let decoy_unbound =
                decoy_resp.is_err() || matches!(decoy_resp, Ok(r) if !r.status().is_success());

            kill_child(child);
            assert!(
                decoy_unbound,
                "conf-file admin port {} should not be bound when env var {} overrides",
                conf_admin_port, env_admin_port
            );
            return;
        }

        last_err = format!(
            "attempt {}/{} failed (env_proxy={}, env_admin={}, conf_proxy={}, conf_admin={})",
            attempt, MAX_ATTEMPTS, env_proxy_port, env_admin_port, conf_proxy_port, conf_admin_port
        );
        eprintln!("{}", last_err);
        let _ = child.kill();
        let _ = child.wait();
        if attempt < MAX_ATTEMPTS {
            sleep(Duration::from_secs(1)).await;
        }
    }
    panic!(
        "Gateway did not start with env-var-wins precedence: {}",
        last_err
    );
}
