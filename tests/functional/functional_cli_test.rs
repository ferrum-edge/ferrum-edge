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
        "version: \"1\"\nproxies:\n  - id: test\n    listen_path: /test\n    backend_scheme: http\n    backend_host: localhost\n    backend_port: 3000\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let output = hermetic_validate_command(&temp_dir, &["--spec", spec_path.to_str().unwrap()])
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
    let temp_dir = TempDir::new().unwrap();

    let output = hermetic_validate_command(&temp_dir, &["--spec", "/nonexistent/config.yaml"])
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

    let output = hermetic_validate_command(&temp_dir, &["--spec", spec_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(!output.status.success());
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_invalid_proxy_host() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("bad-host.yaml");
    std::fs::write(
        &spec_path,
        r#"version: "1"
proxies:
  - id: bad-host
    hosts:
      - "api..example.com"
    listen_path: /test
    backend_scheme: http
    backend_host: localhost
    backend_port: 3000
consumers: []
plugin_configs: []
"#,
    )
    .unwrap();

    let output = hermetic_validate_command(&temp_dir, &["--spec", spec_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        !output.status.success(),
        "invalid host config unexpectedly passed: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("invalid host"),
        "expected hostname validation error, got: {stderr}"
    );
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
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let output = hermetic_validate_command(
        &temp_dir,
        &[
            "--settings",
            settings_path.to_str().unwrap(),
            "--spec",
            spec_path.to_str().unwrap(),
        ],
    )
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

// ── validate: external secret suffixes ──────────────────────────────────────

/// The only non-Ferrum variables carried into a hermetic validate subprocess.
///
/// Everything else is dropped by `env_clear()`, so the child cannot inherit any
/// `FERRUM_*` variable — including provider suffixes — from the invoking shell
/// or CI runner. None of these can influence secret resolution or settings
/// parsing.
const HERMETIC_ENV_PASSTHROUGH: &[&str] = &[
    // Process/loader basics.
    "PATH",
    "HOME",
    "LD_LIBRARY_PATH",
    "DYLD_LIBRARY_PATH",
    "DYLD_FALLBACK_LIBRARY_PATH",
    // Temp-dir resolution.
    "TMPDIR",
    "TMP",
    "TEMP",
    // Windows loader / profile resolution.
    "SystemRoot",
    "USERPROFILE",
    // Keep child counters attributable when the suite runs under
    // `cargo llvm-cov`; the value carries `%p` so processes cannot collide.
    "LLVM_PROFILE_FILE",
    // Diagnostics only; cannot influence secret resolution.
    "RUST_BACKTRACE",
];

/// Replace `cmd`'s environment with a closed-world hermetic one for a
/// database-mode `validate`.
///
/// The environment is built by `env_clear()` plus an allow-list rather than by
/// removing a list of known keys: validate resolves the *entire* `FERRUM_*`
/// environment before settings are parsed, so any inherited
/// `FERRUM_*_{FILE,VAULT,AWS,AZURE,GCP}` — `FERRUM_DB_URL_FILE`, for instance —
/// could fail the command on an unrelated fetch, conflict, or
/// unsupported-suffix error before a test's assertions are ever reached. A
/// deny-list would need extending for every new variable; clearing cannot
/// drift. Any variable set on `cmd` before this call is therefore also dropped,
/// which is what lets a test stage stand-ins for inherited variables and prove
/// they do not survive.
///
/// Database-mode validate requires *both* `FERRUM_DB_TYPE` and `FERRUM_DB_URL`
/// (`EnvConfig::validate`), so both are supplied explicitly; sqlite in-memory
/// keeps the check hermetic and reachable without a live database.
///
/// `current_dir()` is the temp dir so the repo's own `./ferrum.conf` is never
/// picked up by the smart-path search, which means the binary must be spawned
/// through `binary_abs_path()`. Clearing `FERRUM_CONF_PATH` is *not* enough:
/// `resolve_settings_path()` only skips discovery when the variable is set, so
/// an unset value still falls through to the `/etc/ferrum/ferrum.conf`
/// candidate on machines that have one. The variable is therefore pinned to an
/// empty settings file inside the temp dir, which suppresses discovery
/// entirely. An explicit `--settings` flag still wins, because
/// `resolve_settings_path()` returns the flag path before consulting the
/// environment.
///
/// This base helper deliberately does *not* pin a mode or a spec, so it is
/// usable by the `validate --spec ...` tests that rely on file-mode inference.
/// [`apply_hermetic_validate_env`] layers database mode on top.
fn apply_hermetic_env(cmd: &mut Command, temp_dir: &TempDir) {
    let conf_path = temp_dir.path().join("hermetic-ferrum.conf");
    std::fs::write(&conf_path, "").unwrap();

    cmd.env_clear();
    for key in HERMETIC_ENV_PASSTHROUGH {
        if let Ok(value) = std::env::var(key) {
            cmd.env(key, value);
        }
    }

    cmd.env("FERRUM_CONF_PATH", &conf_path)
        .current_dir(temp_dir.path());
}

/// Spawn `ferrum-edge validate` with the given arguments in the hermetic
/// environment, without pinning an operating mode.
///
/// Every `validate` subprocess in this file goes through this or
/// [`validate_database_mode_command`]. Validate now resolves the entire
/// `FERRUM_*` external-secret suffix inventory before settings are parsed, so a
/// stale `FERRUM_DB_URL_FILE` (or any other suffixed variable) inherited from
/// the invoking shell or CI runner can fail the command on an unrelated fetch,
/// conflict, or unsupported-suffix error before a test's own assertions are
/// reached. Isolation is a property of the whole file, not just the
/// secret-specific tests.
fn hermetic_validate_command(temp_dir: &TempDir, args: &[&str]) -> Command {
    let mut cmd = Command::new(binary_abs_path());
    cmd.arg("validate").args(args);
    apply_hermetic_env(&mut cmd, temp_dir);
    cmd
}

/// Database-mode `validate` in the hermetic environment.
///
/// Database-mode validate requires *both* `FERRUM_DB_TYPE` and `FERRUM_DB_URL`
/// (`EnvConfig::validate`), so both are supplied explicitly; sqlite in-memory
/// keeps the check hermetic and reachable without a live database.
/// `FERRUM_FILE_CONFIG_PATH` is pinned to a valid empty spec in the temp dir so
/// host-level spec discovery stays disabled even if the test mode changes
/// later.
///
/// Any variable set on `cmd` before this call is dropped by the `env_clear()`
/// inside [`apply_hermetic_env`], which is what lets a test stage stand-ins for
/// inherited variables and prove they do not survive.
fn apply_hermetic_validate_env(cmd: &mut Command, temp_dir: &TempDir) {
    apply_hermetic_env(cmd, temp_dir);

    let spec_path = temp_dir.path().join("hermetic-resources.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    cmd.env("FERRUM_MODE", "database")
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", "sqlite::memory:")
        .env("FERRUM_FILE_CONFIG_PATH", &spec_path);
}

fn validate_database_mode_command(temp_dir: &TempDir) -> Command {
    let mut cmd = Command::new(binary_abs_path());
    cmd.args(["validate"]);
    apply_hermetic_validate_env(&mut cmd, temp_dir);
    cmd
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_resolves_file_secret_suffix() {
    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        output.status.success(),
        "validate must resolve FERRUM_ADMIN_JWT_SECRET_FILE like run does: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    // Non-vacuous: `FERRUM_ADMIN_JWT_SECRET` is `required_for(["database","cp"])`
    // with `min_len(MIN_JWT_SECRET_LENGTH)`, and the helper clears the base key
    // and pins an empty settings file, so the only way parsing can reach
    // "Validation passed." is if the `_FILE` source was actually materialized
    // into the base variable.
    assert!(stdout.contains("Validation passed."));
    // The report is part of validate's stdout report block, not a tracing
    // record: `init_logging()` defaults `FERRUM_LOG_LEVEL` to `warn`, and the
    // secret-source report is an unconditional `println!` (not gated on
    // `-v/--verbose`), so an `info!` would be unreachable at the default level.
    // The hermetic helper's `env_clear()` drops `RUST_LOG` and
    // `FERRUM_LOG_LEVEL` and pins an empty settings file, so this asserts the
    // *default* invocation is visible — it cannot pass via an inherited
    // verbosity setting.
    assert!(
        stdout.contains("External secrets: OK"),
        "validate must print the external-secret report block by default: {stdout}"
    );
    assert!(
        stdout.contains("Loaded FERRUM_ADMIN_JWT_SECRET from file"),
        "validate must report the non-secret base variable and provider: {stdout}"
    );
    assert!(
        stdout.contains("Resolved 1 env var(s) from external secret sources"),
        "validate must report the resolved-source count: {stdout}"
    );
    // Only the base variable and provider name are reportable. The source
    // reference (the file path) is as sensitive as the value it points at.
    assert!(
        !stdout.contains(secret_path.to_str().unwrap())
            && !String::from_utf8_lossy(&output.stderr).contains(secret_path.to_str().unwrap()),
        "source references must never be reported: {stdout}"
    );
    // The resolved value must never be echoed on either stream.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !stdout.contains("validate-file-secret-with-well-over-32-bytes")
            && !stderr.contains("validate-file-secret-with-well-over-32-bytes"),
        "secret values must never be logged: stdout={stdout}, stderr={stderr}"
    );
}

/// Proves the hermetic helper's closed-world isolation, not just that it is
/// written that way.
///
/// The three variables staged before `apply_hermetic_validate_env()` sit
/// exactly where an inherited variable from the invoking shell or CI runner
/// would sit, and each one alone is fatal if it survives: `FERRUM_DB_URL_FILE`
/// points at a missing file (read failure), `FERRUM_ADMIN_JWT_SECRET_VAULT` is
/// an unsupported-suffix error in a default build and an unreachable fetch in a
/// `cloud-secrets` build, and the bare `FERRUM_ADMIN_JWT_SECRET` alongside the
/// `_FILE` source is a provider conflict. Reaching "Validation passed." is
/// therefore only possible if all three were cleared.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_isolates_inherited_secret_environment() {
    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let mut cmd = Command::new(binary_abs_path());
    cmd.args(["validate"])
        .env(
            "FERRUM_DB_URL_FILE",
            temp_dir.path().join("inherited-missing-db-url"),
        )
        .env(
            "FERRUM_ADMIN_JWT_SECRET_VAULT",
            "secret/data/ferrum/edge#jwt",
        )
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            "inherited-direct-secret-value-well-over-32-bytes",
        );
    apply_hermetic_validate_env(&mut cmd, &temp_dir);

    let output = cmd
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "hermetic env must drop inherited FERRUM_* secret sources: stdout={stdout}, stderr={stderr}"
    );
    assert!(stdout.contains("Validation passed."));
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_secret_source_conflict() {
    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    // A base variable plus a suffixed source for the same key is a provider
    // conflict that `run` rejects; validate must fail identically.
    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            "direct-secret-value-with-well-over-32-bytes",
        )
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        !output.status.success(),
        "validate must reject conflicting secret sources like run does: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Assert the reason, so an unrelated validation failure cannot make this
    // test pass vacuously.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Multiple secret sources configured for FERRUM_ADMIN_JWT_SECRET"),
        "expected a secret source conflict error, got: {stderr}"
    );
    // The resolved value must never reach the error output.
    assert!(
        !stderr.contains("direct-secret-value-with-well-over-32-bytes")
            && !stderr.contains("validate-file-secret-with-well-over-32-bytes"),
        "secret values must never be logged: {stderr}"
    );
}

#[ignore]
#[tokio::test]
async fn functional_cli_validate_fails_on_secret_resolution_error() {
    let temp_dir = TempDir::new().unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            temp_dir.path().join("does-not-exist").to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        !output.status.success(),
        "validate must fail when a suffixed secret source cannot be read: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    // Assert the reason, so an unrelated validation failure cannot make this
    // test pass vacuously.
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to read FERRUM_ADMIN_JWT_SECRET_FILE"),
        "expected a secret read failure error, got: {stderr}"
    );
    // The source reference is as sensitive as the value it points at, and the
    // success report already reports base key + provider only. A failure must
    // not be the path that discloses it.
    let missing_path = temp_dir.path().join("does-not-exist");
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(
        !stderr.contains(missing_path.to_str().unwrap())
            && !stdout.contains(missing_path.to_str().unwrap()),
        "secret source references must never be reported: stdout={stdout}, stderr={stderr}"
    );
}

/// External values are materialized into the environment before
/// `EnvConfig::from_env()`, so an ordinary typed parse failure on a
/// secret-backed variable would otherwise echo the fetched secret verbatim
/// (`Invalid FERRUM_PROXY_HTTP_PORT value '<secret>'`).
///
/// Non-vacuous by construction: the sentinel is the *only* thing that could
/// make `FERRUM_PROXY_HTTP_PORT` fail to parse, so reaching the expected error
/// proves the `_FILE` source really was materialized, and the absence
/// assertions then cover both streams.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_redacts_resolved_value_in_settings_error() {
    const SENTINEL: &str = "ferrum-resolved-secret-sentinel-must-not-be-printed";

    let temp_dir = TempDir::new().unwrap();
    let jwt_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&jwt_path, "validate-file-secret-with-well-over-32-bytes").unwrap();
    let port_path = temp_dir.path().join("proxy-port");
    std::fs::write(&port_path, SENTINEL).unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", jwt_path.to_str().unwrap())
        .env("FERRUM_PROXY_HTTP_PORT_FILE", port_path.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "an unparseable resolved value must fail validation: stdout={stdout}, stderr={stderr}"
    );
    // The variable name and expected shape stay actionable.
    assert!(
        stderr.contains("Invalid FERRUM_PROXY_HTTP_PORT"),
        "expected a typed settings parse failure, got: {stderr}"
    );
    assert!(
        stderr.contains("value from external secret source"),
        "expected the withheld-value marker, got: {stderr}"
    );
    // The resolved value itself must not appear on either stream.
    assert!(
        !stderr.contains(SENTINEL) && !stdout.contains(SENTINEL),
        "externally resolved secret values must never be printed: \
         stdout={stdout}, stderr={stderr}"
    );
}

/// A hand-written `EnvConfig::validate()` scalar diagnostic must withhold a
/// secret-backed value by key, not rely on the textual backstop.
///
/// `FERRUM_HTTP3_INITIAL_MTU` is re-rendered as the canonical `u16` `Display` of
/// what was parsed, so a resolved `071` reaches the operator as `71`. The exact
/// materialized value has no minimum length and would be filtered, but `71` is a
/// *derived* form at two bytes — below `MIN_DERIVED_CANDIDATE_LEN`, which the
/// textual pass deliberately will not admit, because arming a two-digit string
/// process-wide shreds every unrelated diagnostic containing it. So this
/// rendering is only covered if the site names the variable.
///
/// The padding is load-bearing: `071` parses to a legal `u16` but is below
/// `QUIC_INITIAL_MTU_MIN` (1200), so it reaches the range check rather than
/// failing to parse earlier, and it is the *only* thing that can produce this
/// error — reaching it proves the `_FILE` source really was materialized.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_withholds_secret_backed_scalar_in_range_error() {
    let temp_dir = TempDir::new().unwrap();
    let jwt_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&jwt_path, "validate-file-secret-with-well-over-32-bytes").unwrap();
    let mtu_path = temp_dir.path().join("initial-mtu");
    std::fs::write(&mtu_path, "071").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", jwt_path.to_str().unwrap())
        .env("FERRUM_HTTP3_INITIAL_MTU_FILE", mtu_path.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "an out-of-range resolved MTU must fail validation: stdout={stdout}, stderr={stderr}"
    );
    // The variable name and the legal range stay actionable.
    assert!(
        stderr.contains("FERRUM_HTTP3_INITIAL_MTU"),
        "expected the range diagnostic, got: {stderr}"
    );
    assert!(
        stderr.contains("value from external secret source"),
        "expected the withheld-value marker, got: {stderr}"
    );
    // The canonical rendering of the resolved value is what leaked. Assert the
    // exact interpolation rather than a bare `71`, which occurs incidentally in
    // unrelated numbers.
    assert!(
        !stderr.contains("FERRUM_HTTP3_INITIAL_MTU (71)")
            && !stdout.contains("FERRUM_HTTP3_INITIAL_MTU (71)"),
        "the parsed rendering of an externally resolved value must not be printed: \
         stdout={stdout}, stderr={stderr}"
    );
}

/// Non-vacuity control for the test above: an ordinary, non-secret-backed value
/// stays visible in the same diagnostic.
///
/// Key-tied withholding is scoped to variables that were externally resolved.
/// Without this control, a site that withheld the value unconditionally — or one
/// that simply stopped printing it — would satisfy the redaction assertion while
/// making an ordinary misconfiguration undiagnosable.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_shows_ordinary_scalar_in_range_error() {
    let temp_dir = TempDir::new().unwrap();
    let jwt_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&jwt_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", jwt_path.to_str().unwrap())
        // Set directly rather than through a `_FILE` suffix: this variable was
        // not externally resolved, so the value must survive.
        .env("FERRUM_HTTP3_INITIAL_MTU", "1199")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "an out-of-range MTU must fail validation: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.contains("FERRUM_HTTP3_INITIAL_MTU (1199)"),
        "an ordinary configuration value must stay diagnosable, got: {stderr}"
    );
}

/// Redaction must read the original diagnostic only, never the text it just
/// substituted.
///
/// Every value staged here is a substring of `EXTERNAL_SECRET_PLACEHOLDER`
/// (`<redacted: value from external secret source>`), so a redactor that
/// loops `replace()` over the running message
/// feeds each pass the placeholders emitted by the previous one. Each short
/// value then multiplies the diagnostic by that character's density in the
/// placeholder, and ten externally resolved values are enough to turn one
/// startup error into megabytes — a validation-time memory/CPU exhaustion
/// reachable by config alone. `a` is staged under two keys to cover duplicate
/// values, and `f` collides with the sentinel's first character so the run also
/// pins longest-match-first.
///
/// The load-bearing assertion is the *intact* placeholder: substitution output
/// is only ever appended, so it survives passes that would otherwise replace its
/// own `a`/`e`/`s`. A re-scanning redactor shreds its own placeholders and
/// cannot satisfy it. The length bound then covers the amplification directly.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_bounds_redaction_of_short_secret_values() {
    // Invalid only because of the trailing `!`. `validate_namespace()`
    // interpolates the offending value into a hand-written message, which is the
    // class of diagnostic this backstop exists for — unlike a typed `EnvConfig`
    // parse failure, which already withholds the value by key at
    // `invalid_env_value`.
    const SENTINEL: &str = "ferrum-redaction-sentinel-must-not-be-printed!";
    const PROBE_VALUES: &[&str] = &[
        "external", "source", "value", "a", "a", "e", "f", "o", "r", "s",
    ];
    // ~30x headroom over the bounded output (the diagnostic is a few hundred
    // characters and each can expand to one placeholder at most), and well
    // under the amplified megabytes.
    const MAX_OUTPUT_BYTES: usize = 256 * 1024;

    let temp_dir = TempDir::new().unwrap();
    let namespace_path = temp_dir.path().join("namespace");
    std::fs::write(&namespace_path, SENTINEL).unwrap();

    let mut cmd = validate_database_mode_command(&temp_dir);
    cmd.env("FERRUM_NAMESPACE_FILE", namespace_path.to_str().unwrap())
        // The default 64 KiB per-record cap would truncate an amplified
        // diagnostic into looking bounded. Raised to the maximum so the
        // assertion observes the string redaction actually built.
        .env("FERRUM_LOG_MAX_RECORD_BYTES", "1048576");

    for (index, value) in PROBE_VALUES.iter().enumerate() {
        let probe_path = temp_dir.path().join(format!("probe-{index}"));
        std::fs::write(&probe_path, value).unwrap();
        // Unrecognized `FERRUM_*` names are inert for settings parsing but are
        // still discovered by secret resolution, so each adds a resolved value
        // without perturbing the diagnostic under test.
        cmd.env(
            format!("FERRUM_REDACTION_PROBE_{index}_FILE"),
            probe_path.to_str().unwrap(),
        );
    }

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "an invalid resolved namespace must fail validation: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.contains(ferrum_edge::secrets::EXTERNAL_SECRET_PLACEHOLDER),
        "an intact placeholder must survive redaction, proving substituted text \
         is not itself re-scanned: {stderr}"
    );
    assert!(
        !stderr.contains(SENTINEL) && !stdout.contains(SENTINEL),
        "externally resolved secret values must never be printed: \
         stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.len() <= MAX_OUTPUT_BYTES && stdout.len() <= MAX_OUTPUT_BYTES,
        "redaction output must stay bounded in the original diagnostic, got \
         stdout={} bytes, stderr={} bytes",
        stdout.len(),
        stderr.len()
    );
}

/// `loaded_sources` is derived from `HashMap` iteration over the environment,
/// so without an explicit sort two runs on identical input can print the report
/// lines in different orders.
///
/// The two sources are staged in reverse of the expected order, and the
/// assertion is on relative position rather than mere presence.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_reports_secret_sources_in_sorted_order() {
    let temp_dir = TempDir::new().unwrap();
    let admin_path = temp_dir.path().join("admin-jwt-secret");
    std::fs::write(&admin_path, "validate-file-secret-with-well-over-32-bytes").unwrap();
    let cp_dp_path = temp_dir.path().join("cp-dp-jwt-secret");
    std::fs::write(&cp_dp_path, "validate-cp-dp-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_CP_DP_GRPC_JWT_SECRET_FILE",
            cp_dp_path.to_str().unwrap(),
        )
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", admin_path.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "validate failed: stdout={stdout}, stderr={stderr}"
    );

    let admin_line = stdout
        .find("Loaded FERRUM_ADMIN_JWT_SECRET from file")
        .unwrap_or_else(|| panic!("missing FERRUM_ADMIN_JWT_SECRET report line: {stdout}"));
    let cp_dp_line = stdout
        .find("Loaded FERRUM_CP_DP_GRPC_JWT_SECRET from file")
        .unwrap_or_else(|| panic!("missing FERRUM_CP_DP_GRPC_JWT_SECRET report line: {stdout}"));
    assert!(
        admin_line < cp_dp_line,
        "secret source lines must be ordered by base key: {stdout}"
    );
    assert!(
        stdout.contains("Resolved 2 env var(s) from external secret sources"),
        "expected both sources to be counted: {stdout}"
    );
}

/// The returned-error sanitizers cannot see a diagnostic that is never
/// returned.
///
/// `FERRUM_TLS_EARLY_DATA_METHODS` is parsed inside `EnvConfig::from_env()`,
/// which uppercases each token and `warn!`s about any non-`GET` one. That
/// warning is written straight to the log sink on an **otherwise successful**
/// `validate`: there is no `Err` for `redact_external_secret_values` to filter,
/// so redaction has to happen where the record is serialized. The value is also
/// uppercased before interpolation, so it shares no substring with the resolved
/// value — exact-value matching alone would not catch it either.
///
/// Non-vacuous by construction: the sentinel is the only non-`GET` token, so
/// the presence of the placeholder proves the warning fired and was filtered
/// rather than never being emitted.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_redacts_resolved_value_in_startup_warning() {
    const SENTINEL: &str = "ferrum-early-data-method-sentinel";

    let temp_dir = TempDir::new().unwrap();
    let jwt_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&jwt_path, "validate-file-secret-with-well-over-32-bytes").unwrap();
    let methods_path = temp_dir.path().join("early-data-methods");
    std::fs::write(&methods_path, SENTINEL).unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", jwt_path.to_str().unwrap())
        .env(
            "FERRUM_TLS_EARLY_DATA_METHODS_FILE",
            methods_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    // A non-GET method is a warning, not a failure: this is the success path.
    assert!(
        output.status.success(),
        "a non-GET early-data method must warn, not fail: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.contains("FERRUM_TLS_EARLY_DATA_METHODS includes non-GET method"),
        "the warning must still be emitted and actionable: {stderr}"
    );
    assert!(
        stderr.contains("value from external secret source"),
        "the warning must carry the withheld-value marker: {stderr}"
    );
    // Neither the resolved value nor the uppercased form the warning
    // interpolates may appear on either stream.
    let upper = SENTINEL.to_ascii_uppercase();
    assert!(
        !stderr.contains(SENTINEL)
            && !stdout.contains(SENTINEL)
            && !stderr.contains(&upper)
            && !stdout.contains(&upper),
        "an externally resolved value must not leak through a log record, \
         in any case form: stdout={stdout}, stderr={stderr}"
    );
}

/// Some validators echo a *transformed* form of the value, so matching the
/// resolved value verbatim is not enough.
///
/// `FERRUM_CP_NAMESPACES` is parsed as `Vec<String>`, which splits on `,` and
/// trims each entry, and `EnvConfig::validate()` then interpolates the trimmed
/// **entry** into a hand-written error. The staged value carries leading
/// whitespace that `read_secret` (which only trims the *trailing* end) leaves
/// intact, so the resolved environment value and the echoed entry are different
/// strings and only a derived candidate can match.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_redacts_transformed_list_entry() {
    const ENTRY: &str = "ferrum-namespace-entry-sentinel!";

    let temp_dir = TempDir::new().unwrap();
    let jwt_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&jwt_path, "validate-file-secret-with-well-over-32-bytes").unwrap();
    let namespaces_path = temp_dir.path().join("cp-namespaces");
    // Leading whitespace survives `read_secret`'s trailing-only trim.
    std::fs::write(&namespaces_path, format!("   {ENTRY}")).unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", jwt_path.to_str().unwrap())
        .env(
            "FERRUM_CP_NAMESPACES_FILE",
            namespaces_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !output.status.success(),
        "an invalid namespace entry must fail validation: stdout={stdout}, stderr={stderr}"
    );
    // The variable stays named, so the operator knows what to fix.
    assert!(
        stderr.contains("FERRUM_CP_NAMESPACES"),
        "expected the namespace validation failure, got: {stderr}"
    );
    assert!(
        stderr.contains("value from external secret source"),
        "expected the withheld-value marker, got: {stderr}"
    );
    assert!(
        !stderr.contains(ENTRY) && !stdout.contains(ENTRY),
        "a trimmed form of an externally resolved value must not survive: \
         stdout={stdout}, stderr={stderr}"
    );
}

/// The settings path can itself come from an external secret source, and the
/// resolved path must be installed *before* anything reads `ferrum.conf`.
///
/// `CONF_FILE_CACHE` is a process-wide `OnceLock` populated from whatever
/// `FERRUM_CONF_PATH` says the first time any conf-file-aware lookup misses. If
/// secret resolution itself performs such a lookup — as the fetch-timeout read
/// used to — the cache is frozen on the default/discovered settings file before
/// `FERRUM_CONF_PATH_FILE` is materialized, and the intended settings file is
/// silently ignored for the rest of the process.
///
/// Non-vacuous by construction: `FERRUM_ADMIN_JWT_SECRET` is required in
/// database mode and is supplied **only** by the resolved settings file, so
/// `validate` can reach "Validation passed." only if that file was actually
/// read. `FERRUM_CONF_PATH` is removed rather than set, which is the shape an
/// operator using `FERRUM_CONF_PATH_FILE` has; the temp `current_dir` keeps
/// `./ferrum.conf` discovery empty.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_uses_settings_path_from_file_secret_source() {
    let temp_dir = TempDir::new().unwrap();

    let settings_path = temp_dir.path().join("resolved-ferrum.conf");
    std::fs::write(
        &settings_path,
        "FERRUM_ADMIN_JWT_SECRET = settings-file-secret-with-well-over-32-bytes\n",
    )
    .unwrap();

    let settings_pointer = temp_dir.path().join("settings-path-source");
    std::fs::write(&settings_pointer, settings_path.to_str().unwrap()).unwrap();

    let mut cmd = Command::new(binary_abs_path());
    cmd.args(["validate"]);
    apply_hermetic_validate_env(&mut cmd, &temp_dir);
    // The hermetic helper pins an empty settings file; this test is precisely
    // about the path being resolved instead of pre-set.
    cmd.env_remove("FERRUM_CONF_PATH");
    cmd.env("FERRUM_CONF_PATH_FILE", settings_pointer.to_str().unwrap());

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "the settings file resolved from FERRUM_CONF_PATH_FILE must be the one \
         validated: stdout={stdout}, stderr={stderr}"
    );
    assert!(stdout.contains("Validation passed."));
    assert!(
        stdout.contains("Loaded FERRUM_CONF_PATH from file"),
        "the settings path must be reported as an externally resolved source: {stdout}"
    );
    // The resolved value here is a path, and a source reference is as sensitive
    // as the value it points at.
    assert!(
        !stdout.contains(settings_pointer.to_str().unwrap())
            && !stderr.contains(settings_pointer.to_str().unwrap()),
        "source references must never be reported: stdout={stdout}, stderr={stderr}"
    );
}

/// Smart path discovery must yield to a secret-backed settings path.
///
/// Discovery runs in `main()` *before* startup secret resolution, so a
/// `FERRUM_CONF_PATH_FILE` has not been materialized yet and the
/// "is `FERRUM_CONF_PATH` already set?" check sees nothing. Auto-setting a
/// discovered `./ferrum.conf` there is indistinguishable, to
/// `resolve_all_env_secrets`, from an operator who configured two sources — so
/// before the fix, running `validate` in any directory that merely happens to
/// contain a `ferrum.conf` failed the whole command with a multiple-sources
/// error instead of using the secret-backed path the docs promise.
///
/// Non-vacuous by construction: the discovered `./ferrum.conf` carries an
/// admin JWT secret that is *too short* for database mode, and the file behind
/// `FERRUM_CONF_PATH_FILE` carries a valid one. Reaching "Validation passed."
/// is only possible if the resolved path won.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_prefers_secret_settings_path_over_discovered_conf() {
    let temp_dir = TempDir::new().unwrap();

    // The competing auto-discovered source: `./ferrum.conf` in the CWD.
    std::fs::write(
        temp_dir.path().join("ferrum.conf"),
        "FERRUM_ADMIN_JWT_SECRET = too-short\n",
    )
    .unwrap();

    let settings_path = temp_dir.path().join("resolved-ferrum.conf");
    std::fs::write(
        &settings_path,
        "FERRUM_ADMIN_JWT_SECRET = settings-file-secret-with-well-over-32-bytes\n",
    )
    .unwrap();

    let settings_pointer = temp_dir.path().join("settings-path-source");
    std::fs::write(&settings_pointer, settings_path.to_str().unwrap()).unwrap();

    let mut cmd = Command::new(binary_abs_path());
    cmd.args(["validate"]);
    apply_hermetic_validate_env(&mut cmd, &temp_dir);
    cmd.env_remove("FERRUM_CONF_PATH");
    cmd.env("FERRUM_CONF_PATH_FILE", settings_pointer.to_str().unwrap());

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("Multiple secret sources"),
        "an auto-discovered default must not be treated as a competing \
         user-provided source: stderr={stderr}"
    );
    assert!(
        output.status.success(),
        "the secret-backed settings path must win over discovery: \
         stdout={stdout}, stderr={stderr}"
    );
    assert!(stdout.contains("Validation passed."));
    assert!(stdout.contains("Loaded FERRUM_CONF_PATH from file"));
}

/// The same yield, for the resources path — and for the file-mode inference
/// that hangs off it.
///
/// `FERRUM_FILE_CONFIG_PATH_FILE` must both suppress `./resources.yaml`
/// discovery and still count as "a spec is configured" for mode inference,
/// which also runs before resolution. Non-vacuous twice over: the discovered
/// `./resources.yaml` is unparseable, so validating it would fail, and no
/// `FERRUM_MODE` is set, so reaching a spec check at all requires the
/// inference to have seen the suffixed source.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_prefers_secret_spec_path_over_discovered_resources() {
    let temp_dir = TempDir::new().unwrap();

    // The competing auto-discovered source, deliberately invalid.
    std::fs::write(
        temp_dir.path().join("resources.yaml"),
        "this is not: [valid yaml: for ferrum\n",
    )
    .unwrap();

    let spec_path = temp_dir.path().join("resolved-resources.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies:\n  - id: resolved\n    listen_path: /resolved\n    \
         backend_scheme: http\n    backend_host: localhost\n    backend_port: 3000\n\
         consumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let spec_pointer = temp_dir.path().join("spec-path-source");
    std::fs::write(&spec_pointer, spec_path.to_str().unwrap()).unwrap();

    let mut cmd = hermetic_validate_command(&temp_dir, &[]);
    cmd.env(
        "FERRUM_FILE_CONFIG_PATH_FILE",
        spec_pointer.to_str().unwrap(),
    );

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("Multiple secret sources"),
        "discovery must yield to the suffixed spec source: stderr={stderr}"
    );
    assert!(
        output.status.success(),
        "the secret-backed spec path must win over discovery: \
         stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stdout.contains("Mode: File"),
        "a suffixed spec source must still infer file mode: {stdout}"
    );
    assert!(
        stdout.contains("Proxies: 1"),
        "the resolved spec must be the one validated: {stdout}"
    );
    // The resolved path is itself an externally resolved value, so the `Spec
    // (...)` line withholds it rather than echoing it back.
    assert!(
        !stdout.contains(spec_path.to_str().unwrap()),
        "the resolved spec path must not be echoed: {stdout}"
    );
}

/// An externally sourced `FERRUM_MODE` is an explicit env source and must beat
/// the file-mode smart default, even with a spec path configured.
///
/// Inferring before startup secret resolution got this wrong twice over: the
/// suffixed source was invisible, *and* the synthetic `FERRUM_MODE=file` the
/// inference wrote became a second source for the same base key, so the
/// resolver failed the whole command with a multiple-sources error. A
/// deployment that externalizes both its mode and its spec path could not
/// validate or start at all.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_external_mode_source_beats_file_inference() {
    let temp_dir = TempDir::new().unwrap();

    // A spec path is configured directly, which is what used to trigger the
    // premature inference.
    let spec_path = temp_dir.path().join("resources.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let mode_pointer = temp_dir.path().join("mode-source");
    std::fs::write(&mode_pointer, "database").unwrap();

    let mut cmd = hermetic_validate_command(&temp_dir, &[]);
    cmd.env("FERRUM_MODE_FILE", mode_pointer.to_str().unwrap())
        .env("FERRUM_FILE_CONFIG_PATH", spec_path.to_str().unwrap())
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", "sqlite::memory:")
        // Database mode also requires an admin JWT secret of >= 32 bytes.
        // Supplied as a bare env value, not a suffixed source, so it stays out
        // of the external-resolution surface this test is about.
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            "fixture-admin-jwt-secret-not-a-real-credential",
        );

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        !stderr.contains("Multiple secret sources"),
        "mode inference must not synthesize a competing FERRUM_MODE source: stderr={stderr}"
    );
    assert!(
        output.status.success(),
        "externalizing both the mode and the spec path must validate: \
         stdout={stdout}, stderr={stderr}"
    );
    // The Mode field itself is withheld (it *is* the externally resolved
    // value), so the selected mode is proven by what the report does next:
    // file mode validates the spec surface and prints `Spec (...)`, database
    // mode does not.
    assert!(
        !stdout.contains("Spec ("),
        "the smart default must not override an externally sourced database mode: {stdout}"
    );
}

/// The resolved value of an externally sourced `FERRUM_MODE` must not come back
/// out on stdout.
///
/// `validate`'s report is a plain `println!`: it is not a tracing record, so the
/// `RecordWriter` emission boundary never sees it, and a *successful* run
/// returns no error for the final redactor to filter. The mode is also
/// re-rendered rather than echoed — `Mode: {:?}` turns a resolved `database`
/// into `Database`, which textual candidate derivation deliberately does not
/// produce — so the field is withheld by key instead.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_does_not_echo_externally_sourced_mode() {
    // Database mode requires an admin JWT secret of >= 32 bytes. It is a bare
    // env value rather than a suffixed source, so it adds nothing to the
    // redaction plan this test inspects.
    const ADMIN_SECRET: &str = "fixture-admin-jwt-secret-not-a-real-credential";

    let temp_dir = TempDir::new().unwrap();

    let mode_pointer = temp_dir.path().join("mode-source");
    std::fs::write(&mode_pointer, "database").unwrap();

    let mut cmd = hermetic_validate_command(&temp_dir, &[]);
    cmd.env("FERRUM_MODE_FILE", mode_pointer.to_str().unwrap())
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", "sqlite::memory:")
        .env("FERRUM_ADMIN_JWT_SECRET", ADMIN_SECRET);

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "database-mode validate should succeed: stdout={stdout}, stderr={stderr}"
    );
    // Non-vacuous: the report definitely printed a Mode line.
    assert!(
        stdout.contains("  Mode: "),
        "the validate report must still print a Mode field: {stdout}"
    );
    assert!(
        !stdout.contains("Mode: Database"),
        "the externally resolved mode value must not be echoed back: {stdout}"
    );
    assert!(
        stdout.contains("Mode: <redacted: value from external secret source>"),
        "the Mode field must be withheld by key: {stdout}"
    );
    assert!(
        stdout.contains("Validation passed."),
        "withholding the value must not cost the validation result: {stdout}"
    );
    // The fixture's own credential must not ride along in the report either.
    assert!(
        !stdout.contains(ADMIN_SECRET) && !stderr.contains(ADMIN_SECRET),
        "the admin JWT secret must never be reported: stdout={stdout}, stderr={stderr}"
    );
}

/// A mode configured in `ferrum.conf` outranks the file-mode smart default.
///
/// Materializing the inference as `FERRUM_MODE=file` inverts the documented
/// `CLI > env > conf file > smart defaults` order, because `EnvConfig` gives the
/// environment precedence over the settings file. The result is silent: the
/// operator asked to validate a database deployment and got a file-mode check.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_conf_mode_beats_external_spec_inference() {
    let temp_dir = TempDir::new().unwrap();

    let spec_path = temp_dir.path().join("resolved-resources.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();
    let spec_pointer = temp_dir.path().join("spec-path-source");
    std::fs::write(&spec_pointer, spec_path.to_str().unwrap()).unwrap();

    let conf_path = temp_dir.path().join("configured-mode.conf");
    std::fs::write(
        &conf_path,
        // The admin JWT secret is required in database mode and comes from the
        // same settings file whose precedence this test is about.
        "FERRUM_MODE = database\nFERRUM_DB_TYPE = sqlite\nFERRUM_DB_URL = sqlite::memory:\n\
         FERRUM_ADMIN_JWT_SECRET = fixture-admin-jwt-secret-not-a-real-credential\n",
    )
    .unwrap();

    // `--settings` outranks the hermetic helper's own `FERRUM_CONF_PATH`.
    let mut cmd =
        hermetic_validate_command(&temp_dir, &["--settings", conf_path.to_str().unwrap()]);
    cmd.env(
        "FERRUM_FILE_CONFIG_PATH_FILE",
        spec_pointer.to_str().unwrap(),
    );

    let output = cmd
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "database-mode validate should succeed: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stdout.contains("Mode: Database"),
        "the configured conf-file mode must win over the smart default: {stdout}"
    );
    assert!(
        !stdout.contains("Mode: File"),
        "the smart default must not override the settings file: {stdout}"
    );
    // Database mode never reaches the spec check, so a file-mode misfire would
    // also have shown up as a `Spec (...)` line.
    assert!(
        !stdout.contains("Spec ("),
        "database mode must not validate a spec surface: {stdout}"
    );
}

/// Issue #2392 reproduction: a coincidental `./resources.yaml` next to a
/// non-file `ferrum.conf` must not flip `validate` into file mode.
///
/// Smart discovery installs `FERRUM_FILE_CONFIG_PATH` from the CWD candidate,
/// but mode inference is a smart default and must yield to the selected
/// settings file.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_conf_mode_beats_smart_discovered_spec() {
    let temp_dir = TempDir::new().unwrap();

    std::fs::write(
        temp_dir.path().join("resources.yaml"),
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let conf_path = temp_dir.path().join("ferrum.conf");
    std::fs::write(
        &conf_path,
        "FERRUM_MODE = database\nFERRUM_DB_TYPE = sqlite\nFERRUM_DB_URL = sqlite::memory:\n\
         FERRUM_ADMIN_JWT_SECRET = fixture-admin-jwt-secret-not-a-real-credential\n",
    )
    .unwrap();

    // hermetic helper pins an empty FERRUM_CONF_PATH and sets current_dir to the
    // temp dir so ./resources.yaml is the discovery candidate. --settings wins
    // for the settings path; FERRUM_MODE and FERRUM_FILE_CONFIG_PATH stay unset
    // so only conf + discovery drive the decision.
    let output = hermetic_validate_command(&temp_dir, &["--settings", conf_path.to_str().unwrap()])
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "database-mode validate should succeed: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stdout.contains("Mode: Database"),
        "conf-file mode must win over smart-discovered resources: {stdout}"
    );
    assert!(
        !stdout.contains("Mode: File"),
        "smart-discovered resources must not promote file mode: {stdout}"
    );
    assert!(
        !stdout.contains("Spec ("),
        "database mode must not validate a spec surface: {stdout}"
    );
}

/// Explicit `--spec` installs the resources path but must not demote a
/// non-file mode from the selected settings file.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_conf_mode_beats_explicit_spec() {
    let temp_dir = TempDir::new().unwrap();

    let spec_path = temp_dir.path().join("resources.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let conf_path = temp_dir.path().join("ferrum.conf");
    std::fs::write(
        &conf_path,
        "FERRUM_MODE = database\nFERRUM_DB_TYPE = sqlite\nFERRUM_DB_URL = sqlite::memory:\n\
         FERRUM_ADMIN_JWT_SECRET = fixture-admin-jwt-secret-not-a-real-credential\n",
    )
    .unwrap();

    let output = hermetic_validate_command(
        &temp_dir,
        &[
            "--settings",
            conf_path.to_str().unwrap(),
            "--spec",
            spec_path.to_str().unwrap(),
        ],
    )
    .stdout(Stdio::piped())
    .stderr(Stdio::piped())
    .output()
    .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);

    assert!(
        output.status.success(),
        "database-mode validate should succeed: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stdout.contains("Mode: Database"),
        "conf-file mode must win over explicit --spec: {stdout}"
    );
    assert!(
        !stdout.contains("Mode: File"),
        "explicit --spec must not promote file mode over ferrum.conf: {stdout}"
    );
    assert!(
        !stdout.contains("Spec ("),
        "database mode must not validate a spec surface: {stdout}"
    );
}

// ── run ─────────────────────────────────────────────────────────────────────

#[ignore]
#[tokio::test]
async fn functional_cli_run_starts_and_stops() {
    let temp_dir = TempDir::new().unwrap();
    let spec_path = temp_dir.path().join("config.yaml");
    std::fs::write(
        &spec_path,
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
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
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
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
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
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
            r#"version: "1"
proxies:
  - id: "smart-path-proxy"
    listen_path: "/sp"
    backend_scheme: http
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
            r#"version: "1"
proxies:
  - id: "spec-infer-proxy"
    listen_path: "/si"
    backend_scheme: http
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
            r#"version: "1"
proxies:
  - id: "flag-wins-proxy"
    listen_path: "/fw"
    backend_scheme: http
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
        // Hold decoy port listeners so that (a) no other CI process can
        // grab them (eliminating false-positive port collisions) and
        // (b) the gateway would fatal-fail if it tried to bind them.
        let conf_proxy_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind decoy proxy");
        let conf_proxy_port = conf_proxy_listener.local_addr().unwrap().port();
        let conf_admin_listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind decoy admin");
        let conf_admin_port = conf_admin_listener.local_addr().unwrap().port();

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
            "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
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
            // The gateway started and its admin health is reachable on the
            // env-var port. Because the conf-file decoy ports are held by
            // our listeners, the gateway would have fatally failed to start
            // if it tried to bind them — so reaching this point proves
            // env-var precedence works.
            kill_child(child);
            drop(conf_proxy_listener);
            drop(conf_admin_listener);
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

// ── validate: non-Unicode environment ───────────────────────────────────────
//
// Startup secret discovery enumerates the environment before settings are
// parsed. `std::env::vars()` *panics* on any non-Unicode name or value, and it
// panics during iteration — before the `FERRUM_` filter can run — so a single
// unrelated variable was enough to abort `validate` with no diagnostic at all.
// Discovery therefore uses `vars_os()` and screens the prefix on raw bytes.
//
// Unix-gated: these stage genuinely invalid UTF-8 through `OsStr::from_bytes`,
// which is a Unix extension. Windows environment strings are WTF-16 and cannot
// express this case.

/// An unrelated non-Unicode variable must be ignored, not fatal.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_ignores_unrelated_non_unicode_env() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        // Not `FERRUM_`-prefixed, and invalid UTF-8 in both name and value.
        // Set *after* the hermetic builder, whose `env_clear()` would drop it.
        .env(
            std::ffi::OsStr::from_bytes(b"UNRELATED_NON_UNICODE_\xff"),
            std::ffi::OsStr::from_bytes(b"\xff\xfe"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "an unrelated non-Unicode variable must not fail validate: stdout={stdout}, stderr={stderr}"
    );
    // Non-vacuous: proves discovery still ran and resolved the `_FILE` source
    // rather than skipping the environment wholesale.
    assert!(
        stdout.contains("Validation passed."),
        "validate must still succeed: {stdout}"
    );
    assert!(
        stdout.contains("Loaded FERRUM_ADMIN_JWT_SECRET from file"),
        "discovery must still resolve suffixed sources: {stdout}"
    );
}

/// A `FERRUM_*` variable whose *name* is not Unicode fails closed with a
/// sanitized diagnostic. The suffix sits at the end of the name, so an
/// undecodable name may well be a configured source that cannot be read;
/// skipping it would silently drop it.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_non_unicode_ferrum_name() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            std::ffi::OsStr::from_bytes(b"FERRUM_BAD_\xff_FILE"),
            "/nonexistent",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a non-Unicode FERRUM_ name must fail closed: stderr={stderr}"
    );
    assert!(
        stderr.contains("is not valid Unicode"),
        "the diagnostic must name the failure class: {stderr}"
    );
    // Sanitized to its ASCII skeleton: the operator can find the variable, and
    // the undecodable byte is never echoed.
    assert!(
        stderr.contains("FERRUM_BAD_?_FILE"),
        "the diagnostic must name the sanitized variable: {stderr}"
    );
    assert!(
        !output.stderr.contains(&0xffu8),
        "raw undecodable bytes must never reach the operator: {stderr}"
    );
}

/// A recognized suffixed *source* key whose value is not Unicode is an unusable
/// reference and fails closed. An ordinary base key holding undecodable bytes
/// also fails closed, but later and with its own message — see
/// `functional_cli_validate_rejects_non_unicode_direct_value` below.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_non_unicode_source_reference() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            std::ffi::OsStr::from_bytes(b"/tmp/\xff-secret"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an undecodable source reference must fail closed: stderr={stderr}"
    );
    assert!(
        stderr.contains("is not valid Unicode"),
        "the diagnostic must name the failure class: {stderr}"
    );
    assert!(
        stderr.contains("FERRUM_ADMIN_JWT_SECRET_FILE"),
        "the diagnostic must name the variable: {stderr}"
    );
    assert!(
        !output.stderr.contains(&0xffu8),
        "the undecodable reference bytes must never be echoed: {stderr}"
    );
}

/// A *direct* Ferrum configuration value that is not Unicode fails closed.
///
/// This is the silent-misconfiguration case. Every downstream config resolver
/// reads the environment with `std::env::var`, which reports non-Unicode as
/// `Err` — that is, as **unset**. So an undecodable `FERRUM_ADMIN_HTTP_PORT`
/// used to be skipped by secret resolution and then ignored by everything
/// after it: validate succeeded and the gateway would have come up on the
/// `ferrum.conf` entry or the built-in default, on settings the operator never
/// chose and with nothing said about it.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_non_unicode_direct_value() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_HTTP_PORT",
            std::ffi::OsStr::from_bytes(b"84\xff43"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an undecodable direct value must fail closed rather than read as unset: \
         stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.contains("is not valid Unicode"),
        "the diagnostic must name the failure class: {stderr}"
    );
    assert!(
        stderr.contains("FERRUM_ADMIN_HTTP_PORT"),
        "the diagnostic must name the variable: {stderr}"
    );
    assert!(
        !output.stderr.contains(&0xffu8),
        "raw undecodable bytes must never reach the operator: {stderr}"
    );
}

/// The same rule reaches a variable consumed before `EnvConfig` exists.
/// `FERRUM_CONF_PATH` selects the settings file itself, so reading it as unset
/// silently repoints the whole process at a different file.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_non_unicode_direct_conf_path() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_CONF_PATH",
            std::ffi::OsStr::from_bytes(b"/etc/ferrum/\xff.conf"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an undecodable settings-file path must fail closed: stderr={stderr}"
    );
    assert!(
        stderr.contains("is not valid Unicode") && stderr.contains("FERRUM_CONF_PATH"),
        "the diagnostic must name the failure class and the variable: {stderr}"
    );
    assert!(
        !output.stderr.contains(&0xffu8),
        "raw undecodable bytes must never reach the operator: {stderr}"
    );
}

/// The same rule, but with smart discovery actually **armed** — the case the
/// test above cannot reach.
///
/// `functional_cli_validate_rejects_non_unicode_direct_conf_path` runs in a
/// temp `current_dir()` holding `hermetic-ferrum.conf`, not `ferrum.conf`, so
/// `resolve_settings_path()` finds no candidate and returns `None` whatever its
/// presence check does. It therefore passes with or without the bug. Planting a
/// real `./ferrum.conf` is what makes the discovery branch reachable:
///
/// * with a `var(..).is_ok()` presence check the undecodable value reads as
///   **unset**, discovery finds `./ferrum.conf`, `set_var` overwrites the
///   operator's value with a valid path, and `resolve_all_env_secrets()` — which
///   runs *after* the override — sees nothing wrong. Validate then **succeeds**
///   against a settings file the operator never chose.
/// * with `var_os(..).is_some()` the variable is seen as set, discovery yields,
///   and the resolver rejects it.
///
/// The planted file is a valid (empty) settings file precisely so the buggy
/// path would succeed rather than fail for some unrelated reason.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_non_unicode_conf_path_despite_discoverable_conf() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();
    // The candidate `resolve_settings_path()` would discover, in the child's
    // `current_dir()`. Empty parses to an empty map, so it is a *valid*
    // settings file and cannot fail the command by itself.
    std::fs::write(temp_dir.path().join("ferrum.conf"), "").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_CONF_PATH",
            std::ffi::OsStr::from_bytes(b"/etc/ferrum/\xff.conf"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a discoverable ./ferrum.conf must not overwrite an undecodable \
         FERRUM_CONF_PATH before the resolver can reject it: \
         stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.contains("is not valid Unicode") && stderr.contains("FERRUM_CONF_PATH"),
        "the diagnostic must name the failure class and the variable: {stderr}"
    );
    assert!(
        !output.stderr.contains(&0xffu8),
        "raw undecodable bytes must never reach the operator: {stderr}"
    );
}

/// The spec-path half of the same bypass, with `./resources.yaml` planted so
/// `resolve_spec_path()`'s discovery branch is genuinely reachable.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_non_unicode_spec_path_despite_discoverable_spec() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();
    // A *valid* spec, so the buggy path would succeed rather than trip over a
    // malformed document.
    std::fs::write(
        temp_dir.path().join("resources.yaml"),
        "version: \"1\"\nproxies: []\nconsumers: []\nplugin_configs: []\n",
    )
    .unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_FILE_CONFIG_PATH",
            std::ffi::OsStr::from_bytes(b"/etc/ferrum/\xff.yaml"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a discoverable ./resources.yaml must not overwrite an undecodable \
         FERRUM_FILE_CONFIG_PATH before the resolver can reject it: \
         stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.contains("is not valid Unicode") && stderr.contains("FERRUM_FILE_CONFIG_PATH"),
        "the diagnostic must name the failure class and the variable: {stderr}"
    );
    assert!(
        !output.stderr.contains(&0xffu8),
        "raw undecodable bytes must never reach the operator: {stderr}"
    );
}

/// Documented precedence: when an undecodable direct value *also* has a
/// competing suffixed source, the specific multiple-sources diagnostic wins.
///
/// `env_var_os_is_set` counts the undecodable direct value as a configured
/// source, so the conflict check (`registry.rs`) fires before the
/// direct-value Unicode check that follows it. `docs/cli.md` documents this
/// ordering; this pins it.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_prefers_conflict_over_non_unicode_direct_value() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "a-sufficiently-long-admin-jwt-secret-value").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            std::ffi::OsStr::from_bytes(b"direct-\xff-secret"),
        )
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", &secret_path)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "two competing sources must fail closed: {stderr}"
    );
    assert!(
        stderr.contains("Multiple secret sources configured for FERRUM_ADMIN_JWT_SECRET"),
        "the more specific conflict diagnostic must take precedence over the \
         direct-value Unicode error: {stderr}"
    );
    assert!(
        !stderr.contains("Ferrum configuration values must be valid Unicode"),
        "the conflict check runs first, so the direct-value message must not \
         also appear: {stderr}"
    );
    assert!(
        !output.stderr.contains(&0xffu8),
        "raw undecodable bytes must never reach the operator: {stderr}"
    );
}

/// A key ending in `_FILE` that is *not* a secret source is still ordinary
/// Ferrum configuration, so it takes the direct-value path rather than being
/// mistaken for an unreadable source reference.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_non_unicode_non_secret_file_suffix_value() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_DNS_RESOLVER_HOSTS_FILE",
            std::ffi::OsStr::from_bytes(b"/etc/\xff-hosts"),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an undecodable non-secret `_FILE` config value must fail closed: stderr={stderr}"
    );
    assert!(
        stderr.contains("is not valid Unicode")
            && stderr.contains("FERRUM_DNS_RESOLVER_HOSTS_FILE"),
        "the diagnostic must name the failure class and the variable: {stderr}"
    );
}

/// Precedence control: when an undecodable direct value *competes* with a
/// suffixed source, the more specific multiple-sources diagnostic still wins.
/// That case is already caught by the conflict check, which counts the direct
/// value through `var_os`, and it must not be masked by the new check.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_reports_conflict_over_non_unicode_direct_value() {
    use std::os::unix::ffi::OsStrExt;

    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            std::ffi::OsStr::from_bytes(b"direct-\xff-secret"),
        )
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(!output.status.success(), "the conflict must fail: {stderr}");
    assert!(
        stderr.contains("Multiple secret sources configured for FERRUM_ADMIN_JWT_SECRET"),
        "the specific conflict diagnostic must win over the generic Unicode one: {stderr}"
    );
    assert!(
        !output.stderr.contains(&0xffu8),
        "raw undecodable bytes must never reach the operator: {stderr}"
    );
}

/// Benign control: a well-formed direct value is untouched by the new check.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_accepts_valid_direct_values() {
    let temp_dir = TempDir::new().unwrap();
    let secret_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&secret_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        // Database mode requires the admin JWT secret; sourced through `_FILE`
        // so the suffixed path stays exercised alongside the direct values.
        .env(
            "FERRUM_ADMIN_JWT_SECRET_FILE",
            secret_path.to_str().unwrap(),
        )
        .env("FERRUM_ADMIN_HTTP_PORT", "8443")
        .env("FERRUM_DNS_RESOLVER_HOSTS_FILE", "/etc/hosts")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        output.status.success(),
        "ordinary direct configuration must be unaffected: stdout={stdout}, stderr={stderr}"
    );
    assert!(stdout.contains("Validation passed."));
}

/// A short externally resolved `FERRUM_MODE` is withheld from the *invalid
/// mode* diagnostic, which is the one surface that re-renders it.
///
/// `OperatingMode::resolve` lowercases before echoing, so an operator only ever
/// sees a transformation of the resolved value — `DB`, two bytes, surfaces as
/// `db`. The textual backstop deliberately cannot cover that: a two-byte
/// derived candidate armed process-wide would shred every unrelated diagnostic
/// containing `db`, which is the blind short-substring corruption the derived
/// minimum exists to prevent (see
/// `does_not_admit_a_short_case_fold_as_a_global_candidate`). This site is
/// therefore withheld **key-tied**, on `is_external_secret_key("FERRUM_MODE")`,
/// which is exact on provenance and independent of length.
///
/// Driven through the real binary because the guarantee only exists once
/// resolution has actually recorded the key and `EnvConfig` parsing has run.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_validate_withholds_short_externally_resolved_mode() {
    let temp_dir = TempDir::new().unwrap();
    let mode_path = temp_dir.path().join("mode");
    std::fs::write(&mode_path, "DB").unwrap();

    let mut cmd = Command::new(binary_abs_path());
    cmd.arg("validate");
    // Base hermetic env only: `FERRUM_MODE` must come from the `_FILE` source,
    // so it is deliberately not pinned (the helper that pins it would make this
    // a multiple-sources conflict instead).
    apply_hermetic_env(&mut cmd, &temp_dir);
    let output = cmd
        .env("FERRUM_MODE_FILE", mode_path.to_str().unwrap())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "an invalid mode must fail validation: {stderr}"
    );
    // Scoped to the record under test: the expected-value list legitimately
    // names every valid mode, and other lines may mention modes as static
    // strings. The finding is about re-rendering the *resolved value*.
    let line = stderr
        .lines()
        .find(|line| line.contains("Invalid FERRUM_MODE"))
        // Non-vacuous: the assertions below mean nothing unless this is the
        // diagnostic that actually ran.
        .unwrap_or_else(|| panic!("the invalid-mode diagnostic must be emitted: {stderr}"));
    assert!(
        !line.contains("'db'") && !line.contains("'DB'"),
        "neither the resolved value nor its lowercased rendering may be echoed: {line}"
    );
    assert!(
        line.contains("redacted: value from external secret source"),
        "the diagnostic must carry the placeholder: {line}"
    );
    // The actionable part survives.
    assert!(
        line.contains("Expected: database, file, cp, dp"),
        "the expected-value list must be kept: {line}"
    );
}

// ── run: externally resolved operating mode is not disclosed ────────────────

/// `run` logs `Operating mode:` through the tracing sink. That line *re-renders*
/// the value — a resolved `database` becomes the `OperatingMode::Database`
/// Debug rendering — and the structural redactor at the emission boundary
/// deliberately does not derive enum casings, so the line is withheld by key
/// (`secrets::report_env_field`) instead.
///
/// Driven through the real binary rather than a unit test because the leak only
/// exists once resolution, `EnvConfig` parsing, and the tracing sink are all
/// wired together.
#[cfg(unix)]
#[ignore]
#[tokio::test]
async fn functional_cli_run_withholds_externally_resolved_mode() {
    let temp_dir = TempDir::new().unwrap();
    let mode_path = temp_dir.path().join("mode");
    std::fs::write(&mode_path, "database").unwrap();
    let log_path = temp_dir.path().join("run.log");

    // Stdout goes to a file rather than a pipe: an unread `Stdio::piped()` can
    // deadlock the child, and the tracing sink writes continuously so the line
    // is on disk well before the process is signalled.
    let log_file = std::fs::File::create(&log_path).unwrap();

    let mut cmd = Command::new(binary_abs_path());
    cmd.arg("run");
    // Base hermetic env only: the mode must come from the `_FILE` source, so
    // `FERRUM_MODE` is deliberately not pinned.
    apply_hermetic_env(&mut cmd, &temp_dir);
    let mut child = cmd
        .env("FERRUM_MODE_FILE", mode_path.to_str().unwrap())
        .env("FERRUM_DB_TYPE", "sqlite")
        .env("FERRUM_DB_URL", "sqlite::memory:")
        .env(
            "FERRUM_ADMIN_JWT_SECRET",
            "run-mode-fixture-secret-with-well-over-32-bytes",
        )
        // The line is `info!`; the hermetic env drops any inherited level.
        .env("FERRUM_LOG_LEVEL", "info")
        // No listener is needed to observe the startup record. Disable both
        // plaintext listeners so this nextest case cannot contend with the
        // other CLI tests that intentionally exercise fixed listener ports.
        .env("FERRUM_PROXY_HTTP_PORT", "0")
        .env("FERRUM_ADMIN_HTTP_PORT", "0")
        .stdin(Stdio::null())
        .stdout(Stdio::from(log_file))
        .stderr(Stdio::null())
        .spawn()
        .expect("Failed to start ferrum-edge run");

    sleep(Duration::from_secs(3)).await;
    let pid = child.id();
    let _ = std::process::Command::new("kill")
        .args(["-TERM", &pid.to_string()])
        .status();
    let _ = child.wait();

    let logs = std::fs::read_to_string(&log_path).unwrap_or_default();
    // Scoped to the record under test. Mode-specific startup records elsewhere
    // may legitimately mention the mode as a static string chosen by the code
    // path; the finding is about *re-rendering the resolved value*, which is
    // this line.
    let record = logs
        .lines()
        .find(|line| line.contains("Operating mode:"))
        // Non-vacuous: the assertions below are meaningless unless the line was
        // actually emitted at this level with the mode sourced externally.
        .unwrap_or_else(|| panic!("the operating-mode record must be emitted: {logs}"));
    assert!(
        !record.contains("Database"),
        "the externally resolved mode must not reach the log in its Debug \
         rendering: {record}"
    );
    assert!(
        record.contains("redacted: value from external secret source"),
        "the operating-mode record must carry the placeholder: {record}"
    );
}

// ── FERRUM_TRUSTED_PROXIES strict validation (GHSA-pvj7-hhqj-rpv5) ──────────

/// A mistyped entry in the forwarding trust list must fail `validate` (and, by
/// the same `EnvConfig::validate()` call, startup before any listener binds)
/// rather than being warned about and skipped. Skipping it silently narrows the
/// trust boundary: the mistyped hop stops being trusted, so every client behind
/// it collapses onto that hop's socket address for IP policy and per-IP limits.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_rejects_malformed_trusted_proxies() {
    let temp_dir = TempDir::new().unwrap();
    let jwt_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&jwt_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", jwt_path.to_str().unwrap())
        .env("FERRUM_TRUSTED_PROXIES", "10.0.0.0/8,192.168.0.0/33")
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        !output.status.success(),
        "a partial trusted-proxy list must fail: stdout={stdout}, stderr={stderr}"
    );
    assert!(
        stderr.contains("FERRUM_TRUSTED_PROXIES"),
        "expected the trusted-proxy diagnostic, got: {stderr}"
    );
    assert!(
        stderr.contains("192.168.0.0/33"),
        "expected the offending entry to be named, got: {stderr}"
    );
}

/// Non-vacuity control: a fully valid list still passes, so the check above is
/// not simply rejecting the variable's presence.
#[ignore]
#[tokio::test]
async fn functional_cli_validate_accepts_valid_trusted_proxies() {
    let temp_dir = TempDir::new().unwrap();
    let jwt_path = temp_dir.path().join("jwt-secret");
    std::fs::write(&jwt_path, "validate-file-secret-with-well-over-32-bytes").unwrap();

    let output = validate_database_mode_command(&temp_dir)
        .env("FERRUM_ADMIN_JWT_SECRET_FILE", jwt_path.to_str().unwrap())
        .env(
            "FERRUM_TRUSTED_PROXIES",
            "10.0.0.0/8,::1,::ffff:192.0.2.0/120",
        )
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .expect("Failed to run ferrum-edge validate");

    assert!(
        output.status.success(),
        "a fully valid trusted-proxy list must pass: stdout={}, stderr={}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
