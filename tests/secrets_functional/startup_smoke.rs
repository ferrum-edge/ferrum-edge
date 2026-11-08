//! Startup smoke tests: boot the real `ferrum-edge` binary in database mode
//! with `FERRUM_ADMIN_JWT_SECRET` supplied by an external secret provider, and
//! assert the gateway proves ownership of its admin port with an admin JWT
//! signed by the provider-resolved secret, the provider source is logged, and
//! the secret value never appears in the logs.
//!
//! The spawner follows the functional-test rules in `.claude/rules/testing.md`:
//! registry-leased handoff ports outside the ephemeral source range, the
//! `wait_for_owned_gateway_identity` barrier bound to the child, a
//! `GatewayChildGuard` (coverage-aware teardown on every exit path), and a
//! private `FERRUM_TLS_MANAGED_STORE_PATH` / working directory.
//!
//! These spawn the binary, so they are `#[ignore]` (run with `--ignored`, after
//! `cargo build --bin ferrum-edge`) and self-skip when their fake/emulator is
//! unavailable, unless `FERRUM_SECRETS_STARTUP_SMOKE_REQUIRED=1` (set in CI)
//! turns a skip into a failure. They are intentionally minimal — the
//! resolver-level tests in the sibling modules carry the detailed coverage.
//!
//! Azure has no binary smoke test on purpose: the gateway's resolver path
//! constructs a real `ClientSecretCredential` (Entra ID), which a local fake
//! cannot satisfy without a real tenant. Azure is covered at the fetch level in
//! `azure_backend` via an injected dummy token instead.

#![allow(dead_code)] // some helpers are only used by feature-gated smoke tests

use crate::common::gateway_harness::{
    GatewayChildGuard, SpawnedGatewayIdentity, captured_output_reports_listener_addr_in_use,
    configure_coverage_gateway_command, scrub_gateway_capture_for_diagnostics,
    wait_for_owned_gateway_identity,
};
use serial_test::serial;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::Duration;
use tempfile::TempDir;

/// Set to `1` (CI does) to turn every self-skip into a failure, so a missing
/// binary, fake or container cannot make the smoke pass without running.
const REQUIRED_ENV: &str = "FERRUM_SECRETS_STARTUP_SMOKE_REQUIRED";

/// Bounded startup budget per attempt. The barrier fails fast if the child exits.
const STARTUP_TIMEOUT: Duration = Duration::from_secs(20);

/// Fresh ports per attempt; only a demonstrated listener address race retries.
const MAX_ATTEMPTS: u32 = 3;

/// Skip (or, under [`REQUIRED_ENV`], fail) with a reason.
fn skip(reason: &str) {
    assert!(
        std::env::var(REQUIRED_ENV).as_deref() != Ok("1"),
        "{REQUIRED_ENV}=1 but the smoke cannot run: {reason}"
    );
    eprintln!("SKIP {reason}");
}

/// A per-test admin JWT secret (>= the 32-char minimum DB/CP mode requires).
///
/// The test seeds it into the provider under test, so the gateway can only
/// verify this test's admin JWT if it resolved the secret through that
/// provider. It is fresh per test, so no other gateway can hold it.
fn mint_provider_secret() -> String {
    SpawnedGatewayIdentity::mint("secrets-smoke").jwt_secret
}

/// Locate the freshly-built `ferrum-edge` binary next to the test runner.
fn locate_binary() -> Option<PathBuf> {
    let exe = std::env::current_exe().ok()?;
    // exe is .../target/<profile>/deps/secrets_functional-<hash>
    for ancestor in exe.ancestors().skip(1).take(3) {
        let candidate = ancestor.join("ferrum-edge");
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

/// A spawned gateway whose ownership of its admin port has been proven.
///
/// Field order is teardown order: the guard shuts the child down (SIGTERM plus
/// a grace period under coverage) before the temp dir holding its database,
/// managed TLS store and logs is removed.
struct GatewaySmoke {
    child: GatewayChildGuard,
    stdout_path: PathBuf,
    provider_secret: String,
    _tmp: TempDir,
}

/// Why an attempt did not produce a ready gateway.
enum AttemptFailure {
    /// The process could not be spawned at all (missing/unrunnable binary).
    Spawn(std::io::Error),
    /// The child never proved ownership; carries the barrier error and the
    /// child's captured output, read after the child was reaped.
    NotReady { error: String, output: String },
}

impl GatewaySmoke {
    /// Spawn the gateway in database/SQLite mode and wait for the ownership
    /// barrier, retrying on fresh ports only when the child's own output
    /// demonstrates a lost listener address race.
    ///
    /// `extra_env` carries the provider indirection vars (e.g.
    /// `FERRUM_ADMIN_JWT_SECRET_FILE`) that resolve to `provider_secret`.
    async fn start(
        bin: &Path,
        extra_env: &[(String, String)],
        provider_secret: &str,
    ) -> Result<Self, std::io::Error> {
        for attempt in 1..=MAX_ATTEMPTS {
            match Self::attempt(bin, extra_env, provider_secret).await {
                Ok(gateway) => return Ok(gateway),
                Err(AttemptFailure::Spawn(error)) => return Err(error),
                Err(AttemptFailure::NotReady { error, output }) => {
                    let retry = attempt < MAX_ATTEMPTS
                        && captured_output_reports_listener_addr_in_use(&output);
                    let output = scrub_gateway_capture_for_diagnostics(&output, &[provider_secret]);
                    assert!(
                        retry,
                        "gateway did not prove ownership on attempt {attempt}/{MAX_ATTEMPTS}: \
                         {error}\n--- gateway output ---\n{output}"
                    );
                    eprintln!(
                        "gateway attempt {attempt}/{MAX_ATTEMPTS} lost a listener address race; \
                         retrying on fresh ports"
                    );
                }
            }
        }
        unreachable!("every attempt returns, retries, or asserts");
    }

    async fn attempt(
        bin: &Path,
        extra_env: &[(String, String)],
        provider_secret: &str,
    ) -> Result<Self, AttemptFailure> {
        let tmp = TempDir::new().map_err(AttemptFailure::Spawn)?;
        // Registry-leased handoff ports outside the host's ephemeral source
        // range; the leases outlive the handoff, so a retry gets fresh ones.
        let admin_port =
            crate::scaffolding::ports::unbound_tcp_port().map_err(AttemptFailure::Spawn)?;
        let proxy_port =
            crate::scaffolding::ports::unbound_tcp_port().map_err(AttemptFailure::Spawn)?;
        let stdout_path = tmp.path().join("stdout.log");
        let stderr_path = tmp.path().join("stderr.log");
        let db_url = format!("sqlite:{}?mode=rwc", tmp.path().join("smoke.db").display());

        let stdout = std::fs::File::create(&stdout_path).map_err(AttemptFailure::Spawn)?;
        let stderr = std::fs::File::create(&stderr_path).map_err(AttemptFailure::Spawn)?;

        // The admin JWT secret comes from the provider under test. Only the
        // issuer and the observability token are minted here, fresh for this
        // attempt, so the barrier's JWT is unique to this child.
        let minted = SpawnedGatewayIdentity::mint("secrets-smoke");
        let identity = SpawnedGatewayIdentity {
            jwt_secret: provider_secret.to_string(),
            jwt_issuer: minted.jwt_issuer,
            observability_token: minted.observability_token,
        };

        let mut cmd = Command::new(bin);
        cmd.arg("run")
            .env_clear()
            .env("PATH", std::env::var("PATH").unwrap_or_default())
            .env("HOME", std::env::var("HOME").unwrap_or_default())
            .env("RUST_LOG", "info")
            .env("FERRUM_LOG_LEVEL", "info")
            .env("FERRUM_MODE", "database")
            .env("FERRUM_DB_TYPE", "sqlite")
            .env("FERRUM_DB_URL", db_url)
            .env("FERRUM_NAMESPACE", "ferrum")
            .env("FERRUM_POOL_WARMUP_ENABLED", "false")
            .env("FERRUM_PROXY_HTTP_PORT", proxy_port.to_string())
            .env("FERRUM_ADMIN_HTTP_PORT", admin_port.to_string())
            // Not FERRUM_ADMIN_JWT_SECRET itself: a direct value would conflict
            // with the provider suffix this smoke exists to exercise.
            .env("FERRUM_ADMIN_JWT_ISSUER", &identity.jwt_issuer)
            .env("FERRUM_METRICS_BEARER_TOKEN", &identity.observability_token)
            // Keep any managed TLS / ACME / event store out of the checkout
            // (issue #5706); env_clear() alone leaves the `./ferrum-managed-tls`
            // default in the working directory.
            .env(
                "FERRUM_TLS_MANAGED_STORE_PATH",
                tmp.path().join("managed-tls"),
            )
            .current_dir(tmp.path());
        configure_coverage_gateway_command(&mut cmd);
        for (k, v) in extra_env {
            cmd.env(k, v);
        }
        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        let mut child = GatewayChildGuard::new(cmd.spawn().map_err(AttemptFailure::Spawn)?);

        // Ownership, not just readiness: authenticated `/health` ready, an
        // HTTP 200 from JWT-only `GET /proxies` under this attempt's admin JWT
        // (signed with the provider-resolved secret), and `try_wait` liveness.
        match wait_for_owned_gateway_identity(
            child.child_mut(),
            admin_port,
            &identity,
            STARTUP_TIMEOUT,
        )
        .await
        {
            Ok(()) => Ok(Self {
                child,
                stdout_path,
                provider_secret: provider_secret.to_string(),
                _tmp: tmp,
            }),
            Err(error) => {
                // Reap first so the capture files hold everything it wrote.
                child.shutdown();
                let mut output = std::fs::read_to_string(&stderr_path).unwrap_or_default();
                output.push_str(&std::fs::read_to_string(&stdout_path).unwrap_or_default());
                Err(AttemptFailure::NotReady {
                    error: error.to_string(),
                    output,
                })
            }
        }
    }

    fn captured_logs(&self) -> String {
        std::fs::read_to_string(&self.stdout_path).unwrap_or_default()
    }
}

/// Start the gateway, or skip when the binary cannot be spawned at all.
async fn start_or_skip(
    test: &str,
    bin: &Path,
    extra_env: &[(String, String)],
    provider_secret: &str,
) -> Option<GatewaySmoke> {
    match GatewaySmoke::start(bin, extra_env, provider_secret).await {
        Ok(gw) => Some(gw),
        Err(e) => {
            skip(&format!("{test}: could not spawn gateway: {e}"));
            None
        }
    }
}

/// Shared assertions for a provider-backed startup that already proved
/// ownership with an admin JWT signed by the provider-resolved secret.
fn assert_provider_logged_and_clean(mut gw: GatewaySmoke, source_label: &str) {
    let logs = gw.captured_logs();
    let shown = scrub_gateway_capture_for_diagnostics(&logs, &[&gw.provider_secret]);
    assert!(
        logs.contains(&format!(
            "Loaded FERRUM_ADMIN_JWT_SECRET from {source_label}"
        )),
        "logs should record the provider source '{source_label}'; logs:\n{shown}"
    );
    assert!(
        !logs.contains(&gw.provider_secret),
        "the resolved secret value must never appear in logs"
    );
    gw.child.shutdown();
}

#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "spawns the ferrum-edge binary; run with --ignored after building it"]
async fn smoke_file_provider_starts_gateway() {
    let Some(bin) = locate_binary() else {
        skip("smoke_file_provider: ferrum-edge binary not found (build it first)");
        return;
    };
    let secret = mint_provider_secret();
    let tmp = TempDir::new().unwrap();
    let secret_path = tmp.path().join("admin_jwt");
    std::fs::write(&secret_path, format!("{secret}\n")).unwrap();

    let env = vec![(
        "FERRUM_ADMIN_JWT_SECRET_FILE".to_string(),
        secret_path.to_string_lossy().into_owned(),
    )];
    let Some(gw) = start_or_skip("smoke_file_provider", &bin, &env, &secret).await else {
        return;
    };
    assert_provider_logged_and_clean(gw, "file");
}

#[cfg(feature = "secrets-gcp")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "spawns the ferrum-edge binary; run with --ignored after building it"]
async fn smoke_gcp_provider_starts_gateway() {
    use crate::common::fakes::GcpSecretManagerFake;

    let Some(bin) = locate_binary() else {
        skip("smoke_gcp_provider: ferrum-edge binary not found");
        return;
    };
    // The fake runs in this (parent) process; the child gateway reaches it on
    // 127.0.0.1.
    let secret = mint_provider_secret();
    let fake = GcpSecretManagerFake::start().await;
    let resource = "projects/test-project/secrets/ferrum-admin/versions/latest";
    fake.mock_access_success(resource, secret.as_bytes()).await;

    let env = vec![
        (
            "FERRUM_GCP_SECRET_MANAGER_ENDPOINT".to_string(),
            fake.endpoint(),
        ),
        (
            "FERRUM_ADMIN_JWT_SECRET_GCP".to_string(),
            resource.to_string(),
        ),
    ];
    let Some(gw) = start_or_skip("smoke_gcp_provider", &bin, &env, &secret).await else {
        return;
    };
    assert_provider_logged_and_clean(gw, "GCP Secret Manager");
}

#[cfg(feature = "secrets-vault")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "spawns the ferrum-edge binary + Vault container; run with --ignored"]
async fn smoke_vault_provider_starts_gateway() {
    use crate::common::containers::start_vault_dev_container;

    let Some(bin) = locate_binary() else {
        skip("smoke_vault_provider: ferrum-edge binary not found");
        return;
    };
    let vault = match start_vault_dev_container().await {
        Ok(v) => v,
        Err(e) => {
            skip(&format!(
                "smoke_vault_provider: Vault container unavailable: {e}"
            ));
            return;
        }
    };
    // The seeded `secret/data/ferrum#admin_jwt` is "vault-admin-jwt" (12 chars),
    // which is too short for the 32-char admin-secret minimum, so seed a
    // dedicated long secret for the smoke test.
    let secret = mint_provider_secret();
    let client = reqwest::Client::new();
    client
        .post(format!("{}/v1/secret/data/smoke", vault.addr))
        .header("X-Vault-Token", &vault.token)
        .json(&serde_json::json!({ "data": { "admin_jwt": secret } }))
        .send()
        .await
        .and_then(|r| r.error_for_status())
        .expect("seed smoke secret");

    let env = vec![
        ("VAULT_ADDR".to_string(), vault.addr.clone()),
        ("VAULT_TOKEN".to_string(), vault.token.clone()),
        (
            "FERRUM_ADMIN_JWT_SECRET_VAULT".to_string(),
            "secret/data/smoke#admin_jwt".to_string(),
        ),
    ];
    let Some(gw) = start_or_skip("smoke_vault_provider", &bin, &env, &secret).await else {
        return;
    };
    assert_provider_logged_and_clean(gw, "Vault");
}

#[cfg(feature = "secrets-aws")]
#[tokio::test(flavor = "multi_thread")]
#[serial]
#[ignore = "spawns the ferrum-edge binary + LocalStack; run with --ignored"]
async fn smoke_aws_provider_starts_gateway() {
    use crate::common::containers::start_localstack_for_aws_secretsmanager;

    let Some(bin) = locate_binary() else {
        skip("smoke_aws_provider: ferrum-edge binary not found");
        return;
    };
    let ls = match start_localstack_for_aws_secretsmanager().await {
        Ok(ls) => ls,
        Err(e) => {
            skip(&format!("smoke_aws_provider: LocalStack unavailable: {e}"));
            return;
        }
    };
    let secret = mint_provider_secret();
    ls.create_secret_string("ferrum/smoke-admin", &secret)
        .await
        .expect("seed smoke secret");

    let env = vec![
        ("AWS_REGION".to_string(), "us-east-1".to_string()),
        ("AWS_DEFAULT_REGION".to_string(), "us-east-1".to_string()),
        ("AWS_ACCESS_KEY_ID".to_string(), "test".to_string()),
        ("AWS_SECRET_ACCESS_KEY".to_string(), "test".to_string()),
        (
            "AWS_ENDPOINT_URL_SECRETS_MANAGER".to_string(),
            ls.endpoint.clone(),
        ),
        (
            "FERRUM_ADMIN_JWT_SECRET_AWS".to_string(),
            "ferrum/smoke-admin".to_string(),
        ),
    ];
    let Some(gw) = start_or_skip("smoke_aws_provider", &bin, &env, &secret).await else {
        return;
    };
    assert_provider_logged_and_clean(gw, "AWS Secrets Manager");
}
