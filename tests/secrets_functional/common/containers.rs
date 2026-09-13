//! Local container fixtures for the Vault and AWS secret backends, started via
//! `testcontainers` (Docker). These exercise the real provider SDKs against
//! locally-run servers — a HashiCorp Vault dev server and LocalStack's Secrets
//! Manager — so no real cloud account or credentials are ever involved.
//!
//! When Docker is not available the `start_*` helpers return `Err`; callers are
//! expected to print a skip notice and return rather than fail.
//!
//! # Host ports and host-side readiness (issue #5488)
//!
//! Every case in this suite starts its own container, and under plain
//! `cargo test` all of them run in ONE process. Two properties of the original
//! fixture made that sequence order-dependent:
//!
//!   * Host ports were auto-assigned by Docker, i.e. drawn from the same
//!     `ip_local_port_range` the host uses for outbound source ports, and a port
//!     released by one case's container is immediately reusable by the next
//!     case's. That is the bind-drop-rebind family already fixed for the
//!     service-integration suite (issue #3999); ports are now pinned outside the
//!     ephemeral range through [`super::host_ports`] and container start is
//!     retried only on a genuine bind collision.
//!   * Nothing ever proved the PUBLISHED mapping worked. `WaitFor` matches the
//!     container's own stdout and `awslocal` seeding runs inside the container
//!     (`docker exec`), so the first host→container connection of a case was the
//!     one the code under test made — an unreachable mapping surfaced as a
//!     secret-resolution failure instead of a fixture error. Both fixtures now
//!     poll their published endpoint from the host before returning.

#![allow(dead_code)] // helpers are used selectively per feature-gated module

use std::time::{Duration, Instant};

use testcontainers::core::{ExecCommand, IntoContainerPort, WaitFor};
use testcontainers::runners::AsyncRunner;
use testcontainers::{ContainerAsync, GenericImage, ImageExt};

use super::host_ports::{allocate_host_port, retry_on_host_port_collision};

pub type BoxError = Box<dyn std::error::Error + Send + Sync>;

/// Per-request bound for a fixture probe against a container on this host. A
/// loopback service answers in milliseconds; the bound exists so no single
/// probe can hang.
const PROBE_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);
/// Connect bound for the same probe. A refused connection returns immediately;
/// this covers a mapping that accepts the SYN and then never completes.
const PROBE_CONNECT_TIMEOUT: Duration = Duration::from_secs(2);
/// Wall-clock bound on the host-side readiness poll for a published mapping.
const HOST_READY_TIMEOUT: Duration = Duration::from_secs(60);
/// Gap between readiness attempts.
const HOST_READY_INTERVAL: Duration = Duration::from_millis(250);

/// Decide how to handle an unavailable container.
///
/// In CI (`CI` env var set, e.g. GitHub Actions) a container that fails to
/// start is a HARD failure: the `test-secrets` job runs on a Docker-enabled
/// runner, so an image-pull error, a changed wait condition, or broken setup
/// must fail the job rather than let it pass without ever executing the
/// assertions. Outside CI (no Docker locally) it is a graceful skip so the
/// suite stays runnable on a developer machine.
pub fn fail_in_ci_else_skip(test: &str, provider: &str, err: &BoxError) {
    if std::env::var("CI").is_ok() {
        panic!("{test}: {provider} is required in CI but failed to start: {err}");
    }
    eprintln!("SKIP {test}: {provider} unavailable (Docker?): {err}");
}

/// A `reqwest::Client` with request and connect deadlines, for fixture-side
/// probes. Never use `Client::new()` here: its default is no request timeout.
fn probe_http_client() -> Result<reqwest::Client, BoxError> {
    reqwest::Client::builder()
        .timeout(PROBE_REQUEST_TIMEOUT)
        .connect_timeout(PROBE_CONNECT_TIMEOUT)
        .build()
        .map_err(Into::into)
}

/// Poll a container's PUBLISHED endpoint from the host until it answers.
///
/// `require_success` additionally demands a 2xx, for endpoints that report
/// service readiness rather than mere reachability. A breached deadline is a
/// fixture error naming the last observed failure, which is what keeps an
/// unreachable mapping from being reported as a provider/resolution failure by
/// the test that follows.
async fn wait_for_published_endpoint(url: &str, require_success: bool) -> Result<(), BoxError> {
    let client = probe_http_client()?;
    let deadline = Instant::now() + HOST_READY_TIMEOUT;
    loop {
        let last = match client.get(url).send().await {
            Ok(response) if !require_success || response.status().is_success() => return Ok(()),
            Ok(response) => format!("HTTP {}", response.status()),
            Err(error) => error.to_string(),
        };
        if Instant::now() >= deadline {
            return Err(format!(
                "published endpoint {url} was not reachable from the host within {}s: {last}",
                HOST_READY_TIMEOUT.as_secs()
            )
            .into());
        }
        tokio::time::sleep(HOST_READY_INTERVAL).await;
    }
}

/// Combine captured stdout/stderr for a fixture diagnostic.
fn combined_output(stdout: &str, stderr: &str) -> String {
    match (stdout.trim().is_empty(), stderr.trim().is_empty()) {
        (true, true) => String::new(),
        (false, true) => stdout.to_string(),
        (true, false) => stderr.to_string(),
        (false, false) => format!("{stdout}\n{stderr}"),
    }
}

// ---------------------------------------------------------------------------
// HashiCorp Vault dev server (KV v2)
// ---------------------------------------------------------------------------

/// A running Vault dev server with the fixed test fixtures seeded.
pub struct VaultContainer {
    // Held to keep the container alive for the test's lifetime.
    _container: ContainerAsync<GenericImage>,
    /// `http://127.0.0.1:<mapped-port>` — set as `VAULT_ADDR`.
    pub addr: String,
    /// Dev-server root token — set as `VAULT_TOKEN`.
    pub token: String,
}

/// Start a Vault dev server (root token `root`) and seed KV v2 fixtures:
///   - `secret/data/ferrum` → `admin_jwt=vault-admin-jwt`, `db_url=sqlite:///tmp/ferrum.db`
///   - `secret/data/single` → `value=only-one`
pub async fn start_vault_dev_container() -> Result<VaultContainer, BoxError> {
    let (container, host_port) = retry_on_host_port_collision(|| async {
        let host_port = allocate_host_port()?;
        let container = GenericImage::new("hashicorp/vault", "1.15")
            .with_exposed_port(8200.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Vault server started!"))
            .with_mapped_port(host_port, 8200.tcp())
            .with_env_var("VAULT_DEV_ROOT_TOKEN_ID", "root")
            .with_env_var("VAULT_DEV_LISTEN_ADDRESS", "0.0.0.0:8200")
            .with_cmd(["server", "-dev"])
            .start()
            .await?;
        Ok::<_, BoxError>((container, host_port))
    })
    .await?;

    let addr = format!("http://127.0.0.1:{host_port}");
    let token = "root".to_string();

    // Any HTTP answer proves the published mapping reaches Vault; the dev
    // server's own readiness is already covered by the stdout wait condition.
    wait_for_published_endpoint(&format!("{addr}/v1/sys/health"), false).await?;

    seed_vault_kv2(&addr, &token).await?;

    Ok(VaultContainer {
        _container: container,
        addr,
        token,
    })
}

async fn seed_vault_kv2(addr: &str, token: &str) -> Result<(), BoxError> {
    let client = probe_http_client()?;

    // KV v2 writes nest the secret data under a `data` key.
    let ferrum = serde_json::json!({
        "data": { "admin_jwt": "vault-admin-jwt", "db_url": "sqlite:///tmp/ferrum.db" }
    });
    client
        .post(format!("{addr}/v1/secret/data/ferrum"))
        .header("X-Vault-Token", token)
        .json(&ferrum)
        .send()
        .await?
        .error_for_status()?;

    let single = serde_json::json!({ "data": { "value": "only-one" } });
    client
        .post(format!("{addr}/v1/secret/data/single"))
        .header("X-Vault-Token", token)
        .json(&single)
        .send()
        .await?
        .error_for_status()?;

    Ok(())
}

// ---------------------------------------------------------------------------
// LocalStack — AWS Secrets Manager
// ---------------------------------------------------------------------------

/// LocalStack's readiness endpoint. Polled over the published port so the AWS
/// SDK's first request is not also the first host→container connection.
const LOCALSTACK_HEALTH_PATH: &str = "/_localstack/health";

/// A running LocalStack instance with Secrets Manager enabled.
pub struct LocalStackContainer {
    _container: ContainerAsync<GenericImage>,
    /// `http://127.0.0.1:<mapped-port>` — set as `AWS_ENDPOINT_URL_SECRETS_MANAGER`.
    pub endpoint: String,
}

/// Start LocalStack with only the Secrets Manager service enabled.
pub async fn start_localstack_for_aws_secretsmanager() -> Result<LocalStackContainer, BoxError> {
    let (container, host_port) = retry_on_host_port_collision(|| async {
        let host_port = allocate_host_port()?;
        let container = GenericImage::new("localstack/localstack", "3")
            .with_exposed_port(4566.tcp())
            .with_wait_for(WaitFor::message_on_stdout("Ready."))
            .with_mapped_port(host_port, 4566.tcp())
            .with_env_var("SERVICES", "secretsmanager")
            .with_env_var("EAGER_SERVICE_LOADING", "1")
            .start()
            .await?;
        Ok::<_, BoxError>((container, host_port))
    })
    .await?;

    let endpoint = format!("http://127.0.0.1:{host_port}");
    wait_for_published_endpoint(&format!("{endpoint}{LOCALSTACK_HEALTH_PATH}"), true).await?;

    Ok(LocalStackContainer {
        _container: container,
        endpoint,
    })
}

impl LocalStackContainer {
    /// Create a `SecretString` secret via the bundled `awslocal` CLI and return
    /// its ARN.
    pub async fn create_secret_string(&self, name: &str, value: &str) -> Result<String, BoxError> {
        let out = self
            .exec_awslocal(&[
                "secretsmanager",
                "create-secret",
                "--name",
                name,
                "--secret-string",
                value,
                "--output",
                "json",
            ])
            .await?;
        let parsed: serde_json::Value = serde_json::from_str(&out).map_err(|e| {
            format!("could not parse create-secret output as JSON: {e}; raw: {out}")
        })?;
        parsed
            .get("ARN")
            .and_then(|v| v.as_str())
            .map(str::to_string)
            .ok_or_else(|| format!("create-secret output missing ARN: {out}").into())
    }

    /// Create a binary-only secret (no `SecretString`). The bytes are written
    /// to a file in the container and supplied via `fileb://`, which avoids any
    /// AWS-CLI base64/binary-format ambiguity.
    pub async fn create_secret_binary(&self, name: &str, raw_bytes: &[u8]) -> Result<(), BoxError> {
        use base64::Engine;
        let b64 = base64::engine::general_purpose::STANDARD.encode(raw_bytes);
        let script = format!(
            "echo {b64} | base64 -d > /tmp/binsecret && \
             awslocal secretsmanager create-secret --name {name} --secret-binary fileb:///tmp/binsecret"
        );
        self.exec_sh(&script).await?;
        Ok(())
    }

    async fn exec_awslocal(&self, args: &[&str]) -> Result<String, BoxError> {
        let mut cmd: Vec<String> = vec!["awslocal".to_string()];
        cmd.extend(args.iter().map(|s| s.to_string()));
        self.exec_capture(cmd).await
    }

    async fn exec_sh(&self, script: &str) -> Result<String, BoxError> {
        self.exec_capture(vec!["sh".to_string(), "-c".to_string(), script.to_string()])
            .await
    }

    /// Run a command in the container and return its stdout, failing the
    /// fixture on a non-zero exit.
    ///
    /// A seed that silently failed would leave the test asserting against a
    /// "secret does not exist" answer that looks like the behaviour under test
    /// (issue #5488), so the exit code is checked rather than the output alone.
    async fn exec_capture(&self, cmd: Vec<String>) -> Result<String, BoxError> {
        let mut result = self._container.exec(ExecCommand::new(cmd)).await?;
        let stdout = String::from_utf8_lossy(&result.stdout_to_vec().await?).into_owned();
        let stderr = String::from_utf8_lossy(&result.stderr_to_vec().await?).into_owned();
        match result.exit_code().await? {
            Some(0) => Ok(stdout),
            other => Err(format!(
                "container command failed (exit {other:?}): {}",
                combined_output(&stdout, &stderr)
            )
            .into()),
        }
    }
}
