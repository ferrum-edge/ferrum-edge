//! `GatewayHarness` — the high-level entry point for Phase-1 scripted-backend
//! tests.
//!
//! A harness owns a running ferrum-edge gateway configured to point at one
//! or more scripted backends. The harness lets the test:
//!
//! - Obtain an HTTP client pointed at the gateway ([`GatewayHarness::http_client`]).
//! - Read admin metrics / health / config without hand-rolling JSON plumbing
//!   ([`GatewayHarness::metrics`], [`GatewayHarness::health`],
//!   [`GatewayHarness::get_admin_json`]).
//! - Reload the running config when admin API-driven changes are needed.
//! - Shut down cleanly on drop.
//!
//! ## Modes
//!
//! Phase 1 currently ships the [`HarnessMode::Binary`] variant only:
//! the harness spawns the `ferrum-edge` subprocess via the existing
//! [`crate::common::gateway_harness::TestGateway`] path. The
//! [`HarnessMode::InProcess`] variant is reserved; the plan calls for an
//! in-process `ProxyState` spin-up but the existing integration-test code
//! constructs `ProxyState` field-by-field, which is too narrow to drive a
//! full request lifecycle in 50 LOC.
//!
//! Selecting [`HarnessMode::InProcess`] via
//! [`GatewayHarnessBuilder::mode_in_process`] is a hard error in Phase 1 —
//! the variant exists to pin the API shape for Phase 2. Tests that want
//! in-process behaviour will fail loudly rather than silently get binary
//! mode, which would have masked the missing implementation.

use crate::common::gateway_harness::{DbType, TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::Http1Client;
use reqwest::StatusCode;
use serde_json::Value;
use std::path::PathBuf;
use std::time::Duration;

/// Which flavour of gateway the harness runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessMode {
    /// Spawn the built `ferrum-edge` binary as a subprocess. This is the
    /// default and is required for every Phase-1 acceptance test.
    Binary,
    /// Reserved — see module docs. Selecting this variant in Phase 1 falls
    /// back to [`HarnessMode::Binary`] with a warning so tests compile but
    /// don't silently fail; the variant exists to pin the API shape.
    InProcess,
}

/// Fluent builder for [`GatewayHarness`].
pub struct GatewayHarnessBuilder {
    mode: HarnessMode,
    inner: TestGatewayBuilder,
    // Backends recorded here so the harness can install them into a default
    // file-mode config if the caller didn't supply one.
    //
    // For Phase 1 callers explicitly push a file-mode config via
    // [`GatewayHarnessBuilder::mode_file`] — we don't try to infer a config
    // from registered backends automatically.
}

impl Default for GatewayHarnessBuilder {
    fn default() -> Self {
        Self {
            mode: HarnessMode::Binary,
            inner: TestGateway::builder(),
        }
    }
}

impl GatewayHarnessBuilder {
    /// Select binary (subprocess) mode. This is the default.
    pub fn mode_binary(mut self) -> Self {
        self.mode = HarnessMode::Binary;
        self
    }

    /// Reserved for Phase 2. Selecting this mode causes [`Self::spawn`] to
    /// return an error — the variant exists to pin the API shape so Phase 2
    /// can land without changing call sites.
    pub fn mode_in_process(mut self) -> Self {
        self.mode = HarnessMode::InProcess;
        self
    }

    /// Use file-mode config, writing the given YAML into a temp file.
    pub fn file_config(mut self, yaml: impl Into<String>) -> Self {
        self.inner = self.inner.mode_file(yaml);
        self
    }

    /// Use SQLite-backed database mode. The DB lives under the harness's
    /// temp dir.
    pub fn db_sqlite(mut self) -> Self {
        self.inner = self.inner.mode_database_sqlite();
        self
    }

    /// Override log level (defaults to `info`).
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        self.inner = self.inner.log_level(level);
        self
    }

    /// Add an env var. Common uses include `FERRUM_TLS_NO_VERIFY=true` for
    /// letting the gateway talk to scripted TLS backends that use the
    /// harness's self-signed cert.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.inner = self.inner.env(key, value);
        self
    }

    /// Capture gateway stdout/stderr to temp files. Required for log-based
    /// assertions (e.g., looking for a specific `body_error_class`).
    pub fn capture_output(mut self) -> Self {
        self.inner = self.inner.capture_output();
        self
    }

    /// Use a fresh DB type other than SQLite. Exposed for integration with
    /// later phases; Phase-1 tests use file mode.
    pub fn db(mut self, db: DbType) -> Self {
        self.inner = self.inner.mode_database(db);
        self
    }

    /// Override the admin JWT HS256 secret.
    pub fn jwt_secret(mut self, secret: impl Into<String>) -> Self {
        self.inner = self.inner.jwt_secret(secret);
        self
    }

    /// Override the inner spawn-retry budget (default 3, per CLAUDE.md).
    /// Use `1` when the caller is wrapping `spawn()` in its own retry loop
    /// (e.g., to re-reserve a fixed env-pinned port like
    /// `FERRUM_PROXY_HTTPS_PORT`) so internal retries don't waste attempts
    /// on a port that won't change between them.
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.inner = self.inner.max_attempts(attempts);
        self
    }

    /// Finalize the builder and spawn the harness.
    pub async fn spawn(self) -> Result<GatewayHarness, Box<dyn std::error::Error + Send + Sync>> {
        // In-process mode is a Phase-2 deliverable — see module docs. Error
        // rather than silently falling back to binary mode so test authors
        // know they're hitting the unimplemented path.
        if matches!(self.mode, HarnessMode::InProcess) {
            return Err(
                "GatewayHarness: HarnessMode::InProcess is reserved for Phase 2 \
                 and not yet implemented — use mode_binary() instead"
                    .into(),
            );
        }
        let gw = self.inner.spawn().await?;
        Ok(GatewayHarness {
            gateway: gw,
            mode: self.mode,
        })
    }
}

/// A running gateway + plumbing for observing it. Drops the subprocess on
/// `Drop`.
pub struct GatewayHarness {
    gateway: TestGateway,
    #[allow(dead_code)] // Used by future in-process branches; retained for parity.
    mode: HarnessMode,
}

impl GatewayHarness {
    /// Start a new builder.
    pub fn builder() -> GatewayHarnessBuilder {
        GatewayHarnessBuilder::default()
    }

    /// The gateway's proxy-port base URL (e.g., `http://127.0.0.1:12345`).
    pub fn proxy_base_url(&self) -> &str {
        &self.gateway.proxy_base_url
    }

    /// Build a full URL under the proxy port: `proxy_url("/api/x")`.
    pub fn proxy_url(&self, path: &str) -> String {
        self.gateway.proxy_url(path)
    }

    /// The gateway's admin-port base URL.
    pub fn admin_base_url(&self) -> &str {
        &self.gateway.admin_base_url
    }

    /// Build a full URL under the admin port.
    pub fn admin_url(&self, path: &str) -> String {
        self.gateway.admin_url(path)
    }

    /// `Authorization: Bearer <jwt>` header value for admin calls.
    pub fn admin_auth_header(&self) -> String {
        self.gateway.auth_header()
    }

    /// A ready-to-go HTTP/1.1 client.  Accepts any TLS cert so the caller
    /// can point it at either plain or TLS frontends without extra setup.
    pub fn http_client(&self) -> Result<Http1Client, Box<dyn std::error::Error + Send + Sync>> {
        Http1Client::insecure().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })
    }

    /// Write an additional file into the harness's temp dir — useful for
    /// cert/key files referenced by admin API config.
    pub fn write_temp_file(&self, name: &str, contents: &str) -> Result<PathBuf, std::io::Error> {
        self.gateway.write_temp_file(name, contents)
    }

    /// Fetch `/health` and return the JSON body.
    pub async fn health(&self) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        self.get_admin_json_unauth("/health").await
    }

    /// Fetch the admin `/metrics` endpoint (unauthenticated, like a
    /// Prometheus scraper) and return the raw text. The real endpoint
    /// renders Prometheus format, so the caller does its own parsing /
    /// substring assertions.
    pub async fn metrics(&self) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let url = self.admin_url("/metrics");
        let resp = client.get(&url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(format!("GET {url} → {status}: {text}").into());
        }
        Ok(text)
    }

    /// GET the admin JSON endpoint at `path`, returning the parsed body.
    pub async fn get_admin_json(
        &self,
        path: &str,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let url = self.admin_url(path);
        let resp = client
            .get(&url)
            .header("Authorization", self.admin_auth_header())
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(format!("GET {url} → {status}: {text}").into());
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// GET an admin endpoint that doesn't require JWT (e.g., `/health`).
    pub async fn get_admin_json_unauth(
        &self,
        path: &str,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(5))
            .build()?;
        let url = self.admin_url(path);
        let resp = client.get(&url).send().await?;
        let status = resp.status();
        let text = resp.text().await?;
        if status != StatusCode::OK {
            return Err(format!("GET {url} → {status}: {text}").into());
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// POST a JSON body to an admin endpoint (JWT required).
    pub async fn post_admin_json(
        &self,
        path: &str,
        body: &Value,
    ) -> Result<Value, Box<dyn std::error::Error + Send + Sync>> {
        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()?;
        let url = self.admin_url(path);
        let resp = client
            .post(&url)
            .header("Authorization", self.admin_auth_header())
            .json(body)
            .send()
            .await?;
        let status = resp.status();
        let text = resp.text().await?;
        if !status.is_success() {
            return Err(format!("POST {url} → {status}: {text}").into());
        }
        if text.trim().is_empty() {
            return Ok(Value::Null);
        }
        Ok(serde_json::from_str(&text)?)
    }

    /// Wait until the gateway's admin `/health` returns 2xx.
    pub async fn wait_healthy(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        self.gateway.wait_for_health(timeout).await
    }

    /// Read captured gateway stdout/stderr. Requires [`GatewayHarnessBuilder::capture_output`].
    pub fn captured_output(&self) -> Result<(String, String), std::io::Error> {
        self.gateway.read_captured_output()
    }

    /// Combined stderr + stdout (stderr first).
    pub fn captured_combined(&self) -> Result<String, std::io::Error> {
        self.gateway.read_combined_captured_output()
    }

    /// Kill the gateway subprocess and read its full captured output.
    ///
    /// The default [`Self::captured_combined`] is a snapshot — with
    /// `tracing-appender`'s non-blocking writer in play, INFO-level lines
    /// emitted after the last response (notably `stdout_logging`
    /// `TransactionSummary` JSON) may not have drained to the subprocess
    /// pipe yet. Stopping the gateway forces the writer to flush before
    /// the child exits, so this method returns every log line the
    /// gateway intended to emit during the test.
    ///
    /// Use this instead of `captured_combined()` when the assertion
    /// depends on an access-log / TransactionSummary line and polling
    /// would otherwise race the flush.
    pub fn stop_and_collect_logs(&mut self) -> String {
        self.gateway.shutdown();
        self.gateway
            .read_combined_captured_output()
            .unwrap_or_default()
    }

    /// Read-only view of the gateway's temp dir.
    pub fn temp_path(&self) -> &std::path::Path {
        self.gateway.temp_dir.path()
    }

    /// A convenience for typical "send a GET through the proxy" assertions.
    pub async fn proxy_get(
        &self,
        path: &str,
    ) -> Result<crate::scaffolding::clients::ClientResponse, Box<dyn std::error::Error + Send + Sync>>
    {
        let client = self.http_client()?;
        let url = self.proxy_url(path);
        client
            .get(&url)
            .await
            .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { Box::new(e) })
    }

    /// Dump a small debug summary — useful in `panic!` messages.
    pub fn debug_summary(&self) -> String {
        format!(
            "GatewayHarness{{mode={:?}, proxy={}, admin={}}}",
            self.mode, self.gateway.proxy_base_url, self.gateway.admin_base_url
        )
    }
}

/// Convenience: render a JSON value as YAML (same as `write_yaml_value` in
/// common/config_builder).
pub fn yaml(value: &Value) -> String {
    serde_yaml::to_string(value).unwrap_or_else(|_| "<yaml serialize error>".to_string())
}
