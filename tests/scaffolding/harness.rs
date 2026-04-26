//! `GatewayHarness` — the high-level entry point for scripted-backend
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
//! Two modes share the same observable surface — pick by what you're
//! testing:
//!
//! - [`HarnessMode::Binary`] (default): spawn the built `ferrum-edge`
//!   subprocess. Required when you need full CLI-parsing / signal-handling
//!   behaviour (SIGHUP, SIGTERM), or kernel-level features that depend on
//!   process state (kTLS extraction, io_uring submission queues). Each
//!   spawn pays a `cargo build` (cached) + ~2-3s of process bootstrap.
//!
//! - [`HarnessMode::InProcess`]: run the gateway as a tokio task in the
//!   test's own process via [`ferrum_edge::modes::file::serve`]. Reserves
//!   ephemeral TCP ports via `tests/scaffolding/ports.rs`, hands the
//!   pre-bound listeners to the gateway, and skips subprocess overhead
//!   entirely. Typical end-to-end harness setup is well under 100 ms,
//!   versus 2-3 s for binary mode. Use this for fast iteration on
//!   request-path behaviour: routing, plugin pipelines, capability
//!   classification, body streaming, error classification.
//!
//! ## When to prefer which mode
//!
//! - **Default to `InProcess`** for unit-of-routing-or-plugin-behaviour
//!   tests. The whole `ProxyState` is real, the listener is real, the
//!   backend (scripted or otherwise) is real.
//! - **Switch to `Binary`** when the test has to verify:
//!   - Subprocess CLI flag parsing (`ferrum-edge run --settings ...`).
//!   - SIGHUP-driven config reload (file mode reload path).
//!   - Captured stdout/stderr (in-process mode shares the test process's
//!     `tracing` subscriber, so log assertions don't compose well).
//!   - kTLS / io_uring kernel features that depend on the process having
//!     its own runtime.
//!
//! ## Caveats specific to in-process mode
//!
//! - **`FERRUM_POOL_WARMUP_ENABLED` defaults to `false`** in both
//!   harness modes — most tests want cold pools so their per-request
//!   connection-count assertions aren't inflated by the warmup probe.
//!   Tests that depend on the capability registry's first probe
//!   (e.g. `h2_alpn_fallback_downgrades_capability`) explicitly opt
//!   in via [`GatewayHarnessBuilder::pool_warmup_enabled(true)`].
//! - The file-mode YAML loader's strict-loading rules apply identically
//!   in in-process mode — every top-level collection (`consumers`,
//!   `upstreams`, `plugin_configs`) still has to be present in the
//!   YAML, even if empty. The harness writes the YAML to a temp file
//!   and feeds it through the same `load_config_from_file` path.
//!   The helpers in `tests/scaffolding/mod.rs`
//!   ([`crate::scaffolding::file_mode_yaml_for_backend`] and friends)
//!   already include the empty-collection boilerplate.
//! - Logs go to whatever `tracing` subscriber the test process has
//!   installed. `captured_combined()` returns `Err` in in-process mode —
//!   tests that depend on log assertions must stay on binary mode.

use crate::common::gateway_harness::{DbType, TestGateway, TestGatewayBuilder};
use crate::scaffolding::clients::Http1Client;
use crate::scaffolding::ports::{PortReservation, reserve_port_pair};
use chrono::Utc;
use ferrum_edge::admin::jwt_auth::{JwtConfig, JwtManager};
use ferrum_edge::config::types::GatewayConfig;
use ferrum_edge::config::{BackendAllowIps, EnvConfig, OperatingMode};
use ferrum_edge::modes::file::{ServeHandles, ServeOptions};
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::StatusCode;
use serde_json::{Value, json};
use std::io::Write;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tempfile::TempDir;
use tokio::sync::watch;
use tokio::task::JoinHandle;
use uuid::Uuid;

/// Which flavour of gateway the harness runs.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum HarnessMode {
    /// Spawn the built `ferrum-edge` binary as a subprocess. Slower but
    /// exercises the full CLI / signal / process-bootstrap path. Required
    /// for kTLS / io_uring tests and any test that asserts on captured
    /// process logs.
    Binary,
    /// Run the gateway as a tokio task in the test process via
    /// [`ferrum_edge::modes::file::serve`]. Order-of-magnitude faster
    /// startup; share-everything semantics (one tracing subscriber, one
    /// runtime, one rustls provider).
    InProcess,
}

/// Fluent builder for [`GatewayHarness`].
pub struct GatewayHarnessBuilder {
    mode: HarnessMode,
    inner: TestGatewayBuilder,
    file_yaml: Option<String>,
    log_level: String,
    jwt_secret: String,
    jwt_issuer: String,
    pool_warmup_enabled: bool,
    extra_env: Vec<(String, String)>,
}

impl Default for GatewayHarnessBuilder {
    fn default() -> Self {
        Self {
            mode: HarnessMode::Binary,
            inner: TestGateway::builder(),
            file_yaml: None,
            log_level: "info".to_string(),
            jwt_secret: "ferrum-edge-shared-harness-secret-00000".to_string(),
            jwt_issuer: "ferrum-edge-shared-harness".to_string(),
            // Match `TestGateway`'s default — tests that exercise the
            // capability registry's classification path (e.g.
            // `h2_alpn_fallback_downgrades_capability`) explicitly opt
            // in via `pool_warmup_enabled(true)`. Defaulting `true` here
            // would silently double-count the first probe as a backend
            // connection in tests like
            // `h2_direct_pool_reuses_connection_across_requests`.
            pool_warmup_enabled: false,
            extra_env: Vec::new(),
        }
    }
}

impl GatewayHarnessBuilder {
    /// Select binary (subprocess) mode. This is the default.
    pub fn mode_binary(mut self) -> Self {
        self.mode = HarnessMode::Binary;
        self
    }

    /// Run the gateway as a tokio task in the test process (no subprocess).
    /// See module docs for caveats — most importantly, log assertions don't
    /// compose well in this mode.
    pub fn mode_in_process(mut self) -> Self {
        self.mode = HarnessMode::InProcess;
        self
    }

    /// Use file-mode config, writing the given YAML into a temp file.
    pub fn file_config(mut self, yaml: impl Into<String>) -> Self {
        let yaml = yaml.into();
        self.inner = self.inner.mode_file(yaml.clone());
        self.file_yaml = Some(yaml);
        self
    }

    /// Use SQLite-backed database mode. The DB lives under the harness's
    /// temp dir.
    ///
    /// Note: in-process mode currently only supports file mode — selecting
    /// `db_sqlite()` together with `mode_in_process()` is a hard error in
    /// `spawn()`. SQLite-in-process can be a follow-up if there's demand.
    pub fn db_sqlite(mut self) -> Self {
        self.inner = self.inner.mode_database_sqlite();
        self
    }

    /// Override log level (defaults to `info`).
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        let level = level.into();
        self.inner = self.inner.log_level(level.clone());
        self.log_level = level;
        self
    }

    /// Add an env var. In binary mode this maps directly to the subprocess
    /// environment. In in-process mode it maps to the in-process
    /// [`EnvConfig`] override the harness builds before calling
    /// `serve()`.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        let (k, v) = (key.into(), value.into());
        self.inner = self.inner.env(k.clone(), v.clone());
        self.extra_env.push((k, v));
        self
    }

    /// Capture gateway stdout/stderr to temp files. Required for log-based
    /// assertions (e.g., looking for a specific `body_error_class`).
    /// **Binary mode only** — in-process mode shares the test process's
    /// tracing subscriber and `captured_combined()` returns an error.
    pub fn capture_output(mut self) -> Self {
        self.inner = self.inner.capture_output();
        self
    }

    /// Use a fresh DB type other than SQLite. Exposed for integration with
    /// later phases; in-process mode only supports file mode for now.
    pub fn db(mut self, db: DbType) -> Self {
        self.inner = self.inner.mode_database(db);
        self
    }

    /// Override the admin JWT HS256 secret.
    pub fn jwt_secret(mut self, secret: impl Into<String>) -> Self {
        let s = secret.into();
        self.inner = self.inner.jwt_secret(s.clone());
        self.jwt_secret = s;
        self
    }

    /// Override the connection pool warmup behaviour.
    ///
    /// Defaults to **disabled** in both modes — most tests want cold pools
    /// because their assertion counts backend connections per RPC and the
    /// warmup probe would inflate that count by one. Tests that depend on
    /// the capability registry's first-probe (e.g.
    /// `h2_alpn_fallback_downgrades_capability`) opt in via
    /// `pool_warmup_enabled(true)`.
    pub fn pool_warmup_enabled(mut self, enabled: bool) -> Self {
        self.pool_warmup_enabled = enabled;
        // Explicit env override on every call so binary mode picks up the
        // setting regardless of TestGateway's defaults.
        let v = if enabled { "true" } else { "false" };
        self.inner = self.inner.env("FERRUM_POOL_WARMUP_ENABLED", v);
        self
    }

    /// Finalize the builder and spawn the harness.
    pub async fn spawn(self) -> Result<GatewayHarness, Box<dyn std::error::Error + Send + Sync>> {
        match self.mode {
            HarnessMode::Binary => self.spawn_binary().await,
            HarnessMode::InProcess => self.spawn_in_process().await,
        }
    }

    async fn spawn_binary(
        self,
    ) -> Result<GatewayHarness, Box<dyn std::error::Error + Send + Sync>> {
        let gw = self.inner.spawn().await?;
        Ok(GatewayHarness {
            mode: HarnessMode::Binary,
            backend: Backend::Binary {
                gateway: Box::new(gw),
            },
        })
    }

    async fn spawn_in_process(
        self,
    ) -> Result<GatewayHarness, Box<dyn std::error::Error + Send + Sync>> {
        // Today the in-process path only supports file mode — anything that
        // wants DB/CP/DP must go through the binary path.
        let yaml = self.file_yaml.as_deref().ok_or_else(
            || -> Box<dyn std::error::Error + Send + Sync> {
                "GatewayHarness::mode_in_process requires file_config(yaml) — \
                 in-process DB/CP/DP support is a follow-up"
                    .into()
            },
        )?;

        // Up to MAX_ATTEMPTS retries on bind race (matches the binary
        // path's port-allocation rules — see CLAUDE.md "bind-drop-rebind").
        const MAX_ATTEMPTS: u32 = 5;
        let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
        for attempt in 1..=MAX_ATTEMPTS {
            match try_spawn_in_process(&self, yaml).await {
                Ok(h) => return Ok(h),
                Err(e) => {
                    eprintln!(
                        "GatewayHarness in-process attempt {}/{} failed: {}",
                        attempt, MAX_ATTEMPTS, e
                    );
                    last_err = Some(e);
                }
            }
        }
        Err(last_err.unwrap_or_else(|| {
            "GatewayHarness::spawn_in_process exhausted retries with no recorded error".into()
        }))
    }
}

async fn try_spawn_in_process(
    builder: &GatewayHarnessBuilder,
    yaml: &str,
) -> Result<GatewayHarness, Box<dyn std::error::Error + Send + Sync>> {
    // Reserve a fresh port pair per attempt — never reuse listeners
    // across retries (CLAUDE.md "Functional test port allocation").
    let (proxy_reservation, admin_reservation): (PortReservation, PortReservation) =
        reserve_port_pair().await?;
    let proxy_port = proxy_reservation.port;
    let admin_port = admin_reservation.port;

    let temp_dir = TempDir::new()?;

    // Persist the YAML so the file-mode loader runs identically to binary
    // mode (same validation pipeline, same migrations, same field-level
    // checks). In-process mode does not bypass the loader — it just skips
    // the subprocess.
    let config_path = temp_dir.path().join("ferrum.yaml");
    {
        let mut f = std::fs::File::create(&config_path)?;
        f.write_all(yaml.as_bytes())?;
    }

    // Build EnvConfig with sensible test defaults. We deliberately leave
    // most fields at their `Default` so the test sees production-like
    // behaviour; only the fields the harness controls are overridden.
    let mut env_config = EnvConfig {
        mode: OperatingMode::File,
        log_level: builder.log_level.clone(),
        // Default port=0 (disabled) so a typo in the harness can't ever
        // bind to a real port behind the test's back. The pre-bound
        // listeners take precedence.
        proxy_http_port: proxy_port,
        proxy_https_port: 0,
        admin_http_port: admin_port,
        admin_https_port: 0,
        admin_jwt_secret: Some(builder.jwt_secret.clone()),
        admin_jwt_issuer: builder.jwt_issuer.clone(),
        // Tests don't need 30s drain — let the harness drop quickly.
        shutdown_drain_seconds: 0,
        pool_warmup_enabled: builder.pool_warmup_enabled,
        // Minimal connection cap — we're testing logic, not throughput.
        max_connections: 0,
        ..EnvConfig::default()
    };

    // Apply caller-provided env-var overrides BEFORE loading the YAML.
    // The file loader reads `namespace` (post-load resource filter) and
    // `backend_allow_ips` (field-level validation in
    // `validate_all_fields_with_ip_policy`) from these fields, so applying
    // overrides afterwards would let the wrong namespace's resources slip
    // through and accept backend IP policies the real gateway would reject.
    //
    // Today we only honour the small subset that maps cleanly to EnvConfig
    // fields used by the in-process scripted-backend tests; pass an
    // unrecognised key and the override is silently ignored (binary mode
    // would forward it to the subprocess). Add new fields as tests need
    // them.
    apply_env_overrides(&mut env_config, &builder.extra_env);

    let config = ferrum_edge::config::file_loader::load_config_from_file(
        config_path.to_string_lossy().as_ref(),
        env_config.tls_cert_expiry_warning_days,
        &env_config.backend_allow_ips,
        &env_config.namespace,
    )
    .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
        format!("file_loader failed: {e}").into()
    })?;

    let jwt_manager = JwtManager::new(JwtConfig {
        secret: builder.jwt_secret.clone(),
        issuer: builder.jwt_issuer.clone(),
        max_ttl_seconds: 3600,
        algorithm: jsonwebtoken::Algorithm::HS256,
    });

    let proxy_listener = proxy_reservation.into_listener();
    let admin_listener = admin_reservation.into_listener();

    let opts = ServeOptions {
        proxy_http: Some(proxy_listener),
        admin_http: Some(admin_listener),
        admin_jwt_manager: Some(jwt_manager),
        // Cold harness: skip the immediate backend capability probe
        // unless the caller has explicitly enabled pool warmup.
        // The probe opens an h2c connection to plaintext HTTP backends
        // and would consume scripted-backend `ExpectRequest` steps or
        // perturb per-test connection counts. Warmup-on tests still get
        // the probe via `warmup_connection_pools()`, which is awaited
        // before `serve()` returns.
        skip_initial_capability_refresh: !builder.pool_warmup_enabled,
        ..ServeOptions::default()
    };

    let (shutdown_tx, _) = watch::channel(false);
    let handles = ferrum_edge::modes::file::serve(env_config, config, opts, shutdown_tx.clone())
        .await
        .map_err(|e| -> Box<dyn std::error::Error + Send + Sync> {
            format!("file::serve failed: {e}").into()
        })?;

    let proxy_base_url = format!("http://127.0.0.1:{proxy_port}");
    let admin_base_url = format!("http://127.0.0.1:{admin_port}");

    let join_handle = tokio::spawn(async move {
        // ServeHandles owns the listeners' join handles. We move it onto
        // its own task so dropping the harness waits for clean drain.
        // A listener panic returns Err(JoinError) — surface it as an
        // eprintln so a flaky listener doesn't disappear silently into
        // the test runtime; the test that triggered it is already in
        // teardown by the time this runs, so we can't fail it directly.
        if let Err(err) = handles.join().await {
            eprintln!("In-process gateway listener panicked: {err}");
        }
    });

    Ok(GatewayHarness {
        mode: HarnessMode::InProcess,
        backend: Backend::InProcess(Box::new(InProcessBackend {
            proxy_base_url,
            admin_base_url,
            proxy_port,
            admin_port,
            jwt_secret: builder.jwt_secret.clone(),
            jwt_issuer: builder.jwt_issuer.clone(),
            shutdown_tx: Some(shutdown_tx),
            join: Some(join_handle),
            _temp_dir: Arc::new(temp_dir),
            config_path,
        })),
    })
}

fn apply_env_overrides(env_config: &mut EnvConfig, overrides: &[(String, String)]) {
    for (k, v) in overrides {
        match k.as_str() {
            "FERRUM_NAMESPACE" => env_config.namespace = v.clone(),
            "FERRUM_LOG_LEVEL" => env_config.log_level = v.clone(),
            "FERRUM_TLS_NO_VERIFY" => env_config.tls_no_verify = parse_bool(v),
            "FERRUM_POOL_WARMUP_ENABLED" => env_config.pool_warmup_enabled = parse_bool(v),
            "FERRUM_TRUSTED_PROXIES" => env_config.trusted_proxies = v.clone(),
            "FERRUM_BACKEND_ALLOW_IPS" => match v.as_str() {
                "private" => env_config.backend_allow_ips = BackendAllowIps::Private,
                "public" => env_config.backend_allow_ips = BackendAllowIps::Public,
                _ => env_config.backend_allow_ips = BackendAllowIps::Both,
            },
            "FERRUM_MAX_CONNECTIONS" => {
                if let Ok(n) = v.parse() {
                    env_config.max_connections = n;
                }
            }
            "FERRUM_SHUTDOWN_DRAIN_SECONDS" => {
                if let Ok(n) = v.parse() {
                    env_config.shutdown_drain_seconds = n;
                }
            }
            // Unknown vars: ignored. Add cases as tests need them.
            _ => {}
        }
    }
}

fn parse_bool(s: &str) -> bool {
    matches!(s.to_lowercase().as_str(), "true" | "1" | "yes" | "on")
}

/// A running gateway + plumbing for observing it. Drops the underlying
/// gateway (subprocess or in-process task) on `Drop`.
pub struct GatewayHarness {
    backend: Backend,
    #[allow(dead_code)] // Used only by debug_summary().
    mode: HarnessMode,
}

// Both variants are boxed: TestGateway carries TempDir + Child + many
// String fields (~300 B), and InProcessBackend carries similar volume of
// state. Without Box, `large_enum_variant` fires for whichever side is
// bigger this week.
#[allow(clippy::large_enum_variant)]
enum Backend {
    Binary { gateway: Box<TestGateway> },
    InProcess(Box<InProcessBackend>),
}

struct InProcessBackend {
    proxy_base_url: String,
    admin_base_url: String,
    #[allow(dead_code)] // For potential future plumbing (port-aware error messages).
    proxy_port: u16,
    #[allow(dead_code)]
    admin_port: u16,
    jwt_secret: String,
    jwt_issuer: String,
    shutdown_tx: Option<watch::Sender<bool>>,
    join: Option<JoinHandle<()>>,
    _temp_dir: Arc<TempDir>,
    #[allow(dead_code)] // Retained for diagnostic dumps.
    config_path: PathBuf,
}

impl Drop for InProcessBackend {
    fn drop(&mut self) {
        // Signal graceful shutdown — every listener / background task
        // subscribed to the watch channel observes this and exits on its
        // own.
        if let Some(tx) = self.shutdown_tx.take() {
            let _ = tx.send(true);
        }
        // Drop the JoinHandle without aborting. `abort()` would cancel
        // the task running `ServeHandles::join`, which is the ONLY task
        // awaiting the inner listener / background JoinHandles — those
        // would then drop unawaited, detaching the underlying tasks and
        // letting them outlive the harness. Detached tasks holding onto
        // ProxyState / DNS cache / stream listeners can pile up across a
        // full `cargo test` run and (for stream proxies) keep listening
        // sockets open. By NOT aborting, the join task continues to
        // drain in the background; tokio will run it to completion via
        // the shutdown signal we just sent.
        let _ = self.join.take();
    }
}

impl GatewayHarness {
    /// Start a new builder.
    pub fn builder() -> GatewayHarnessBuilder {
        GatewayHarnessBuilder::default()
    }

    /// The gateway's proxy-port base URL (e.g., `http://127.0.0.1:12345`).
    pub fn proxy_base_url(&self) -> &str {
        match &self.backend {
            Backend::Binary { gateway } => &gateway.proxy_base_url,
            Backend::InProcess(b) => &b.proxy_base_url,
        }
    }

    /// Build a full URL under the proxy port: `proxy_url("/api/x")`.
    pub fn proxy_url(&self, path: &str) -> String {
        match &self.backend {
            Backend::Binary { gateway } => gateway.proxy_url(path),
            Backend::InProcess(b) => format!("{}{}", b.proxy_base_url, path),
        }
    }

    /// The gateway's admin-port base URL.
    pub fn admin_base_url(&self) -> &str {
        match &self.backend {
            Backend::Binary { gateway } => &gateway.admin_base_url,
            Backend::InProcess(b) => &b.admin_base_url,
        }
    }

    /// Build a full URL under the admin port.
    pub fn admin_url(&self, path: &str) -> String {
        match &self.backend {
            Backend::Binary { gateway } => gateway.admin_url(path),
            Backend::InProcess(b) => format!("{}{}", b.admin_base_url, path),
        }
    }

    /// `Authorization: Bearer <jwt>` header value for admin calls.
    pub fn admin_auth_header(&self) -> String {
        match &self.backend {
            Backend::Binary { gateway } => gateway.auth_header(),
            Backend::InProcess(b) => format!("Bearer {}", mint_jwt(&b.jwt_secret, &b.jwt_issuer)),
        }
    }

    /// A ready-to-go HTTP/1.1 client. Accepts any TLS cert so the caller
    /// can point it at either plain or TLS frontends without extra setup.
    pub fn http_client(&self) -> Result<Http1Client, Box<dyn std::error::Error + Send + Sync>> {
        Http1Client::insecure().map_err(|e| -> Box<dyn std::error::Error + Send + Sync> { e })
    }

    /// Write an additional file into the harness's temp dir — useful for
    /// cert/key files referenced by admin API config.
    pub fn write_temp_file(&self, name: &str, contents: &str) -> Result<PathBuf, std::io::Error> {
        match &self.backend {
            Backend::Binary { gateway } => gateway.write_temp_file(name, contents),
            Backend::InProcess(b) => {
                let p = b._temp_dir.path().join(name);
                std::fs::write(&p, contents)?;
                Ok(p)
            }
        }
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
        match &self.backend {
            Backend::Binary { gateway } => gateway.wait_for_health(timeout).await,
            Backend::InProcess(b) => wait_for_in_process_health(&b.admin_base_url, timeout).await,
        }
    }

    /// Read captured gateway stdout/stderr. **Binary mode only** —
    /// in-process mode shares the test process's tracing subscriber and
    /// returns an io::Error here. Tests that depend on log assertions
    /// must stay on binary mode.
    pub fn captured_output(&self) -> Result<(String, String), std::io::Error> {
        match &self.backend {
            Backend::Binary { gateway } => gateway.read_captured_output(),
            Backend::InProcess(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "captured_output() is only available in binary mode — \
                 use mode_binary().capture_output() if you need log capture",
            )),
        }
    }

    /// Combined stderr + stdout (stderr first). **Binary mode only.**
    pub fn captured_combined(&self) -> Result<String, std::io::Error> {
        match &self.backend {
            Backend::Binary { gateway } => gateway.read_combined_captured_output(),
            Backend::InProcess(_) => Err(std::io::Error::new(
                std::io::ErrorKind::Unsupported,
                "captured_combined() is only available in binary mode",
            )),
        }
    }

    /// Kill the gateway and read its full captured output. **Binary mode
    /// only.** In-process mode returns an empty string after triggering
    /// shutdown — log capture isn't available.
    pub fn stop_and_collect_logs(&mut self) -> String {
        match &mut self.backend {
            Backend::Binary { gateway } => {
                gateway.shutdown();
                gateway.read_combined_captured_output().unwrap_or_default()
            }
            Backend::InProcess(b) => {
                if let Some(tx) = b.shutdown_tx.take() {
                    let _ = tx.send(true);
                }
                if let Some(handle) = b.join.take() {
                    handle.abort();
                }
                String::new()
            }
        }
    }

    /// Read-only view of the gateway's temp dir.
    pub fn temp_path(&self) -> &std::path::Path {
        match &self.backend {
            Backend::Binary { gateway } => gateway.temp_dir.path(),
            Backend::InProcess(b) => b._temp_dir.path(),
        }
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
            self.mode,
            self.proxy_base_url(),
            self.admin_base_url()
        )
    }
}

fn mint_jwt(secret: &str, issuer: &str) -> String {
    let now = Utc::now();
    let claims = json!({
        "iss": issuer,
        "sub": "test-admin",
        "iat": now.timestamp(),
        "nbf": now.timestamp(),
        "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
        "jti": Uuid::new_v4().to_string(),
    });
    let header = Header::new(jsonwebtoken::Algorithm::HS256);
    let key = EncodingKey::from_secret(secret.as_bytes());
    encode(&header, &claims, &key).expect("encode admin JWT")
}

async fn wait_for_in_process_health(
    admin_base_url: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = std::time::Instant::now() + timeout;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(2))
        .build()?;
    let url = format!("{admin_base_url}/health");
    loop {
        match client.get(&url).send().await {
            Ok(resp) if resp.status().is_success() => return Ok(()),
            _ => {}
        }
        if std::time::Instant::now() >= deadline {
            return Err(format!("in-process gateway not healthy within {timeout:?}").into());
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

/// Convenience: render a JSON value as YAML (same as `write_yaml_value` in
/// common/config_builder).
pub fn yaml(value: &Value) -> String {
    serde_yaml::to_string(value).unwrap_or_else(|_| "<yaml serialize error>".to_string())
}
