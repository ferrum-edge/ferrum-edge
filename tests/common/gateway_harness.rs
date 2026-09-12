//! Shared functional-test harness for spawning the `ferrum-edge` binary.
//!
//! The old per-test `TestHarness` / `AdminTestHarness` / `LoadTestHarness`
//! structs all implemented the same skeleton: 3-attempt retry → ephemeral
//! ports → spawn binary with `Stdio::null()` → `wait_for_health` → `Drop`
//! cleanup. See CLAUDE.md "Functional test port allocation — MUST use retry
//! pattern" for the required behaviour.
//!
//! This module centralises that skeleton in [`TestGateway`] + [`TestGatewayBuilder`]
//! so each new test reaches for a builder instead of copy-pasting ~120 LOC.
//!
//! # Invariants preserved from CLAUDE.md
//!
//! - **3-attempt retry** with fresh ports + fresh temp dir each attempt,
//!   killing any surviving child before retrying. File-mode startup does
//!   not start backend capability refresh until the exclusive proxy bind
//!   has succeeded (issue #4080), so an abandoned EADDRINUSE child cannot
//!   consume a caller-owned scripted backend before the retry.
//!   Callers that pin `FERRUM_PROXY_HTTP_PORT` / `FERRUM_ADMIN_HTTP_PORT` via
//!   [`.env`](TestGatewayBuilder::env) keep that fixed value across attempts,
//!   so a bind-drop-rebind reservation outside the harness defeats the retry.
//!   Prefer letting the harness allocate and reading [`TestGateway::proxy_port`]
//!   after a successful spawn unless a coordinated fixed port is required.
//!   When other listener ports are pinned (e.g. `FERRUM_PROXY_HTTPS_PORT` for
//!   H3), the harness excludes them from its automatic admin/proxy allocations
//!   within each attempt so plaintext and TLS listeners cannot collide.
//! - **`Stdio::null()`** on stdin/stdout/stderr unless
//!   [`TestGatewayBuilder::capture_output`] is enabled. Piped stdout without
//!   reading causes pipe-buffer deadlock; see CLAUDE.md "Functional test
//!   subprocess rule". Failed attempts that capture output append a
//!   secret-scrubbed, size-bounded snapshot to the error.
//! - **Backend/echo listeners held** — this struct only owns the gateway's
//!   own listen ports. Echo servers in `echo_servers.rs` keep their listener.
//! - **`Drop` cleans up the child** so a panic in a test cannot leave a zombie
//!   process holding the admin or proxy port.
//! - **Admin JWT** is HS256 with ≥32-char secret (CLAUDE.md `FERRUM_ADMIN_JWT_SECRET`).
//!
//! # Process identity (issue #3428)
//!
//! [`ephemeral_port`] binds `127.0.0.1:0` and drops the listener, so between
//! reservation and the child's own bind another parallel gateway can claim
//! either port. Readiness alone cannot tell the two apart: a bare TCP accept
//! proves only that *some* listener answers, and an unauthenticated `/health`
//! is served identically by every gateway on the box.
//!
//! Every spawn attempt therefore mints a [`SpawnedGatewayIdentity`] — a fresh
//! admin JWT secret/issuer plus a fresh `FERRUM_METRICS_BEARER_TOKEN` — and
//! startup only succeeds once **this child** is still alive and:
//!
//! 1. the admin port answers `/health` as `ready: true` (readiness), and
//! 2. `GET /proxies` accepts a JWT minted from this attempt's secret/issuer
//!    (ownership).
//!
//! Authenticated `/health` detail is **not** ownership by itself.
//! `observability_detail_allowed` in `src/admin/mod.rs` also grants the full
//! body to `FERRUM_METRICS_ALLOWED_CIDRS` (parallel functional tests do this for
//! `127.0.0.1/32,::1`). A foreign gateway that won the admin port can therefore
//! look ready even when the metrics bearer is wrong. `GET /proxies` is
//! JWT-only and cannot be satisfied by that CIDR grant.
//!
//! - `ready` flips only after `wait_for_start_signals` observed *every*
//!   listener bind — including the proxy HTTP listener — so a live, JWT-owned,
//!   ready child is proof that the child, not a squatter, owns the proxy port.
//!   The child holds that socket for its whole lifetime, so the proof stays
//!   valid while it runs.
//! - That ownership claim requires an **exclusive** proxy bind. Production
//!   binds one exclusive listen socket and duplicates it for
//!   `FERRUM_ACCEPT_THREADS` accept workers — it never sets `SO_REUSEPORT` —
//!   so a second process cannot join the same TCP proxy port. The harness
//!   still pins `FERRUM_ACCEPT_THREADS=1` unless the caller overrides it, so a
//!   colliding bind is a single-socket `EADDRINUSE` and the spawn retry picks
//!   a fresh port.
//!
//! Both waits poll `Child::try_wait` before probes, after a successful health
//! response, while waiting on the JWT endpoint, and immediately before
//! returning success. A child that dies after a partial bind — or after a
//! foreign full-detail `/health` — fails fast instead of attaching to whatever
//! else answers on the released port.
//!
//! Callers that pin `FERRUM_ADMIN_JWT_SECRET` / `FERRUM_METRICS_BEARER_TOKEN`
//! (or open `FERRUM_METRICS_ALLOWED_CIDRS`) keep their explicit value; identity
//! is then only as unique as what they chose.

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::Client;
use serde_json::json;
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::OnceLock;
use std::thread;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::net::{TcpListener, TcpStream};
use uuid::Uuid;

/// Database backend used by a [`TestGateway`] in `database`/`cp` mode.
#[derive(Clone, Debug)]
pub enum DbType {
    /// Embedded SQLite in the harness's temp dir.
    Sqlite,
    /// External Postgres server at the given URL.
    Postgres(String),
    /// External MySQL server at the given URL.
    MySql(String),
    /// External MongoDB server at the given URL.
    Mongo(String),
    /// Fully custom `(db_type, db_url)` — escape hatch for niche TLS or
    /// replica-set configurations.
    Custom { db_type: String, db_url: String },
}

impl DbType {
    /// `FERRUM_DB_TYPE` value.
    fn db_type_value(&self) -> &str {
        match self {
            DbType::Sqlite => "sqlite",
            DbType::Postgres(_) => "postgres",
            DbType::MySql(_) => "mysql",
            DbType::Mongo(_) => "mongodb",
            DbType::Custom { db_type, .. } => db_type,
        }
    }
}

/// The operating mode of the gateway under test.
///
/// Mirrors `FERRUM_MODE` variants from CLAUDE.md §Architecture.
#[derive(Clone, Debug)]
pub enum GatewayMode {
    /// `FERRUM_MODE=database`.
    Database(DbType),
    /// `FERRUM_MODE=file`. The YAML content is written to a temp file.
    File { config_yaml: String },
    /// `FERRUM_MODE=cp`. Read-write admin API + gRPC config distribution.
    ControlPlane {
        db: DbType,
        grpc_listen_addr: Option<String>,
    },
    /// `FERRUM_MODE=dp`. Read-only admin API + gRPC stream from CP.
    DataPlane { cp_grpc_urls: Vec<String> },
}

/// A running gateway subprocess, with helpers for admin/proxy URLs and auth.
///
/// Drop cleans up the process. Under coverage it first asks the gateway to exit
/// normally so profile data can flush, then falls back to a hard kill.
pub struct TestGateway {
    pub temp_dir: TempDir,
    child: Option<Child>,
    pub proxy_port: u16,
    pub admin_port: u16,
    pub proxy_base_url: String,
    pub admin_base_url: String,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    /// Per-spawn `FERRUM_METRICS_BEARER_TOKEN`. Used for authenticated
    /// `/health` readiness probes, not as the sole ownership proof (see the
    /// module docs). Treat it as a secret: never interpolate it into an
    /// assertion message or a log line.
    pub observability_token: String,
    pub basic_auth_hmac_secret: String,
    /// `FERRUM_DB_URL` the gateway was launched with (for DB-mode harnesses).
    pub db_url: Option<String>,
    /// Path to the YAML/JSON config file (file mode only).
    pub config_path: Option<PathBuf>,
    stdout_path: Option<PathBuf>,
    stderr_path: Option<PathBuf>,
    /// Environment the child was actually launched with (post-override).
    /// Lets tests read back per-attempt values such as the ports allocated by
    /// [`TestGatewayBuilder::env_ephemeral_port`].
    launch_env: HashMap<String, String>,
}

impl TestGateway {
    /// Start a fluent builder. Sets sensible defaults: `FERRUM_MODE=database`
    /// with SQLite, `FERRUM_LOG_LEVEL=info`, 30s health timeout, 3 retry
    /// attempts, pool warmup disabled (tests are ephemeral).
    pub fn builder() -> TestGatewayBuilder {
        TestGatewayBuilder::default()
    }

    /// Full URL for a proxy-port path, e.g. `gw.proxy_url("/echo/hi")`.
    pub fn proxy_url(&self, path: &str) -> String {
        format!("{}{}", self.proxy_base_url, path)
    }

    /// Full URL for an admin-port path, e.g. `gw.admin_url("/proxies")`.
    pub fn admin_url(&self, path: &str) -> String {
        format!("{}{}", self.admin_base_url, path)
    }

    /// Mint a fresh admin JWT bearer token (1-hour TTL, fresh `jti`).
    pub fn admin_token(&self) -> String {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "role": "admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "jti": Uuid::new_v4().to_string(),
        });
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        encode(&header, &claims, &key).expect("encode admin JWT")
    }

    /// `Authorization: Bearer <jwt>` header value.
    pub fn auth_header(&self) -> String {
        format!("Bearer {}", self.admin_token())
    }

    /// Poll the admin `/health` endpoint until **this child process** answers
    /// it as ready. Safe to call again after startup to confirm the gateway is
    /// still up (e.g. after a SIGHUP reload).
    ///
    /// This is the identity-anchored probe described in the module docs: it
    /// requires the authenticated detail tier for this instance's
    /// [`observability_token`](Self::observability_token) *and* `ready: true`.
    /// Spawn-time ownership still requires JWT `GET /proxies` on the same
    /// `Child`; `/health` detail can be granted by allowed source CIDRs.
    pub async fn wait_for_health(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        probe_gateway_identity(self.admin_port, &self.observability_token, timeout).await
    }

    /// Poll the admin `/health` endpoint until it reports `"ready": true`.
    ///
    /// Every serving mode binds the admin HTTP listener *before* the rest of
    /// startup (admin HTTPS setup, the CP gRPC bind, `wait_for_start_signals`),
    /// so a bare TCP accept — or any check that tolerates a non-2xx `/health` —
    /// does not prove startup completed. `ready` is stored only after that
    /// barrier, which is also why it doubles as the proxy-listener bind proof
    /// (see the module docs).
    ///
    /// Identical to [`wait_for_health`](Self::wait_for_health); both re-check
    /// authenticated-detail readiness after the spawn-time JWT ownership
    /// barrier. Kept as a distinct name because callers use it to express
    /// "I depend on full startup", not just liveness.
    pub async fn wait_for_ready(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        probe_gateway_identity(self.admin_port, &self.observability_token, timeout).await
    }

    /// Whether the gateway subprocess is still running. `false` once it has
    /// exited, or if the child was already shut down / taken by the caller.
    pub fn is_running(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(None)),
            None => false,
        }
    }

    /// Poll `GET /proxies` until the configured JWT is accepted. Prefer
    /// [`wait_for_owned_gateway_identity`] at spawn time so the JWT wait is
    /// coupled to the same `Child` as readiness.
    pub async fn wait_for_admin_auth(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        wait_for_admin_auth_inner(self.admin_port, &self.auth_header(), timeout, None).await
    }

    /// Poll the proxy port with a raw TCP connect until it accepts or the
    /// deadline expires. Tests that bypass `reqwest` (raw HTTP, hyper H2 prior
    /// knowledge, TCP/UDP listeners) should call this after `spawn` because the
    /// proxy listener is bound on a separate spawned task and there is a brief
    /// window where the admin port answers but the proxy port hasn't propagated
    /// through the kernel's accept queue yet on a loaded CI runner.
    ///
    /// A bare TCP accept proves only that *some* listener answers, so this
    /// first re-proves admin-port ownership (issue #3428). A live, identified
    /// child bound the proxy listener before it ever reported `ready` and never
    /// releases that socket, so the accept that follows is this child's.
    pub async fn wait_for_proxy_port(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        // One shared deadline: re-proving identity must not silently double the
        // caller's timeout budget.
        let deadline = Instant::now() + timeout;
        probe_gateway_identity(self.admin_port, &self.observability_token, timeout).await?;
        let remaining = deadline
            .saturating_duration_since(Instant::now())
            .max(Duration::from_millis(1));
        wait_for_tcp_port_inner("proxy", self.proxy_port, remaining).await
    }

    /// Explicit shutdown. Safe to call multiple times; subsequent calls are
    /// no-ops. Drop also cleans up the child if this was not called.
    pub fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            shutdown_gateway_child(&mut child);
        }
    }

    /// Return the `Child` handle without dropping it (e.g. to send a signal).
    /// After this call, `Drop` will no longer clean up the process — the caller
    /// is responsible for termination.
    pub fn take_child(&mut self) -> Option<Child> {
        self.child.take()
    }

    /// OS PID of the running gateway process, if any. Use for `kill -HUP <pid>`
    /// in file-mode config-reload tests without relinquishing ownership
    /// (Drop still cleans up).
    pub fn pid(&self) -> Option<u32> {
        self.child.as_ref().map(|c| c.id())
    }

    /// Write a YAML/JSON file into the harness's temp dir. Returns the
    /// absolute path. The file is cleaned up when the harness drops.
    /// The launched child's env var `key` parsed as a port, if set.
    ///
    /// This is how a test reads the effective value of a port the harness
    /// allocated per attempt via
    /// [`TestGatewayBuilder::env_ephemeral_port`] — the local variable a
    /// caller-side reservation would have captured does not exist there.
    pub fn env_port(&self, key: &str) -> Option<u16> {
        self.launch_env.get(key)?.parse().ok()
    }

    pub fn write_temp_file(&self, name: &str, contents: &str) -> Result<PathBuf, std::io::Error> {
        let p = self.temp_dir.path().join(name);
        std::fs::write(&p, contents)?;
        Ok(p)
    }

    /// Read the captured stdout/stderr files when [`TestGatewayBuilder::capture_output`]
    /// was enabled. Missing capture files return empty strings.
    pub fn read_captured_output(&self) -> Result<(String, String), std::io::Error> {
        let stdout = self
            .stdout_path
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()?
            .unwrap_or_default();
        let stderr = self
            .stderr_path
            .as_ref()
            .map(std::fs::read_to_string)
            .transpose()?
            .unwrap_or_default();
        Ok((stdout, stderr))
    }

    /// Read captured stderr + stdout in one string, keeping stderr first to
    /// match the previous logging-test behaviour.
    pub fn read_combined_captured_output(&self) -> Result<String, std::io::Error> {
        let (stdout, stderr) = self.read_captured_output()?;
        let mut combined = stderr;
        if !stdout.is_empty() {
            if !combined.is_empty() && !combined.ends_with('\n') {
                combined.push('\n');
            }
            combined.push_str(&stdout);
        }
        Ok(combined)
    }

    /// Secret-scrubbed, size-bounded view of captured child output for failure
    /// diagnostics. Never includes the raw JWT secret, observability token, or
    /// basic-auth HMAC material held by this gateway.
    pub fn diagnostic_captured_output(&self) -> String {
        let raw = self.read_combined_captured_output().unwrap_or_default();
        scrub_gateway_capture_for_diagnostics(
            &raw,
            &[
                self.jwt_secret.as_str(),
                self.observability_token.as_str(),
                self.basic_auth_hmac_secret.as_str(),
            ],
        )
    }

    /// Poll [`read_combined_captured_output`](Self::read_combined_captured_output)
    /// until `predicate` matches, then return that snapshot. On timeout (or a
    /// persistent read error) the last result is returned so the caller can
    /// assert on it and print the output it actually saw.
    ///
    /// The gateway logs through an async `NonBlockingSink`, so a line the child
    /// has already emitted may not have reached the capture file yet — a
    /// readiness or exit barrier does not imply the log worker drained. Polling
    /// is strictly safer than a one-shot read: it can only turn a flush-race
    /// miss into a hit, never a hit into a miss. If the line is never emitted,
    /// the predicate stays false and the caller fails exactly as before.
    ///
    /// Requires [`TestGatewayBuilder::capture_output`]; without it both capture
    /// files are absent, the snapshot is always empty, and the predicate never
    /// matches.
    pub async fn wait_for_captured_output<F>(
        &self,
        predicate: F,
        timeout: Duration,
    ) -> Result<String, std::io::Error>
    where
        F: Fn(&str) -> bool,
    {
        let deadline = Instant::now() + timeout;
        loop {
            let snapshot = self.read_combined_captured_output();
            let matched = snapshot
                .as_ref()
                .is_ok_and(|output| predicate(output.as_str()));
            if matched || Instant::now() >= deadline {
                return snapshot;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        self.shutdown();
    }
}

/// An owned, panic-safe handle to a spawned gateway child.
///
/// A raw [`std::process::Child`] does **not** kill its process when dropped, so
/// any early exit between spawn and the explicit shutdown call — an assertion
/// panic, a `?`, an early `return` — leaves a live gateway reparented to init,
/// still owning its listen ports and contaminating every later run on those
/// fixed ports (issue #4991). Wrapping the child the instant it is spawned
/// makes teardown a property of scope instead of a property of reaching the
/// last line of a test.
///
/// Teardown goes through [`shutdown_gateway_child`], so the coverage build
/// still gets its SIGTERM grace period rather than an immediate `kill`.
pub struct GatewayChildGuard {
    child: Option<Child>,
}

impl GatewayChildGuard {
    /// Take ownership of a freshly spawned gateway.
    pub fn new(child: Child) -> Self {
        Self { child: Some(child) }
    }

    /// Borrow the child for readiness probes (`try_wait`) and log reads.
    pub fn child_mut(&mut self) -> &mut Child {
        self.child
            .as_mut()
            .expect("gateway child was already reaped by this guard")
    }

    /// The child's OS process id while it is still owned.
    pub fn id(&self) -> Option<u32> {
        self.child.as_ref().map(Child::id)
    }

    /// Whether the child has already exited on its own.
    pub fn has_exited(&mut self) -> bool {
        match self.child.as_mut() {
            Some(child) => matches!(child.try_wait(), Ok(Some(_))),
            None => true,
        }
    }

    /// Shut the gateway down now. Idempotent: the guard's `Drop` becomes a
    /// no-op afterwards, so an explicit shutdown and an unwind cannot both
    /// reap the same child.
    pub fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            shutdown_gateway_child(&mut child);
        }
    }
}

impl Drop for GatewayChildGuard {
    fn drop(&mut self) {
        self.shutdown();
    }
}

pub fn shutdown_gateway_child(child: &mut Child) {
    if coverage_profiles_enabled() {
        terminate_child_for_coverage(child, Duration::from_secs(15));
    } else {
        let _ = child.kill();
        let _ = child.wait();
    }
}

pub fn configure_coverage_gateway_command(cmd: &mut Command) {
    if coverage_profiles_enabled() {
        // Keep SIGTERM teardown inside the coverage helper's grace period; the
        // gateway still runs its fixed cleanup step before LLVM profiles flush.
        cmd.env("FERRUM_SHUTDOWN_DRAIN_SECONDS", "0");
    }
}

fn coverage_profiles_enabled() -> bool {
    std::env::var_os("LLVM_PROFILE_FILE").is_some()
}

fn terminate_child_for_coverage(child: &mut Child, timeout: Duration) {
    if matches!(child.try_wait(), Ok(Some(_))) {
        return;
    }

    #[cfg(unix)]
    {
        // Coverage profiles are written on normal process exit. SIGTERM lets
        // the gateway's shutdown handler flush coverage data; kill remains the
        // fallback so failed tests do not leak subprocesses.
        let _ = unsafe { libc::kill(child.id() as libc::pid_t, libc::SIGTERM) };
    }

    #[cfg(not(unix))]
    {
        let _ = child.kill();
        let _ = child.wait();
        return;
    }

    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        match child.try_wait() {
            Ok(Some(_)) => return,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => break,
        }
    }

    let _ = child.kill();
    let _ = child.wait();
}

/// Fluent builder for [`TestGateway`].
///
/// Typical use:
///
/// ```ignore
/// let gw = TestGateway::builder()
///     .mode_database_sqlite()
///     .log_level("warn")
///     .env("FERRUM_TRUSTED_PROXIES", "127.0.0.1")
///     .spawn()
///     .await?;
/// ```
pub struct TestGatewayBuilder {
    mode: GatewayMode,
    /// `None` ⇒ mint a per-spawn-attempt secret so no other gateway on the box
    /// can satisfy this instance's admin auth (issue #3428).
    jwt_secret: Option<String>,
    /// `None` ⇒ mint a per-spawn-attempt issuer, for the same reason.
    jwt_issuer: Option<String>,
    /// `None` ⇒ mint a per-spawn-attempt `FERRUM_METRICS_BEARER_TOKEN` for
    /// authenticated `/health` readiness. Ownership still requires the JWT.
    observability_token: Option<String>,
    basic_auth_hmac_secret: String,
    log_level: String,
    health_timeout: Duration,
    max_attempts: u32,
    auto_build: bool,
    prefer_release: bool,
    extra_env: Vec<(String, String)>,
    /// Env var names that receive a FRESH ephemeral port on every spawn
    /// attempt (see [`Self::env_ephemeral_port`]).
    ephemeral_port_env: Vec<String>,
    /// Listener ports carried outside `extra_env` (for example, raw stream
    /// ports embedded in file-mode YAML). Automatic allocations must not reuse
    /// them within a spawn attempt.
    reserved_listener_ports: HashSet<u16>,
    /// Extra env vars to **remove** before spawning. Handy when the caller's
    /// parent shell has `FERRUM_*` set.
    scrub_env: Vec<String>,
    clear_env: bool,
    capture_output: bool,
    omit_admin_jwt_secret: bool,
    namespace: Option<String>,
    db_poll_interval_seconds: u64,
}

impl Default for TestGatewayBuilder {
    fn default() -> Self {
        Self {
            mode: GatewayMode::Database(DbType::Sqlite),
            // Minted per spawn attempt by `SpawnedGatewayIdentity::mint_for_builder`.
            // Secrets are ≥32 chars per the admin-JWT rule.
            jwt_secret: None,
            jwt_issuer: None,
            observability_token: None,
            // Not an identity factor: the HMAC secret is asserted on by
            // basic-auth tests, so it stays a stable shared default.
            basic_auth_hmac_secret: "ferrum-edge-shared-harness-hmac-secret".to_string(),
            log_level: "info".to_string(),
            health_timeout: Duration::from_secs(30),
            max_attempts: 3,
            auto_build: true,
            prefer_release: false,
            extra_env: Vec::new(),
            ephemeral_port_env: Vec::new(),
            reserved_listener_ports: HashSet::new(),
            scrub_env: Vec::new(),
            clear_env: false,
            capture_output: false,
            omit_admin_jwt_secret: false,
            namespace: None,
            db_poll_interval_seconds: 2,
        }
    }
}

impl TestGatewayBuilder {
    // ────── Mode selection ──────────────────────────────────────────────

    /// Database mode, SQLite in the harness's temp dir (`test.db`). This is
    /// the default.
    pub fn mode_database_sqlite(mut self) -> Self {
        self.mode = GatewayMode::Database(DbType::Sqlite);
        self
    }

    /// Database mode with a caller-supplied DB type + URL.
    pub fn mode_database(mut self, db: DbType) -> Self {
        self.mode = GatewayMode::Database(db);
        self
    }

    /// File mode. The YAML config string is written into the harness's
    /// temp dir at `ferrum.yaml` and passed via `FERRUM_FILE_CONFIG_PATH`.
    pub fn mode_file(mut self, config_yaml: impl Into<String>) -> Self {
        self.mode = GatewayMode::File {
            config_yaml: config_yaml.into(),
        };
        self
    }

    /// Control-plane mode with the given DB backend. If `grpc_listen_addr`
    /// is `None`, the harness picks an ephemeral port.
    pub fn mode_cp(mut self, db: DbType, grpc_listen_addr: Option<String>) -> Self {
        self.mode = GatewayMode::ControlPlane {
            db,
            grpc_listen_addr,
        };
        self
    }

    /// Data-plane mode pointing at one or more CP gRPC URLs (primary first,
    /// fallbacks after). Passed as `FERRUM_DP_CP_GRPC_URLS` when >1 URL.
    pub fn mode_dp(mut self, cp_grpc_urls: Vec<String>) -> Self {
        self.mode = GatewayMode::DataPlane { cp_grpc_urls };
        self
    }

    // ────── Env/config tuning ───────────────────────────────────────────

    /// Override the admin JWT HS256 secret. Must be ≥32 characters for
    /// database/CP modes (CLAUDE.md §Admin JWT secret handling).
    ///
    /// Pinning a shared literal here weakens the JWT ownership proof; a unique
    /// per-attempt secret is the credential a CIDR-granted foreign `/health`
    /// cannot satisfy.
    pub fn jwt_secret(mut self, secret: impl Into<String>) -> Self {
        self.jwt_secret = Some(secret.into());
        self
    }

    /// Override the admin JWT issuer claim (`iss`).
    pub fn jwt_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.jwt_issuer = Some(issuer.into());
        self
    }

    /// Override `FERRUM_METRICS_BEARER_TOKEN`. Only needed by tests that assert
    /// on the metrics auth policy itself — the harness otherwise mints a fresh
    /// token per spawn attempt for authenticated `/health` readiness.
    pub fn observability_token(mut self, token: impl Into<String>) -> Self {
        self.observability_token = Some(token.into());
        self
    }

    /// Override the basic-auth HMAC secret (`FERRUM_BASIC_AUTH_HMAC_SECRET`).
    pub fn basic_auth_hmac_secret(mut self, secret: impl Into<String>) -> Self {
        self.basic_auth_hmac_secret = secret.into();
        self
    }

    /// Set `FERRUM_LOG_LEVEL`. Defaults to `info`.
    pub fn log_level(mut self, level: impl Into<String>) -> Self {
        self.log_level = level.into();
        self
    }

    /// How long to wait for `/health` to respond. Default 30s.
    pub fn health_timeout(mut self, timeout: Duration) -> Self {
        self.health_timeout = timeout;
        self
    }

    /// How many spawn attempts before giving up. Default 3 (per CLAUDE.md).
    pub fn max_attempts(mut self, attempts: u32) -> Self {
        self.max_attempts = attempts;
        self
    }

    /// Skip the `cargo build --bin ferrum-edge` step. The binary must
    /// already exist under `target/debug/` or `target/release/`.
    pub fn skip_auto_build(mut self) -> Self {
        self.auto_build = false;
        self
    }

    /// Prefer `target/release/ferrum-edge` if it exists. Defaults to debug.
    /// Useful for perf/load tests.
    pub fn prefer_release(mut self) -> Self {
        self.prefer_release = true;
        self
    }

    /// Add a custom env var. Takes precedence over the builder's defaults,
    /// so `.env("FERRUM_LOG_LEVEL", "debug")` overrides `.log_level(..)`.
    pub fn env(mut self, key: impl Into<String>, value: impl Into<String>) -> Self {
        self.extra_env.push((key.into(), value.into()));
        self
    }

    /// Set `key` to a FRESH ephemeral port on every spawn attempt.
    ///
    /// A caller-side bind-drop reservation passed through [`.env`](Self::env)
    /// keeps its fixed value across the harness's retry loop, so a single
    /// port steal defeats all attempts (every retry re-collides on the same
    /// port and the child exits 1 at bind). This variant participates in the
    /// per-attempt fresh-port contract instead: each attempt allocates a new
    /// port against the same exclusion set as the admin/proxy allocations, so
    /// it cannot collide with this attempt's other listeners. Read the
    /// effective value after spawn with [`TestGateway::env_port`].
    pub fn env_ephemeral_port(mut self, key: impl Into<String>) -> Self {
        self.ephemeral_port_env.push(key.into());
        self
    }

    /// Reserve a nonzero listener port that is configured outside the
    /// builder's environment map, such as a raw TCP/UDP `listen_port` embedded
    /// in file-mode YAML. Automatic admin, proxy HTTP, and CP gRPC allocations
    /// will not reuse it within a spawn attempt.
    pub fn reserve_listener_port(mut self, port: u16) -> Self {
        if port != 0 {
            self.reserved_listener_ports.insert(port);
        }
        self
    }

    /// Remove a var from the subprocess environment. Useful when the parent
    /// shell has `FERRUM_*` vars set that would override builder defaults.
    pub fn scrub_env(mut self, key: impl Into<String>) -> Self {
        self.scrub_env.push(key.into());
        self
    }

    /// Start from a clean environment, preserving only command lookup,
    /// home/temp dirs, locale vars, and platform loader paths before
    /// applying the builder's explicit `FERRUM_*` settings.
    pub fn clear_env(mut self) -> Self {
        self.clear_env = true;
        self
    }

    /// Redirect stdout/stderr to temp files so tests can inspect structured
    /// logs without risking pipe-buffer deadlocks.
    pub fn capture_output(mut self) -> Self {
        self.capture_output = true;
        self
    }

    /// Omit `FERRUM_ADMIN_JWT_SECRET` from the subprocess env. Useful for
    /// negative tests that assert database/CP mode rejects missing admin JWT
    /// configuration.
    pub fn omit_admin_jwt_secret(mut self) -> Self {
        self.omit_admin_jwt_secret = true;
        self
    }

    /// Set `FERRUM_NAMESPACE`. When omitted, the gateway uses the default
    /// (`ferrum`).
    pub fn namespace(mut self, ns: impl Into<String>) -> Self {
        self.namespace = Some(ns.into());
        self
    }

    /// Set `FERRUM_DB_POLL_INTERVAL` in seconds. Default 2 (fast reload for
    /// tests; production default is 30).
    pub fn db_poll_interval_seconds(mut self, secs: u64) -> Self {
        self.db_poll_interval_seconds = secs;
        self
    }

    // ────── Spawn ───────────────────────────────────────────────────────

    /// Attempt to spawn the gateway, retrying up to `max_attempts` times to
    /// absorb ephemeral-port races. Each attempt allocates a fresh port
    /// pair and a fresh temp dir for the DB / config file.
    pub async fn spawn(mut self) -> Result<TestGateway, Box<dyn std::error::Error + Send + Sync>> {
        if self.auto_build {
            ensure_gateway_built()?;
        }
        let max_attempts = self.max_attempts.max(1);
        let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
        for attempt in 1..=max_attempts {
            match self.try_spawn().await {
                Ok(gw) => return Ok(gw),
                Err(e) => {
                    eprintln!(
                        "TestGateway spawn attempt {}/{} failed: {}",
                        attempt, max_attempts, e
                    );
                    last_err = Some(e);
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "spawn failed with no recorded error".into()))
    }

    /// Spawn once and classify a failure, instead of retrying every error.
    ///
    /// `spawn`'s blanket `max_attempts` loop is right for suites that only care
    /// that a gateway came up, but it also silently re-rolls deterministic
    /// failures — a rejected config, a bad JWT secret, a parse error, a child
    /// that died on its own fault — and reports them, three attempts later, as
    /// "gateway failed to start". A caller that needs a flake budget bounded to
    /// the one race that a fresh port set can fix uses this instead: it makes
    /// exactly one attempt and hands back
    /// [`GatewaySpawnFailure::listener_addr_in_use`], which is `true` only when
    /// THIS child reported a listener bind that failed because the address was
    /// already in use.
    pub async fn spawn_classified(mut self) -> Result<TestGateway, GatewaySpawnFailure> {
        // Classification reads the CHILD's own records, so the capture is not
        // optional on this path: without it `detail` is the harness observation
        // alone ("gateway process exited ... before proving ownership of admin
        // port N"), which can never name a listener, and a genuinely lost port
        // race is reported as `listener_addr_in_use=false` and panics instead
        // of retrying on a fresh port (issue #4972).
        self.capture_output = true;
        if self.auto_build
            && let Err(error) = ensure_gateway_built()
        {
            return GatewaySpawnFailure::from_detail(error.to_string());
        }
        match self.try_spawn().await {
            Ok(gateway) => Ok(gateway),
            Err(error) => GatewaySpawnFailure::from_detail(error.to_string()),
        }
    }

    /// Spawn the gateway and assert it exits non-zero within `timeout`.
    ///
    /// This is useful for conflict-detection / missing-required-env tests where
    /// success is the process rejecting bad configuration before it starts.
    pub async fn spawn_expect_failure(
        mut self,
        timeout: Duration,
    ) -> Result<FailedGatewayStart, Box<dyn std::error::Error + Send + Sync>> {
        if self.auto_build {
            ensure_gateway_built()?;
        }
        let max_attempts = self.max_attempts.max(1);
        let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
        for attempt in 1..=max_attempts {
            match self.try_spawn_expect_failure(timeout).await {
                Ok(result) => return Ok(result),
                Err(e) => {
                    eprintln!(
                        "TestGateway expected-failure attempt {}/{} failed: {}",
                        attempt, max_attempts, e
                    );
                    last_err = Some(e);
                    if attempt < max_attempts {
                        tokio::time::sleep(Duration::from_secs(1)).await;
                    }
                }
            }
        }
        Err(last_err.unwrap_or_else(|| "expected failure failed with no recorded error".into()))
    }

    async fn try_spawn(&mut self) -> Result<TestGateway, Box<dyn std::error::Error + Send + Sync>> {
        let temp_dir = TempDir::new()?;
        let mut excluded_ports = collect_builder_pinned_ports(self);
        // Held, not merely sampled: the sockets stay bound until immediately
        // before `cmd.spawn()` below, so no other process on the runner can
        // take these numbers while the env, config file, and database are
        // still being assembled (issue #4972).
        let admin_hold = hold_ephemeral_port_excluding(&mut excluded_ports).await?;
        let proxy_hold = hold_ephemeral_port_excluding(&mut excluded_ports).await?;
        let admin_port = admin_hold.port;
        let proxy_port = proxy_hold.port;
        let mut port_holds = vec![admin_hold, proxy_hold];
        // Fresh per *attempt*, not per builder: a previous attempt's child may
        // still be winding down, and a retry must never be satisfiable by it.
        let identity = SpawnedGatewayIdentity::mint_for_builder(self);

        let binary = locate_binary(self.prefer_release)?;

        let (mut env, mut db_url, config_path) = build_env(
            self,
            &identity,
            &temp_dir,
            admin_port,
            proxy_port,
            &mut excluded_ports,
        )
        .await?;

        // Caller overrides win — append after defaults so they replace keys.
        for (k, v) in &self.extra_env {
            env.insert(k.clone(), v.clone());
        }

        // Per-attempt ephemeral env ports (see `env_ephemeral_port`): applied
        // after caller overrides so every retry gets a genuinely fresh value,
        // allocated against the same exclusion set as this attempt's
        // admin/proxy ports so listeners cannot collide within the attempt.
        for key in &self.ephemeral_port_env {
            let hold = hold_ephemeral_port_excluding(&mut excluded_ports).await?;
            env.insert(key.clone(), hold.port.to_string());
            port_holds.push(hold);
        }

        let mut cmd = Command::new(&binary);
        cmd.arg("run");
        if self.clear_env {
            cmd.env_clear();
            preserve_base_env(&mut cmd);
        }
        for key in &self.scrub_env {
            cmd.env_remove(key);
        }
        // Clear common parent-shell `FERRUM_*` leakage so builder defaults win
        // deterministically. Only vars not explicitly set by the builder get
        // removed — `env` below re-sets the ones we care about.
        for var in SCRUB_DEFAULTS.iter() {
            if !env.contains_key(*var) {
                cmd.env_remove(*var);
            }
        }
        for (k, v) in &env {
            cmd.env(k, v);
        }
        let stdout_path = self
            .capture_output
            .then(|| temp_dir.path().join("gateway.stdout.log"));
        let stderr_path = self
            .capture_output
            .then(|| temp_dir.path().join("gateway.stderr.log"));
        cmd.stdin(Stdio::null());
        if let Some(path) = &stdout_path {
            cmd.stdout(Stdio::from(File::create(path)?));
        } else {
            cmd.stdout(Stdio::null());
        }
        if let Some(path) = &stderr_path {
            cmd.stderr(Stdio::from(File::create(path)?));
        } else {
            cmd.stderr(Stdio::null());
        }

        // Hand the reserved ports over: release them at the last possible
        // moment so the window in which the child has not yet bound them is
        // the spawn itself rather than every step since allocation.
        drop(port_holds);
        let child = cmd.spawn()?;

        // A final sanity check: pull the db_url we ended up using back out,
        // in case `build_env` picked a fresh path per-attempt.
        if db_url.is_none() {
            db_url = env.get("FERRUM_DB_URL").cloned();
        }

        let effective_proxy_port = parse_port_override(&env, "FERRUM_PROXY_HTTP_PORT", proxy_port)?;
        let effective_admin_port = parse_port_override(&env, "FERRUM_ADMIN_HTTP_PORT", admin_port)?;

        let effective_jwt_secret = env
            .get("FERRUM_ADMIN_JWT_SECRET")
            .cloned()
            .unwrap_or_else(|| identity.jwt_secret.clone());
        let effective_jwt_issuer = env
            .get("FERRUM_ADMIN_JWT_ISSUER")
            .cloned()
            .unwrap_or_else(|| identity.jwt_issuer.clone());
        // Caller `.env(..)` overrides win over the minted token, so read the
        // effective value back rather than trusting `identity`.
        let effective_observability_token = env
            .get("FERRUM_METRICS_BEARER_TOKEN")
            .cloned()
            .unwrap_or_else(|| identity.observability_token.clone());
        let should_verify_admin_auth = env.contains_key("FERRUM_ADMIN_JWT_SECRET");

        let mut gw = TestGateway {
            temp_dir,
            child: Some(child),
            proxy_port: effective_proxy_port,
            admin_port: effective_admin_port,
            proxy_base_url: format!("http://127.0.0.1:{}", effective_proxy_port),
            admin_base_url: format!("http://127.0.0.1:{}", effective_admin_port),
            jwt_secret: effective_jwt_secret,
            jwt_issuer: effective_jwt_issuer,
            observability_token: effective_observability_token,
            basic_auth_hmac_secret: self.basic_auth_hmac_secret.clone(),
            db_url,
            config_path,
            stdout_path,
            stderr_path,
            launch_env: env,
        };

        // Ownership barrier. Health proves readiness; JWT `GET /proxies`
        // proves this child (not a CIDR-granted foreign listener) owns the
        // port. `Child::try_wait` is coupled to both waits.
        let identity_result = {
            let owned = SpawnedGatewayIdentity {
                jwt_secret: gw.jwt_secret.clone(),
                jwt_issuer: gw.jwt_issuer.clone(),
                observability_token: gw.observability_token.clone(),
            };
            let child_handle = gw
                .child
                .as_mut()
                .expect("spawned child must still be owned during identity wait");
            if should_verify_admin_auth {
                wait_for_owned_gateway_identity(
                    child_handle,
                    effective_admin_port,
                    &owned,
                    self.health_timeout,
                )
                .await
            } else {
                wait_for_gateway_identity(
                    effective_admin_port,
                    &owned.observability_token,
                    self.health_timeout,
                    Some(child_handle),
                )
                .await
            }
        };

        match identity_result {
            Ok(()) => Ok(gw),
            Err(e) => {
                let combined_logs = gw.diagnostic_captured_output();
                // Clean up the failed child so the retry loop starts fresh.
                gw.shutdown();
                if combined_logs.is_empty() {
                    Err(e)
                } else {
                    Err(format!("{e}\n--- captured gateway output ---\n{combined_logs}").into())
                }
            }
        }
    }

    async fn try_spawn_expect_failure(
        &mut self,
        timeout: Duration,
    ) -> Result<FailedGatewayStart, Box<dyn std::error::Error + Send + Sync>> {
        let temp_dir = TempDir::new()?;
        let mut excluded_ports = collect_builder_pinned_ports(self);
        let admin_port = ephemeral_port_excluding(&mut excluded_ports).await?;
        let proxy_port = ephemeral_port_excluding(&mut excluded_ports).await?;
        let identity = SpawnedGatewayIdentity::mint_for_builder(self);
        let binary = locate_binary(self.prefer_release)?;
        let (mut env, db_url, config_path) = build_env(
            self,
            &identity,
            &temp_dir,
            admin_port,
            proxy_port,
            &mut excluded_ports,
        )
        .await?;
        for (k, v) in &self.extra_env {
            env.insert(k.clone(), v.clone());
        }

        let mut cmd = Command::new(&binary);
        cmd.arg("run");
        if self.clear_env {
            cmd.env_clear();
            preserve_base_env(&mut cmd);
        }
        for key in &self.scrub_env {
            cmd.env_remove(key);
        }
        for var in SCRUB_DEFAULTS.iter() {
            if !env.contains_key(*var) {
                cmd.env_remove(*var);
            }
        }
        for (k, v) in &env {
            cmd.env(k, v);
        }
        parse_port_override(&env, "FERRUM_PROXY_HTTP_PORT", proxy_port)?;
        parse_port_override(&env, "FERRUM_ADMIN_HTTP_PORT", admin_port)?;
        let stdout_path = temp_dir.path().join("gateway.stdout.log");
        let stderr_path = temp_dir.path().join("gateway.stderr.log");
        cmd.stdin(Stdio::null())
            .stdout(Stdio::from(File::create(&stdout_path)?))
            .stderr(Stdio::from(File::create(&stderr_path)?));

        let mut child = cmd.spawn()?;
        let deadline = Instant::now() + timeout;
        let status = loop {
            if let Some(status) = child.try_wait()? {
                break status;
            }
            if Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
                let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
                return Err(format!(
                    "gateway did not exit within {:?}\n--- stdout ---\n{}\n--- stderr ---\n{}",
                    timeout, stdout, stderr
                )
                .into());
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        };

        if status.success() {
            let stdout = std::fs::read_to_string(&stdout_path).unwrap_or_default();
            let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
            return Err(format!(
                "gateway unexpectedly exited successfully\n--- stdout ---\n{}\n--- stderr ---\n{}",
                stdout, stderr
            )
            .into());
        }

        Ok(FailedGatewayStart {
            status: Some(status),
            stdout: std::fs::read_to_string(&stdout_path).unwrap_or_default(),
            stderr: std::fs::read_to_string(&stderr_path).unwrap_or_default(),
            db_url,
            config_path,
            env,
            // Keep the harness temp dir alive for as long as callers hold this
            // result: `db_url` / `config_path` (and the captured log files we
            // already read) live inside it. Dropping it here would make those
            // public diagnostics point at already-deleted paths.
            _temp_dir: temp_dir,
        })
    }
}

/// A classified `TestGateway` spawn failure.
///
/// The classification exists so a suite can bound its retries to the ONE
/// failure a fresh port set can fix. Anything else — a rejected config, a JWT
/// or auth failure, a parse error, a missing binary, a readiness timeout, a
/// child that died on its own fault — must surface immediately with evidence
/// rather than being re-rolled until the attempt budget runs out.
#[derive(Debug)]
pub struct GatewaySpawnFailure {
    /// `true` only when the spawned child itself reported a listener bind that
    /// failed because the address was already in use.
    pub listener_addr_in_use: bool,
    /// Harness observation plus the child's captured (secret-scrubbed) output.
    pub detail: String,
}

impl GatewaySpawnFailure {
    fn from_detail<T>(detail: String) -> Result<T, Self> {
        Err(Self {
            listener_addr_in_use: captured_output_reports_listener_addr_in_use(&detail),
            detail,
        })
    }

    /// Whether attempt `attempt` (1-based, of `max_attempts`) may be re-rolled
    /// on a fresh port set.
    ///
    /// Exactly one failure is retryable — THIS child losing an address race —
    /// and only while a later attempt remains, so the last attempt always
    /// surfaces its own diagnostic instead of the caller's loop falling
    /// through to a contentless "the gateway never started".
    pub fn is_retryable_port_race(&self, attempt: u32, max_attempts: u32) -> bool {
        self.listener_addr_in_use && attempt < max_attempts
    }
}

impl std::fmt::Display for GatewaySpawnFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "listener_addr_in_use={}: {}",
            self.listener_addr_in_use, self.detail
        )
    }
}

/// The gateway's own listener-failure messages. A record must carry one of
/// these AND an address-in-use indication to be classified retryable.
///
/// The first two interpolate the bind error into the message itself. The third
/// is `crate::startup::flip_ready_off_on_listener_failure`, whose message is
/// fixed and whose cause lives in a sibling `error` field — see
/// [`record_reports_listener_addr_in_use`].
const LISTENER_BIND_MARKERS: [&str; 3] = [
    "Gateway listener task",
    "Stream listener(s) failed to bind",
    "Serving listener task exited with an error",
];

/// Spellings of `std::io::ErrorKind::AddrInUse`. The gateway interpolates the
/// OS error string (Linux and macOS both render "Address already in use"), and
/// a `std::io::Error` constructed from the kind alone renders "address in use".
const ADDR_IN_USE_MARKERS: [&str; 2] = ["address already in use", "address in use"];

/// Decide whether captured gateway output proves a listener bind lost an
/// address race.
///
/// Deliberately **structural**, not a substring scan of the whole capture. The
/// gateway's stdout is the JSON tracing stream, so each line is parsed and only
/// the record's own message (`fields.message`, or a flattened root `message`)
/// is examined. Config values, request bodies, header names, and every other
/// operator- or fixture-supplied string live in different fields and can never
/// satisfy this, so a test whose config happens to contain the phrase is not
/// misclassified as a port race. Non-JSON lines (the pre-subscriber bootstrap
/// error path) are matched as a whole line but still require BOTH a
/// gateway-authored listener marker and an address-in-use marker.
pub fn captured_output_reports_listener_addr_in_use(captured: &str) -> bool {
    captured.lines().any(|line| {
        let line = line.trim();
        if line.is_empty() {
            return false;
        }
        match serde_json::from_str::<serde_json::Value>(line) {
            Ok(record) => record_reports_listener_addr_in_use(&record),
            Err(_) => message_reports_listener_addr_in_use(line),
        }
    })
}

/// Decide whether one structured tracing record is the gateway reporting a
/// lost address race.
///
/// Two shapes qualify. The mode runtimes that interpolate the bind error into
/// the message (`Gateway listener task '<name>' failed: <io error>`) are
/// matched on the message alone. `flip_ready_off_on_listener_failure` — the
/// path every admin/CP/mesh listener takes when its bind fails after the
/// runtime is up — instead emits a FIXED message with the listener name and
/// the rendered `io::Error` in sibling `listener` / `error` fields, so the
/// address-in-use half is read from `error`. Both halves stay gateway-authored
/// and the `error` field is only consulted once the record's own message names
/// a listener failure, so a fixture- or operator-supplied string elsewhere in
/// the record still cannot classify as a port race.
fn record_reports_listener_addr_in_use(record: &serde_json::Value) -> bool {
    let field = |name: &str| {
        record
            .get("fields")
            .and_then(|fields| fields.get(name))
            .or_else(|| record.get(name))
            .and_then(serde_json::Value::as_str)
    };
    let Some(message) = field("message") else {
        return false;
    };
    if message_reports_listener_addr_in_use(message) {
        return true;
    }
    names_listener(message) && field("error").is_some_and(reports_addr_in_use)
}

fn message_reports_listener_addr_in_use(message: &str) -> bool {
    names_listener(message) && reports_addr_in_use(message)
}

fn names_listener(message: &str) -> bool {
    LISTENER_BIND_MARKERS.iter().any(|m| message.contains(m))
}

fn reports_addr_in_use(text: &str) -> bool {
    let lowered = text.to_ascii_lowercase();
    ADDR_IN_USE_MARKERS.iter().any(|m| lowered.contains(m))
}

#[derive(Debug)]
pub struct FailedGatewayStart {
    pub status: Option<ExitStatus>,
    pub stdout: String,
    pub stderr: String,
    pub db_url: Option<String>,
    pub config_path: Option<PathBuf>,
    env: HashMap<String, String>,
    /// Retains the spawn temp dir so `db_url` / `config_path` stay valid while
    /// this result is inspected. Not part of the public diagnostic surface.
    _temp_dir: TempDir,
}

impl FailedGatewayStart {
    pub fn combined_output(&self) -> String {
        let mut combined = self.stderr.clone();
        if !self.stdout.is_empty() {
            if !combined.is_empty() && !combined.ends_with('\n') {
                combined.push('\n');
            }
            combined.push_str(&self.stdout);
        }
        combined
    }

    pub fn env_port(&self, key: &str) -> Option<u16> {
        self.env.get(key)?.parse().ok()
    }
}

/// Env var names we scrub unless the builder explicitly sets them. Prevents
/// parent-shell leakage from fighting the builder's defaults.
const SCRUB_DEFAULTS: &[&str] = &[
    "FERRUM_MODE",
    "FERRUM_FILE_CONFIG_PATH",
    "FERRUM_CP_GRPC_LISTEN_ADDR",
    "FERRUM_DP_CP_GRPC_URLS",
    "FERRUM_PROXY_HTTP_PORT",
    "FERRUM_PROXY_HTTPS_PORT",
    "FERRUM_ADMIN_HTTP_PORT",
    "FERRUM_ADMIN_HTTPS_PORT",
    "FERRUM_ADMIN_MAX_CONNECTIONS",
    "FERRUM_ADMIN_MAX_CONNECTIONS_PER_IP",
    "FERRUM_LOG_LEVEL",
    "FERRUM_POOL_WARMUP_ENABLED",
    "FERRUM_ACCEPT_THREADS",
    "FERRUM_BASIC_AUTH_HMAC_SECRET",
    "FERRUM_NAMESPACE",
    "FERRUM_DB_TYPE",
    "FERRUM_DB_URL",
    "FERRUM_DB_POLL_INTERVAL",
    "FERRUM_DB_TLS_MODE",
    "FERRUM_DB_TLS_CA_CERT_PATH",
    "FERRUM_DB_TLS_CLIENT_CERT_PATH",
    "FERRUM_DB_TLS_CLIENT_KEY_PATH",
    "FERRUM_ADMIN_JWT_SECRET",
    "FERRUM_ADMIN_JWT_ISSUER",
    "FERRUM_CP_DP_GRPC_JWT_SECRET",
    "FERRUM_SHUTDOWN_DRAIN_SECONDS",
    // Identity factors (issue #3428). A leaked parent-shell value here would
    // let a foreign gateway answer the ownership probe.
    "FERRUM_METRICS_BEARER_TOKEN",
    "FERRUM_METRICS_ALLOWED_CIDRS",
];

/// Per-spawn-attempt credentials that make one gateway process individually
/// identifiable on its admin port.
///
/// Nothing here is a real secret — it exists so that two gateways started by
/// two parallel tests can never be mistaken for each other — but the values
/// are still handled like secrets: they are never printed, and identity
/// failures report only *why* the probe failed, never the credential.
///
/// The admin JWT secret is always at least 32 characters (the repository
/// minimum for `FERRUM_ADMIN_JWT_SECRET`).
#[derive(Clone)]
pub struct SpawnedGatewayIdentity {
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub observability_token: String,
}

impl SpawnedGatewayIdentity {
    /// Mint fresh credentials for a bespoke `Command` spawn that does not go
    /// through [`TestGateway`]. `label` is a short test-local prefix.
    pub fn mint(label: &str) -> Self {
        let nonce = Uuid::new_v4().simple().to_string();
        let jwt_secret = format!("ferrum-edge-{label}-admin-secret-{nonce}");
        debug_assert!(
            jwt_secret.len() >= 32,
            "minted admin JWT secret must satisfy the repository minimum"
        );
        Self {
            jwt_secret,
            jwt_issuer: format!("ferrum-edge-{label}-{nonce}"),
            observability_token: format!("ferrum-edge-{label}-probe-{nonce}"),
        }
    }

    /// Mint fresh credentials, honouring any the caller pinned on the builder.
    fn mint_for_builder(b: &TestGatewayBuilder) -> Self {
        let minted = Self::mint("harness");
        Self {
            jwt_secret: b.jwt_secret.clone().unwrap_or(minted.jwt_secret),
            jwt_issuer: b.jwt_issuer.clone().unwrap_or(minted.jwt_issuer),
            observability_token: b
                .observability_token
                .clone()
                .unwrap_or(minted.observability_token),
        }
    }

    /// Configure this identity on a spawned-gateway `Command`. The same values
    /// must be used by [`wait_for_owned_gateway_identity`].
    pub fn apply_to_command(&self, cmd: &mut Command) {
        cmd.env("FERRUM_ADMIN_JWT_SECRET", &self.jwt_secret)
            .env("FERRUM_ADMIN_JWT_ISSUER", &self.jwt_issuer)
            .env("FERRUM_METRICS_BEARER_TOKEN", &self.observability_token);
    }

    /// Mint an HS256 admin JWT (1-hour TTL, fresh `jti`).
    pub fn admin_token(&self) -> String {
        let now = Utc::now();
        let claims = json!({
            "iss": self.jwt_issuer,
            "sub": "test-admin",
            "role": "admin",
            "iat": now.timestamp(),
            "nbf": now.timestamp(),
            "exp": (now + chrono::Duration::seconds(3600)).timestamp(),
            "jti": Uuid::new_v4().to_string(),
        });
        let header = Header::new(jsonwebtoken::Algorithm::HS256);
        let key = EncodingKey::from_secret(self.jwt_secret.as_bytes());
        encode(&header, &claims, &key).expect("encode admin JWT")
    }

    /// `Authorization: Bearer <jwt>` header value.
    pub fn auth_header(&self) -> String {
        format!("Bearer {}", self.admin_token())
    }
}

/// Build the subprocess env map from the builder's mode + tuning knobs.
///
/// Returns (env, db_url, optional config file path). The config file (file
/// mode) is written inside the temp dir so it outlives just the env build.
async fn build_env(
    b: &TestGatewayBuilder,
    identity: &SpawnedGatewayIdentity,
    temp: &TempDir,
    admin_port: u16,
    proxy_port: u16,
    excluded_ports: &mut HashSet<u16>,
) -> Result<
    (HashMap<String, String>, Option<String>, Option<PathBuf>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("FERRUM_PROXY_HTTP_PORT".into(), proxy_port.to_string());
    env.insert("FERRUM_ADMIN_HTTP_PORT".into(), admin_port.to_string());
    env.insert("FERRUM_LOG_LEVEL".into(), b.log_level.clone());
    // A test subprocess gets one accept socket unless the test explicitly
    // overrides this. Production accept workers share one exclusive listen
    // socket (never SO_REUSEPORT); pinning a single accept task keeps the
    // harness bind/drop retry's EADDRINUSE path simple.
    env.insert("FERRUM_ACCEPT_THREADS".into(), "1".into());
    // Tests don't need the 5s warmup stall; pool warmup failures are
    // non-fatal but noisy in test logs.
    env.insert("FERRUM_POOL_WARMUP_ENABLED".into(), "false".into());
    if coverage_profiles_enabled() {
        env.insert("FERRUM_SHUTDOWN_DRAIN_SECONDS".into(), "0".into());
    }
    env.insert(
        "FERRUM_BASIC_AUTH_HMAC_SECRET".into(),
        b.basic_auth_hmac_secret.clone(),
    );
    // Presenting this token unlocks the authenticated detail tier of `/health`
    // for readiness. Ownership still requires the JWT on `GET /proxies`
    // because allowed source CIDRs can grant the same health detail.
    env.insert(
        "FERRUM_METRICS_BEARER_TOKEN".into(),
        identity.observability_token.clone(),
    );
    if let Some(ns) = &b.namespace {
        env.insert("FERRUM_NAMESPACE".into(), ns.clone());
    }

    let mut db_url: Option<String> = None;
    let mut config_path: Option<PathBuf> = None;

    match &b.mode {
        GatewayMode::Database(db) => {
            env.insert("FERRUM_MODE".into(), "database".into());
            if !b.omit_admin_jwt_secret {
                env.insert(
                    "FERRUM_ADMIN_JWT_SECRET".into(),
                    identity.jwt_secret.clone(),
                );
            }
            env.insert(
                "FERRUM_ADMIN_JWT_ISSUER".into(),
                identity.jwt_issuer.clone(),
            );
            env.insert(
                "FERRUM_DB_POLL_INTERVAL".into(),
                b.db_poll_interval_seconds.to_string(),
            );
            let (db_type, url) = resolve_db(db, temp);
            env.insert("FERRUM_DB_TYPE".into(), db_type);
            env.insert("FERRUM_DB_URL".into(), url.clone());
            db_url = Some(url);
        }
        GatewayMode::File { config_yaml } => {
            env.insert("FERRUM_MODE".into(), "file".into());
            // File mode generates its own admin JWT secret internally (read-only
            // API), but setting a secret makes admin tokens testable.
            if !b.omit_admin_jwt_secret {
                env.insert(
                    "FERRUM_ADMIN_JWT_SECRET".into(),
                    identity.jwt_secret.clone(),
                );
            }
            env.insert(
                "FERRUM_ADMIN_JWT_ISSUER".into(),
                identity.jwt_issuer.clone(),
            );
            let path = temp.path().join("ferrum.yaml");
            std::fs::write(&path, config_yaml)?;
            env.insert(
                "FERRUM_FILE_CONFIG_PATH".into(),
                path.to_string_lossy().into_owned(),
            );
            config_path = Some(path);
        }
        GatewayMode::ControlPlane {
            db,
            grpc_listen_addr,
        } => {
            env.insert("FERRUM_MODE".into(), "cp".into());
            if !b.omit_admin_jwt_secret {
                env.insert(
                    "FERRUM_ADMIN_JWT_SECRET".into(),
                    identity.jwt_secret.clone(),
                );
            }
            env.insert(
                "FERRUM_ADMIN_JWT_ISSUER".into(),
                identity.jwt_issuer.clone(),
            );
            env.insert(
                "FERRUM_DB_POLL_INTERVAL".into(),
                b.db_poll_interval_seconds.to_string(),
            );
            // CP/DP gRPC JWT is a separate secret from the admin JWT.
            env.insert(
                "FERRUM_CP_DP_GRPC_JWT_SECRET".into(),
                "ferrum-edge-shared-harness-grpc-secret00".into(),
            );
            let (db_type, url) = resolve_db(db, temp);
            env.insert("FERRUM_DB_TYPE".into(), db_type);
            env.insert("FERRUM_DB_URL".into(), url.clone());
            db_url = Some(url);

            let addr = match grpc_listen_addr {
                Some(a) => a.clone(),
                None => {
                    let port = ephemeral_port_excluding(excluded_ports).await?;
                    format!("127.0.0.1:{port}")
                }
            };
            env.insert("FERRUM_CP_GRPC_LISTEN_ADDR".into(), addr);
        }
        GatewayMode::DataPlane { cp_grpc_urls } => {
            env.insert("FERRUM_MODE".into(), "dp".into());
            if !b.omit_admin_jwt_secret {
                env.insert(
                    "FERRUM_ADMIN_JWT_SECRET".into(),
                    identity.jwt_secret.clone(),
                );
            }
            env.insert(
                "FERRUM_ADMIN_JWT_ISSUER".into(),
                identity.jwt_issuer.clone(),
            );
            env.insert(
                "FERRUM_CP_DP_GRPC_JWT_SECRET".into(),
                "ferrum-edge-shared-harness-grpc-secret00".into(),
            );
            if cp_grpc_urls.is_empty() {
                return Err("mode_dp requires at least one CP gRPC URL".into());
            }
            env.insert("FERRUM_DP_CP_GRPC_URLS".into(), cp_grpc_urls.join(","));
        }
    }

    Ok((env, db_url, config_path))
}

fn resolve_db(db: &DbType, temp: &TempDir) -> (String, String) {
    match db {
        DbType::Sqlite => {
            let path = temp.path().join("test.db");
            (
                "sqlite".to_string(),
                format!("sqlite:{}?mode=rwc", path.to_string_lossy()),
            )
        }
        DbType::Postgres(url) => ("postgres".to_string(), url.clone()),
        DbType::MySql(url) => ("mysql".to_string(), url.clone()),
        DbType::Mongo(url) => ("mongodb".to_string(), url.clone()),
        DbType::Custom { db_type, db_url } => (db_type.clone(), db_url.clone()),
    }
}

/// Env vars that pin a gateway listener port when set via
/// [`TestGatewayBuilder::env`]. Automatic allocations within one spawn attempt
/// must not reuse these values, or a bind-drop-rebind reservation outside the
/// harness can collide with an auto-picked plaintext port (issue: ACME policy
/// path flake — TLS alert bytes on a raw H1 client).
const LISTENER_PORT_ENV_KEYS: &[&str] = &[
    "FERRUM_PROXY_HTTP_PORT",
    "FERRUM_PROXY_HTTPS_PORT",
    "FERRUM_ADMIN_HTTP_PORT",
    "FERRUM_ADMIN_HTTPS_PORT",
];

/// Ports explicitly pinned through [`TestGatewayBuilder::env`] before spawn.
fn collect_env_pinned_ports(extra_env: &[(String, String)]) -> HashSet<u16> {
    let mut pinned = HashSet::new();
    for (key, value) in extra_env {
        if LISTENER_PORT_ENV_KEYS.contains(&key.as_str()) {
            if let Ok(port) = value.parse::<u16>()
                && port != 0
            {
                pinned.insert(port);
            }
        } else if key == "FERRUM_CP_GRPC_LISTEN_ADDR"
            && let Some(port) = parse_listen_addr_port(value)
            && port != 0
        {
            pinned.insert(port);
        }
    }
    pinned
}

/// Every listener port known to the builder before automatic allocation.
/// Explicit CP addresses are part of the mode rather than `extra_env`; raw
/// stream ports embedded in file config are supplied through
/// [`TestGatewayBuilder::reserve_listener_port`].
fn collect_builder_pinned_ports(builder: &TestGatewayBuilder) -> HashSet<u16> {
    let mut pinned = builder.reserved_listener_ports.clone();
    pinned.extend(collect_env_pinned_ports(&builder.extra_env));
    if let GatewayMode::ControlPlane {
        grpc_listen_addr: Some(addr),
        ..
    } = &builder.mode
        && let Some(port) = parse_listen_addr_port(addr)
        && port != 0
    {
        pinned.insert(port);
    }
    pinned
}

fn parse_listen_addr_port(addr: &str) -> Option<u16> {
    let (_, port_str) = addr.rsplit_once(':')?;
    port_str.parse().ok()
}

/// Bind an ephemeral port, then drop the listener. Not race-free — the
/// caller must retry if the gateway binds fail. This is what the
/// `max_attempts` loop in [`TestGatewayBuilder::spawn`] exists for.
pub async fn ephemeral_port() -> Result<u16, std::io::Error> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
}

/// An ephemeral port kept bound until the caller hands it over.
///
/// [`ephemeral_port_excluding`] frees its port the instant it returns, so
/// every step between allocation and the child's own bind is a window in which
/// another process on the runner can take the number. Holding the listener
/// collapses that window to the spawn call itself.
pub struct HeldEphemeralPort {
    /// The held port.
    pub port: u16,
    _listener: TcpListener,
}

/// Like [`ephemeral_port_excluding`], but keeps the listener bound. Drop the
/// return value immediately before spawning the process that binds the port.
pub async fn hold_ephemeral_port_excluding(
    excluded: &mut HashSet<u16>,
) -> Result<HeldEphemeralPort, std::io::Error> {
    const MAX_ATTEMPTS: u32 = 50;
    for _ in 0..MAX_ATTEMPTS {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let port = listener.local_addr()?.port();
        if excluded.contains(&port) {
            continue;
        }
        excluded.insert(port);
        return Ok(HeldEphemeralPort {
            port,
            _listener: listener,
        });
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "exhausted held ephemeral port allocation while excluding pinned ports",
    ))
}

/// Like [`ephemeral_port`], but never returns a port already present in
/// `excluded`. On success, inserts the chosen port into `excluded` so later
/// allocations in the same spawn attempt stay distinct.
pub async fn ephemeral_port_excluding(excluded: &mut HashSet<u16>) -> Result<u16, std::io::Error> {
    const MAX_ATTEMPTS: u32 = 50;
    for _ in 0..MAX_ATTEMPTS {
        let port = ephemeral_port().await?;
        if excluded.contains(&port) {
            continue;
        }
        excluded.insert(port);
        return Ok(port);
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AddrInUse,
        "exhausted ephemeral port allocation while excluding pinned ports",
    ))
}

/// Field that `/health` emits only in the authenticated (detail) tier. The
/// unauthenticated tier is exactly `{"status": …, "ready": …}`, so seeing this
/// key proves the responder accepted our per-instance credential.
///
/// Keep in sync with the `/health` handler in `src/admin/mod.rs`, which sets
/// `cached_config` unconditionally in every serving mode (including DP before
/// its first CP snapshot, where it reports `available: false`) and returns the
/// full body only when `observability_detail_allowed` is true.
const HEALTH_DETAIL_TIER_MARKER: &str = "cached_config";

/// One ownership probe against an admin port. `Ok` means the responder is the
/// process holding `observability_token` *and* it reports `ready`.
///
/// Errors describe why the probe failed without ever echoing the credential.
/// The `/health` body is also not echoed wholesale: on a foreign gateway it
/// belongs to an unrelated test, and reproducing it here would be confusing
/// rather than diagnostic.
async fn probe_gateway_identity_once(
    client: &Client,
    admin_port: u16,
    observability_token: &str,
) -> Result<(), String> {
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    let response = client
        .get(&health_url)
        .header("Authorization", format!("Bearer {observability_token}"))
        .send()
        .await
        .map_err(|err| err.to_string())?;
    let status = response.status();
    let body = response.text().await.unwrap_or_default();
    let value: serde_json::Value = serde_json::from_str(&body)
        .map_err(|err| format!("HTTP {status}: /health body was not JSON ({err})"))?;
    if value.get(HEALTH_DETAIL_TIER_MARKER).is_none() {
        return Err(format!(
            "HTTP {status}: /health answered in the unauthenticated tier — the listener on \
             this port did not accept this instance's credential, so it is not the spawned child"
        ));
    }
    if !status.is_success() {
        return Err(format!("HTTP {status}"));
    }
    if value.get("ready").and_then(serde_json::Value::as_bool) != Some(true) {
        return Err(format!(
            "HTTP {status}: identified gateway is not ready yet"
        ));
    }
    Ok(())
}

/// Poll [`probe_gateway_identity_once`] until it succeeds or the deadline
/// expires, optionally failing fast when the spawned child exits first.
///
/// Passing the child is what keeps a partial bind from looking like success: a
/// gateway that binds the admin listener and then dies during
/// `wait_for_start_signals` releases the port, and without this check the loop
/// would keep polling whatever claims it next until the full timeout elapses.
/// A successful health response is re-checked against `Child::try_wait`
/// before returning so a foreign full-detail responder cannot win while this
/// child is concurrently exiting.
async fn wait_for_gateway_identity(
    admin_port: u16,
    observability_token: &str,
    timeout: Duration,
    mut child: Option<&mut Child>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let deadline = Instant::now() + timeout;
    let mut last_observation = String::from("no response yet");
    loop {
        if let Some(child) = child.as_deref_mut() {
            fail_if_child_exited(child, admin_port, &last_observation)?;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "gateway did not prove readiness on admin port {admin_port} within {timeout:?} \
                 (last observation: {last_observation})"
            )
            .into());
        }
        match probe_gateway_identity_once(&client, admin_port, observability_token).await {
            Ok(()) => {
                last_observation = "authenticated /health ready".to_string();
                if let Some(child) = child.as_deref_mut() {
                    fail_if_child_exited(child, admin_port, &last_observation)?;
                }
                return Ok(());
            }
            Err(observation) => last_observation = observation,
        }
        tokio::time::sleep(Duration::from_millis(250)).await;
    }
}

fn fail_if_child_exited(
    child: &mut Child,
    admin_port: u16,
    last_observation: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    match child.try_wait() {
        Ok(None) => Ok(()),
        Ok(Some(status)) => Err(format!(
            "gateway process exited with {status} before proving ownership of admin \
             port {admin_port} (last observation: {last_observation})"
        )
        .into()),
        Err(err) => Err(format!(
            "could not confirm gateway process is still alive on admin port {admin_port} \
             (try_wait failed: {err}; last observation: {last_observation})"
        )
        .into()),
    }
}

/// Ownership probe without a child handle — for callers that only hold the
/// admin port and the instance token (post-startup re-checks, and the
/// foreign-listener regression tests). This is readiness, not JWT ownership.
pub async fn probe_gateway_identity(
    admin_port: u16,
    observability_token: &str,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    wait_for_gateway_identity(admin_port, observability_token, timeout, None).await
}

/// Fail-fast ownership barrier for a spawned child.
///
/// Couples authenticated `/health` readiness and JWT-only `GET /proxies` to
/// the same `Child`. A foreign gateway granted full `/health` detail by
/// `FERRUM_METRICS_ALLOWED_CIDRS` cannot satisfy the unique per-attempt JWT.
/// `Child::try_wait` runs before probes, after health success, while waiting on
/// `/proxies`, and immediately before returning success.
pub async fn wait_for_owned_gateway_identity(
    child: &mut Child,
    admin_port: u16,
    identity: &SpawnedGatewayIdentity,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + timeout;
    wait_for_gateway_identity(
        admin_port,
        &identity.observability_token,
        timeout,
        Some(child),
    )
    .await?;
    fail_if_child_exited(
        child,
        admin_port,
        "authenticated /health ready; waiting for JWT /proxies",
    )?;
    let remaining = deadline
        .saturating_duration_since(Instant::now())
        .max(Duration::from_millis(1));
    wait_for_admin_auth_inner(admin_port, &identity.auth_header(), remaining, Some(child)).await?;
    fail_if_child_exited(
        child,
        admin_port,
        "authenticated /health ready; JWT /proxies accepted",
    )
}

async fn wait_for_admin_auth_inner(
    admin_port: u16,
    auth_header: &str,
    timeout: Duration,
    mut child: Option<&mut Child>,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let auth_url = format!("http://127.0.0.1:{}/proxies", admin_port);
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let deadline = Instant::now() + timeout;
    let mut last_observation = String::from("no response yet");
    loop {
        if let Some(child) = child.as_deref_mut() {
            fail_if_child_exited(child, admin_port, &last_observation)?;
        }
        if Instant::now() >= deadline {
            return Err(format!(
                "gateway admin JWT did not validate on port {} within {:?} (last observation: {})",
                admin_port, timeout, last_observation
            )
            .into());
        }
        match client
            .get(&auth_url)
            .header("Authorization", auth_header)
            .send()
            .await
        {
            Ok(r) => {
                let status = r.status();
                // Drain the body so the connection can close, but never echo it:
                // a foreign listener may be serving another test's admin data.
                let _ = r.bytes().await;
                if status.as_u16() == 200 {
                    last_observation = "HTTP 200 on GET /proxies".to_string();
                    if let Some(child) = child.as_deref_mut() {
                        fail_if_child_exited(child, admin_port, &last_observation)?;
                    }
                    return Ok(());
                }
                last_observation = format!("HTTP {status} on GET /proxies");
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
            Err(err) => {
                last_observation = err.to_string();
                tokio::time::sleep(Duration::from_millis(250)).await;
            }
        }
    }
}

async fn wait_for_tcp_port_inner(
    label: &str,
    port: u16,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let deadline = Instant::now() + timeout;
    let mut last_err: Option<std::io::Error> = None;
    loop {
        if Instant::now() >= deadline {
            let observation = last_err
                .map(|e| e.to_string())
                .unwrap_or_else(|| "no response yet".to_string());
            return Err(format!(
                "gateway {label} port {port} did not accept TCP connections within {timeout:?} (last observation: {observation})"
            )
            .into());
        }
        match TcpStream::connect(("127.0.0.1", port)).await {
            Ok(stream) => {
                drop(stream);
                return Ok(());
            }
            Err(err) => {
                last_err = Some(err);
                tokio::time::sleep(Duration::from_millis(25)).await;
            }
        }
    }
}

fn parse_port_override(
    env: &HashMap<String, String>,
    key: &str,
    fallback: u16,
) -> Result<u16, std::io::Error> {
    match env.get(key) {
        Some(raw) => raw.parse::<u16>().map_err(|err| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("invalid {key} override '{raw}': {err}"),
            )
        }),
        None => Ok(fallback),
    }
}

fn preserve_base_env(cmd: &mut Command) {
    for key in [
        "PATH",
        "HOME",
        "TMPDIR",
        "TMP",
        "TEMP",
        "LANG",
        "LC_ALL",
        "LC_CTYPE",
        "LD_LIBRARY_PATH",
        "DYLD_LIBRARY_PATH",
        "DYLD_FALLBACK_LIBRARY_PATH",
        "LLVM_PROFILE_FILE",
        "LLVM_PROFILE_MERGER_POOL_SIZE",
    ] {
        if let Ok(value) = std::env::var(key) {
            cmd.env(key, value);
        }
    }
    for (key, value) in std::env::vars() {
        if key.starts_with("LC_") && key != "LC_ALL" && key != "LC_CTYPE" {
            cmd.env(key, value);
        }
    }
}

pub fn explicit_test_binary() -> Option<PathBuf> {
    for key in ["FERRUM_EDGE_TEST_BIN", "CARGO_BIN_EXE_ferrum-edge"] {
        if let Some(path) = std::env::var_os(key).map(PathBuf::from)
            && path.exists()
        {
            return Some(path);
        }
    }
    None
}

/// Locate the built `ferrum-edge` binary. Preference order:
/// 1. `FERRUM_EDGE_TEST_BIN`, when an outer harness wants an explicit binary.
/// 2. `CARGO_BIN_EXE_ferrum-edge`, when Cargo built an instrumented binary.
/// 3. `target/release/ferrum-edge` if `prefer_release` (load tests).
/// 4. `target/debug/ferrum-edge` (normal).
/// 5. `target/release/ferrum-edge` as a fallback.
fn locate_binary(
    prefer_release: bool,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
    if let Some(path) = explicit_test_binary() {
        return Ok(path);
    }

    let debug = PathBuf::from("./target/debug/ferrum-edge");
    let release = PathBuf::from("./target/release/ferrum-edge");
    if prefer_release && release.exists() {
        return Ok(release);
    }
    if debug.exists() {
        return Ok(debug);
    }
    if release.exists() {
        return Ok(release);
    }
    Err("ferrum-edge binary not found. Run `cargo build --bin ferrum-edge` first.".into())
}

/// Build the gateway binary at most once per test-binary process. Parallel
/// tests share the result via `OnceLock`.
///
/// Always invokes `cargo build --bin ferrum-edge` — cargo's own incremental
/// build is a no-op (~100ms) when nothing has changed, and guarantees that
/// tests never run against a stale binary after a source edit. Callers that
/// want to skip the build entirely (e.g. when the binary was built by an
/// outer CI step) can opt out via [`TestGatewayBuilder::skip_auto_build`].
///
/// Setting `FERRUM_SKIP_GATEWAY_BUILD=1` short-circuits the cargo invocation
/// globally — used in CI when a prebuilt binary has already been downloaded
/// into `target/debug/` (or `target/release/`) by an upstream job. With
/// nextest (one process per test) that single env var saves N cargo
/// fingerprint checks per shard, where N is the number of tests.
///
/// Exposed publicly so functional tests with their own subprocess helpers
/// (rather than [`TestGateway`]) share the same skip-build contract without
/// duplicating the env-var + path-existence dance.
pub fn ensure_gateway_built() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    static RESULT: OnceLock<Result<(), String>> = OnceLock::new();
    let result = RESULT.get_or_init(|| -> Result<(), String> {
        if explicit_test_binary().is_some() {
            return Ok(());
        }

        if std::env::var_os("FERRUM_SKIP_GATEWAY_BUILD").is_some() {
            let debug = PathBuf::from("./target/debug/ferrum-edge");
            let release = PathBuf::from("./target/release/ferrum-edge");
            if !debug.exists() && !release.exists() {
                return Err(
                    "FERRUM_SKIP_GATEWAY_BUILD set but ferrum-edge binary not found in \
                     ./target/debug/ or ./target/release/"
                        .to_string(),
                );
            }
            return Ok(());
        }
        let status = Command::new("cargo")
            .args(["build", "--bin", "ferrum-edge"])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .map_err(|e| format!("cargo build spawn failed: {e}"))?;
        if !status.success() {
            return Err(format!("cargo build --bin ferrum-edge failed: {}", status));
        }
        Ok(())
    });
    match result {
        Ok(()) => Ok(()),
        Err(msg) => Err(msg.clone().into()),
    }
}

/// Maximum bytes of captured gateway output retained in spawn-failure errors.
const GATEWAY_CAPTURE_DIAGNOSTIC_MAX_BYTES: usize = 16 * 1024;

/// Scrub secrets and bound captured gateway logs for harness failure diagnostics.
///
/// Redacts URL userinfo before replacing every provided non-empty secret (empty
/// strings are skipped because replacing them would corrupt the entire capture)
/// (`scheme://user:pass@host`), and keeps only the trailing
/// `GATEWAY_CAPTURE_DIAGNOSTIC_MAX_BYTES` so hosted CI stays actionable without
/// dumping unbounded child output.
pub fn scrub_gateway_capture_for_diagnostics(raw: &str, secrets: &[&str]) -> String {
    // Preserve URL delimiters until userinfo has been removed: a short caller
    // secret such as `/`, `:`, or `@` could otherwise make the URL unrecognizable.
    let mut text = scrub_url_userinfo_in_text(raw);
    for secret in secrets {
        if !secret.is_empty() {
            text = text.replace(secret, "***");
        }
    }
    truncate_utf8_suffix(&text, GATEWAY_CAPTURE_DIAGNOSTIC_MAX_BYTES)
}

fn scrub_url_userinfo_in_text(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(scheme_rel) = rest.find("://") {
        let after_scheme = scheme_rel + 3;
        out.push_str(&rest[..after_scheme]);
        let tail = &rest[after_scheme..];
        match tail.find('@') {
            Some(at_rel)
                if !tail[..at_rel].is_empty()
                    && !tail[..at_rel].contains('/')
                    && !tail[..at_rel].contains(|c: char| c.is_whitespace()) =>
            {
                out.push_str("***");
                rest = &tail[at_rel..];
            }
            _ => {
                rest = tail;
            }
        }
    }
    out.push_str(rest);
    out
}

fn truncate_utf8_suffix(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }
    let mut start = text.len() - max_bytes;
    while start < text.len() && !text.is_char_boundary(start) {
        start += 1;
    }
    format!("…[truncated]…\n{}", &text[start..])
}

#[cfg(test)]
mod port_allocation_tests {
    use super::*;

    #[tokio::test]
    async fn ephemeral_port_excluding_skips_pinned_port() {
        let mut excluded = HashSet::from([42424u16]);
        let port = ephemeral_port_excluding(&mut excluded)
            .await
            .expect("allocate excluding pinned port");
        assert_ne!(port, 42424, "must not reuse an env-pinned listener port");
        assert!(excluded.contains(&port));
    }

    #[tokio::test]
    async fn ephemeral_port_excluding_keeps_allocations_distinct() {
        let mut excluded = HashSet::new();
        let first = ephemeral_port_excluding(&mut excluded)
            .await
            .expect("first allocation");
        let second = ephemeral_port_excluding(&mut excluded)
            .await
            .expect("second allocation");
        assert_ne!(first, second, "ports within one spawn attempt must differ");
    }

    #[test]
    fn collect_env_pinned_ports_reads_listener_overrides() {
        let extra_env = vec![
            ("FERRUM_PROXY_HTTPS_PORT".to_string(), "3443".to_string()),
            (
                "FERRUM_CP_GRPC_LISTEN_ADDR".to_string(),
                "127.0.0.1:9090".to_string(),
            ),
            ("FERRUM_PROXY_HTTP_PORT".to_string(), "0".to_string()),
        ];
        let pinned = collect_env_pinned_ports(&extra_env);
        assert_eq!(pinned, HashSet::from([3443, 9090]));
    }

    #[test]
    fn collect_builder_pinned_ports_includes_mode_and_reserved_listeners() {
        let builder = TestGateway::builder()
            .mode_cp(DbType::Sqlite, Some("127.0.0.1:9443".to_string()))
            .reserve_listener_port(7443)
            .reserve_listener_port(0)
            .env("FERRUM_PROXY_HTTPS_PORT", "3443");
        let pinned = collect_builder_pinned_ports(&builder);
        assert_eq!(pinned, HashSet::from([3443, 7443, 9443]));
    }

    /// Deterministic classification: only the gateway's own listener-bind
    /// failure counts as a retryable port race.
    #[test]
    fn listener_addr_in_use_classification_is_structural() {
        // Real shape: a JSON tracing record whose `fields.message` is the
        // gateway's listener-task failure carrying the OS error.
        let record = r#"{"timestamp":"2026-08-05T00:00:00Z","level":"ERROR","fields":{"message":"Gateway listener task 'proxy_https' failed: Address already in use (os error 98)"},"target":"ferrum_edge::modes::file"}"#;
        assert!(captured_output_reports_listener_addr_in_use(record));

        // Stream-listener bind failures are the same class.
        let stream = r#"{"level":"ERROR","fields":{"message":"Stream listener(s) failed to bind:\n  tcp 9000: Address already in use (os error 48)"}}"#;
        assert!(captured_output_reports_listener_addr_in_use(stream));

        // A DIFFERENT deterministic failure must not be retried.
        let config_error = r#"{"level":"ERROR","fields":{"message":"Configuration validation failed: 1 invalid upstream reference(s) found"}}"#;
        assert!(!captured_output_reports_listener_addr_in_use(config_error));

        // A listener message without the address-in-use cause is not a port race.
        let other_bind = r#"{"level":"ERROR","fields":{"message":"Gateway listener task 'proxy_https' failed: Permission denied (os error 13)"}}"#;
        assert!(!captured_output_reports_listener_addr_in_use(other_bind));

        // The phrase appearing in operator-controlled DATA must not classify:
        // it is not the record's own message.
        let data_only = r#"{"level":"INFO","fields":{"message":"Configuration loaded"},"config":"Gateway listener task Address already in use"}"#;
        assert!(!captured_output_reports_listener_addr_in_use(data_only));

        // ...and neither must a body/echo field that merely quotes it.
        let echoed = r#"{"level":"INFO","fields":{"message":"proxy response","body":"Gateway listener task 'x' failed: Address already in use"}}"#;
        assert!(!captured_output_reports_listener_addr_in_use(echoed));

        // The pre-subscriber bootstrap path is plain text, and still needs BOTH
        // markers on the same line.
        assert!(captured_output_reports_listener_addr_in_use(
            "Gateway listener task failed: Address already in use (os error 98)"
        ));
        assert!(!captured_output_reports_listener_addr_in_use(
            "Address already in use"
        ));
        assert!(!captured_output_reports_listener_addr_in_use(""));
    }

    /// Issue #4972: `flip_ready_off_on_listener_failure` keeps its message
    /// fixed and puts the cause in a sibling `error` field, so a classifier
    /// that only reads `fields.message` calls a lost admin-port race
    /// `listener_addr_in_use=false` and the caller panics instead of retrying.
    #[test]
    fn listener_addr_in_use_classification_reads_the_structured_error_field() {
        // Verbatim shape of the CP admin listener failure captured in CI.
        let admin_race = r#"{"timestamp":"2026-09-09T00:00:00Z","level":"ERROR","fields":{"message":"Serving listener task exited with an error; marked serving degraded and flipped readiness to not-ready","listener":"CP admin HTTP listener","error":"Address already in use (os error 98)"},"target":"ferrum_edge::startup"}"#;
        assert!(captured_output_reports_listener_addr_in_use(admin_race));

        // The same listener failure with a DIFFERENT cause stays deterministic.
        let denied = r#"{"level":"ERROR","fields":{"message":"Serving listener task exited with an error; marked serving degraded and flipped readiness to not-ready","listener":"CP admin HTTP listener","error":"Permission denied (os error 13)"}}"#;
        assert!(!captured_output_reports_listener_addr_in_use(denied));

        // An `error` field alone does not classify: the record's own message
        // must still be a gateway-authored listener failure.
        let unrelated = r#"{"level":"ERROR","fields":{"message":"Configuration validation failed: 1 invalid upstream reference(s) found","error":"Address already in use (os error 98)"}}"#;
        assert!(!captured_output_reports_listener_addr_in_use(unrelated));

        // Neither does a record with no message at all.
        let messageless = r#"{"level":"ERROR","fields":{"listener":"CP admin HTTP listener","error":"Address already in use (os error 98)"}}"#;
        assert!(!captured_output_reports_listener_addr_in_use(messageless));
    }

    /// The retry budget callers share: a classified port race is re-rolled
    /// only while a later attempt remains, and nothing else is ever re-rolled.
    #[test]
    fn retryable_port_race_is_bounded_to_the_classified_race() {
        let race = GatewaySpawnFailure {
            listener_addr_in_use: true,
            detail: "port race".to_string(),
        };
        assert!(race.is_retryable_port_race(1, 3));
        assert!(race.is_retryable_port_race(2, 3));
        // The final attempt surfaces its diagnostic rather than being consumed.
        assert!(!race.is_retryable_port_race(3, 3));
        assert!(!race.is_retryable_port_race(1, 1));

        let deterministic = GatewaySpawnFailure {
            listener_addr_in_use: false,
            detail: "Configuration validation failed".to_string(),
        };
        assert!(!deterministic.is_retryable_port_race(1, 3));
    }

    #[tokio::test]
    async fn held_ephemeral_port_cannot_be_stolen_until_dropped() {
        let mut excluded = HashSet::new();
        let hold = hold_ephemeral_port_excluding(&mut excluded)
            .await
            .expect("hold ephemeral port");
        let port = hold.port;
        assert!(excluded.contains(&port));
        assert!(
            TcpListener::bind(("127.0.0.1", port)).await.is_err(),
            "a held reservation must keep the port from being stolen"
        );
        drop(hold);
        TcpListener::bind(("127.0.0.1", port))
            .await
            .expect("released port must be bindable again");
    }

    #[tokio::test]
    async fn held_ephemeral_ports_are_distinct() {
        let mut excluded = HashSet::new();
        let first = hold_ephemeral_port_excluding(&mut excluded)
            .await
            .expect("first hold");
        let second = hold_ephemeral_port_excluding(&mut excluded)
            .await
            .expect("second hold");
        assert_ne!(first.port, second.port);
    }
}

#[cfg(test)]
mod ownership_proof_tests {
    use super::*;
    use std::process::{Command, Stdio};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    #[derive(Clone)]
    enum FakeAdminBehavior {
        /// Full `/health` detail for every caller (CIDR grant) and 401 on
        /// JWT-only `GET /proxies`.
        CidrHealthJwtRejected,
        /// Full `/health` detail (CIDR grant) and a non-401 non-success
        /// `GET /proxies` — must not count as JWT ownership.
        CidrHealthProxiesNonSuccess,
        /// Full `/health` detail after SIGKILL of `pid`, then 200 on `/proxies`.
        #[cfg(unix)]
        KillChildThenHealth { pid: u32 },
    }

    async fn spawn_fake_admin(behavior: FakeAdminBehavior) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind fake admin");
        let port = listener.local_addr().expect("addr").port();
        let handle = tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = listener.accept().await else {
                    return;
                };
                let behavior = behavior.clone();
                tokio::spawn(async move {
                    let mut request = Vec::new();
                    let mut chunk = [0u8; 1024];
                    loop {
                        match stream.read(&mut chunk).await {
                            Ok(0) => break,
                            Ok(n) => {
                                request.extend_from_slice(&chunk[..n]);
                                if request.windows(4).any(|w| w == b"\r\n\r\n") {
                                    break;
                                }
                            }
                            Err(_) => return,
                        }
                    }
                    let request = String::from_utf8_lossy(&request).into_owned();
                    let is_proxies = request.lines().next().unwrap_or("").contains(" /proxies");
                    #[cfg(unix)]
                    if !is_proxies && let FakeAdminBehavior::KillChildThenHealth { pid } = &behavior
                    {
                        let _ = unsafe { libc::kill(*pid as libc::pid_t, libc::SIGKILL) };
                    }
                    let body = if is_proxies {
                        match &behavior {
                            FakeAdminBehavior::CidrHealthJwtRejected => {
                                r#"{"error":"Token verification failed: InvalidSignature"}"#
                            }
                            FakeAdminBehavior::CidrHealthProxiesNonSuccess => {
                                r#"{"error":"internal"}"#
                            }
                            #[cfg(unix)]
                            FakeAdminBehavior::KillChildThenHealth { .. } => "[]",
                        }
                    } else {
                        r#"{"status":"ok","ready":true,"cached_config":{"available":true}}"#
                    };
                    let status = if is_proxies {
                        match &behavior {
                            FakeAdminBehavior::CidrHealthJwtRejected => "401 Unauthorized",
                            FakeAdminBehavior::CidrHealthProxiesNonSuccess => {
                                "500 Internal Server Error"
                            }
                            #[cfg(unix)]
                            FakeAdminBehavior::KillChildThenHealth { .. } => "200 OK",
                        }
                    } else {
                        "200 OK"
                    };
                    let response = format!(
                        "HTTP/1.1 {status}\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    let _ = stream.flush().await;
                });
            }
        });
        (port, handle)
    }

    #[test]
    fn minted_admin_jwt_secret_meets_repository_minimum() {
        let identity = SpawnedGatewayIdentity::mint("sse");
        assert!(identity.jwt_secret.len() >= 32);
        assert!(!identity.jwt_secret.is_empty());
        assert!(!identity.jwt_issuer.is_empty());
    }

    #[tokio::test]
    async fn jwt_ownership_rejects_cidr_granted_foreign_health() {
        let (port, listener) = spawn_fake_admin(FakeAdminBehavior::CidrHealthJwtRejected).await;
        let identity = SpawnedGatewayIdentity::mint("cidr-foreign");
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn live child");

        let err =
            wait_for_owned_gateway_identity(&mut child, port, &identity, Duration::from_secs(2))
                .await
                .expect_err("CIDR-granted /health must not satisfy unique JWT /proxies");
        let err = err.to_string();
        assert!(
            err.contains("GET /proxies") || err.contains("401") || err.contains("JWT"),
            "error should name the JWT-only proof, got: {err}"
        );
        assert!(
            !err.contains(&identity.jwt_secret) && !err.contains(&identity.observability_token),
            "diagnostics must not echo credentials: {err}"
        );

        let _ = child.kill();
        let _ = child.wait();
        listener.abort();
    }

    #[tokio::test]
    async fn jwt_ownership_rejects_non_success_foreign_proxies() {
        let (port, listener) =
            spawn_fake_admin(FakeAdminBehavior::CidrHealthProxiesNonSuccess).await;
        let identity = SpawnedGatewayIdentity::mint("proxies-non-success");
        let mut child = Command::new("sleep")
            .arg("30")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn live child");

        let err =
            wait_for_owned_gateway_identity(&mut child, port, &identity, Duration::from_secs(2))
                .await
                .expect_err("HTTP 500 on GET /proxies must not satisfy JWT ownership");
        let err = err.to_string();
        assert!(
            err.contains("GET /proxies") && err.contains("500"),
            "error should name the unsuccessful JWT proof, got: {err}"
        );
        assert!(
            !err.contains(&identity.jwt_secret) && !err.contains(&identity.observability_token),
            "diagnostics must not echo credentials: {err}"
        );
        assert!(
            !err.contains("internal"),
            "diagnostics must not echo the foreign response body: {err}"
        );

        let _ = child.kill();
        let _ = child.wait();
        listener.abort();
    }

    #[test]
    fn mint_produces_unique_admin_credentials_per_call() {
        let a = SpawnedGatewayIdentity::mint("shared-harness");
        let b = SpawnedGatewayIdentity::mint("shared-harness");
        assert_ne!(a.jwt_secret, b.jwt_secret);
        assert_ne!(a.jwt_issuer, b.jwt_issuer);
        assert_ne!(a.observability_token, b.observability_token);
        assert!(a.jwt_secret.len() >= 32);
        assert!(b.jwt_secret.len() >= 32);
    }

    #[tokio::test]
    async fn ownership_wait_rejects_child_that_already_exited() {
        let (port, listener) = spawn_fake_admin(FakeAdminBehavior::CidrHealthJwtRejected).await;
        let identity = SpawnedGatewayIdentity::mint("dead-child");
        let mut child = Command::new("true")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn exiting child");
        let _ = child.wait().expect("reap exited child");

        let err =
            wait_for_owned_gateway_identity(&mut child, port, &identity, Duration::from_secs(2))
                .await
                .expect_err("an exited child must not attach to a foreign health responder");
        let err = err.to_string();
        assert!(
            err.contains("exited"),
            "error should report child exit, got: {err}"
        );

        listener.abort();
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn ownership_wait_rejects_child_killed_at_health_success_boundary() {
        let mut child = Command::new("sleep")
            .arg("60")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn live child");
        let pid = child.id();
        let (port, listener) =
            spawn_fake_admin(FakeAdminBehavior::KillChildThenHealth { pid }).await;
        let identity = SpawnedGatewayIdentity::mint("health-boundary");

        let err =
            wait_for_owned_gateway_identity(&mut child, port, &identity, Duration::from_secs(2))
                .await
                .expect_err("child death at health success must fail ownership");
        let err = err.to_string();
        assert!(
            err.contains("exited"),
            "post-health child check must reject, got: {err}"
        );
        assert!(
            !err.contains(&identity.jwt_secret),
            "diagnostics must not echo the JWT secret: {err}"
        );

        let _ = child.wait();
        listener.abort();
    }
}
