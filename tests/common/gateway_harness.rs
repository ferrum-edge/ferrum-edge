//! Shared functional-test harness for spawning the `ferrum-edge` binary.
//!
//! The old per-test `TestHarness` / `AdminTestHarness` / `LoadTestHarness`
//! structs all implemented the same skeleton: 3-attempt retry → ephemeral
//! ports → spawn binary with `Stdio::null()` → `wait_for_health` → `Drop`
//! kill. See CLAUDE.md "Functional test port allocation — MUST use retry
//! pattern" for the required behaviour.
//!
//! This module centralises that skeleton in [`TestGateway`] + [`TestGatewayBuilder`]
//! so each new test reaches for a builder instead of copy-pasting ~120 LOC.
//!
//! # Invariants preserved from CLAUDE.md
//!
//! - **3-attempt retry** with fresh ports + fresh temp dir each attempt,
//!   killing any surviving child before retrying.
//! - **`Stdio::null()`** on stdin/stdout/stderr. Piped stdout without
//!   reading causes pipe-buffer deadlock; see CLAUDE.md "Functional test
//!   subprocess rule".
//! - **Backend/echo listeners held** — this struct only owns the gateway's
//!   own listen ports. Echo servers in `echo_servers.rs` keep their listener.
//! - **`Drop` kills the child** so a panic in a test cannot leave a zombie
//!   process holding the admin or proxy port.
//! - **Admin JWT** is HS256 with ≥32-char secret (CLAUDE.md `FERRUM_ADMIN_JWT_SECRET`).

use chrono::Utc;
use jsonwebtoken::{EncodingKey, Header, encode};
use reqwest::Client;
use serde_json::json;
use std::collections::HashMap;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::sync::OnceLock;
use std::time::{Duration, Instant};
use tempfile::TempDir;
use tokio::net::TcpListener;
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
/// Drop kills the process. Call [`TestGateway::shutdown`] for explicit teardown
/// if you want to observe clean exit.
pub struct TestGateway {
    pub temp_dir: TempDir,
    child: Option<Child>,
    pub proxy_port: u16,
    pub admin_port: u16,
    pub proxy_base_url: String,
    pub admin_base_url: String,
    pub jwt_secret: String,
    pub jwt_issuer: String,
    pub basic_auth_hmac_secret: String,
    /// `FERRUM_DB_URL` the gateway was launched with (for DB-mode harnesses).
    pub db_url: Option<String>,
    /// Path to the YAML/JSON config file (file mode only).
    pub config_path: Option<PathBuf>,
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

    /// Poll the admin `/health` endpoint until it returns 2xx or the deadline
    /// expires. Safe to call again after startup to confirm the gateway is
    /// still up (e.g. after a SIGHUP reload).
    pub async fn wait_for_health(
        &self,
        timeout: Duration,
    ) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
        wait_for_health_inner(self.admin_port, timeout).await
    }

    /// Explicit shutdown. Safe to call multiple times; subsequent calls are
    /// no-ops. Drop also kills the child if this was not called.
    pub fn shutdown(&mut self) {
        if let Some(mut child) = self.child.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }

    /// Return the `Child` handle without dropping it (e.g. to send a signal).
    /// After this call, `Drop` will no longer kill the process — the caller
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
    pub fn write_temp_file(&self, name: &str, contents: &str) -> Result<PathBuf, std::io::Error> {
        let p = self.temp_dir.path().join(name);
        std::fs::write(&p, contents)?;
        Ok(p)
    }
}

impl Drop for TestGateway {
    fn drop(&mut self) {
        self.shutdown();
    }
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
    jwt_secret: String,
    jwt_issuer: String,
    basic_auth_hmac_secret: String,
    log_level: String,
    health_timeout: Duration,
    max_attempts: u32,
    auto_build: bool,
    prefer_release: bool,
    extra_env: Vec<(String, String)>,
    /// Extra env vars to **remove** before spawning. Handy when the caller's
    /// parent shell has `FERRUM_*` set.
    scrub_env: Vec<String>,
    namespace: Option<String>,
    db_poll_interval_seconds: u64,
}

impl Default for TestGatewayBuilder {
    fn default() -> Self {
        Self {
            mode: GatewayMode::Database(DbType::Sqlite),
            // Secrets are ≥32 chars per CLAUDE.md's admin-JWT rule.
            jwt_secret: "ferrum-edge-shared-harness-secret-00000".to_string(),
            jwt_issuer: "ferrum-edge-shared-harness".to_string(),
            basic_auth_hmac_secret: "ferrum-edge-shared-harness-hmac".to_string(),
            log_level: "info".to_string(),
            health_timeout: Duration::from_secs(30),
            max_attempts: 3,
            auto_build: true,
            prefer_release: false,
            extra_env: Vec::new(),
            scrub_env: Vec::new(),
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
    pub fn jwt_secret(mut self, secret: impl Into<String>) -> Self {
        self.jwt_secret = secret.into();
        self
    }

    /// Override the admin JWT issuer claim (`iss`).
    pub fn jwt_issuer(mut self, issuer: impl Into<String>) -> Self {
        self.jwt_issuer = issuer.into();
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

    /// Remove a var from the subprocess environment. Useful when the parent
    /// shell has `FERRUM_*` vars set that would override builder defaults.
    pub fn scrub_env(mut self, key: impl Into<String>) -> Self {
        self.scrub_env.push(key.into());
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

    async fn try_spawn(&mut self) -> Result<TestGateway, Box<dyn std::error::Error + Send + Sync>> {
        let temp_dir = TempDir::new()?;
        let admin_port = ephemeral_port().await?;
        let proxy_port = ephemeral_port().await?;

        let binary = locate_binary(self.prefer_release)?;

        let (mut env, mut db_url, config_path) =
            build_env(self, &temp_dir, admin_port, proxy_port).await?;

        // Caller overrides win — append after defaults so they replace keys.
        for (k, v) in &self.extra_env {
            env.insert(k.clone(), v.clone());
        }

        let mut cmd = Command::new(&binary);
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
        cmd.stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());

        let child = cmd.spawn()?;

        // A final sanity check: pull the db_url we ended up using back out,
        // in case `build_env` picked a fresh path per-attempt.
        if db_url.is_none() {
            db_url = env.get("FERRUM_DB_URL").cloned();
        }

        let mut gw = TestGateway {
            temp_dir,
            child: Some(child),
            proxy_port,
            admin_port,
            proxy_base_url: format!("http://127.0.0.1:{}", proxy_port),
            admin_base_url: format!("http://127.0.0.1:{}", admin_port),
            jwt_secret: self.jwt_secret.clone(),
            jwt_issuer: self.jwt_issuer.clone(),
            basic_auth_hmac_secret: self.basic_auth_hmac_secret.clone(),
            db_url,
            config_path,
        };

        match gw.wait_for_health(self.health_timeout).await {
            Ok(()) => Ok(gw),
            Err(e) => {
                // Clean up the failed child so the retry loop starts fresh.
                gw.shutdown();
                Err(e)
            }
        }
    }
}

/// Env var names we scrub unless the builder explicitly sets them. Prevents
/// parent-shell leakage from fighting the builder's defaults.
const SCRUB_DEFAULTS: &[&str] = &[
    "FERRUM_FILE_CONFIG_PATH",
    "FERRUM_CP_GRPC_LISTEN_ADDR",
    "FERRUM_DP_CP_GRPC_URL",
    "FERRUM_DP_CP_GRPC_URLS",
];

/// Build the subprocess env map from the builder's mode + tuning knobs.
///
/// Returns (env, db_url, optional config file path). The config file (file
/// mode) is written inside the temp dir so it outlives just the env build.
async fn build_env(
    b: &TestGatewayBuilder,
    temp: &TempDir,
    admin_port: u16,
    proxy_port: u16,
) -> Result<
    (HashMap<String, String>, Option<String>, Option<PathBuf>),
    Box<dyn std::error::Error + Send + Sync>,
> {
    let mut env: HashMap<String, String> = HashMap::new();
    env.insert("FERRUM_PROXY_HTTP_PORT".into(), proxy_port.to_string());
    env.insert("FERRUM_ADMIN_HTTP_PORT".into(), admin_port.to_string());
    env.insert("FERRUM_LOG_LEVEL".into(), b.log_level.clone());
    // Tests don't need the 5s warmup stall; pool warmup failures are
    // non-fatal but noisy in test logs.
    env.insert("FERRUM_POOL_WARMUP_ENABLED".into(), "false".into());
    env.insert(
        "FERRUM_BASIC_AUTH_HMAC_SECRET".into(),
        b.basic_auth_hmac_secret.clone(),
    );
    if let Some(ns) = &b.namespace {
        env.insert("FERRUM_NAMESPACE".into(), ns.clone());
    }

    let mut db_url: Option<String> = None;
    let mut config_path: Option<PathBuf> = None;

    match &b.mode {
        GatewayMode::Database(db) => {
            env.insert("FERRUM_MODE".into(), "database".into());
            env.insert("FERRUM_ADMIN_JWT_SECRET".into(), b.jwt_secret.clone());
            env.insert("FERRUM_ADMIN_JWT_ISSUER".into(), b.jwt_issuer.clone());
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
            env.insert("FERRUM_ADMIN_JWT_SECRET".into(), b.jwt_secret.clone());
            env.insert("FERRUM_ADMIN_JWT_ISSUER".into(), b.jwt_issuer.clone());
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
            env.insert("FERRUM_ADMIN_JWT_SECRET".into(), b.jwt_secret.clone());
            env.insert("FERRUM_ADMIN_JWT_ISSUER".into(), b.jwt_issuer.clone());
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
                    let port = ephemeral_port().await?;
                    format!("127.0.0.1:{port}")
                }
            };
            env.insert("FERRUM_CP_GRPC_LISTEN_ADDR".into(), addr);
        }
        GatewayMode::DataPlane { cp_grpc_urls } => {
            env.insert("FERRUM_MODE".into(), "dp".into());
            env.insert("FERRUM_ADMIN_JWT_SECRET".into(), b.jwt_secret.clone());
            env.insert("FERRUM_ADMIN_JWT_ISSUER".into(), b.jwt_issuer.clone());
            env.insert(
                "FERRUM_CP_DP_GRPC_JWT_SECRET".into(),
                "ferrum-edge-shared-harness-grpc-secret00".into(),
            );
            if cp_grpc_urls.is_empty() {
                return Err("mode_dp requires at least one CP gRPC URL".into());
            }
            if cp_grpc_urls.len() == 1 {
                env.insert("FERRUM_DP_CP_GRPC_URL".into(), cp_grpc_urls[0].clone());
            } else {
                env.insert("FERRUM_DP_CP_GRPC_URLS".into(), cp_grpc_urls.join(","));
            }
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

/// Bind an ephemeral port, then drop the listener. Not race-free — the
/// caller must retry if the gateway binds fail. This is what the
/// `max_attempts` loop in [`TestGatewayBuilder::spawn`] exists for.
async fn ephemeral_port() -> Result<u16, std::io::Error> {
    let l = TcpListener::bind("127.0.0.1:0").await?;
    let port = l.local_addr()?.port();
    drop(l);
    Ok(port)
}

async fn wait_for_health_inner(
    admin_port: u16,
    timeout: Duration,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let health_url = format!("http://127.0.0.1:{}/health", admin_port);
    let client = Client::builder().timeout(Duration::from_secs(2)).build()?;
    let deadline = Instant::now() + timeout;
    loop {
        if Instant::now() >= deadline {
            return Err(format!(
                "gateway admin /health did not become ready on port {} within {:?}",
                admin_port, timeout
            )
            .into());
        }
        match client.get(&health_url).send().await {
            Ok(r) if r.status().is_success() => return Ok(()),
            _ => tokio::time::sleep(Duration::from_millis(250)).await,
        }
    }
}

/// Locate the built `ferrum-edge` binary. Preference order:
/// 1. `target/release/ferrum-edge` if `prefer_release` (load tests).
/// 2. `target/debug/ferrum-edge` (normal).
/// 3. `target/release/ferrum-edge` as a fallback.
fn locate_binary(
    prefer_release: bool,
) -> Result<PathBuf, Box<dyn std::error::Error + Send + Sync>> {
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
fn ensure_gateway_built() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    static RESULT: OnceLock<Result<(), String>> = OnceLock::new();
    let result = RESULT.get_or_init(|| -> Result<(), String> {
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
