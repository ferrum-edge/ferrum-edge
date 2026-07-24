//! CLI subcommand definitions and argument handling.
//!
//! The CLI layer is a thin translation shim: it resolves paths, sets env vars,
//! and delegates to the existing `EnvConfig` / mode dispatch pipeline. No
//! config resolution logic lives here — that stays in `env_config.rs`.
//!
//! **Ordering contract**: `apply_cli_overrides()` must run before any call to
//! `resolve_ferrum_var()` or `ConfFile::load()`, because the `CONF_FILE_CACHE`
//! `OnceLock` captures `FERRUM_CONF_PATH` on first access and never re-reads it.

use clap::{ArgAction, Parser, Subcommand};
use std::path::{Path, PathBuf};

/// Ferrum Edge — a high-performance edge proxy.
#[derive(Parser)]
#[command(
    name = "ferrum-edge",
    version,
    about = "A high-performance edge proxy built in Rust"
)]
pub struct Cli {
    #[command(subcommand)]
    pub command: Option<Command>,
}

#[derive(Subcommand)]
pub enum Command {
    /// Start the gateway in the foreground.
    Run(RunArgs),
    /// Validate configuration files without starting the gateway.
    Validate(ValidateArgs),
    /// Send a reload signal (SIGHUP) to a running gateway instance.
    Reload(ReloadArgs),
    /// Print version information.
    Version(VersionArgs),
    /// Check if the gateway is healthy (for Docker HEALTHCHECK in distroless images).
    Health(HealthArgs),
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// Path to ferrum.conf (operational settings).
    #[arg(short = 's', long = "settings")]
    pub settings: Option<PathBuf>,

    /// Path to resources YAML/JSON (proxies, consumers, upstreams, plugins).
    #[arg(short = 'c', long = "spec")]
    pub spec: Option<PathBuf>,

    /// Operating mode (database, file, cp, dp, mesh, injector, node_agent, migrate).
    #[arg(short = 'm', long = "mode")]
    pub mode: Option<String>,

    /// Increase log verbosity (-v=info, -vv=debug, -vvv=trace).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,
}

#[derive(clap::Args)]
pub struct ValidateArgs {
    /// Path to ferrum.conf (operational settings).
    #[arg(short = 's', long = "settings")]
    pub settings: Option<PathBuf>,

    /// Path to resources YAML/JSON (proxies, consumers, upstreams, plugins).
    #[arg(short = 'c', long = "spec")]
    pub spec: Option<PathBuf>,
}

#[derive(clap::Args)]
pub struct ReloadArgs {
    /// PID of the running gateway (auto-detected if omitted).
    #[arg(short = 'p', long = "pid")]
    pub pid: Option<u32>,
}

#[derive(clap::Args)]
pub struct VersionArgs {
    /// Output version info as JSON.
    #[arg(long)]
    pub json: bool,
}

#[derive(clap::Args)]
pub struct HealthArgs {
    /// Admin API port to check (defaults to FERRUM_ADMIN_HTTP_PORT, or
    /// FERRUM_ADMIN_HTTPS_PORT when --tls is set, or 9000/9443 respectively).
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    /// Admin API host to connect to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Use TLS (HTTPS) to connect to the admin API.
    /// Required when the plaintext admin HTTP listener is disabled (FERRUM_ADMIN_HTTP_PORT=0).
    #[arg(long)]
    pub tls: bool,

    /// Skip TLS certificate verification (for self-signed certs / testing only).
    #[arg(long)]
    pub tls_no_verify: bool,

    /// Probe liveness (GET /live) instead of readiness (GET /health).
    /// `/live` returns 200 whenever the process and admin listener are up — even
    /// during startup or while serving degraded — so a Kubernetes livenessProbe
    /// won't restart-loop an alive-but-unready pod. Without this flag the check
    /// hits `/health`, which returns 503 until the gateway is ready.
    #[arg(long)]
    pub live: bool,
}

// ── Smart path resolution ───────────────────────────────────────────────────

/// Search well-known locations for a settings file when no explicit path is given
/// and the `FERRUM_CONF_PATH` env var is not set.
pub fn resolve_settings_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(resolve_path(p));
    }
    // Don't override if the env var is already set. `var_os`, not `var`: see
    // [`direct_env_var_is_set`] — a non-Unicode value is *set*, and smart
    // discovery must not overwrite it before the resolver can reject it.
    if direct_env_var_is_set("FERRUM_CONF_PATH") {
        return None;
    }
    if externally_sourced("FERRUM_CONF_PATH") {
        return None;
    }
    let candidates = [
        "./ferrum.conf",
        "./config/ferrum.conf",
        "/etc/ferrum/ferrum.conf",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(PathBuf::from)
}

/// Search well-known locations for a spec (resources) file when no explicit
/// path is given and `FERRUM_FILE_CONFIG_PATH` is not set.
pub fn resolve_spec_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(resolve_path(p));
    }
    if direct_env_var_is_set("FERRUM_FILE_CONFIG_PATH") {
        return None;
    }
    if externally_sourced("FERRUM_FILE_CONFIG_PATH") {
        return None;
    }
    let candidates = [
        "./resources.yaml",
        "./resources.json",
        "./config/resources.yaml",
        "./config/resources.json",
        "/etc/ferrum/config.yaml",
        "/etc/ferrum/config.json",
    ];
    candidates
        .iter()
        .map(Path::new)
        .find(|p| p.exists())
        .map(PathBuf::from)
}

/// True when `base_key` is configured to come from an external secret source
/// (`_FILE`, `_VAULT`, `_AWS`, `_AZURE`, `_GCP`).
///
/// Smart discovery must yield to such a source. It runs in `main()` *before*
/// startup secret resolution, so at this point a secret-backed
/// `FERRUM_CONF_PATH`/`FERRUM_FILE_CONFIG_PATH` does not exist yet and the
/// direct-variable check above sees nothing. Auto-setting a discovered
/// `./ferrum.conf` there is then indistinguishable, to
/// `secrets::resolve_all_env_secrets`, from an operator who set both — and it
/// fails the whole command with `Multiple secret sources configured for
/// FERRUM_CONF_PATH` in any working directory that merely happens to contain a
/// settings or resources file.
///
/// Yielding is correct rather than merely convenient: a discovered default is
/// the lowest-precedence source there is (`CLI > env > conf file > smart
/// defaults`), below the suffixed variable in every ordering the docs promise.
/// An **explicit** `-s`/`-c` path is handled before this check and still
/// conflicts, because that is a genuine two-sources-for-one-key mistake the
/// operator made and should be told about.
fn externally_sourced(base_key: &str) -> bool {
    crate::secrets::external_source_configured(base_key)
}

/// True when `key` is present in the environment *at all*, decodable or not.
///
/// Deliberately `var_os`, never `var`. `std::env::var` reports a non-Unicode
/// value as `Err`, i.e. as **unset** — so a `FERRUM_CONF_PATH` holding
/// undecodable bytes would look absent to a `var(..).is_ok()` presence check,
/// smart discovery would find `./ferrum.conf` and `set_var` over it, and the
/// operator's invalid value would be gone before anything could complain about
/// it. That matters because the overwrite happens *first*: these checks run in
/// `apply_run_overrides`/`apply_validate_overrides` (`main.rs`, before logging
/// init), while the fail-closed rejection lives in
/// `secrets::resolve_all_env_secrets` further down `main()`. Overwriting turns
/// a command that must fail with `Ferrum configuration values must be valid
/// Unicode` into one that silently starts on a settings file the operator
/// never chose — exactly the silent-misconfiguration hazard
/// `secrets::registry` documents and exists to prevent.
///
/// Presence semantics, not validity semantics: this only answers "did the
/// operator set this variable", and every judgment about the *value* stays with
/// the resolver, which is the one place that can report it safely (the bytes
/// are never echoed — the name is reduced to an ASCII skeleton).
fn direct_env_var_is_set(key: &str) -> bool {
    std::env::var_os(key).is_some()
}

/// Resolve a user-provided path: absolute paths are kept as-is, relative paths
/// are resolved against the current working directory.
fn resolve_path(p: &Path) -> PathBuf {
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(p))
            .unwrap_or_else(|_| p.to_path_buf())
    }
}

// ── CLI → env var injection ─────────────────────────────────────────────────

/// Translate CLI flags into environment variables so the existing `EnvConfig`
/// resolution chain picks them up. Must be called **before** logging init and
/// `ConfFile::load()`.
///
/// # Safety
/// Uses `std::env::set_var` which is unsafe in Rust 2024 edition. This is safe
/// here because it runs in `main()` before any multi-threaded runtime starts,
/// identical to the existing secret resolution code in `main.rs`.
pub fn apply_run_overrides(args: &RunArgs) {
    apply_common_overrides(args.settings.as_deref(), args.spec.as_deref());

    if let Some(ref mode) = args.mode {
        // SAFETY: single-threaded context, before tokio runtime.
        unsafe { std::env::set_var("FERRUM_MODE", mode) };
    }

    if args.verbose > 0 {
        let level = match args.verbose {
            1 => "info",
            2 => "debug",
            _ => "trace",
        };
        // SAFETY: single-threaded context, before tokio runtime.
        unsafe { std::env::set_var("FERRUM_LOG_LEVEL", level) };
    }
}

/// Apply settings/spec overrides shared between `run` and `validate`.
pub fn apply_validate_overrides(args: &ValidateArgs) {
    apply_common_overrides(args.settings.as_deref(), args.spec.as_deref());
}

/// Infer file mode when a spec is available but no mode is configured anywhere.
///
/// **`--spec` / `-c` interaction:** `apply_common_overrides` may install
/// `FERRUM_FILE_CONFIG_PATH` from an explicit `--spec`, an env value, or smart
/// path discovery. That path assignment is independent of mode selection.
/// This helper never treats `--spec` as an implicit `--mode file`: a
/// non-empty `FERRUM_MODE` from CLI (`apply_run_overrides`), the process
/// environment, or the selected `ferrum.conf` always wins, preserving
/// `CLI > env > conf file > smart defaults`.
///
/// # Ordering: must run *after* startup secret resolution
///
/// This is the last rung of `CLI > env > conf file > smart defaults >
/// hardcoded`, so it may only fire once every higher-precedence source has had
/// its say. Two of them are not observable before
/// `main::resolve_startup_secrets` has run:
///
/// * `FERRUM_MODE_FILE`/`_VAULT`/`_AWS`/`_AZURE`/`_GCP` — an explicit *env*
///   source for the mode. Inferring before resolution both ignores it and,
///   worse, writes a synthetic direct `FERRUM_MODE` that the resolver then sees
///   as a second source for the same base key, failing the whole command with
///   `Multiple secret sources configured for FERRUM_MODE`. A deployment that
///   externalizes both the mode and the spec path could not start or validate.
/// * `FERRUM_FILE_CONFIG_PATH_*` — the spec path that triggers the inference.
///   After resolution it is materialized into `FERRUM_FILE_CONFIG_PATH`, so the
///   plain env check below covers a secret-backed spec path with no special
///   case, and the pre-resolution `externally_sourced` probe this used to need
///   is gone.
///
/// The settings file is the third: `FERRUM_MODE` in `ferrum.conf` outranks a
/// smart default, and materializing `FERRUM_MODE=file` as an env var would
/// *invert* that — `EnvConfig` gives the environment precedence over the conf
/// file, so `validate`/startup would silently check the wrong surface for an
/// operator who configured `FERRUM_MODE = database`. Reading it is correct only
/// at this point, because `FERRUM_CONF_PATH` is only final once a
/// `FERRUM_CONF_PATH_FILE` source has been materialized; before that this would
/// consult the wrong settings file.
///
/// The read goes through a fresh `ConfFile::load()`, not
/// `config::conf_file::resolve_ferrum_var`. The latter memoizes into the
/// process-wide `CONF_FILE_CACHE`, and this helper must not be the thing that
/// pins that cache for the rest of the process — `EnvConfig::from_env()` loads
/// the file itself and reports a malformed one properly. A load failure here is
/// therefore *not* treated as "a mode is configured": inference proceeds and the
/// real error surfaces from settings validation a moment later.
pub fn infer_file_mode() {
    use crate::config::conf_file::ConfFile;

    // `-m/--mode` was already written to the environment by
    // `apply_run_overrides`, so this one check covers CLI and env alike.
    if direct_env_var_is_set("FERRUM_MODE") {
        return;
    }
    let conf_mode = ConfFile::load()
        .ok()
        .and_then(|conf| conf.get("FERRUM_MODE").map(str::to_string));
    if conf_mode.is_some_and(|mode| !mode.trim().is_empty()) {
        return;
    }
    if direct_env_var_is_set("FERRUM_FILE_CONFIG_PATH") {
        // SAFETY: single-threaded context, before the multi-threaded runtime.
        unsafe { std::env::set_var("FERRUM_MODE", "file") };
    }
}

fn apply_common_overrides(settings: Option<&Path>, spec: Option<&Path>) {
    if let Some(path) = resolve_settings_path(settings) {
        // SAFETY: single-threaded context, before tokio runtime.
        unsafe { std::env::set_var("FERRUM_CONF_PATH", path) };
    }

    if let Some(path) = resolve_spec_path(spec) {
        // SAFETY: single-threaded context, before tokio runtime.
        unsafe { std::env::set_var("FERRUM_FILE_CONFIG_PATH", path) };
    }
}

fn format_host_port(host: &str, port: u16) -> String {
    if !host.starts_with('[') && host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{}]:{}", host, port)
    } else {
        format!("{}:{}", host, port)
    }
}

// ── Subcommand executors ────────────────────────────────────────────────────

/// Print version information and exit.
pub fn execute_version(args: &VersionArgs) {
    let version = env!("CARGO_PKG_VERSION");
    let target = env!("TARGET");
    if args.json {
        println!("{{\"version\":\"{}\",\"target\":\"{}\"}}", version, target);
    } else {
        println!("ferrum-edge {} ({})", version, target);
    }
}

/// Send SIGHUP to a running gateway process.
pub fn execute_reload(args: &ReloadArgs) -> Result<(), String> {
    #[cfg(unix)]
    {
        let pid = match args.pid {
            Some(p) => p,
            None => find_gateway_pid()?,
        };
        let status = std::process::Command::new("kill")
            .args(["-HUP", &pid.to_string()])
            .status()
            .map_err(|e| format!("Failed to execute kill: {}", e))?;
        if status.success() {
            println!("Sent SIGHUP to PID {}", pid);
            Ok(())
        } else {
            Err(format!("Failed to send SIGHUP to PID {}", pid))
        }
    }

    #[cfg(not(unix))]
    {
        let _ = args;
        Err("reload is only supported on Unix platforms".into())
    }
}

/// Render a `validate` report field whose value is derived from `env_key`.
///
/// The report goes to stdout with `println!`, which bypasses both redaction
/// boundaries that cover everything else: it is not a tracing record, so
/// `logging::non_blocking::RecordWriter::submit` never sees it, and a
/// *successful* validation returns no error for `redact_external_secret_values`
/// to filter. Every value-bearing line is therefore filtered at its own call
/// site.
///
/// The key-tied rule and its rationale live with the redaction design in
/// [`crate::secrets::report_env_field`] — in short, the report *re-renders*
/// values (`Mode: {:?}` turns a resolved `database` into `Database`, a form
/// candidate derivation deliberately does not produce), so the variable is
/// withheld by name rather than by matching text. `run`'s `Operating mode:`
/// record shares that helper, so both surfaces withhold the same re-rendered
/// value.
///
/// The textual second pass still covers a field that interpolates some *other*
/// externally resolved variable's value verbatim (the spec path is one such: it
/// is the value of `FERRUM_FILE_CONFIG_PATH`, but a future field could embed
/// one).
fn report_field(env_key: &str, rendered: &str) -> String {
    crate::secrets::report_env_field(env_key, rendered)
}

/// Validate configuration without starting the gateway.
pub fn execute_validate() -> Result<(), String> {
    use crate::config::{EnvConfig, OperatingMode, file_loader};

    let env_config =
        EnvConfig::from_env().map_err(|e| format!("Settings validation failed: {}", e))?;
    println!("Settings (ferrum.conf): OK");
    println!(
        "  Mode: {}",
        report_field("FERRUM_MODE", &format!("{:?}", env_config.mode))
    );

    // Side-effect-free env TLS/security loaders that the selected serving mode
    // treats as startup-fatal. Must stay free of listeners, servers, migrations,
    // or other runtime side effects (parity with `run` admission).
    validate_env_security_surfaces(&env_config)?;
    println!("Env TLS/security surfaces: OK");

    if env_config.mode == OperatingMode::File {
        let config_path = env_config
            .file_config_path
            .as_deref()
            .ok_or("FERRUM_FILE_CONFIG_PATH not set (required for file mode)")?;

        let config = file_loader::load_config_from_file(
            config_path,
            env_config.tls_cert_expiry_warning_days,
            &env_config.backend_allow_ips,
            &env_config.namespace,
        )
        .map_err(|e| format!("Spec validation failed: {}", e))?;

        // Validate stream proxy port conflicts
        let reserved_ports = env_config.reserved_gateway_ports();
        if let Err(errors) = config.validate_stream_proxy_port_conflicts(&reserved_ports) {
            return Err(format!("Port conflict errors:\n  {}", errors.join("\n  ")));
        }

        // `FERRUM_FILE_CONFIG_PATH` can itself be materialized from an external
        // secret source, and this `println!` bypasses the tracing sink's
        // emission-boundary redaction. Filter it the same way.
        println!(
            "Spec ({}): OK",
            report_field("FERRUM_FILE_CONFIG_PATH", config_path)
        );
        // The counts below are cardinalities of the *loaded spec document*, not
        // renderings of any environment value, so there is nothing key-tied to
        // withhold and nothing an external source could have supplied.
        println!("  Proxies: {}", config.proxies.len());
        println!("  Consumers: {}", config.consumers.len());
        println!("  Upstreams: {}", config.upstreams.len());
        println!("  Plugin configs: {}", config.plugin_configs.len());
    }

    println!("\nValidation passed.");
    Ok(())
}

/// Exercise every side-effect-free env TLS/security loader that the selected
/// serving mode treats as startup-fatal.
///
/// Covers TLS policy/CRLs, trusted admin CIDRs, metrics auth, configured
/// frontend/admin TLS pairs, DTLS certificate expiry, and admin JWT admission
/// rules (including file/mesh/node_agent "unset → random at runtime" vs
/// "set-but-invalid → fail").
pub fn validate_env_security_surfaces(env_config: &crate::config::EnvConfig) -> Result<(), String> {
    use crate::admin::jwt_auth::create_jwt_manager_from_env;
    use crate::config::OperatingMode;
    use crate::tls::{self, TlsPolicy};

    match env_config.mode {
        OperatingMode::Migrate | OperatingMode::Injector => {
            // Migrate never starts listeners; injector validates its own TLS
            // serving paths separately at injector startup.
            return Ok(());
        }
        OperatingMode::NodeAgent => {
            validate_admin_cidrs_and_metrics_auth(env_config)?;
            validate_admin_jwt_for_mode(env_config.mode, create_jwt_manager_from_env)?;
            return Ok(());
        }
        OperatingMode::ControlPlane => {
            let tls_policy = TlsPolicy::from_env_config(env_config)
                .map_err(|e| format!("TLS policy validation failed: {e}"))?;
            let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())
                .map_err(|e| format!("CRL validation failed: {e}"))?;
            validate_admin_cidrs_and_metrics_auth(env_config)?;
            validate_admin_tls_pair_if_configured(env_config, &tls_policy, crls.as_slice())?;
            validate_admin_jwt_for_mode(env_config.mode, create_jwt_manager_from_env)?;
            return Ok(());
        }
        OperatingMode::File
        | OperatingMode::Database
        | OperatingMode::DataPlane
        | OperatingMode::Mesh => {}
    }

    let tls_policy = TlsPolicy::from_env_config(env_config)
        .map_err(|e| format!("TLS policy validation failed: {e}"))?;
    let crls = tls::load_crls(env_config.tls_crl_file_path.as_deref())
        .map_err(|e| format!("CRL validation failed: {e}"))?;
    validate_admin_cidrs_and_metrics_auth(env_config)?;
    validate_frontend_tls_pair_if_configured(env_config, &tls_policy, crls.as_slice())?;
    validate_dtls_certs_if_configured(env_config)?;
    validate_admin_tls_pair_if_configured(env_config, &tls_policy, crls.as_slice())?;
    validate_admin_jwt_for_mode(env_config.mode, create_jwt_manager_from_env)?;
    Ok(())
}

fn validate_admin_cidrs_and_metrics_auth(
    env_config: &crate::config::EnvConfig,
) -> Result<(), String> {
    crate::proxy::client_ip::TrustedProxies::parse_strict(&env_config.admin_allowed_cidrs)
        .map_err(|e| format!("FERRUM_ADMIN_ALLOWED_CIDRS: {e}"))?;
    crate::admin::MetricsAuthPolicy::from_env(env_config)?;
    Ok(())
}

fn validate_frontend_tls_pair_if_configured(
    env_config: &crate::config::EnvConfig,
    tls_policy: &crate::tls::TlsPolicy,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
) -> Result<(), String> {
    let (Some(cert_path), Some(key_path)) = (
        env_config.frontend_tls_cert_path.as_deref(),
        env_config.frontend_tls_key_path.as_deref(),
    ) else {
        return Ok(());
    };
    crate::tls::load_tls_config_with_client_auth_and_ocsp(
        cert_path,
        key_path,
        env_config.frontend_tls_client_ca_bundle_path.as_deref(),
        env_config.frontend_tls_ocsp_response_source.as_deref(),
        false,
        tls_policy,
        env_config.tls_cert_expiry_warning_days,
        crls,
    )
    .map_err(|e| format!("Invalid frontend TLS configuration: {e}"))?;
    Ok(())
}

fn validate_admin_tls_pair_if_configured(
    env_config: &crate::config::EnvConfig,
    tls_policy: &crate::tls::TlsPolicy,
    crls: &[rustls::pki_types::CertificateRevocationListDer<'static>],
) -> Result<(), String> {
    // Mirror serving-mode gates: admin HTTPS port `0` disables the listener
    // (and material load) unless an in-process embedder supplies a pre-bound
    // socket — validate never has one, so port `0` skips admin TLS load.
    if env_config.admin_https_port == 0 {
        return Ok(());
    }
    let (Some(cert_path), Some(key_path)) = (
        env_config.admin_tls_cert_path.as_deref(),
        env_config.admin_tls_key_path.as_deref(),
    ) else {
        return Ok(());
    };
    crate::tls::load_tls_config_with_client_auth_and_ocsp(
        cert_path,
        key_path,
        env_config.admin_tls_client_ca_bundle_path.as_deref(),
        env_config.admin_tls_ocsp_response_source.as_deref(),
        env_config.admin_tls_no_verify,
        tls_policy,
        env_config.tls_cert_expiry_warning_days,
        crls,
    )
    .map_err(|e| format!("Invalid admin TLS configuration: {e}"))?;
    Ok(())
}

fn validate_dtls_certs_if_configured(env_config: &crate::config::EnvConfig) -> Result<(), String> {
    let (Some(cert_path), Some(_key_path)) = (
        env_config.dtls_cert_path.as_deref(),
        env_config.dtls_key_path.as_deref(),
    ) else {
        return Ok(());
    };
    crate::tls::check_cert_expiry(
        cert_path,
        "DTLS frontend cert",
        env_config.tls_cert_expiry_warning_days,
    )
    .map_err(|e| format!("Invalid DTLS frontend cert: {e}"))?;
    if let Some(ca_path) = env_config.dtls_client_ca_cert_path.as_deref() {
        crate::tls::check_cert_expiry(
            ca_path,
            "DTLS client CA cert",
            env_config.tls_cert_expiry_warning_days,
        )
        .map_err(|e| format!("Invalid DTLS client CA cert: {e}"))?;
    }
    Ok(())
}

fn validate_admin_jwt_for_mode<F>(
    mode: crate::config::OperatingMode,
    create: F,
) -> Result<(), String>
where
    F: FnOnce() -> Result<crate::admin::jwt_auth::JwtManager, crate::admin::jwt_auth::JwtError>,
{
    use crate::admin::jwt_auth::JwtError;
    use crate::config::OperatingMode;

    match create() {
        Ok(_) => Ok(()),
        Err(JwtError::NotConfigured) => match mode {
            // Read-only modes mint a random secret at runtime when unset.
            OperatingMode::File | OperatingMode::Mesh | OperatingMode::NodeAgent => Ok(()),
            other => Err(format!(
                "FERRUM_ADMIN_JWT_SECRET must be set and non-empty for {:?} mode",
                other
            )),
        },
        Err(err) => Err(format!(
            "Invalid admin JWT configuration: {err}. \
             A configured-but-invalid secret or TTL fails validation (file/mesh/node_agent \
             generate a random secret only when the secret is unset)."
        )),
    }
}

const HEALTH_RESPONSE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const HEALTH_RESPONSE_HEAD_MAX_BYTES: usize = 16 * 1024;
const HEALTH_MAX_INFORMATIONAL_RESPONSES: usize = 8;

struct HealthResponse {
    status_code: u16,
    status_line: String,
}

/// A TCP stream that reapplies the remaining absolute deadline before every
/// socket operation. This also covers reads rustls performs internally while
/// assembling a TLS record or completing the handshake.
struct DeadlineTcpStream {
    stream: std::net::TcpStream,
    deadline: std::time::Instant,
}

impl DeadlineTcpStream {
    fn new(stream: std::net::TcpStream, deadline: std::time::Instant) -> Self {
        Self { stream, deadline }
    }

    fn remaining(&self) -> std::io::Result<std::time::Duration> {
        self.deadline
            .checked_duration_since(std::time::Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(|| {
                std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "health response deadline elapsed",
                )
            })
    }
}

impl std::io::Read for DeadlineTcpStream {
    fn read(&mut self, buffer: &mut [u8]) -> std::io::Result<usize> {
        self.stream.set_read_timeout(Some(self.remaining()?))?;
        std::io::Read::read(&mut self.stream, buffer)
    }
}

impl std::io::Write for DeadlineTcpStream {
    fn write(&mut self, buffer: &[u8]) -> std::io::Result<usize> {
        self.stream.set_write_timeout(Some(self.remaining()?))?;
        std::io::Write::write(&mut self.stream, buffer)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        std::io::Write::flush(&mut self.stream)
    }
}

/// Check gateway health by connecting to the admin API.
///
/// By default this probes readiness via `GET /health` (503 until the gateway is
/// ready). With `--live` it probes liveness via `GET /live`, which returns 200
/// whenever the process and admin listener are up — the correct target for a
/// Kubernetes livenessProbe so an alive-but-unready pod is not restart-looped.
///
/// Uses a raw TCP connection + minimal HTTP/1.1 request to avoid pulling in
/// async runtime or reqwest for this one-shot diagnostic.
///
/// When `--tls` is passed, wraps the TCP socket in a rustls `StreamOwned` for
/// HTTPS. This is needed when `FERRUM_ADMIN_HTTP_PORT=0` disables plaintext.
pub fn execute_health(args: &HealthArgs) -> Result<(), String> {
    use std::net::{TcpStream, ToSocketAddrs};
    use std::time::Instant;

    // Auto-detect TLS when admin HTTP port is explicitly disabled (port=0) and
    // the user didn't pass --port to override.
    let auto_tls = args.port.is_none()
        && !args.tls
        && std::env::var("FERRUM_ADMIN_HTTP_PORT")
            .ok()
            .and_then(|v| v.parse::<u16>().ok())
            == Some(0);
    let use_tls = args.tls || auto_tls;

    let port = args.port.unwrap_or_else(|| {
        if use_tls {
            std::env::var("FERRUM_ADMIN_HTTPS_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(9443)
        } else {
            std::env::var("FERRUM_ADMIN_HTTP_PORT")
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(9000)
        }
    });

    let addr_str = format_host_port(&args.host, port);
    let sock_addr = addr_str
        .to_socket_addrs()
        .map_err(|e| format!("Cannot resolve {}: {}", addr_str, e))?
        .next()
        .ok_or_else(|| format!("No addresses found for {}", addr_str))?;
    let stream = TcpStream::connect_timeout(&sock_addr, HEALTH_RESPONSE_TIMEOUT)
        .map_err(|e| format!("Cannot connect to {}: {}", addr_str, e))?;

    let host_header = format_host_port(&args.host, port);
    let path = if args.live { "/live" } else { "/health" };
    let request =
        format!("GET {path} HTTP/1.1\r\nHost: {host_header}\r\nConnection: close\r\n\r\n");
    let response_deadline = Instant::now() + HEALTH_RESPONSE_TIMEOUT;
    let stream = DeadlineTcpStream::new(stream, response_deadline);

    let response = if use_tls {
        health_request_tls(
            stream,
            &request,
            &args.host,
            args.tls_no_verify,
            response_deadline,
        )?
    } else {
        health_request_plain(stream, &request, response_deadline)?
    };

    if response.status_code == 200 {
        Ok(())
    } else {
        Err(format!("Unhealthy: {:?}", response.status_line))
    }
}

/// Read complete HTTP response-head sections until the final response arrives.
///
/// The total bytes and number of informational responses are deliberately
/// small and bounded because this is a one-shot health probe. The underlying
/// deadline stream reapplies the remaining overall deadline to every socket
/// operation, so a peer cannot keep the probe alive by trickling bytes.
fn read_health_response_head<R>(
    reader: &mut R,
    deadline: std::time::Instant,
    transport: &str,
) -> Result<HealthResponse, String>
where
    R: std::io::Read,
{
    use std::io::ErrorKind;

    let mut buffered = Vec::with_capacity(1024);
    let mut informational_responses = 0usize;
    let mut total_bytes_read = 0usize;

    loop {
        if std::time::Instant::now() >= deadline {
            return Err(format!(
                "Timed out reading {transport} response head after {} seconds",
                HEALTH_RESPONSE_TIMEOUT.as_secs()
            ));
        }

        while let Some(section_end) = buffered.windows(4).position(|window| window == b"\r\n\r\n") {
            let section_len = section_end + 4;
            let response = parse_response_head_section(&buffered[..section_len])?;
            drop(buffered.drain(..section_len));

            if (100..200).contains(&response.status_code) && response.status_code != 101 {
                informational_responses += 1;
                if informational_responses > HEALTH_MAX_INFORMATIONAL_RESPONSES {
                    return Err(format!(
                        "HTTP response exceeded the limit of {} informational sections",
                        HEALTH_MAX_INFORMATIONAL_RESPONSES
                    ));
                }
                continue;
            }

            return Ok(response);
        }

        if total_bytes_read >= HEALTH_RESPONSE_HEAD_MAX_BYTES {
            return Err(format!(
                "HTTP response heads exceeded the {}-byte limit",
                HEALTH_RESPONSE_HEAD_MAX_BYTES
            ));
        }

        let mut chunk = [0u8; 1024];
        let read_limit = chunk
            .len()
            .min(HEALTH_RESPONSE_HEAD_MAX_BYTES - total_bytes_read);
        match reader.read(&mut chunk[..read_limit]) {
            Ok(0) => {
                return Err("Unexpected EOF before a complete final HTTP response head".to_string());
            }
            Ok(read) => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "Timed out reading {transport} response head after {} seconds",
                        HEALTH_RESPONSE_TIMEOUT.as_secs()
                    ));
                }
                buffered.extend_from_slice(&chunk[..read]);
                total_bytes_read += read;
            }
            Err(e) if e.kind() == ErrorKind::Interrupted => continue,
            Err(e) if matches!(e.kind(), ErrorKind::TimedOut | ErrorKind::WouldBlock) => {
                if std::time::Instant::now() >= deadline {
                    return Err(format!(
                        "Timed out reading {transport} response head after {} seconds",
                        HEALTH_RESPONSE_TIMEOUT.as_secs()
                    ));
                }
            }
            Err(e) => return Err(format!("Failed to read {transport} response head: {e}")),
        }
    }
}

/// Parse and validate one complete HTTP response-head section.
fn parse_response_head_section(section: &[u8]) -> Result<HealthResponse, String> {
    let head = section
        .strip_suffix(b"\r\n\r\n")
        .ok_or_else(|| "HTTP response head is not terminated by CRLF CRLF".to_string())?;
    let head = std::str::from_utf8(head)
        .map_err(|e| format!("HTTP response head is not valid UTF-8: {e}"))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .filter(|line| !line.is_empty())
        .ok_or_else(|| "missing HTTP status line".to_string())?;
    let status_code = parse_response_status_line(status_line)?;

    for header in lines {
        validate_response_header_line(header)?;
    }

    Ok(HealthResponse {
        status_code,
        status_line: status_line.to_string(),
    })
}

fn parse_response_status_line(status_line: &str) -> Result<u16, String> {
    let malformed = || format!("malformed HTTP status line: {status_line:?}");
    if status_line.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(malformed());
    }

    let (version, remainder) = status_line.split_once(' ').ok_or_else(&malformed)?;
    let version = version.as_bytes();
    if version.len() != 8
        || &version[..5] != b"HTTP/"
        || !version[5].is_ascii_digit()
        || version[6] != b'.'
        || !version[7].is_ascii_digit()
    {
        return Err(malformed());
    }

    let code = remainder.as_bytes();
    if code.len() < 3
        || !code[..3].iter().all(|byte| byte.is_ascii_digit())
        || (code.len() > 3 && code[3] != b' ')
    {
        return Err(malformed());
    }

    // Exactly three ASCII digits are in 000..=999, so this conversion is
    // infallible and always fits in u16.
    Ok(
        u16::from(code[0] - b'0') * 100
            + u16::from(code[1] - b'0') * 10
            + u16::from(code[2] - b'0'),
    )
}

fn validate_response_header_line(header: &str) -> Result<(), String> {
    let malformed = || format!("malformed HTTP response header: {header:?}");
    if header.is_empty() || header.bytes().any(|byte| byte.is_ascii_control()) {
        return Err(malformed());
    }

    let (name, _value) = header.split_once(':').ok_or_else(&malformed)?;
    if name.is_empty() || !name.bytes().all(is_http_token_byte) {
        return Err(malformed());
    }
    Ok(())
}

fn is_http_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Send health request over plaintext TCP.
fn health_request_plain(
    mut stream: DeadlineTcpStream,
    request: &str,
    deadline: std::time::Instant,
) -> Result<HealthResponse, String> {
    use std::io::Write;

    stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Failed to send request: {}", e))?;
    read_health_response_head(&mut stream, deadline, "plaintext")
}

/// Send health request over TLS (rustls).
fn health_request_tls(
    stream: DeadlineTcpStream,
    request: &str,
    host: &str,
    no_verify: bool,
    deadline: std::time::Instant,
) -> Result<HealthResponse, String> {
    use std::io::Write;
    use std::sync::Arc;

    // `execute_health` is an early-exit subcommand that returns from `main()`
    // before the global `CryptoProvider::install_default()` call. Build the
    // ClientConfig with an explicit provider so we don't depend on (or panic
    // on) a globally installed one.
    let provider = Arc::new(rustls::crypto::ring::default_provider());

    let mut root_store = rustls::RootCertStore::empty();
    root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let builder = rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()
        .map_err(|e| format!("Failed to build rustls client config: {}", e))?
        .with_root_certificates(root_store);
    let mut tls_config = builder.with_no_client_auth();
    if no_verify {
        tls_config
            .dangerous()
            .set_certificate_verifier(Arc::new(NoVerifier));
    }

    let server_name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|e| format!("Invalid server name '{}': {}", host, e))?;

    let conn = rustls::ClientConnection::new(Arc::new(tls_config), server_name).map_err(|e| {
        format!(
            "TLS handshake failed (use --tls-no-verify for self-signed certs): {}",
            e,
        )
    })?;

    let mut tls_stream = rustls::StreamOwned::new(conn, stream);
    tls_stream
        .write_all(request.as_bytes())
        .map_err(|e| format!("Failed to send TLS request: {}", e))?;
    read_health_response_head(&mut tls_stream, deadline, "TLS")
}

/// Certificate verifier that accepts any certificate (testing / self-signed).
#[derive(Debug)]
struct NoVerifier;

impl rustls::client::danger::ServerCertVerifier for NoVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        rustls::crypto::ring::default_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Attempt to find a running ferrum-edge process via `pgrep`.
#[cfg(unix)]
fn find_gateway_pid() -> Result<u32, String> {
    let output = std::process::Command::new("pgrep")
        .args(["-x", "ferrum-edge"])
        .output()
        .map_err(|e| format!("Failed to run pgrep: {}", e))?;

    if !output.status.success() {
        return Err("No running ferrum-edge process found. Use --pid to specify the PID.".into());
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let pids: Vec<&str> = stdout.trim().lines().collect();

    match pids.len() {
        0 => Err("No running ferrum-edge process found. Use --pid to specify the PID.".into()),
        1 => pids[0]
            .trim()
            .parse::<u32>()
            .map_err(|e| format!("Failed to parse PID: {}", e)),
        n => Err(format!(
            "Found {} ferrum-edge processes. Use --pid to specify which one:\n  {}",
            n,
            pids.join("\n  ")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener};

    #[test]
    fn format_host_port_brackets_ipv6_literals() {
        assert_eq!(format_host_port("::1", 9443), "[::1]:9443");
        assert_eq!(format_host_port("[::1]", 9443), "[::1]:9443");
        assert_eq!(format_host_port("127.0.0.1", 9000), "127.0.0.1:9000");
        assert_eq!(format_host_port("admin.local", 9000), "admin.local:9000");
    }

    #[test]
    fn execute_health_plaintext_supports_ipv6_literal_host() {
        let listener = TcpListener::bind(SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 0))
            .expect("IPv6 loopback should be available for CLI health tests");
        let port = listener.local_addr().unwrap().port();

        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buf = [0u8; 1024];
            let n = stream.read(&mut buf).unwrap();
            let request = String::from_utf8_lossy(&buf[..n]);
            assert!(
                request.contains(&format!("Host: [::1]:{port}")),
                "request used malformed IPv6 Host header: {request}"
            );
            stream
                .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok")
                .unwrap();
        });

        let args = HealthArgs {
            port: Some(port),
            host: "::1".to_string(),
            tls: false,
            tls_no_verify: false,
            live: false,
        };

        execute_health(&args).unwrap();
        server.join().unwrap();
    }
}
