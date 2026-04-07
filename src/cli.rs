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
    about = "A high-performance edge proxy built in Rust",
    subcommand_required = false,
    arg_required_else_help = false
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
}

#[derive(clap::Args)]
pub struct RunArgs {
    /// Path to ferrum.conf (operational settings).
    #[arg(short = 's', long = "settings")]
    pub settings: Option<PathBuf>,

    /// Path to resources YAML/JSON (proxies, consumers, upstreams, plugins).
    #[arg(short = 'c', long = "spec")]
    pub spec: Option<PathBuf>,

    /// Operating mode (database, file, cp, dp, migrate).
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

// ── Smart path resolution ───────────────────────────────────────────────────

/// Search well-known locations for a settings file when no explicit path is given
/// and the `FERRUM_CONF_PATH` env var is not set.
pub fn resolve_settings_path(explicit: Option<&Path>) -> Option<PathBuf> {
    if let Some(p) = explicit {
        return Some(resolve_path(p));
    }
    // Don't override if the env var is already set.
    if std::env::var("FERRUM_CONF_PATH").is_ok() {
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
    if std::env::var("FERRUM_FILE_CONFIG_PATH").is_ok() {
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

    // Infer file mode when a spec is available but no mode is configured.
    if std::env::var("FERRUM_MODE").is_err() && std::env::var("FERRUM_FILE_CONFIG_PATH").is_ok() {
        // SAFETY: single-threaded context.
        unsafe { std::env::set_var("FERRUM_MODE", "file") };
    }
}

/// Apply settings/spec overrides shared between `run` and `validate`.
pub fn apply_validate_overrides(args: &ValidateArgs) {
    apply_common_overrides(args.settings.as_deref(), args.spec.as_deref());

    // Infer file mode when a spec is available but no mode is configured.
    if std::env::var("FERRUM_MODE").is_err() && std::env::var("FERRUM_FILE_CONFIG_PATH").is_ok() {
        // SAFETY: single-threaded context.
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

/// Validate configuration without starting the gateway.
pub fn execute_validate() -> Result<(), String> {
    use crate::config::{EnvConfig, OperatingMode, file_loader};

    let env_config =
        EnvConfig::from_env().map_err(|e| format!("Settings validation failed: {}", e))?;
    println!("Settings (ferrum.conf): OK");
    println!("  Mode: {:?}", env_config.mode);

    if env_config.mode == OperatingMode::File {
        let config_path = env_config
            .file_config_path
            .as_deref()
            .ok_or("FERRUM_FILE_CONFIG_PATH not set (required for file mode)")?;

        let config = file_loader::load_config_from_file(
            config_path,
            env_config.tls_cert_expiry_warning_days,
            &env_config.backend_allow_ips,
        )
        .map_err(|e| format!("Spec validation failed: {}", e))?;

        // Validate stream proxy port conflicts
        let reserved_ports = env_config.reserved_gateway_ports();
        if let Err(errors) = config.validate_stream_proxy_port_conflicts(&reserved_ports) {
            return Err(format!("Port conflict errors:\n  {}", errors.join("\n  ")));
        }

        println!("Spec ({}): OK", config_path);
        println!("  Proxies: {}", config.proxies.len());
        println!("  Consumers: {}", config.consumers.len());
        println!("  Upstreams: {}", config.upstreams.len());
        println!("  Plugin configs: {}", config.plugin_configs.len());
    }

    println!("\nValidation passed.");
    Ok(())
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
