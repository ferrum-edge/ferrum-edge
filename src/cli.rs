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
    /// Retire Ambient UDP predecessor placements on this node and publish the
    /// node-scoped cleanup proof the steady-state host producer requires.
    ///
    /// Runs as a privileged INIT CONTAINER in the Ambient DaemonSet's own pod,
    /// beside its unprivileged steady-state container (issue #3809). Same-pod
    /// placement is the point: Kubernetes orders an init container before the
    /// app container, and orders nothing at all between two DaemonSets, so this
    /// is what guarantees the steady-state producer cannot read a leftover
    /// identity/proof pair a same-boot, same-name Node recreation left on the
    /// shared registry hostPath. A node with no durable placement record cannot
    /// tell a fresh/rebooted node from a pre-contract node whose running
    /// workloads still redirect UDP to a retired listener, so it proves the
    /// distinction by doing the retirement rather than by trusting release-level
    /// desired state. Exits non-zero without publishing anything when it cannot
    /// prove completion, which keeps the whole pod non-running.
    ///
    /// It takes no pod-scoped `hostPID` for that: `--host-proc-root` points its
    /// TARGET-pid reads at a read-only host `/proc` mount declared on this
    /// container alone, so the long-running proxy beside it stays out of the
    /// host PID namespace. `SYS_ADMIN`/`SYS_PTRACE` are likewise init-only.
    AmbientUdpPreflight(AmbientUdpPreflightArgs),
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

    /// FIPS deployment mode: `off` (default) or `enforce`.
    ///
    /// Highest-precedence source for the FIPS request; it is materialized into
    /// `FERRUM_FIPS_MODE` before the crypto provider is installed. A request
    /// that only appears in `ferrum.conf` arrives too late to select the
    /// AWS-LC FIPS provider profile and is refused. See docs/fips.md.
    #[arg(long = "fips-mode")]
    pub fips_mode: Option<String>,

    /// Increase log verbosity (-v=info, -vv=debug, -vvv=trace).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,
}

#[derive(clap::Args)]
pub struct ValidateArgs {
    /// Path to ferrum.conf (operational settings).
    #[arg(short = 's', long = "settings")]
    pub settings: Option<PathBuf>,

    /// Path to resources YAML/JSON, or a localized `{version?, mesh}` slice when
    /// validating mesh file protocol.
    #[arg(short = 'c', long = "spec")]
    pub spec: Option<PathBuf>,

    /// Operating mode (database, file, cp, dp, mesh, injector, node_agent, migrate).
    #[arg(short = 'm', long = "mode")]
    pub mode: Option<String>,

    /// FIPS deployment mode: `off` (default) or `enforce`.
    ///
    /// Highest-precedence source for the FIPS request; it is materialized into
    /// `FERRUM_FIPS_MODE` before the crypto provider is installed. A request
    /// that only appears in `ferrum.conf` arrives too late to select the
    /// AWS-LC FIPS provider profile and is refused. See docs/fips.md.
    #[arg(long = "fips-mode")]
    pub fips_mode: Option<String>,

    /// Increase log verbosity (-v=info, -vv=debug, -vvv=trace).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,
}

#[derive(clap::Args)]
pub struct ReloadArgs {
    /// PID of the running gateway (auto-detected if omitted).
    ///
    /// Must be a positive process ID. `0` is rejected because POSIX `kill`
    /// treats it as this process group. This CLI process is also rejected.
    #[arg(
        short = 'p',
        long = "pid",
        value_parser = clap::value_parser!(u32).range(1..)
    )]
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
    /// Path to ferrum.conf for inferred admin ports (env values take precedence).
    #[arg(short = 's', long = "settings")]
    pub settings: Option<PathBuf>,

    /// Admin API port to check (defaults to FERRUM_ADMIN_HTTP_PORT, or
    /// FERRUM_ADMIN_HTTPS_PORT when --tls is set, or 9000/9443 respectively).
    #[arg(short = 'p', long = "port")]
    pub port: Option<u16>,

    /// Admin API host to connect to.
    #[arg(long, default_value = "127.0.0.1")]
    pub host: String,

    /// Use TLS (HTTPS) to connect to the admin API.
    /// Selected automatically when HTTP is disabled and --port is not supplied.
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

    // The FIPS request must reach the environment before `main()` installs the
    // crypto provider, which happens immediately after this call. `ferrum.conf`
    // is not readable that early, so CLI and environment are the only sources
    // that can select the AWS-LC FIPS provider profile. A settings-file-only
    // request is caught and refused by `fips::verify_resolved_mode`.
    if let Some(ref fips_mode) = args.fips_mode {
        // SAFETY: single-threaded context, before tokio runtime.
        unsafe { std::env::set_var(crate::fips::FIPS_MODE_ENV, fips_mode) };
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

/// Apply settings/spec/mode/verbose overrides shared between `run` and `validate`.
pub fn apply_validate_overrides(args: &ValidateArgs) {
    apply_common_overrides(args.settings.as_deref(), args.spec.as_deref());

    if let Some(ref mode) = args.mode {
        // SAFETY: single-threaded context, before tokio runtime.
        unsafe { std::env::set_var("FERRUM_MODE", mode) };
    }

    // The FIPS request must reach the environment before `main()` installs the
    // crypto provider, which happens immediately after this call. `ferrum.conf`
    // is not readable that early, so CLI and environment are the only sources
    // that can select the AWS-LC FIPS provider profile. A settings-file-only
    // request is caught and refused by `fips::verify_resolved_mode`.
    if let Some(ref fips_mode) = args.fips_mode {
        // SAFETY: single-threaded context, before tokio runtime.
        unsafe { std::env::set_var(crate::fips::FIPS_MODE_ENV, fips_mode) };
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

/// Materialize the Ambient UDP node preflight's `--settings` and `-v` overrides
/// before any config read and before worker threads exist, matching `run` /
/// `validate`. Does not set a serving mode or parse `EnvConfig`.
pub fn apply_ambient_udp_preflight_overrides(args: &AmbientUdpPreflightArgs) {
    apply_common_overrides(args.settings.as_deref(), None);

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
/// The read goes through `ConfFile::load()` so it shares the process-wide
/// immutable settings snapshot with every later consumer. A load failure here
/// is *not* treated as "a mode is configured": inference proceeds and
/// `EnvConfig::from_env()` surfaces the same cached error before any listener
/// starts.
pub fn infer_file_mode() {
    use crate::config::conf_file::ConfFile;

    // `-m/--mode` was already written to the environment by
    // `apply_run_overrides` / `apply_validate_overrides`, so this one check
    // covers CLI and env alike.
    if direct_env_var_is_set("FERRUM_MODE") {
        return;
    }
    let conf_mode = ConfFile::load()
        .ok()
        .and_then(|conf| conf.get("FERRUM_MODE").map(str::to_string));
    infer_file_mode_from_conf_mode(conf_mode.as_deref());
}

/// Apply the file-mode smart default after the immutable settings snapshot has
/// already been resolved.
///
/// Kept as a small public seam because process-level callers may already hold
/// the accepted `ferrum.conf` value, and tests must not attempt to replace the
/// process-wide `OnceLock` snapshot with several different files.
#[doc(hidden)]
pub fn infer_file_mode_from_conf_mode(conf_mode: Option<&str>) {
    // Preserve CLI/direct-env precedence even for callers that already loaded
    // the settings snapshot.
    if direct_env_var_is_set("FERRUM_MODE") {
        return;
    }
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

#[derive(clap::Args)]
pub struct AmbientUdpPreflightArgs {
    /// Path to ferrum.conf (operational settings).
    #[arg(short = 's', long = "settings")]
    pub settings: Option<PathBuf>,

    /// Maximum seconds to spend proving predecessor retirement before failing
    /// closed. The init stage must fail rather than block pod creation forever.
    #[arg(long = "timeout-seconds", default_value_t = 300)]
    pub timeout_seconds: u64,

    /// Procfs root to resolve TARGET pids through (default: this process's own
    /// `/proc`).
    ///
    /// This is what lets the preflight stay an init container in the ambient pod
    /// — preserving Kubernetes' init-before-container ordering against the
    /// steady-state proxy — WITHOUT pod-scoped `hostPID`, which Kubernetes would
    /// apply to the long-running proxy container for its whole lifetime. The
    /// chart mounts the host's own `/proc` read-only on this container alone and
    /// points this flag at it.
    ///
    /// It redirects nothing else. `/proc/self/ns/net` — the caller's own namespace
    /// identity and the `setns` save/restore handle — always comes from this
    /// container's own procfs, because the preflight runs in the host network
    /// namespace already and must compare pod namespaces against ITS OWN.
    ///
    /// Deliberately a flag and not a `FERRUM_*` variable: it is an internal
    /// contract between one chart-rendered mount and one chart-rendered
    /// argument, not an operator-tunable runtime setting, and the ambient env
    /// map is copied verbatim into this container.
    #[arg(long = "host-proc-root")]
    pub host_proc_root: Option<PathBuf>,

    /// Increase log verbosity (-v=info, -vv=debug, -vvv=trace).
    #[arg(short = 'v', long = "verbose", action = ArgAction::Count)]
    pub verbose: u8,
}

/// Validate an explicit `--host-proc-root` before anything depends on it.
///
/// Fails closed rather than silently degrading to `/proc`: a typo'd or
/// unmounted root would otherwise send every target-pid read back at the
/// container's own procfs, where the enrolled pods' pids do not exist, and the
/// preflight would report "no live PID" for pods that are running fine. A
/// missing mount is an operator/rendering error, not a node state to interpret.
pub fn validate_host_proc_root(root: &std::path::Path) -> Result<PathBuf, String> {
    if !root.is_absolute() {
        return Err(format!(
            "--host-proc-root must be an absolute path, got {}",
            root.display()
        ));
    }
    let metadata = std::fs::metadata(root).map_err(|error| {
        format!(
            "--host-proc-root {} is not readable: {error}",
            root.display()
        )
    })?;
    if !metadata.is_dir() {
        return Err(format!(
            "--host-proc-root {} is not a directory",
            root.display()
        ));
    }
    // `self/ns/net` exists in every procfs instance, including one bind-mounted
    // from another PID namespace, so it distinguishes a real procfs from an
    // empty mount point that would resolve nothing.
    if cfg!(target_os = "linux") && !root.join("self").join("ns").join("net").exists() {
        return Err(format!(
            "--host-proc-root {} does not look like a mounted procfs (no self/ns/net)",
            root.display()
        ));
    }
    Ok(root.to_path_buf())
}

// ── Subcommand executors ────────────────────────────────────────────────────

/// Retire both Ambient UDP predecessor placements on this node and publish the
/// node-scoped cleanup attestation.
///
/// This is deliberately the ONLY producer of that attestation. Every invocation
/// retracts any leftover proof and re-runs predecessor retirement; an existing
/// attestation is never treated as authority to skip the work. Cleanup itself is
/// ownership-safe to repeat. The command publishes nothing it could not prove
/// under one continuous node-agent registry publication, and it never writes
/// durable placement ownership — the steady-state process still decides that
/// from its own guard.
///
/// `--timeout-seconds` is a hard wall-clock ceiling: stalled `sh`/iptables/ip
/// children are killed with their process group before this process reports
/// timeout, explicit-root host-proc target-PID scans observe the same Instant
/// during the walk, stderr collection is bounded so an orphaned grandchild
/// cannot pin the caller, process-group cleanup failure is reported rather than
/// claimed as success, and no usable attestation remains after the deadline
/// wins.
///
/// Node identity is resolved AUTHORITATIVELY here from a validated explicit
/// `FERRUM_K8S_NODE_UID`, or otherwise from this node's own Kubernetes object,
/// and never from the node-agent's published `.node-identity-v1.json`. That file
/// records the CURRENT boot id even when it was written by a PREVIOUS Kubernetes
/// Node object on this same boot, so no reader can tell a stale publication from
/// a live one — and the node-agent DaemonSet has no startup ordering against
/// this pod, so the replacement node-agent may not have retracted it yet when
/// this stage runs. Consuming it would let a stale identity and the stale cleanup proof
/// written under it agree and authorize node-name reuse under the wrong
/// immutable UID. When no explicit UID is supplied, one bounded `get` on this
/// node's own object, bound to the node name the downward API gave this pod,
/// settles it. In either case the resolver retracts the publication before it
/// reads the boot id or resolves the UID, and republishes only what it proved,
/// so every failure after entry leaves no identity and the steady-state
/// container that starts next reads an identity this pod established.
pub fn execute_ambient_udp_preflight(args: &AmbientUdpPreflightArgs) -> Result<(), String> {
    use crate::config::conf_file::resolve_ferrum_var;
    use crate::proxy::owned_shell::OwnedShellError;
    use crate::proxy::udp_placement_migration::{
        UdpMigrationContext, UdpPlacement, node_proof_generation_from_env,
        parse_explicit_k8s_node_uid, resolve_authoritative_node_identity,
        retract_node_cleanup_proof,
    };

    let settings = crate::capture::udp_capture_settings_from_env()
        .map_err(|error| format!("invalid Ambient UDP capture settings: {error}"))?;
    let target = UdpPlacement::from_capture_settings(
        settings.udp_capture_enabled,
        settings.udp_host_netns_enabled,
    );
    if target != UdpPlacement::HostNetns {
        // Only the host placement drops the setns privileges that would let the
        // steady-state process inspect a pod netns, so only it needs an
        // out-of-band node proof. Every other placement proves predecessor
        // retirement from its own runtime path.
        println!(
            "ambient-udp-preflight: nothing to prove for placement {}",
            target.as_str()
        );
        return Ok(());
    }

    let registry_dir = resolve_ferrum_var("FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR")
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            "FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR is required by the Ambient UDP node preflight"
                .to_string()
        })?;
    let registry_dir = PathBuf::from(registry_dir.trim());
    let generation = node_proof_generation_from_env()?.ok_or_else(|| {
        "FERRUM_MESH_CAPTURE_UDP_NODE_PROOF_GENERATION is required by the Ambient UDP node preflight"
            .to_string()
    })?;
    let explicit_node_uid =
        parse_explicit_k8s_node_uid(resolve_ferrum_var("FERRUM_K8S_NODE_UID").as_deref())?;
    let node_name = resolve_ferrum_var("FERRUM_K8S_NODE_NAME")
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let target_proc_root = args
        .host_proc_root
        .as_deref()
        .map(validate_host_proc_root)
        .transpose()?;

    let source = std::sync::Arc::new(crate::proxy::netns_capture::DirectoryCaptureSource::new(
        registry_dir.clone(),
    ));
    let (_shutdown_tx, shutdown_rx) = tokio::sync::watch::channel(false);
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|error| format!("could not build the preflight runtime: {error}"))?;
    let timeout_seconds = args.timeout_seconds.clamp(1, 3600);
    let std_deadline = std::time::Instant::now() + std::time::Duration::from_secs(timeout_seconds);
    let outcome = runtime.block_on(async move {
        if crate::proxy::owned_shell::deadline_elapsed(Some(std_deadline)) {
            return Ok(crate::proxy::udp_placement_cleanup::UdpCleanupOutcome::DeadlineElapsed);
        }
        let lookup_timeout = std::time::Duration::from_secs(NODE_UID_LOOKUP_TIMEOUT_SECONDS).min(
            crate::proxy::owned_shell::remaining(Some(std_deadline))
                .unwrap_or(std::time::Duration::from_secs(0)),
        );
        let node = resolve_authoritative_node_identity(
            &registry_dir,
            explicit_node_uid.as_deref(),
            node_name.as_deref(),
            |name| fetch_this_node_uid(name, lookup_timeout),
        )
        .await?;

        // A leftover proof is not authority for this pod. A Helm rollback, a
        // re-applied historical manifest, or a restored ConfigMap can recreate
        // an earlier era's generation token, and a mutable monotonic counter
        // cannot prove that did not happen. Retract whatever is present and run
        // predecessor retirement on every invocation; publish only after this
        // pod's own authoritative lookup and two complete passes succeed.
        retract_node_cleanup_proof(&registry_dir)?;
        if crate::proxy::owned_shell::deadline_elapsed(Some(std_deadline)) {
            return Ok(crate::proxy::udp_placement_cleanup::UdpCleanupOutcome::DeadlineElapsed);
        }

        match crate::proxy::netns_udp_capture::preflight_capture_tools_until(
            true,
            Some(std_deadline),
        ) {
            Ok(()) => {}
            Err(error) if error.is_deadline_elapsed() => {
                if let Some(reason) = error.deadline_operator_reason() {
                    tracing::warn!("{reason}");
                }
                return Ok(
                    crate::proxy::udp_placement_cleanup::UdpCleanupOutcome::DeadlineElapsed,
                );
            }
            Err(OwnedShellError::DeadlineUnsupported { .. }) => {
                return Err(
                    "the Ambient UDP node preflight could not establish a bounded command collector; no proof was published"
                        .to_string(),
                );
            }
            Err(OwnedShellError::Io(error)) => {
                return Err(format!(
                    "the Ambient UDP node preflight image cannot run the required tooling: Ambient UDP capture is enabled but `sh` is not available in the runtime image \
                     (the producer runs in-netns `sh -c` scripts that call `ip`/`iptables`): {error}. Use a \
                     runtime image that ships a shell + iproute2 + iptables, or unset \
                     FERRUM_MESH_CAPTURE_UDP_ENABLED."
                ));
            }
            Err(OwnedShellError::Failed { .. }) => {
                return Err(
                    "the Ambient UDP node preflight image cannot run the required tooling: Ambient UDP capture is enabled but `ip`, `iptables` with the mangle table, and `ip6tables` with the mangle table \
                     (IPv6 UDP capture is set to `required`) are not available in the runtime image; \
                     the per-pod-netns producer needs them to install UDP TPROXY rules. Use a runtime \
                     image that ships iproute2 + iptables (the distroless default lacks them), or unset \
                     FERRUM_MESH_CAPTURE_UDP_ENABLED."
                        .to_string(),
                );
            }
            Err(error) => {
                return Err(format!(
                    "the Ambient UDP node preflight image cannot run the required tooling: {}",
                    error
                        .deadline_operator_reason()
                        .unwrap_or("unexpected tool probe failure")
                ));
            }
        }

        let context =
            UdpMigrationContext::for_node_preflight(&registry_dir, target, node, &generation)?;
        let context = context.with_target_proc_root(target_proc_root);
        let remaining = crate::proxy::owned_shell::remaining(Some(std_deadline))
            .unwrap_or(std::time::Duration::from_secs(0));
        let deadline = tokio::time::Instant::now() + remaining;
        let outcome = crate::proxy::udp_placement_cleanup::run_udp_placement_cleanup(
            context,
            source,
            shutdown_rx,
            Some(deadline),
        )
        .await;
        Ok::<_, String>(outcome)
    })?;
    match outcome {
        crate::proxy::udp_placement_cleanup::UdpCleanupOutcome::Complete => {
            println!("ambient-udp-preflight: predecessor placements retired and proof published");
            Ok(())
        }
        crate::proxy::udp_placement_cleanup::UdpCleanupOutcome::DeadlineElapsed => Err(
            "the Ambient UDP node preflight could not prove predecessor retirement within its timeout; no proof was published"
                .to_string(),
        ),
        crate::proxy::udp_placement_cleanup::UdpCleanupOutcome::ShuttingDown => Err(
            "the Ambient UDP node preflight was interrupted; no proof was published".to_string(),
        ),
    }
}

/// Read THIS node's immutable `Node.metadata.uid` with one bounded, named,
/// timeout-guarded `get`.
///
/// The request is bound to the node name the downward API stamped on this pod
/// (`FERRUM_K8S_NODE_NAME` from `spec.nodeName`), so this process only ever
/// asks for the machine it is running on. Authority is the in-cluster
/// service-account config: a missing in-cluster config fails closed unless
/// `FERRUM_K8S_NODE_UID` was supplied (that path never reaches this lookup).
/// The RBAC the chart grants alongside it is a read-only `nodes: get` — no
/// list, no watch, no write. That cannot enumerate or mutate nodes, but a
/// `get` without `resourceNames` is not a single-object restriction:
/// Kubernetes permits a named GET for any node whose name the caller already
/// knows. The runtime request is the binding, not the Role. Nothing from the
/// returned object other than the UID is read. The UID itself is never logged:
/// it is an identity binding, not diagnostics. Lookup failures are
/// material-free so kube diagnostics cannot leak names, URLs, or tokens.
async fn fetch_this_node_uid(
    node_name: String,
    timeout: std::time::Duration,
) -> Result<String, String> {
    use k8s_openapi::api::core::v1::Node;
    use kube::Api;

    let config = kube::Config::incluster().map_err(|_| {
        "could not build an in-cluster Kubernetes client to resolve this node's UID; \
         supply FERRUM_K8S_NODE_UID or run this command inside a Kubernetes pod"
            .to_string()
    })?;
    let client = kube::Client::try_from(config).map_err(|_| {
        "could not build an in-cluster Kubernetes client to resolve this node's UID; \
         supply FERRUM_K8S_NODE_UID or run this command inside a Kubernetes pod"
            .to_string()
    })?;
    let nodes: Api<Node> = Api::all(client);
    let node = match tokio::time::timeout(timeout, nodes.get(&node_name)).await {
        Ok(Ok(node)) => node,
        Ok(Err(_)) => {
            return Err("could not read this node's Kubernetes object".to_string());
        }
        Err(_) => return Err("timed out reading this node's Kubernetes object".to_string()),
    };
    node.metadata
        .uid
        .filter(|uid| !uid.trim().is_empty())
        .ok_or_else(|| "this node's Kubernetes object carries no UID".to_string())
}

/// Matches the node-agent's own bounded node lookup, so both authorities fail in
/// the same window rather than one masking the other's outage.
const NODE_UID_LOOKUP_TIMEOUT_SECONDS: u64 = 10;

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

/// Operator-facing scope of what SIGHUP actually does (issue #4548).
///
/// The target is resolved by `pgrep -x ferrum-edge` when `--pid` is omitted,
/// which cannot distinguish a file-mode gateway from a database-mode one. The
/// signal is delivered either way, so the exit status stays `0`; this line says
/// what the receiving process will do with it. Every mode now registers a
/// hangup stream, so a SIGHUP to a non-reloading mode is a logged no-op rather
/// than an undrained termination.
pub const RELOAD_SCOPE_NOTICE: &str = "Note: SIGHUP triggers a config reload only in file mode, \
and in mesh mode with a local file or xDS config source. Other modes log the signal and ignore \
it — use database polling, control-plane push, or a rolling restart instead.";

/// Send SIGHUP to a running gateway process.
pub fn execute_reload(args: &ReloadArgs) -> Result<(), String> {
    #[cfg(unix)]
    {
        let pid = match args.pid {
            Some(p) => p,
            None => find_gateway_pid()?,
        };
        let target = unix_reload_pid_t(pid)?;
        // SAFETY: `target` is a positive `pid_t` (not 0, not this CLI
        // process). `SIGHUP` is a valid signal. `kill` does not dereference
        // memory; a failure returns -1 and sets errno.
        let rc = unsafe { libc::kill(target, libc::SIGHUP) };
        if rc == 0 {
            println!("Sent SIGHUP to PID {}", pid);
            println!("{}", RELOAD_SCOPE_NOTICE);
            Ok(())
        } else {
            Err(format!(
                "Failed to send SIGHUP to PID {}: {}",
                pid,
                std::io::Error::last_os_error()
            ))
        }
    }

    #[cfg(not(unix))]
    {
        let _ = args;
        Err("reload is only supported on Unix platforms".into())
    }
}

/// Convert a CLI `--pid` into a `pid_t` that is safe to pass to POSIX `kill`.
///
/// `kill(pid, …)` with `pid == 0` signals every process in the caller's
/// process group, not a process named "0". Negative special values cannot
/// arrive through `u32`, but values that do not fit in `pid_t` also cannot
/// name a live process. The reload CLI itself is refused so an explicit
/// `--pid` cannot SIGHUP this process.
///
/// Identity and liveness of the target are not probed first: `/proc` or
/// `kill(pid, 0)` would be racy with PID reuse, and explicit `--pid` already
/// bypasses `pgrep` auto-detection by contract. `kill(SIGHUP)` itself reports
/// ESRCH / EPERM.
#[cfg(unix)]
fn unix_reload_pid_t(pid: u32) -> Result<libc::pid_t, String> {
    if pid == 0 {
        return Err(
            "invalid --pid 0: POSIX kill treats 0 as this process group, not a gateway PID".into(),
        );
    }
    let self_pid = std::process::id();
    if pid == self_pid {
        return Err(format!(
            "invalid --pid {pid}: that is this CLI process, not a running ferrum-edge gateway"
        ));
    }
    libc::pid_t::try_from(pid)
        .map_err(|_| format!("invalid --pid {pid}: value is outside the range of a process ID"))
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
    use crate::modes::mesh::MeshConfigProtocol;
    use crate::modes::startup_security::{StartupSecurityScope, load_startup_security};

    crate::modes::mesh::validate::prepare_validate_file_source()?;

    let env_config =
        EnvConfig::from_env().map_err(|e| format!("Settings validation failed: {}", e))?;
    println!("Settings (ferrum.conf): OK");
    println!(
        "  Mode: {}",
        report_field("FERRUM_MODE", &format!("{:?}", env_config.mode))
    );

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

        // FIPS gateway-document admission, evaluated with exactly the policy
        // that startup, SIGHUP reload, database poll apply, CP publication, and
        // DP apply use, so `validate` cannot pass a document the gateway would
        // then refuse. Inert when FIPS mode is off.
        crate::fips::policy::check_gateway_config(&config)
            .map_err(|e| format!("FIPS policy validation failed: {e}"))?;

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

    // Env-level TLS/security surfaces that `run` hard-fails on must also fail
    // `validate`. Shared loaders in `modes::startup_security` are side-effect
    // free (no binds, no servers, no store mutation, no random JWT mint).
    let security_scope = StartupSecurityScope::for_mode(&env_config.mode);
    if !security_scope.is_empty() {
        load_startup_security(&env_config)
            .map_err(|e| format!("Startup security validation failed: {}", e))?;
        println!("Startup security (env TLS/CIDRs/metrics): OK");
    }

    // Mesh runtime admission (stock xDS transport posture, protocol/CP
    // requirements) lives in `MeshRuntimeConfig::from_env_config` and is what
    // `run` fail-closes on before dialing. Validate must exercise the same
    // gate so a production plaintext ADS URL cannot report success.
    if env_config.mode == OperatingMode::Mesh {
        let runtime = crate::modes::mesh::MeshRuntimeConfig::from_env_config(&env_config)
            .map_err(|e| format!("Mesh runtime validation failed: {e}"))?;
        if runtime.config_protocol.requires_local_policy_document() {
            let path = runtime.file_config_path.as_deref().ok_or_else(|| {
                format!(
                    "FERRUM_MESH_FILE_CONFIG_PATH is required when \
                     FERRUM_MESH_CONFIG_PROTOCOL={}",
                    runtime.config_protocol.as_str()
                )
            })?;
            match runtime.config_protocol {
                MeshConfigProtocol::File => {
                    crate::modes::mesh::config_consumer::file_source::load_mesh_slice_from_file(
                        std::path::Path::new(path),
                        runtime.mesh_slice_request(),
                    )
                    .map_err(|e| format!("Mesh spec validation failed: {e}"))?;
                }
                MeshConfigProtocol::StockXds => {
                    crate::modes::mesh::config_consumer::stock_xds_client::load_stock_policy_baseline(
                        std::path::Path::new(path),
                    )
                    .map_err(|e| format!("Mesh spec validation failed: {e}"))?;
                }
                MeshConfigProtocol::Native | MeshConfigProtocol::Xds => {
                    return Err("internal mesh validation protocol mismatch".to_string());
                }
            }
            println!(
                "Mesh spec ({}): OK",
                report_field("FERRUM_MESH_FILE_CONFIG_PATH", path)
            );
        }
        println!("Mesh runtime: OK");
    }

    println!("\nValidation passed.");
    Ok(())
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

/// Resolve only the settings needed by the one-shot health probe. Explicit
/// ports keep their existing independent behavior; inferred ports use the same
/// stable settings reader and env-over-conf resolver as gateway startup.
fn resolve_health_target(args: &HealthArgs) -> Result<(u16, bool), String> {
    use crate::config::conf_file::ConfFile;
    use crate::config::env_config::resolve_var;

    if let Some(port) = args.port {
        return Ok((port, args.tls));
    }
    let conf = match resolve_settings_path(args.settings.as_deref()) {
        Some(path) => ConfFile::load_from_path(&path, false)?,
        None => ConfFile::load()?,
    };
    let configured_port = |key: &str, default: u16| -> Result<u16, String> {
        match resolve_var(&conf, key) {
            Some(value) => value
                .parse::<u16>()
                .map_err(|_| format!("{key} must be an integer from 0 to 65535")),
            None => Ok(default),
        }
    };
    let use_tls = args.tls || configured_port("FERRUM_ADMIN_HTTP_PORT", 9000)? == 0;
    let port = if use_tls {
        configured_port("FERRUM_ADMIN_HTTPS_PORT", 9443)?
    } else {
        configured_port("FERRUM_ADMIN_HTTP_PORT", 9000)?
    };
    Ok((port, use_tls))
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

    let (port, use_tls) = resolve_health_target(args)?;

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
    let provider = Arc::new(crate::fips::base_crypto_provider());

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
        crate::fips::base_crypto_provider()
            .signature_verification_algorithms
            .supported_schemes()
    }
}

// ── Helpers ─────────────────────────────────────────────────────────────────

/// Select a gateway PID from a list, excluding the caller's own PID.
///
/// Used by `find_gateway_pid` to pick the target of a `reload` SIGHUP. The
/// caller's PID is excluded first so the reload process never signals itself,
/// then the zero/one/many selection runs on the filtered set.
pub fn select_gateway_pid(pids: Vec<u32>, self_pid: u32) -> Result<u32, String> {
    let filtered: Vec<u32> = pids.into_iter().filter(|p| *p != self_pid).collect();
    match filtered.len() {
        0 => Err("No running ferrum-edge process found. Use --pid to specify the PID.".into()),
        1 => Ok(filtered[0]),
        n => Err(format!(
            "Found {} ferrum-edge processes. Use --pid to specify which one:\n  {}",
            n,
            filtered
                .iter()
                .map(|p| p.to_string())
                .collect::<Vec<_>>()
                .join("\n  ")
        )),
    }
}

/// Attempt to find a running ferrum-edge process via `pgrep`.
///
/// `pgrep -x ferrum-edge` matches by exact process name. Because the `reload`
/// subcommand is itself named `ferrum-edge`, pgrep returns the reload process's
/// PID alongside any gateway PIDs. `select_gateway_pid` filters out the caller's
/// own PID before the zero/one/many selection, so a single-gateway host no
/// longer reports "Found 2 ferrum-edge processes" and a no-gateway host no
/// longer SIGHUPs itself.
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
    let self_pid = std::process::id();
    let pids: Vec<u32> = stdout
        .trim()
        .lines()
        .map(|line| {
            line.trim()
                .parse::<u32>()
                .map_err(|_| "pgrep returned a non-numeric process ID".to_string())
        })
        .collect::<Result<_, _>>()?;

    select_gateway_pid(pids, self_pid)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{IpAddr, Ipv6Addr, SocketAddr, TcpListener};

    #[test]
    fn health_target_respects_settings_and_overrides() {
        const CHILD_CASE: &str = "FERRUM_TEST_HEALTH_SETTINGS_CASE";
        let cases = [
            (
                "FERRUM_ADMIN_HTTP_PORT = 9001\n",
                vec!["health"],
                None,
                None,
                Ok((9001, false)),
            ),
            (
                "FERRUM_ADMIN_HTTP_PORT = 0\nFERRUM_ADMIN_HTTPS_PORT = 9555\n",
                vec!["health", "-s", "custom.conf"],
                None,
                None,
                Ok((9555, true)),
            ),
            (
                "FERRUM_ADMIN_HTTP_PORT = 0\n",
                vec!["health"],
                Some("9222"),
                None,
                Ok((9222, false)),
            ),
            (
                "FERRUM_ADMIN_HTTP_PORT = 9001\n",
                vec!["health", "--tls"],
                None,
                Some("9666"),
                Ok((9666, true)),
            ),
            (
                "FERRUM_ADMIN_HTTP_PORT = 0\n",
                vec!["health", "-p", "9777"],
                None,
                None,
                Ok((9777, false)),
            ),
            ("", vec!["health"], None, None, Ok((9000, false))),
            (
                "FERRUM_ADMIN_HTTP_PORT = 0\n",
                vec!["health"],
                None,
                None,
                Ok((9443, true)),
            ),
            (
                "invalid settings\n",
                vec!["health"],
                None,
                None,
                Err("Invalid conf file syntax"),
            ),
            (
                "FERRUM_ADMIN_HTTP_PORT = invalid\n",
                vec!["health"],
                None,
                None,
                Err("FERRUM_ADMIN_HTTP_PORT must be an integer"),
            ),
            (
                "FERRUM_ADMIN_HTTP_PORT = 9001\n",
                vec!["health", "-s", "missing.conf"],
                None,
                None,
                Err("ferrum.conf"),
            ),
        ];
        if let Ok(index) = std::env::var(CHILD_CASE) {
            let (_, arguments, _, _, expected) = &cases[index.parse::<usize>().unwrap()];
            let cli =
                Cli::parse_from(std::iter::once("ferrum-edge").chain(arguments.iter().copied()));
            let Some(Command::Health(args)) = cli.command else {
                panic!("expected health command");
            };
            let actual = resolve_health_target(&args);
            match expected {
                Ok(target) => assert_eq!(actual.unwrap(), *target),
                Err(message) => assert!(actual.unwrap_err().contains(*message)),
            }
            return;
        }
        for (index, (settings, _, http, https, _)) in cases.iter().enumerate() {
            let directory = tempfile::tempdir().unwrap();
            std::fs::write(directory.path().join("ferrum.conf"), settings).unwrap();
            std::fs::write(directory.path().join("custom.conf"), settings).unwrap();
            if index == 1 || index == 2 {
                // Explicit CLI/env paths must win over a conflicting discovered file.
                std::fs::write(directory.path().join("ferrum.conf"), "invalid fallback\n").unwrap();
            }
            let mut command = std::process::Command::new(std::env::current_exe().unwrap());
            command
                .arg("--exact")
                .arg("cli::tests::health_target_respects_settings_and_overrides")
                .current_dir(directory.path())
                .env(CHILD_CASE, index.to_string());
            for key in [
                "FERRUM_CONF_PATH",
                "FERRUM_CONF_PATH_FILE",
                "FERRUM_CONF_PATH_VAULT",
                "FERRUM_CONF_PATH_AWS",
                "FERRUM_CONF_PATH_AZURE",
                "FERRUM_CONF_PATH_GCP",
                "FERRUM_ADMIN_HTTP_PORT",
                "FERRUM_ADMIN_HTTPS_PORT",
            ] {
                command.env_remove(key);
            }
            if let Some(value) = http {
                command.env("FERRUM_ADMIN_HTTP_PORT", value);
            }
            if let Some(value) = https {
                command.env("FERRUM_ADMIN_HTTPS_PORT", value);
            }
            // A direct environment path must work as well as smart discovery.
            if index == 2 {
                command.env("FERRUM_CONF_PATH", directory.path().join("custom.conf"));
            }
            let output = command.output().unwrap();
            assert!(
                output.status.success(),
                "case {index}: {} {}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            assert!(String::from_utf8_lossy(&output.stdout).contains("1 passed"));
        }
    }

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
            settings: None,
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
