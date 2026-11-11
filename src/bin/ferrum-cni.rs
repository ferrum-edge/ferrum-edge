//! `ferrum-cni` — minimal CNI plugin that forwards each ADD / DEL / CHECK /
//! STATUS / GC invocation to the long-lived node-agent over a Unix domain
//! socket.
//!
//! Wire contract: kubelet invokes us per the CNI spec with stdin JSON
//! (the chained network configuration) and the `CNI_*` environment
//! variables (command verb, container id, netns path, args, plugin
//! search path). We parse those, extract the K8s pod identity from
//! `CNI_ARGS` (for attachment verbs), send a [`CniRpcRequest`] to the
//! node-agent, and translate the response back into CNI-spec JSON on
//! stdout. STATUS probes node-agent readiness without attachment fields.
//! GC carries a bounded `cni.dev/valid-attachments` valid set instead of a
//! single pod identity.
//!
//! Why this is in `src/bin/` and not its own crate:
//! - The CNI binary needs the same `cni::spec` / `cni::rpc` /
//!   `cni::client` modules as the node-agent server, so sharing the
//!   library crate avoids code duplication.
//! - Both binaries live in the same docker image: the node-agent image
//!   ships it at `/app/ferrum-cni`, and the chart's init container runs
//!   `/app/ferrum-cni install`, which publishes the binary into the host's
//!   `/opt/cni/bin/`.
//! - cargo's `[[bin]]` targets compile against the parent crate's
//!   `lib.rs`, so this file is intentionally tiny.
//!
//! Stub on non-Unix: CNI is a Linux concept. Non-Unix (Windows) builds
//! print an error and exit 1 so the binary target compiles in the CI
//! matrix without requiring conditional compilation in `Cargo.toml`.

#[cfg(unix)]
mod cni_main {
    use std::io::Write;
    use std::process::ExitCode;
    use std::time::Duration;

    use ferrum_edge::cni::client::{DEFAULT_RPC_TIMEOUT, send_rpc};
    use ferrum_edge::cni::install;
    use ferrum_edge::cni::lifecycle::{
        self, CleanupWaitConfig, RollbackWatchConfig, RollbackWatchOutcome, probe_node_agent_status,
    };
    use ferrum_edge::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
    use ferrum_edge::cni::spec::{
        CniCommand, CniError, CniInvocation, CniNetConfig, CniSuccessResult, K8sPodIdentity,
        MAX_CNI_ATTACHMENT_FIELD_BYTES, MAX_CNI_STDIN_BYTES, SUPPORTED_CNI_VERSIONS,
        build_error_result, cni_version_supports_gc, cni_version_supports_status, ingest_cni_args,
        ingest_valid_attachments, is_safe_cni_container_id, is_safe_cni_netns_path,
        is_safe_cni_network_name, is_supported_cni_version, read_stdin_bounded,
    };

    /// Default socket path the binary connects to when the chained CNI
    /// conflist does not override it via `ferrum.socketPath`. Must agree
    /// with the `FERRUM_NODE_AGENT_CNI_SOCKET_PATH` default in
    /// `src/config/env_config.rs`; the Helm install renders both from the
    /// same value.
    const DEFAULT_CNI_SOCKET_PATH: &str = "/var/run/ferrum/node-agent-cni.sock";

    pub fn run() -> ExitCode {
        // Lifecycle verbs are driven by the Helm chart's init container,
        // rollback sidecar, and pre-delete cleanup hook. kubelet never passes
        // argv to a CNI plugin, so an argument-bearing invocation is
        // unambiguously the lifecycle CLI and never a plugin call.
        match std::env::args().nth(1).as_deref() {
            Some("install") => {
                init_lifecycle_logging();
                return run_install();
            }
            Some("uninstall") => {
                init_lifecycle_logging();
                return run_uninstall();
            }
            Some("uninstall-status") => return run_uninstall_status(),
            Some("await-cleanup") => {
                init_lifecycle_logging();
                return run_await_cleanup();
            }
            Some("rollback-watch") => {
                init_lifecycle_logging();
                return run_rollback_watch();
            }
            Some(_) => {
                // The argument is not echoed: it is untrusted process input
                // and the accepted set is fixed and short.
                eprintln!(
                    "ferrum-cni: unknown subcommand; expected one of \
                     install | uninstall | uninstall-status | await-cleanup | rollback-watch"
                );
                return ExitCode::from(2);
            }
            None => {}
        }

        let command = match CniInvocation::command_from_env() {
            Ok(CniCommand::Version) => {
                // VERSION may arrive without stdin; advertise the full
                // supported set including CNI 1.1.0 (STATUS + GC).
                return emit_version("1.1.0");
            }
            Ok(CniCommand::Unsupported) => {
                return emit_error("0.4.0", &CniError::UnsupportedCommand);
            }
            Ok(command) => command,
            Err(err) => return emit_error("0.4.0", &err),
        };

        let stdin_buf = match read_stdin_bounded(MAX_CNI_STDIN_BYTES) {
            Ok(buf) => buf,
            Err(err) => return emit_error("0.4.0", &err),
        };
        if ferrum_edge::util::json_dup_keys::str_ambiguity(&stdin_buf).is_some() {
            return emit_error(
                "0.4.0",
                &CniError::BadConfig("ambiguous CNI configuration JSON".to_string()),
            );
        }
        let net_config: CniNetConfig = match serde_json::from_str(&stdin_buf) {
            Ok(cfg) => cfg,
            Err(err) => return emit_error("0.4.0", &CniError::BadConfig(err.to_string())),
        };
        let cni_version = net_config.cni_version.clone();

        if !is_supported_cni_version(&cni_version) {
            return emit_error(&cni_version, &CniError::UnsupportedVersion);
        }
        if !is_safe_cni_network_name(&net_config.name) {
            return emit_error(
                &cni_version,
                &CniError::BadConfig("invalid CNI network name".to_string()),
            );
        }
        if net_config.plugin_type.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES
            || !is_safe_cni_container_id(&net_config.plugin_type)
        {
            return emit_error(
                &cni_version,
                &CniError::BadConfig("invalid CNI plugin type".to_string()),
            );
        }

        let invocation = match CniInvocation::from_env_for_command(command) {
            Ok(inv) => inv,
            Err(err) => return emit_error(&cni_version, &err),
        };

        match invocation.command {
            CniCommand::Version => emit_version(&cni_version),
            CniCommand::Unsupported => emit_error(&cni_version, &CniError::UnsupportedCommand),
            CniCommand::Status => handle_status(&net_config),
            CniCommand::Gc => handle_gc(&net_config),
            verb @ (CniCommand::Add | CniCommand::Del | CniCommand::Check) => {
                handle_verb(verb, &net_config, &invocation)
            }
        }
    }

    /// Route the shared `cni::install` / `cni::lifecycle` diagnostics (ignored
    /// ownership manifests, skipped neighbour configs) to stderr for the
    /// lifecycle verbs. Those modules log through `tracing` because the
    /// node-agent, which has a subscriber, calls them too; without one here the
    /// init container and hooks would drop them. Plugin invocations never
    /// install it: their stdout is the CNI result and stays untouched either
    /// way. `RUST_LOG` overrides the default `info` level.
    fn init_lifecycle_logging() {
        let filter = tracing_subscriber::EnvFilter::try_from_default_env()
            .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"));
        let _ = tracing_subscriber::fmt()
            .with_env_filter(filter)
            .with_writer(std::io::stderr)
            .with_ansi(false)
            .try_init();
    }

    /// `ferrum-cni install` — copy the binary and write the chained conflist.
    fn run_install() -> ExitCode {
        match install::install_from_env() {
            Ok(path) => {
                eprintln!(
                    "ferrum-cni: installed chained CNI config at {}",
                    path.display()
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("ferrum-cni: install failed: {err}");
                ExitCode::from(1)
            }
        }
    }

    /// `ferrum-cni uninstall` — remove the Ferrum-owned artifacts, then
    /// optionally hold so a Helm hook can wait on readiness.
    ///
    /// Exit 1 whenever the chained conflist is still in place: leaving that
    /// file behind is the node-wide pod-creation dependency, and reporting
    /// success for it would let `helm uninstall` declare a clean removal that
    /// silently strands the node.
    fn run_uninstall() -> ExitCode {
        // Retract any marker a PREVIOUS start of this container published,
        // before touching the node. `/tmp` is an emptyDir that outlives a
        // container restart, so a marker left by an earlier run would make the
        // readiness probe pass for work this invocation has not done yet.
        // Holding is opt-in: absent `READY_MARKER_PATH` this is a plain
        // one-shot cleanup (manual runs, Jobs) with no marker at all.
        let marker_path = lifecycle::ready_marker_path_from_env().ok();
        if let Some(marker_path) = marker_path.as_deref()
            && let Err(err) = lifecycle::clear_stale_ready_marker(marker_path)
        {
            eprintln!(
                "ferrum-cni: refusing to run: the cleanup readiness marker from a previous \
                 start could not be retracted: {err}"
            );
            return ExitCode::from(1);
        }

        let report = match install::uninstall_from_env() {
            Ok(report) => report,
            Err(err) => {
                eprintln!("ferrum-cni: uninstall failed: {err}");
                return ExitCode::from(1);
            }
        };
        for line in report.summary_lines() {
            eprintln!("ferrum-cni: {line}");
        }
        if !report.is_success() {
            eprintln!(
                "ferrum-cni: uninstall did NOT clear the chained CNI configuration. \
                 Pod creation on this node still traverses ferrum-cni. Inspect the \
                 file above and remove it manually once you have confirmed it is the \
                 Ferrum-generated chain; the primary CNI configuration it chains \
                 behind was never modified and needs no repair."
            );
            return ExitCode::from(1);
        }
        if !report.chain_lifted() {
            // Success, but not because this node stopped depending on the
            // node-agent: another Ferrum install owns the chain and this run
            // must not touch it. Say so rather than implying a clean node.
            eprintln!(
                "ferrum-cni: the chained CNI configuration is owned by a different Ferrum \
                 install and was deliberately left in place. This node still traverses \
                 ferrum-cni for that other release."
            );
        }

        // Readiness is published only now, by THIS invocation, after its own
        // cleanup succeeded. With the marker set the process then stays up so
        // a DaemonSet-shaped Helm hook can observe readiness.
        match marker_path {
            None => ExitCode::SUCCESS,
            Some(marker_path) => {
                if let Err(err) = lifecycle::write_ready_marker(&marker_path) {
                    eprintln!(
                        "ferrum-cni: cleanup succeeded but the readiness marker at \
                         {marker_path} could not be written: {err}"
                    );
                    return ExitCode::from(1);
                }
                eprintln!(
                    "ferrum-cni: cleanup complete on this node; holding so the release \
                     hook can observe readiness"
                );
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            }
        }
    }

    /// `ferrum-cni uninstall-status` — readiness probe for the cleanup hook.
    fn run_uninstall_status() -> ExitCode {
        match lifecycle::ready_marker_path_from_env() {
            Ok(marker_path) if lifecycle::ready_marker_present(&marker_path) => ExitCode::SUCCESS,
            Ok(_) => ExitCode::from(1),
            Err(err) => {
                eprintln!("ferrum-cni: {err}");
                ExitCode::from(1)
            }
        }
    }

    /// `ferrum-cni await-cleanup` — the completion boundary for the Helm
    /// pre-delete phase.
    ///
    /// Helm's hook wait only watches `Job` and `Pod` kinds, so a hook
    /// DaemonSet alone would be fire-and-forget and the release could be torn
    /// down while cleanup was still starting on some nodes. This runs as a
    /// later-weighted hook Job, blocks until every cleanup pod is Ready, and
    /// then deletes the cleanup DaemonSet and confirms it is gone — the
    /// DaemonSet carries no `hook-succeeded` policy precisely so that a
    /// failure here leaves it, and its logs, in place for the retry.
    fn run_await_cleanup() -> ExitCode {
        let config = match CleanupWaitConfig::from_env() {
            Ok(config) => config,
            Err(err) => {
                eprintln!("ferrum-cni: cleanup wait could not start: {err}");
                return ExitCode::from(1);
            }
        };
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                eprintln!("ferrum-cni: could not start the cleanup wait runtime: {err}");
                return ExitCode::from(1);
            }
        };
        match runtime.block_on(lifecycle::run_cleanup_phase(&config)) {
            Ok(report) => {
                eprintln!(
                    "ferrum-cni: CNI cleanup completed on {} of {} scheduled nodes",
                    report.ready, report.desired
                );
                ExitCode::SUCCESS
            }
            Err(message) => {
                eprintln!("ferrum-cni: {message}");
                ExitCode::from(1)
            }
        }
    }

    /// `ferrum-cni rollback-watch` — remove this generation's artifacts when
    /// the node-agent never reaches CNI readiness.
    fn run_rollback_watch() -> ExitCode {
        let config = match RollbackWatchConfig::from_env() {
            Ok(config) => config,
            Err(err) => {
                eprintln!("ferrum-cni: rollback watch could not start: {err}");
                return ExitCode::from(1);
            }
        };
        eprintln!(
            "ferrum-cni: waiting for this generation's chained configuration to be published \
             (budget {}s), then for node-agent CNI readiness (budget {}s, poll {}s)",
            config.publish_timeout.as_secs(),
            config.ready_timeout.as_secs(),
            config.poll_interval.as_secs()
        );
        let mut probe = || probe_node_agent_status(&config);
        match lifecycle::run_rollback_watch(&config, &mut probe) {
            Ok(RollbackWatchOutcome::Ready) => {
                eprintln!(
                    "ferrum-cni: node-agent reached CNI readiness; retaining the chained \
                     configuration for the lifetime of this pod"
                );
                loop {
                    std::thread::sleep(Duration::from_secs(3600));
                }
            }
            Ok(RollbackWatchOutcome::NeverPublished) => {
                // Nothing was removed because nothing was ever chained: an
                // installer that never published a conflist never made this
                // node depend on the node-agent. Still a failed pod, so this
                // stays visibly non-zero.
                eprintln!(
                    "ferrum-cni: this generation never published a chained CNI configuration \
                     within {}s, so pod creation on this node never depended on the node-agent \
                     and nothing was removed. Inspect the installer init container.",
                    config.publish_timeout.as_secs()
                );
                ExitCode::from(1)
            }
            Ok(RollbackWatchOutcome::RolledBack(report)) => {
                eprintln!(
                    "ferrum-cni: node-agent did not reach CNI readiness within {}s; rolling \
                     back this install generation's CNI artifacts",
                    config.ready_timeout.as_secs()
                );
                for line in report.summary_lines() {
                    eprintln!("ferrum-cni: {line}");
                }
                eprintln!(
                    "ferrum-cni: the chained configuration is gone, so pod creation on this \
                     node no longer depends on the node-agent; enrollment falls back to the \
                     kube-rs watcher. Any artifact reported above as retained was left in \
                     place on purpose. Recreate the node-agent pod to reinstall the chain \
                     once the underlying failure is fixed."
                );
                ExitCode::from(1)
            }
            Ok(RollbackWatchOutcome::Superseded(report)) => {
                // A newer install owns the artifacts now. Deleting nothing is
                // the correct outcome, and claiming a rollback happened would
                // be a lie about the node's state.
                eprintln!(
                    "ferrum-cni: a newer install generation owns the CNI artifacts on this \
                     node; this watcher removed nothing and the chained configuration is \
                     still in place under the newer generation's ownership."
                );
                for line in report.summary_lines() {
                    eprintln!("ferrum-cni: {line}");
                }
                ExitCode::from(1)
            }
            Ok(RollbackWatchOutcome::RollbackIncomplete(report)) => {
                eprintln!(
                    "ferrum-cni: rollback did NOT clear the chained CNI configuration. Pod \
                     creation on this node still traverses ferrum-cni. Inspect the file \
                     reported below and remove it manually once you have confirmed it is the \
                     Ferrum-generated chain; the primary CNI configuration it chains behind \
                     was never modified and needs no repair."
                );
                for line in report.summary_lines() {
                    eprintln!("ferrum-cni: {line}");
                }
                ExitCode::from(1)
            }
            Err(err) => {
                eprintln!("ferrum-cni: rollback failed: {err}");
                ExitCode::from(1)
            }
        }
    }

    fn handle_status(net_config: &CniNetConfig) -> ExitCode {
        let cni_version = net_config.cni_version.clone();
        if !cni_version_supports_status(&cni_version) {
            // Fail closed: older negotiated versions keep ADD/DEL/CHECK only.
            return emit_error(&cni_version, &CniError::UnsupportedVersion);
        }

        // STATUS is readiness-only. Attachment-specific reserved fields are
        // protocol-malformed for this verb.
        if net_config.valid_attachments.is_some() {
            return emit_error(
                &cni_version,
                &CniError::BadConfig(
                    "STATUS request must not carry cni.dev/valid-attachments".to_string(),
                ),
            );
        }
        if net_config
            .extra
            .keys()
            .any(|key| key.starts_with("cni.dev/"))
        {
            return emit_error(
                &cni_version,
                &CniError::BadConfig(
                    "unsupported reserved cni.dev/ field in STATUS request".to_string(),
                ),
            );
        }

        let socket_path = match cni_socket_path(net_config) {
            Ok(path) => path,
            Err(err) => return emit_error(&cni_version, &err),
        };

        let request = CniRpcRequest {
            verb: RpcVerb::Status,
            network_name: net_config.name.clone(),
            pod_namespace: String::new(),
            pod_name: String::new(),
            pod_uid: None,
            container_id: String::new(),
            ifname: None,
            netns_path: None,
            valid_attachments: Vec::new(),
        };

        if let Err(reason) = request.validate() {
            return emit_error(&cni_version, &CniError::BadConfig(reason));
        }

        match send_rpc(&socket_path, &request, rpc_timeout()) {
            // SPEC: STATUS success is exit 0 with no required stdout payload.
            Ok(CniRpcResponse::Ok) => emit_empty_success(),
            Ok(CniRpcResponse::Rejected { .. }) | Ok(CniRpcResponse::Error { .. }) => {
                // Do not echo node-agent reason strings that could carry
                // hostile input; STATUS only needs the availability code.
                emit_error(
                    &cni_version,
                    &CniError::NotAvailable("node-agent is not ready".to_string()),
                )
            }
            Err(_) => {
                // Socket missing / connect / framing failure: the dependency
                // daemon is unavailable for ADD. Avoid echoing socket paths
                // or raw IO detail into the CNI error msg.
                emit_error(
                    &cni_version,
                    &CniError::NotAvailable("node-agent is unavailable".to_string()),
                )
            }
        }
    }

    fn handle_gc(net_config: &CniNetConfig) -> ExitCode {
        let cni_version = net_config.cni_version.clone();
        if !cni_version_supports_gc(&cni_version) {
            // Fail closed: older negotiated versions keep ADD/DEL/CHECK only.
            return emit_error(&cni_version, &CniError::UnsupportedVersion);
        }

        if net_config
            .extra
            .keys()
            .any(|key| key.starts_with("cni.dev/"))
        {
            return emit_error(
                &cni_version,
                &CniError::BadConfig(
                    "unsupported reserved cni.dev/ field in GC request".to_string(),
                ),
            );
        }
        let Some(runtime_attachments) = net_config.valid_attachments.clone() else {
            return emit_error(
                &cni_version,
                &CniError::BadConfig("GC request is missing cni.dev/valid-attachments".to_string()),
            );
        };
        let valid_attachments = match ingest_valid_attachments(runtime_attachments) {
            Ok(attachments) => attachments,
            Err(err) => return emit_error(&cni_version, &err),
        };

        let socket_path = match cni_socket_path(net_config) {
            Ok(path) => path,
            Err(err) => return emit_error(&cni_version, &err),
        };

        let request = CniRpcRequest {
            verb: RpcVerb::Gc,
            network_name: net_config.name.clone(),
            pod_namespace: String::new(),
            pod_name: String::new(),
            pod_uid: None,
            container_id: String::new(),
            ifname: None,
            netns_path: None,
            valid_attachments,
        };

        if let Err(reason) = request.validate() {
            return emit_error(&cni_version, &CniError::BadConfig(reason));
        }

        match send_rpc(&socket_path, &request, rpc_timeout()) {
            // SPEC: GC success emits no stdout payload.
            Ok(CniRpcResponse::Ok) => emit_empty_success(),
            Ok(CniRpcResponse::Rejected { reason }) => {
                emit_error(&cni_version, &CniError::Rejected(reason))
            }
            Ok(CniRpcResponse::Error { reason }) => {
                emit_error(&cni_version, &CniError::IpcFailed(reason))
            }
            Err(err) => emit_error(&cni_version, &err),
        }
    }

    fn handle_verb(
        command: CniCommand,
        net_config: &CniNetConfig,
        invocation: &CniInvocation,
    ) -> ExitCode {
        let cni_version = net_config.cni_version.clone();
        let args_map = match invocation.args.as_deref() {
            Some(raw) => match ingest_cni_args(raw) {
                Ok(args) => args,
                Err(err) => return emit_error(&cni_version, &err),
            },
            None => Default::default(),
        };
        let identity = match K8sPodIdentity::from_args(&args_map) {
            Some(id) => id,
            None => {
                return emit_error(
                    &cni_version,
                    &CniError::BadConfig(
                        "CNI_ARGS missing K8S_POD_NAMESPACE / K8S_POD_NAME".to_string(),
                    ),
                );
            }
        };

        let verb = match command {
            CniCommand::Add => RpcVerb::Add,
            CniCommand::Del => RpcVerb::Del,
            CniCommand::Check => RpcVerb::Check,
            _ => return emit_error(&cni_version, &CniError::UnsupportedCommand),
        };

        let socket_path = match cni_socket_path(net_config) {
            Ok(path) => path,
            Err(err) => return emit_error(&cni_version, &err),
        };

        let request = CniRpcRequest {
            verb,
            network_name: net_config.name.clone(),
            pod_namespace: identity.namespace,
            pod_name: identity.name,
            pod_uid: identity.pod_uid,
            container_id: invocation.container_id.clone(),
            ifname: invocation.ifname.clone(),
            netns_path: invocation.netns.clone(),
            valid_attachments: Vec::new(),
        };

        if let Err(reason) = request.validate() {
            return emit_error(&cni_version, &CniError::BadConfig(reason));
        }

        match send_rpc(&socket_path, &request, rpc_timeout()) {
            Ok(CniRpcResponse::Ok) => match command {
                CniCommand::Del => emit_empty_success(),
                _ => emit_success(&cni_version, net_config.prev_result.as_ref()),
            },
            Ok(CniRpcResponse::Rejected { reason }) => {
                eprintln!("ferrum-cni: node-agent rejected enrollment: {reason}");
                match command {
                    CniCommand::Check => emit_error(&cni_version, &CniError::Rejected(reason)),
                    CniCommand::Del => emit_empty_success(),
                    _ => emit_success(&cni_version, net_config.prev_result.as_ref()),
                }
            }
            Ok(CniRpcResponse::Error { reason }) => {
                emit_error(&cni_version, &CniError::IpcFailed(reason))
            }
            Err(err) => match command {
                // DEL must not block pod teardown when the node-agent is absent.
                // Stale Ferrum state is reclaimed by CNI GC and node-agent sweeps.
                CniCommand::Del => {
                    log_del_ipc_transport_failure(&err);
                    emit_empty_success()
                }
                // CHECK cannot verify attachment without the node-agent (CNI spec).
                _ => emit_error(&cni_version, &err),
            },
        }
    }

    /// Log a redacted, actionable DEL transport-failure diagnostic. Must not
    /// echo socket paths, request fields, or other untrusted IPC detail.
    fn log_del_ipc_transport_failure(err: &CniError) {
        let category = match err {
            CniError::IpcFailed(msg) if msg.starts_with("connect failed:") => {
                "node-agent socket missing or connect refused"
            }
            CniError::IpcFailed(msg) if msg.contains("TimedOut") || msg.contains("timeout") => {
                "node-agent RPC timed out"
            }
            CniError::IpcFailed(_) => "node-agent IPC failed",
            _ => "node-agent unavailable",
        };
        eprintln!(
            "ferrum-cni: {category}; treating DEL as idempotent success so \
             kubelet can finish pod teardown. Stale Ferrum capture state is \
             reclaimed by CNI GC and node-agent sweeps. Restart or recreate the \
             node-agent pod if immediate cleanup is required."
        );
    }

    fn rpc_timeout() -> Duration {
        DEFAULT_RPC_TIMEOUT
    }

    fn cni_socket_path(net_config: &CniNetConfig) -> Result<String, CniError> {
        let path = net_config
            .ferrum
            .as_ref()
            .and_then(|f| f.socket_path.clone())
            .unwrap_or_else(|| DEFAULT_CNI_SOCKET_PATH.to_string());
        if !is_safe_cni_netns_path(&path) {
            return Err(CniError::BadConfig(
                "invalid Ferrum CNI socket path".to_string(),
            ));
        }
        Ok(path)
    }

    fn emit_version(cni_version: &str) -> ExitCode {
        let payload = serde_json::json!({
            "cniVersion": cni_version,
            "supportedVersions": SUPPORTED_CNI_VERSIONS,
        });
        write_stdout(&payload);
        ExitCode::SUCCESS
    }

    fn emit_success(cni_version: &str, prev_result: Option<&serde_json::Value>) -> ExitCode {
        let result = CniSuccessResult::passthrough(cni_version, prev_result);
        match serde_json::to_string(&result) {
            Ok(json) => {
                let _ = std::io::stdout().write_all(json.as_bytes());
                let _ = std::io::stdout().write_all(b"\n");
            }
            Err(_err) => return ExitCode::from(1),
        }
        ExitCode::SUCCESS
    }

    fn emit_empty_success() -> ExitCode {
        ExitCode::SUCCESS
    }

    fn emit_error(cni_version: &str, err: &CniError) -> ExitCode {
        let payload = build_error_result(cni_version, err);
        match serde_json::to_string(&payload) {
            Ok(json) => {
                let _ = std::io::stdout().write_all(json.as_bytes());
                let _ = std::io::stdout().write_all(b"\n");
            }
            Err(serde_err) => {
                let _ = std::io::stderr().write_all(
                    format!("ferrum-cni: failed to serialize CNI error result: {serde_err}\n")
                        .as_bytes(),
                );
                let _ = std::io::stdout().write_all(
                    br#"{"cniVersion":"0.4.0","code":11,"msg":"internal serialization failure"}"#,
                );
                let _ = std::io::stdout().write_all(b"\n");
            }
        }
        ExitCode::from(1)
    }

    fn write_stdout(payload: &serde_json::Value) {
        if let Ok(json) = serde_json::to_string(payload) {
            let _ = std::io::stdout().write_all(json.as_bytes());
            let _ = std::io::stdout().write_all(b"\n");
        }
    }
}

#[cfg(unix)]
fn main() -> std::process::ExitCode {
    cni_main::run()
}

/// On macOS / Windows the binary still compiles so the CI matrix is uniform,
/// but invoking it as a CNI plugin makes no sense. Print a short message
/// and exit 1 — kubelet only ever runs this binary on Linux nodes.
#[cfg(not(unix))]
fn main() -> std::process::ExitCode {
    eprintln!(
        "ferrum-cni: CNI plugins run on Linux only; this is a non-Unix build for matrix parity"
    );
    std::process::ExitCode::from(1)
}
