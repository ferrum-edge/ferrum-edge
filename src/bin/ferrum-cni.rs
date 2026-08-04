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
//! - Both binaries live in the same docker image. Helm's install
//!   init-container copies `ferrum-cni` out of `/usr/local/bin/`
//!   on the node-agent image into the host's `/opt/cni/bin/`.
//! - cargo's `[[bin]]` targets compile against the parent crate's
//!   `lib.rs`, so this file is intentionally tiny.
//!
//! Stub on non-Linux: CNI is a Linux concept. macOS/Windows builds
//! print an error and exit 1 so the binary target compiles in the CI
//! matrix without requiring conditional compilation in `Cargo.toml`.

#[cfg(unix)]
mod cni_main {
    use std::io::Write;
    use std::process::ExitCode;
    use std::time::Duration;

    use ferrum_edge::cni::client::{DEFAULT_RPC_TIMEOUT, send_rpc};
    use ferrum_edge::cni::install;
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
        if std::env::args().nth(1).as_deref() == Some("install") {
            return match install::install_from_env() {
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
            };
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
            args: Default::default(),
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
            args: Default::default(),
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
            args: args_map,
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
            Err(err) => emit_error(&cni_version, &err),
        }
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
