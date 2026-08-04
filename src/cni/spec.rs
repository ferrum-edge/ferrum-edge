//! Minimal CNI specification types (stdin JSON + `CNI_*` env vars + stdout
//! JSON).
//!
//! We implement the CNI spec on the wire directly rather than vendoring a
//! library because Ferrum's CNI surface is intentionally narrow — we chain
//! behind the cluster's primary CNI (which already does IP allocation,
//! interface setup, etc.) and only need the ADD/DEL/CHECK/STATUS/GC lifecycle
//! hook so the node-agent can enroll pods into eBPF capture deterministically
//! at sandbox setup time, instead of racing the kube-rs watcher.
//!
//! Spec reference: <https://github.com/containernetworking/cni/blob/spec-v1.1.0/SPEC.md>
//! (we target v0.4.0+ for ADD/DEL/CHECK; STATUS and GC require CNI 1.1.0).

use std::collections::{HashMap, HashSet};
use std::env;
use std::str::FromStr;

use serde::{Deserialize, Serialize};

/// Hard cap on `cni.dev/valid-attachments` entries accepted for one GC call.
/// Large enough for dense nodes; small enough to keep reconciliation bounded.
pub const MAX_CNI_GC_ATTACHMENTS: usize = 8192;

/// Per-field byte cap for GC attachment `containerID` / `ifname` values.
pub const MAX_CNI_ATTACHMENT_FIELD_BYTES: usize = 256;

/// Maximum byte length accepted for a CNI network name.
pub const MAX_CNI_NETWORK_NAME_BYTES: usize = 256;

/// Maximum byte length accepted for a network-namespace path.
pub const MAX_CNI_NETNS_PATH_BYTES: usize = 4096;

/// Explicit CNI_ARGS resource limits before values cross the local RPC.
pub const MAX_CNI_ARGS_BYTES: usize = 16 * 1024;
pub const MAX_CNI_ARGS_ENTRIES: usize = 64;
pub const MAX_CNI_ARG_FIELD_BYTES: usize = 1024;

/// Hard cap on CNI stdin JSON size. Prevents hostile kubelet/runtime input
/// from forcing unbounded allocation into the short-lived plugin process.
pub const MAX_CNI_STDIN_BYTES: usize = 512 * 1024;

/// CNI versions Ferrum advertises via VERSION and accepts for lifecycle verbs.
pub const SUPPORTED_CNI_VERSIONS: &[&str] = &["0.3.0", "0.3.1", "0.4.0", "1.0.0", "1.1.0"];

/// The CNI command verb supplied via the `CNI_COMMAND` environment variable.
///
/// Ferrum implements the pod-lifecycle verbs (ADD/DEL/CHECK) plus STATUS and
/// GC on CNI 1.1.0 configurations. VERSION is the negotiation handshake
/// handled inline by the binary. Unknown verbs map to
/// [`CniCommand::Unsupported`] so the binary can emit a structured error
/// result and exit with code 4 per the spec's error-code table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CniCommand {
    Add,
    Del,
    Check,
    Status,
    Gc,
    Version,
    Unsupported,
}

impl CniCommand {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Add => "ADD",
            Self::Del => "DEL",
            Self::Check => "CHECK",
            Self::Status => "STATUS",
            Self::Gc => "GC",
            Self::Version => "VERSION",
            Self::Unsupported => "UNSUPPORTED",
        }
    }
}

impl FromStr for CniCommand {
    type Err = ();

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        Ok(match s.trim().to_ascii_uppercase().as_str() {
            "ADD" => Self::Add,
            "DEL" => Self::Del,
            "CHECK" => Self::Check,
            "STATUS" => Self::Status,
            "GC" => Self::Gc,
            "VERSION" => Self::Version,
            _ => Self::Unsupported,
        })
    }
}

/// Returns true when `version` is in [`SUPPORTED_CNI_VERSIONS`].
pub fn is_supported_cni_version(version: &str) -> bool {
    SUPPORTED_CNI_VERSIONS
        .iter()
        .any(|supported| *supported == version.trim())
}

/// STATUS and GC are defined by CNI 1.1.0. Older negotiated versions keep
/// ADD/DEL/CHECK only and must fail closed on those verbs rather than
/// advertising incomplete 1.1 protocol support.
pub fn cni_version_supports_status(version: &str) -> bool {
    version.trim() == "1.1.0"
}

/// GC is defined by CNI 1.1.0. Older negotiated versions keep ADD/DEL/CHECK
/// only and must fail closed on GC rather than silently ignoring stale state.
pub fn cni_version_supports_gc(version: &str) -> bool {
    cni_version_supports_status(version)
}

/// Parsed CNI invocation environment as defined by SPEC §2.1 (Parameters).
///
/// The kubelet sets each of these per invocation; we read them all up front
/// so the rest of the CNI binary works on a normalized in-memory shape
/// instead of poking `std::env` repeatedly. `cni_args` is the raw
/// semicolon-separated form (e.g. `K8S_POD_NAMESPACE=foo;K8S_POD_NAME=bar`)
/// — see [`parse_cni_args`] for the parsed map.
///
/// STATUS, GC, and VERSION do not carry attachment parameters; those
/// commands leave `container_id` empty and optional fields unset.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CniInvocation {
    pub command: CniCommand,
    pub container_id: String,
    pub netns: Option<String>,
    pub ifname: Option<String>,
    pub args: Option<String>,
    pub path: Option<String>,
}

impl CniInvocation {
    pub fn command_from_env() -> Result<CniCommand, CniError> {
        env::var("CNI_COMMAND")
            .map_err(|_| CniError::missing_env("CNI_COMMAND"))?
            .parse::<CniCommand>()
            .map_err(|_| CniError::missing_env("CNI_COMMAND"))
    }

    /// Read the CNI invocation from `std::env`.
    ///
    /// Empty `CNI_NETNS` is normalized to `None`; the spec allows DEL to
    /// pass an empty netns when the sandbox is already gone, and treating
    /// `""` and unset identically here saves the node-agent server from
    /// having to do the same dance.
    pub fn from_env() -> Result<Self, CniError> {
        let command = Self::command_from_env()?;
        Self::from_env_for_command(command)
    }

    pub fn from_env_for_command(command: CniCommand) -> Result<Self, CniError> {
        match command {
            CniCommand::Version => Ok(Self {
                command,
                container_id: String::new(),
                netns: None,
                ifname: None,
                args: None,
                path: env::var("CNI_PATH").ok().filter(|v| !v.trim().is_empty()),
            }),
            CniCommand::Status => {
                // SPEC §2 STATUS: only CNI_COMMAND is required. CNI_PATH is
                // optional. Attachment parameters are not part of STATUS.
                Ok(Self {
                    command,
                    container_id: String::new(),
                    netns: None,
                    ifname: None,
                    args: None,
                    path: env::var("CNI_PATH").ok().filter(|v| !v.trim().is_empty()),
                })
            }
            CniCommand::Gc => {
                // SPEC §2 GC: only CNI_COMMAND + CNI_PATH are required; there
                // are no attachment parameters.
                let path = env::var("CNI_PATH").map_err(|_| CniError::missing_env("CNI_PATH"))?;
                if path.trim().is_empty() {
                    return Err(CniError::missing_env("CNI_PATH"));
                }
                Ok(Self {
                    command,
                    container_id: String::new(),
                    netns: None,
                    ifname: None,
                    args: None,
                    path: Some(path),
                })
            }
            CniCommand::Unsupported => Ok(Self {
                command,
                container_id: String::new(),
                netns: None,
                ifname: None,
                args: None,
                path: None,
            }),
            CniCommand::Add | CniCommand::Del | CniCommand::Check => {
                let container_id = env::var("CNI_CONTAINERID")
                    .map_err(|_| CniError::missing_env("CNI_CONTAINERID"))?;
                if !is_safe_cni_container_id(&container_id)
                    || container_id.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES
                {
                    return Err(CniError::missing_env("CNI_CONTAINERID"));
                }
                let netns = env::var("CNI_NETNS").ok().filter(|v| !v.trim().is_empty());
                if matches!(command, CniCommand::Add | CniCommand::Check) && netns.is_none() {
                    return Err(CniError::missing_env("CNI_NETNS"));
                }
                if netns
                    .as_deref()
                    .is_some_and(|path| !is_safe_cni_netns_path(path))
                {
                    return Err(CniError::missing_env("CNI_NETNS"));
                }
                let ifname = env::var("CNI_IFNAME").ok().filter(|v| !v.trim().is_empty());
                if !ifname.as_deref().is_some_and(is_safe_cni_ifname) {
                    return Err(CniError::missing_env("CNI_IFNAME"));
                }
                let args = env::var("CNI_ARGS").ok().filter(|v| !v.trim().is_empty());
                let path = env::var("CNI_PATH").ok().filter(|v| !v.trim().is_empty());
                Ok(Self {
                    command,
                    container_id,
                    netns,
                    ifname,
                    args,
                    path,
                })
            }
        }
    }
}

/// Parse `CNI_ARGS` into a key/value map.
///
/// The wire format is `K=V;K=V;...`. Tokens with no `=` are skipped (the
/// spec is loose about that); empty values are kept (kubelet sometimes
/// passes `IgnoreUnknown=1;K8S_POD_NAME=`). Keys are normalized to
/// uppercase so `K8S_POD_NAMESPACE` and `k8s_pod_namespace` collapse to
/// the same entry — kubelets in the wild are inconsistent.
pub fn parse_cni_args(raw: &str) -> HashMap<String, String> {
    raw.split(';')
        .filter_map(|kv| {
            let (k, v) = kv.split_once('=')?;
            let key = k.trim().to_ascii_uppercase();
            if key.is_empty() {
                return None;
            }
            Some((key, v.trim().to_string()))
        })
        .collect()
}

/// Strict, bounded CNI_ARGS ingestion for the executable boundary.
///
/// Duplicate keys are rejected after case normalization so pod identity cannot
/// depend on first-wins versus last-wins interpretation.
pub fn ingest_cni_args(raw: &str) -> Result<HashMap<String, String>, CniError> {
    if raw.len() > MAX_CNI_ARGS_BYTES {
        return Err(CniError::BadConfig(format!(
            "CNI_ARGS exceeds {MAX_CNI_ARGS_BYTES} byte cap"
        )));
    }
    let mut args = HashMap::new();
    let mut tokens = raw.split(';').peekable();
    while let Some(token) = tokens.next() {
        if token.is_empty() {
            if tokens.peek().is_none() {
                // Some runtimes emit one harmless trailing delimiter.
                continue;
            }
            return Err(CniError::BadConfig(
                "CNI_ARGS contains a malformed key-value token".to_string(),
            ));
        }
        let Some((raw_key, value)) = token.split_once('=') else {
            return Err(CniError::BadConfig(
                "CNI_ARGS contains a malformed key-value token".to_string(),
            ));
        };
        let trimmed_key = raw_key.trim();
        if raw_key != trimmed_key {
            return Err(CniError::BadConfig(
                "CNI_ARGS contains an invalid or oversized field".to_string(),
            ));
        }
        let key = trimmed_key.to_ascii_uppercase();
        let value = value.trim();
        if !is_safe_cni_arg_key(&key)
            || key.len() > MAX_CNI_ARG_FIELD_BYTES
            || value.len() > MAX_CNI_ARG_FIELD_BYTES
            || value.chars().any(char::is_control)
        {
            return Err(CniError::BadConfig(
                "CNI_ARGS contains an invalid or oversized field".to_string(),
            ));
        }
        if args.len() >= MAX_CNI_ARGS_ENTRIES {
            return Err(CniError::BadConfig(format!(
                "CNI_ARGS exceeds {MAX_CNI_ARGS_ENTRIES} entry cap"
            )));
        }
        if args.insert(key, value.to_string()).is_some() {
            return Err(CniError::BadConfig(
                "CNI_ARGS contains a duplicate key".to_string(),
            ));
        }
    }
    Ok(args)
}

fn is_safe_cni_arg_key(key: &str) -> bool {
    !key.is_empty()
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'-'))
}

/// Extracted Kubernetes pod identity from CNI_ARGS.
///
/// kubelet always supplies `K8S_POD_NAMESPACE`, `K8S_POD_NAME`,
/// `K8S_POD_UID`, and `K8S_POD_INFRA_CONTAINER_ID` per CNI conventions.
/// `K8S_POD_UID` was added later than the others and is occasionally
/// missing on older CRIs; the wire surface to the node-agent treats it as
/// optional so older clusters still get a working ADD/DEL round-trip.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct K8sPodIdentity {
    pub namespace: String,
    pub name: String,
    pub pod_uid: Option<String>,
    pub infra_container_id: Option<String>,
}

impl K8sPodIdentity {
    /// Pull pod identity out of a parsed `CNI_ARGS` map. Returns `None` when
    /// the namespace+name pair is missing (we cannot enroll a pod whose
    /// identity we don't know).
    pub fn from_args(args: &HashMap<String, String>) -> Option<Self> {
        let namespace = args.get("K8S_POD_NAMESPACE")?.clone();
        let name = args.get("K8S_POD_NAME")?.clone();
        if namespace.is_empty() || name.is_empty() {
            return None;
        }
        let pod_uid = args.get("K8S_POD_UID").cloned().filter(|v| !v.is_empty());
        let infra_container_id = args
            .get("K8S_POD_INFRA_CONTAINER_ID")
            .cloned()
            .filter(|v| !v.is_empty());
        Some(Self {
            namespace,
            name,
            pod_uid,
            infra_container_id,
        })
    }
}

/// CNI network configuration JSON passed on stdin.
///
/// We accept the full shape but only inspect the fields we care about
/// (cniVersion, type, name, prevResult, valid attachments for GC).
/// `prevResult` is the chained CNI's output from the previous plugin in the
/// conflist — Ferrum passes it through verbatim on ADD so the next plugin
/// (if any) sees the same shape, and so the kubelet sees the IP/interface
/// allocation the primary CNI made. We do NOT mutate prevResult.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniNetConfig {
    #[serde(rename = "cniVersion", default = "default_cni_version")]
    pub cni_version: String,
    pub name: String,
    #[serde(rename = "type")]
    pub plugin_type: String,
    #[serde(
        rename = "prevResult",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub prev_result: Option<serde_json::Value>,
    /// Optional Ferrum-specific tuning carried on the conflist entry.
    /// Defaults to `Default` when missing.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ferrum: Option<FerrumCniOptions>,
    /// Still-valid attachments supplied on GC (CNI 1.1
    /// `cni.dev/valid-attachments`).
    ///
    /// `None` is distinct from an explicitly empty list: the specification
    /// requires the runtime-generated key on GC, and treating omission as an
    /// empty authoritative set would widen cleanup on malformed requests.
    #[serde(
        rename = "cni.dev/valid-attachments",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub valid_attachments: Option<Vec<CniValidAttachment>>,
    /// Pass-through for any conflist fields we don't model explicitly
    /// (chained plugins may add fields kubelet round-trips). Preserving
    /// them keeps Ferrum invisible to neighbour plugins.
    #[serde(flatten)]
    pub extra: HashMap<String, serde_json::Value>,
}

fn default_cni_version() -> String {
    "0.4.0".to_string()
}

/// One still-valid CNI attachment from a GC request (`containerID`, `ifname`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
#[serde(deny_unknown_fields)]
pub struct CniValidAttachment {
    #[serde(rename = "containerID")]
    pub container_id: String,
    pub ifname: String,
}

impl CniValidAttachment {
    /// Validate field shape and reject hostile path-like values.
    pub fn validate(&self) -> Result<(), CniError> {
        validate_attachment_field("containerID", &self.container_id)?;
        validate_attachment_field("ifname", &self.ifname)?;
        if !is_safe_cni_container_id(&self.container_id) {
            return Err(CniError::BadConfig(
                "containerID is not a valid CNI container id".to_string(),
            ));
        }
        if !is_safe_cni_ifname(&self.ifname) {
            return Err(CniError::BadConfig(
                "ifname is not a valid CNI interface name".to_string(),
            ));
        }
        Ok(())
    }
}

fn validate_attachment_field(field: &str, value: &str) -> Result<(), CniError> {
    if value.is_empty() {
        return Err(CniError::BadConfig(format!(
            "cni.dev/valid-attachments entry missing {field}"
        )));
    }
    if value.len() > MAX_CNI_ATTACHMENT_FIELD_BYTES {
        return Err(CniError::BadConfig(format!(
            "{field} exceeds {MAX_CNI_ATTACHMENT_FIELD_BYTES} byte cap"
        )));
    }
    if value.contains('\0') || value.contains('/') || value.contains('\\') {
        return Err(CniError::BadConfig(format!(
            "{field} contains forbidden path or NUL characters"
        )));
    }
    Ok(())
}

/// CNI container IDs must start with an alphanumeric character and continue
/// with alphanumerics, `_`, `.`, or `-` (SPEC §2).
pub fn is_safe_cni_container_id(value: &str) -> bool {
    let mut chars = value.chars();
    let Some(first) = chars.next() else {
        return false;
    };
    if !first.is_ascii_alphanumeric() {
        return false;
    }
    chars.all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-')
}

/// Interface names are short host identifiers; reject separators and control
/// bytes so GC matching cannot be steered by path-like input.
pub fn is_safe_cni_ifname(value: &str) -> bool {
    if value.is_empty() || value.len() > 15 {
        return false;
    }
    value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '.' || c == '-' || c == '@')
}

/// CNI network names use the same safe grammar as container IDs and are
/// additionally bounded before they cross the node-agent RPC boundary.
pub fn is_safe_cni_network_name(value: &str) -> bool {
    value.len() <= MAX_CNI_NETWORK_NAME_BYTES && is_safe_cni_container_id(value)
}

/// Validate a network-namespace path without touching the filesystem.
///
/// Runtimes may use different absolute roots, so the boundary checks shape,
/// length, NULs, and parent traversal rather than pinning one host prefix.
pub fn is_safe_cni_netns_path(value: &str) -> bool {
    use std::path::{Component, Path};

    if value.is_empty()
        || value.len() > MAX_CNI_NETNS_PATH_BYTES
        || value.chars().any(char::is_control)
    {
        return false;
    }
    let path = Path::new(value);
    path.is_absolute()
        && !path
            .components()
            .any(|component| matches!(component, Component::ParentDir))
}

/// Bound, validate, and dedupe a GC valid-attachment list. Fail closed on
/// oversized or hostile input rather than partially applying GC.
pub fn ingest_valid_attachments(
    attachments: Vec<CniValidAttachment>,
) -> Result<Vec<CniValidAttachment>, CniError> {
    if attachments.len() > MAX_CNI_GC_ATTACHMENTS {
        return Err(CniError::BadConfig(format!(
            "cni.dev/valid-attachments has {} entries; cap is {MAX_CNI_GC_ATTACHMENTS}",
            attachments.len()
        )));
    }
    let mut seen = HashSet::with_capacity(attachments.len());
    let mut out = Vec::with_capacity(attachments.len());
    for attachment in attachments {
        attachment.validate()?;
        if seen.insert((attachment.container_id.clone(), attachment.ifname.clone())) {
            out.push(attachment);
        }
    }
    Ok(out)
}

/// Read stdin with a hard byte cap so GC (and other verbs) cannot force
/// unbounded allocation from hostile input.
pub fn read_stdin_bounded(max_bytes: usize) -> Result<String, CniError> {
    use std::io::Read;
    let mut limited =
        std::io::stdin().take(u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX));
    let mut buf = Vec::new();
    limited
        .read_to_end(&mut buf)
        .map_err(|err| CniError::BadConfig(format!("read stdin: {err}")))?;
    if buf.len() > max_bytes {
        return Err(CniError::BadConfig(format!(
            "stdin exceeds {max_bytes} byte cap"
        )));
    }
    String::from_utf8(buf).map_err(|err| CniError::BadConfig(format!("stdin is not UTF-8: {err}")))
}

/// Plugin-specific options the operator may set on the chained conflist
/// entry. Kept narrow on purpose — the Helm chart writes a Ferrum-owned
/// conflist that the operator generally should not edit; this exists so
/// downstream operators chaining Ferrum manually can override the UDS
/// path without rebuilding the binary.
#[derive(Debug, Clone, Default, Serialize, Deserialize, PartialEq, Eq)]
pub struct FerrumCniOptions {
    /// Override the default Unix socket path the node-agent listens on.
    /// When unset the binary falls back to
    /// [`crate::ebpf::DEFAULT_NODE_AGENT_SOCKET_PATH`]'s sibling
    /// `node-agent-cni.sock`. Operators rarely need to set this.
    #[serde(
        rename = "socketPath",
        default,
        skip_serializing_if = "Option::is_none"
    )]
    pub socket_path: Option<String>,
}

/// CNI result returned on stdout for ADD/CHECK.
///
/// Ferrum is a chained "meta-plugin" that does NOT allocate IPs or
/// interfaces of its own — those come from the primary CNI (Calico,
/// Cilium, etc.). On ADD we pass `prevResult` allocation fields through
/// while dropping its nested `cniVersion`, because the result already emits
/// a top-level `cniVersion`. On a fresh (non-chained) conflist where
/// `prevResult` is absent, we emit a minimal valid `Result` with just
/// `cniVersion` — kubelet tolerates that for meta-plugins.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniSuccessResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    #[serde(flatten)]
    pub prev_result: HashMap<String, serde_json::Value>,
}

impl CniSuccessResult {
    pub fn passthrough(cni_version: &str, prev_result: Option<&serde_json::Value>) -> Self {
        let mut prev_result: HashMap<String, serde_json::Value> = match prev_result {
            Some(serde_json::Value::Object(map)) => {
                map.iter().map(|(k, v)| (k.clone(), v.clone())).collect()
            }
            _ => HashMap::new(),
        };
        prev_result.remove("cniVersion");
        Self {
            cni_version: cni_version.to_string(),
            prev_result,
        }
    }
}

/// CNI error JSON result, written to stdout on failure. The process also
/// exits non-zero — kubelet inspects both. See SPEC §5.2.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CniErrorResult {
    #[serde(rename = "cniVersion")]
    pub cni_version: String,
    pub code: u32,
    pub msg: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub details: Option<String>,
}

/// Closed set of CNI errors the binary returns. Codes 1-99 are reserved
/// for plugin-specific errors per the spec; 1-7 are the common
/// values we map onto, and 50/51 are the CNI 1.1 STATUS availability codes.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CniError {
    #[error("required environment variable {0} is missing or invalid")]
    MissingEnv(String),
    #[error("network configuration JSON is invalid: {0}")]
    BadConfig(String),
    #[error("unsupported CNI version negotiation")]
    UnsupportedVersion,
    #[error("node-agent IPC failed: {0}")]
    IpcFailed(String),
    #[error("node-agent rejected the request: {0}")]
    Rejected(String),
    #[error("unsupported CNI command")]
    UnsupportedCommand,
    /// CNI 1.1 STATUS code 50: plugin cannot service ADD requests.
    #[error("CNI plugin is not available: {0}")]
    NotAvailable(String),
    /// CNI 1.1 STATUS code 51: unavailable and existing attachments may be
    /// degraded. Reserved for cases where Ferrum knows capture/connectivity
    /// for already-enrolled pods may also be limited.
    #[error(
        "CNI plugin is not available and existing containers may have limited connectivity: {0}"
    )]
    NotAvailableDegraded(String),
}

impl CniError {
    pub fn missing_env(var: &str) -> Self {
        Self::MissingEnv(var.to_string())
    }

    /// CNI spec error code per §5.2 of the reference container spec.
    pub fn code(&self) -> u32 {
        match self {
            Self::MissingEnv(_) | Self::UnsupportedCommand => 4,
            Self::BadConfig(_) => 7,
            Self::UnsupportedVersion => 1,
            Self::IpcFailed(_) => 11,
            Self::Rejected(_) => 12,
            Self::NotAvailable(_) => 50,
            Self::NotAvailableDegraded(_) => 51,
        }
    }
}

/// Build the response payload for a failure. The CNI binary writes this
/// to stdout AND exits non-zero so both contracts are satisfied.
pub fn build_error_result(cni_version: &str, err: &CniError) -> CniErrorResult {
    CniErrorResult {
        cni_version: cni_version.to_string(),
        code: err.code(),
        msg: err.to_string(),
        details: None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_cni_command_accepts_known_verbs() {
        assert_eq!(CniCommand::from_str("ADD"), Ok(CniCommand::Add));
        assert_eq!(CniCommand::from_str("del"), Ok(CniCommand::Del));
        assert_eq!(CniCommand::from_str("Check"), Ok(CniCommand::Check));
        assert_eq!(CniCommand::from_str("STATUS"), Ok(CniCommand::Status));
        assert_eq!(CniCommand::from_str("status"), Ok(CniCommand::Status));
        assert_eq!(CniCommand::from_str("GC"), Ok(CniCommand::Gc));
        assert_eq!(CniCommand::from_str("VERSION"), Ok(CniCommand::Version));
    }

    #[test]
    fn parse_cni_command_unknown_maps_to_unsupported() {
        assert_eq!(CniCommand::from_str("FOO"), Ok(CniCommand::Unsupported));
        assert_eq!(CniCommand::from_str("PING"), Ok(CniCommand::Unsupported));
    }

    #[test]
    fn status_and_gc_require_cni_1_1() {
        assert!(cni_version_supports_status("1.1.0"));
        assert!(!cni_version_supports_status("1.0.0"));
        assert!(!cni_version_supports_status("0.4.0"));
        assert!(cni_version_supports_gc("1.1.0"));
        assert!(!cni_version_supports_gc("1.0.0"));
        assert!(!cni_version_supports_gc("0.4.0"));
        assert!(is_supported_cni_version("1.1.0"));
        assert!(is_supported_cni_version("0.4.0"));
        assert!(!is_supported_cni_version("2.0.0"));
    }

    #[test]
    fn parse_cni_args_decodes_kv_pairs() {
        let args = parse_cni_args(
            "IgnoreUnknown=1;K8S_POD_NAMESPACE=demo;K8S_POD_NAME=alpha;K8S_POD_UID=abc-123",
        );
        assert_eq!(args.get("IGNOREUNKNOWN").map(String::as_str), Some("1"));
        assert_eq!(
            args.get("K8S_POD_NAMESPACE").map(String::as_str),
            Some("demo")
        );
        assert_eq!(args.get("K8S_POD_NAME").map(String::as_str), Some("alpha"));
        assert_eq!(args.get("K8S_POD_UID").map(String::as_str), Some("abc-123"));
    }

    #[test]
    fn parse_cni_args_ignores_malformed_tokens() {
        let args = parse_cni_args("=value;onlykey;=;K8S_POD_NAME=ok");
        assert_eq!(args.len(), 1, "only valid k=v pair should remain");
        assert_eq!(args.get("K8S_POD_NAME").map(String::as_str), Some("ok"));
    }

    #[test]
    fn k8s_identity_requires_namespace_and_name() {
        let mut args = HashMap::new();
        assert!(K8sPodIdentity::from_args(&args).is_none());
        args.insert("K8S_POD_NAMESPACE".to_string(), "demo".to_string());
        assert!(K8sPodIdentity::from_args(&args).is_none());
        args.insert("K8S_POD_NAME".to_string(), "alpha".to_string());
        let id = K8sPodIdentity::from_args(&args).expect("identity should parse");
        assert_eq!(id.namespace, "demo");
        assert_eq!(id.name, "alpha");
        assert!(id.pod_uid.is_none());
        assert!(id.infra_container_id.is_none());

        args.insert("K8S_POD_UID".to_string(), "uid-1".to_string());
        args.insert(
            "K8S_POD_INFRA_CONTAINER_ID".to_string(),
            "infra-1".to_string(),
        );
        let id = K8sPodIdentity::from_args(&args).expect("identity should parse with extras");
        assert_eq!(id.pod_uid.as_deref(), Some("uid-1"));
        assert_eq!(id.infra_container_id.as_deref(), Some("infra-1"));
    }

    #[test]
    fn k8s_identity_skips_empty_optional_fields() {
        let mut args = HashMap::new();
        args.insert("K8S_POD_NAMESPACE".to_string(), "demo".to_string());
        args.insert("K8S_POD_NAME".to_string(), "alpha".to_string());
        args.insert("K8S_POD_UID".to_string(), "".to_string());
        let id = K8sPodIdentity::from_args(&args).expect("identity should parse");
        assert!(
            id.pod_uid.is_none(),
            "empty K8S_POD_UID should normalize to None"
        );
    }

    #[test]
    fn net_config_deserializes_minimal_shape() {
        let raw = serde_json::json!({
            "cniVersion": "0.4.0",
            "name": "ferrum-mesh",
            "type": "ferrum-cni",
        });
        let cfg: CniNetConfig = serde_json::from_value(raw).expect("net config should parse");
        assert_eq!(cfg.cni_version, "0.4.0");
        assert_eq!(cfg.name, "ferrum-mesh");
        assert_eq!(cfg.plugin_type, "ferrum-cni");
        assert!(cfg.prev_result.is_none());
        assert!(cfg.ferrum.is_none());
    }

    #[test]
    fn net_config_passes_through_prev_result_and_ferrum_options() {
        let raw = serde_json::json!({
            "cniVersion": "1.0.0",
            "name": "ferrum-mesh",
            "type": "ferrum-cni",
            "prevResult": {"interfaces": [], "ips": []},
            "ferrum": {"socketPath": "/tmp/x.sock"},
            "extra-key": "value",
        });
        let cfg: CniNetConfig = serde_json::from_value(raw).expect("net config should parse");
        assert!(cfg.prev_result.is_some());
        assert_eq!(
            cfg.ferrum.as_ref().and_then(|f| f.socket_path.as_deref()),
            Some("/tmp/x.sock")
        );
        assert!(cfg.extra.contains_key("extra-key"));
        assert!(cfg.valid_attachments.is_none());
    }

    #[test]
    fn net_config_parses_gc_valid_attachments() {
        let raw = serde_json::json!({
            "cniVersion": "1.1.0",
            "name": "ferrum-mesh",
            "type": "ferrum-cni",
            "cni.dev/valid-attachments": [
                {"containerID": "ctr-alive", "ifname": "eth0"},
                {"containerID": "ctr-alive", "ifname": "eth0"},
                {"containerID": "ctr-other", "ifname": "eth1"}
            ]
        });
        let cfg: CniNetConfig = serde_json::from_value(raw).expect("net config should parse");
        let ingested = ingest_valid_attachments(
            cfg.valid_attachments
                .expect("GC attachment field should be present"),
        )
        .expect("ingest");
        assert_eq!(ingested.len(), 2, "duplicate attachments should dedupe");
        assert_eq!(ingested[0].container_id, "ctr-alive");
        assert_eq!(ingested[1].container_id, "ctr-other");
    }

    #[test]
    fn ingest_valid_attachments_rejects_hostile_and_oversized_input() {
        let path_like = CniValidAttachment {
            container_id: "../escape".to_string(),
            ifname: "eth0".to_string(),
        };
        assert!(ingest_valid_attachments(vec![path_like]).is_err());

        let bad_ifname = CniValidAttachment {
            container_id: "ctr-1".to_string(),
            ifname: "eth0/../lo".to_string(),
        };
        assert!(ingest_valid_attachments(vec![bad_ifname]).is_err());

        let too_many = (0..=MAX_CNI_GC_ATTACHMENTS)
            .map(|i| CniValidAttachment {
                container_id: format!("ctr-{i}"),
                ifname: "eth0".to_string(),
            })
            .collect::<Vec<_>>();
        let err = ingest_valid_attachments(too_many).expect_err("cap exceeded");
        assert!(err.to_string().contains("cap is"));
    }

    #[test]
    fn passthrough_result_inlines_prev_result_fields() {
        let prev = serde_json::json!({
            "cniVersion": "0.4.0",
            "interfaces": [{"name": "eth0"}],
            "ips": [{"address": "10.0.0.1/24"}],
        });
        let result = CniSuccessResult::passthrough("0.4.0", Some(&prev));
        assert_eq!(result.cni_version, "0.4.0");
        assert_eq!(result.prev_result.len(), 2);
        let json = serde_json::to_string(&result).expect("serializes");
        assert_eq!(
            json.matches("cniVersion").count(),
            1,
            "top-level cniVersion should not be duplicated from prevResult"
        );
        assert!(json.contains("\"interfaces\""));
        assert!(json.contains("\"ips\""));
    }

    #[test]
    fn passthrough_result_emits_minimal_shape_without_prev() {
        let result = CniSuccessResult::passthrough("0.4.0", None);
        assert_eq!(result.cni_version, "0.4.0");
        assert!(result.prev_result.is_empty());
        let json = serde_json::to_string(&result).expect("serializes");
        assert_eq!(json, r#"{"cniVersion":"0.4.0"}"#);
    }

    #[test]
    fn cni_error_codes_match_spec_buckets() {
        assert_eq!(CniError::missing_env("x").code(), 4);
        assert_eq!(CniError::UnsupportedCommand.code(), 4);
        assert_eq!(CniError::BadConfig("x".to_string()).code(), 7);
        assert_eq!(CniError::UnsupportedVersion.code(), 1);
        assert_eq!(CniError::IpcFailed("x".to_string()).code(), 11);
        assert_eq!(CniError::Rejected("x".to_string()).code(), 12);
        assert_eq!(CniError::NotAvailable("x".to_string()).code(), 50);
        assert_eq!(CniError::NotAvailableDegraded("x".to_string()).code(), 51);
    }

    #[test]
    fn build_error_result_includes_code_and_msg() {
        let err = CniError::IpcFailed("connect refused".to_string());
        let payload = build_error_result("0.4.0", &err);
        assert_eq!(payload.code, 11);
        assert!(payload.msg.contains("connect refused"));
    }
}
