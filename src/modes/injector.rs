//! Kubernetes sidecar-injector mode (Layer 8).
//!
//! The serving path is a narrow AdmissionReview webhook. It only produces JSON
//! patches; all mesh runtime work remains in `FERRUM_MODE=mesh`.

use std::convert::Infallible;
use std::net::SocketAddr;
use std::sync::Arc;

use base64::Engine as _;
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Method, Request, Response, StatusCode};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio::sync::{Semaphore, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::capture::{
    CaptureConfig, CaptureMode, DEFAULT_PROXY_UID, FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION,
    ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION, IncludeOutboundPorts, Ip6TablesMode, IptablesPlan,
    UdpCaptureSettings, include_outbound_ports_from_annotations, udp_capture_settings_from_env,
    validate_cidr_list,
};
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::identity::spiffe::TrustDomain;
use crate::tls::{self, TlsPolicy};
use crate::util::body_limit::is_length_limit_error;
use crate::util::mesh_enrollment::{
    inject_annotation_blocks_injection, inject_annotation_is_unrecognized,
    inject_annotation_opts_in, mesh_label_blocks_injection, mesh_label_is_unrecognized,
    mesh_label_opts_in,
};

const DEFAULT_INJECTOR_LISTEN_ADDR: &str = "0.0.0.0:9443";
const DEFAULT_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB: usize = 4;
const MAX_INJECTOR_ADMISSION_REVIEW_BODY_SIZE_MIB: usize = 64;
const MIB_BYTES: usize = 1024 * 1024;
const DEFAULT_SIDECAR_IMAGE: &str = "ferrum-edge:latest";
const DEFAULT_INJECTOR_TRUST_DOMAIN: &str = "cluster.local";
const ISTIO_EXCLUDE_OUTBOUND_PORTS_ANNOTATION: &str =
    "traffic.sidecar.istio.io/excludeOutboundPorts";
const FERRUM_EXCLUDE_OUTBOUND_PORTS_ANNOTATION: &str = "ferrum.io/excludeOutboundPorts";
const ISTIO_EXCLUDE_INBOUND_PORTS_ANNOTATION: &str = "traffic.sidecar.istio.io/excludeInboundPorts";
const FERRUM_EXCLUDE_INBOUND_PORTS_ANNOTATION: &str = "ferrum.io/excludeInboundPorts";
const ISTIO_EXCLUDE_OUTBOUND_IP_RANGES_ANNOTATION: &str =
    "traffic.sidecar.istio.io/excludeOutboundIPRanges";
const ISTIO_INCLUDE_OUTBOUND_IP_RANGES_ANNOTATION: &str =
    "traffic.sidecar.istio.io/includeOutboundIPRanges";
const DEFAULT_SIDECAR_CPU_REQUEST: &str = "25m";
const DEFAULT_SIDECAR_MEMORY_REQUEST: &str = "64Mi";
const DEFAULT_SIDECAR_CPU_LIMIT: &str = "250m";
const DEFAULT_SIDECAR_MEMORY_LIMIT: &str = "256Mi";
const DEFAULT_INIT_CPU_REQUEST: &str = "10m";
const DEFAULT_INIT_MEMORY_REQUEST: &str = "32Mi";
const DEFAULT_INIT_CPU_LIMIT: &str = "100m";
const DEFAULT_INIT_MEMORY_LIMIT: &str = "128Mi";
const SIDECAR_ENV_KEYS: &[&str] = &[
    "FERRUM_DP_CP_GRPC_URLS",
    "FERRUM_CP_DP_GRPC_JWT_ISSUER",
    "FERRUM_DP_GRPC_TLS_CA_CERT_PATH",
    "FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH",
    "FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH",
    "FERRUM_DP_GRPC_TLS_NO_VERIFY",
    "FERRUM_MESH_CONFIG_PROTOCOL",
];
const SIDECAR_CONTAINER_NAME: &str = "ferrum-edge";
const INIT_CONTAINER_NAME: &str = "ferrum-edge-init";
const NATIVE_SIDECAR_PATCH_PATH: &str = "/spec/initContainers/0";
const IPTABLES_INIT_PATCH_PATH: &str = "/spec/initContainers/1";
const SIDECAR_HEALTH_BINARY: &str = "/app/ferrum-edge";
const SIDECAR_HEALTH_ADMIN_PORT: &str = "9000";
const SIDECAR_STARTUP_PROBE_PERIOD_SECONDS: u64 = 2;
const SIDECAR_STARTUP_PROBE_FAILURE_THRESHOLD: u64 = 150;
const SIDECAR_READINESS_PROBE_PERIOD_SECONDS: u64 = 5;
const SIDECAR_READINESS_PROBE_FAILURE_THRESHOLD: u64 = 3;
const CONTAINER_PROBE_FIELDS: [&str; 3] = ["startupProbe", "readinessProbe", "livenessProbe"];
const POD_CONTAINER_LIST_POINTERS: [&str; 3] = [
    "/spec/containers",
    "/spec/initContainers",
    "/spec/ephemeralContainers",
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SecretKeyRef {
    pub name: String,
    pub key: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ContainerResourceConfig {
    pub cpu_request: String,
    pub memory_request: String,
    pub cpu_limit: String,
    pub memory_limit: String,
}

impl ContainerResourceConfig {
    fn new(
        cpu_request: impl Into<String>,
        memory_request: impl Into<String>,
        cpu_limit: impl Into<String>,
        memory_limit: impl Into<String>,
    ) -> Self {
        Self {
            cpu_request: cpu_request.into(),
            memory_request: memory_request.into(),
            cpu_limit: cpu_limit.into(),
            memory_limit: memory_limit.into(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InjectorConfig {
    pub listen_addr: SocketAddr,
    pub namespace: String,
    pub sidecar_image: String,
    pub sidecar_env: Vec<(String, String)>,
    pub jwt_secret_ref: Option<SecretKeyRef>,
    pub sidecar_resources: ContainerResourceConfig,
    pub init_resources: ContainerResourceConfig,
    pub require_annotation: bool,
    pub capture_mode: CaptureMode,
    pub proxy_uid: Option<u32>,
    pub exclude_outbound_ports: Vec<u16>,
    /// TCP destination ports excluded from inbound iptables capture. Mirrors
    /// Istio's `excludeInboundPorts`. Each listed port emits a `RETURN` rule
    /// inserted BEFORE the inbound REDIRECT so the proxy never sees that port.
    pub exclude_inbound_ports: Vec<u16>,
    /// CIDRs included for outbound iptables capture. Per Istio semantics,
    /// pod annotation `includeOutboundIPRanges` REPLACES this value when set.
    pub include_outbound_cidrs: Vec<String>,
    /// CIDRs excluded from outbound iptables capture. Per Istio semantics,
    /// pod annotation `excludeOutboundIPRanges` APPENDS to this value.
    pub exclude_outbound_cidrs: Vec<String>,
    pub ip6tables_mode: Ip6TablesMode,
    /// Whether the injected init container emits UDP TPROXY capture rules
    /// (F3 §3.3 Stage 2). Default `false`: the consuming UDP listener arrives in
    /// Stage 3, so an upgraded injector must not redirect UDP into a void.
    pub udp_capture_enabled: bool,
    /// UDP TPROXY listener port (Stage 3 consumer); distinct from the TCP
    /// outbound REDIRECT port.
    pub udp_outbound_port: u16,
    /// Firewall mark stamped on TPROXY'd UDP datagrams.
    pub tproxy_mark: u32,
    pub trust_domain: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    /// Dev-only escape hatch. Kubernetes mandates HTTPS for admission webhooks,
    /// so production must serve TLS. When `false` (default) the injector refuses
    /// to start without a cert+key. Setting `FERRUM_INJECTOR_ALLOW_PLAINTEXT=true`
    /// permits plaintext HTTP for local development with a loud startup warning.
    pub allow_plaintext: bool,
    pub tls_handshake_timeout_seconds: u64,
    /// HTTP/1 header read timeout for admission connections, mirroring the
    /// proxy/admin listeners (`FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS`).
    /// `0` disables the timeout.
    pub http_header_read_timeout_seconds: u64,
    pub admission_review_max_body_bytes: usize,
}

impl InjectorConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, String> {
        let listen_addr = resolve_ferrum_var("FERRUM_INJECTOR_LISTEN_ADDR")
            .unwrap_or_else(|| DEFAULT_INJECTOR_LISTEN_ADDR.to_string())
            .parse::<SocketAddr>()
            .map_err(|e| format!("Invalid FERRUM_INJECTOR_LISTEN_ADDR: {e}"))?;
        let sidecar_image = resolve_ferrum_var("FERRUM_INJECTOR_SIDECAR_IMAGE")
            .unwrap_or_else(|| DEFAULT_SIDECAR_IMAGE.to_string());
        let sidecar_env = sidecar_env_from_runtime();
        let jwt_secret_ref = jwt_secret_ref_from_runtime()?;
        let sidecar_resources = container_resources_from_runtime(
            "FERRUM_INJECTOR_SIDECAR",
            default_sidecar_resources(),
        )?;
        let init_resources =
            container_resources_from_runtime("FERRUM_INJECTOR_INIT", default_init_resources())?;
        let require_annotation = resolve_ferrum_var("FERRUM_INJECTOR_REQUIRE_ANNOTATION")
            .and_then(|value| value.parse::<bool>().ok())
            .unwrap_or(true);
        let capture_mode = CaptureMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_CAPTURE_MODE")
                .unwrap_or_else(|| "explicit".to_string()),
        )?;
        let proxy_uid = parse_injector_proxy_uid(resolve_ferrum_var("FERRUM_MESH_PROXY_UID"))?;
        let exclude_outbound_ports =
            parse_port_list(resolve_ferrum_var("FERRUM_MESH_EXCLUDE_OUTBOUND_PORTS").as_deref())?;
        let exclude_inbound_ports = parse_port_list(
            resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_INBOUND_PORTS").as_deref(),
        )?;
        let include_outbound_cidrs =
            parse_cidr_list_env(resolve_ferrum_var("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS").as_deref());
        if !include_outbound_cidrs.is_empty() {
            validate_cidr_list(&include_outbound_cidrs)
                .map_err(|e| format!("Invalid FERRUM_MESH_CAPTURE_INCLUDE_CIDRS: {e}"))?;
        }
        let exclude_outbound_cidrs =
            parse_cidr_list_env(resolve_ferrum_var("FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS").as_deref());
        if !exclude_outbound_cidrs.is_empty() {
            validate_cidr_list(&exclude_outbound_cidrs)
                .map_err(|e| format!("Invalid FERRUM_MESH_CAPTURE_EXCLUDE_CIDRS: {e}"))?;
        }
        let ip6tables_mode = Ip6TablesMode::parse(
            &resolve_ferrum_var("FERRUM_MESH_IP6TABLES_ENABLED")
                .unwrap_or_else(|| "auto".to_string()),
        )?;
        let UdpCaptureSettings {
            udp_capture_enabled,
            udp_outbound_port,
            tproxy_mark,
            // The injector always renders the POD-netns init-container script; the
            // host-network capture path is an Ambient mesh-proxy placement and has
            // no injector representation.
            udp_host_netns_enabled: _,
        } = udp_capture_settings_from_env()?;
        let trust_domain = resolve_ferrum_var("FERRUM_INJECTOR_TRUST_DOMAIN")
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| DEFAULT_INJECTOR_TRUST_DOMAIN.to_string());
        validate_injector_trust_domain(&trust_domain)?;
        let admission_review_max_body_bytes =
            parse_injector_admission_review_max_body_bytes_from_mib(
                resolve_ferrum_var("FERRUM_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB").as_deref(),
            )?;
        let tls_cert_path = resolve_ferrum_var("FERRUM_INJECTOR_TLS_CERT_PATH");
        let tls_key_path = resolve_ferrum_var("FERRUM_INJECTOR_TLS_KEY_PATH");
        let allow_plaintext = resolve_ferrum_var("FERRUM_INJECTOR_ALLOW_PLAINTEXT")
            .and_then(|value| value.trim().parse::<bool>().ok())
            .unwrap_or(false);
        validate_injector_tls_serving(
            tls_cert_path.as_deref(),
            tls_key_path.as_deref(),
            allow_plaintext,
        )?;

        Ok(Self {
            listen_addr,
            namespace: env_config.namespace.clone(),
            sidecar_image,
            sidecar_env,
            jwt_secret_ref,
            sidecar_resources,
            init_resources,
            require_annotation,
            capture_mode,
            proxy_uid,
            exclude_outbound_ports,
            exclude_inbound_ports,
            include_outbound_cidrs,
            exclude_outbound_cidrs,
            ip6tables_mode,
            udp_capture_enabled,
            udp_outbound_port,
            tproxy_mark,
            trust_domain,
            tls_cert_path,
            tls_key_path,
            allow_plaintext,
            tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
            http_header_read_timeout_seconds: env_config.http_header_read_timeout_seconds,
            admission_review_max_body_bytes,
        })
    }
}

fn parse_injector_admission_review_max_body_bytes_from_mib(
    value: Option<&str>,
) -> Result<usize, String> {
    let Some(raw) = value.map(str::trim).filter(|s| !s.is_empty()) else {
        return Ok(DEFAULT_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB * MIB_BYTES);
    };
    let parsed = raw.parse::<usize>().map_err(|_| {
        "Invalid FERRUM_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB: must be an unsigned integer"
            .to_string()
    })?;
    if parsed == 0 {
        return Err(
            "Invalid FERRUM_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB: must be greater than zero"
                .to_string(),
        );
    }
    if parsed > MAX_INJECTOR_ADMISSION_REVIEW_BODY_SIZE_MIB {
        return Err(format!(
            "Invalid FERRUM_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB: must be at most {MAX_INJECTOR_ADMISSION_REVIEW_BODY_SIZE_MIB} MiB"
        ));
    }
    // `parsed` is capped at 64 MiB above, so this cannot overflow on the
    // supported 32-bit and 64-bit targets.
    Ok(parsed * MIB_BYTES)
}

/// Parse a comma-separated CIDR list. Trims whitespace and skips empty tokens.
/// Returns an empty `Vec` for `None`/empty input. Validation is the caller's
/// responsibility (use [`validate_cidr_list`]).
fn parse_cidr_list_env(raw: Option<&str>) -> Vec<String> {
    let Some(raw) = raw else {
        return Vec::new();
    };
    raw.split(',')
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(String::from)
        .collect()
}

fn validate_injector_trust_domain(value: &str) -> Result<(), String> {
    TrustDomain::new(value.to_string())
        .map(|_| ())
        .map_err(|e| format!("Invalid FERRUM_INJECTOR_TRUST_DOMAIN: {e}"))
}

/// Validate the injector's TLS serving inputs, fail-closed for production.
///
/// Kubernetes calls admission webhooks over HTTPS, so a production injector must
/// serve TLS. Both the cert and key are required together. When neither is set,
/// plaintext serving is refused unless `allow_plaintext` (the
/// `FERRUM_INJECTOR_ALLOW_PLAINTEXT` dev-only escape hatch) is explicitly set.
fn validate_injector_tls_serving(
    tls_cert_path: Option<&str>,
    tls_key_path: Option<&str>,
    allow_plaintext: bool,
) -> Result<(), String> {
    match (tls_cert_path, tls_key_path) {
        (Some(_), Some(_)) => Ok(()),
        (None, None) => {
            if allow_plaintext {
                Ok(())
            } else {
                Err(
                    "injector requires TLS: set FERRUM_INJECTOR_TLS_CERT_PATH and \
                     FERRUM_INJECTOR_TLS_KEY_PATH (Kubernetes admission webhooks must use \
                     HTTPS). For local development only, set FERRUM_INJECTOR_ALLOW_PLAINTEXT=true \
                     to serve plaintext HTTP."
                        .to_string(),
                )
            }
        }
        (Some(_), None) => {
            Err("FERRUM_INJECTOR_TLS_CERT_PATH requires FERRUM_INJECTOR_TLS_KEY_PATH".to_string())
        }
        (None, Some(_)) => {
            Err("FERRUM_INJECTOR_TLS_KEY_PATH requires FERRUM_INJECTOR_TLS_CERT_PATH".to_string())
        }
    }
}

fn parse_port_list(raw: Option<&str>) -> Result<Vec<u16>, String> {
    let Some(raw) = raw.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(Vec::new());
    };

    let mut ports = Vec::new();
    for token in raw
        .split(',')
        .map(str::trim)
        .filter(|token| !token.is_empty())
    {
        let port = token
            .parse::<u16>()
            .map_err(|e| format!("port '{token}': {e}"))?;
        if port == 0 {
            return Err("port '0': port must be 1-65535".to_string());
        }
        ports.push(port);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn parse_injector_proxy_uid(value: Option<String>) -> Result<Option<u32>, String> {
    let Some(value) = value.map(|value| value.trim().to_string()) else {
        return Ok(None);
    };
    if value.is_empty() {
        return Ok(None);
    }

    let uid = value
        .parse::<u32>()
        .map_err(|e| format!("Invalid FERRUM_MESH_PROXY_UID '{value}': {e}"))?;
    if uid == 0 {
        return Err(
            "Invalid FERRUM_MESH_PROXY_UID: injected sidecars set runAsNonRoot=true, so the proxy UID must be non-zero"
                .to_string(),
        );
    }

    Ok(Some(uid))
}

fn jwt_secret_ref_from_runtime() -> Result<Option<SecretKeyRef>, String> {
    let name = resolve_ferrum_var("FERRUM_INJECTOR_JWT_SECRET_REF_NAME")
        .filter(|value| !value.trim().is_empty());
    let key = resolve_ferrum_var("FERRUM_INJECTOR_JWT_SECRET_REF_KEY")
        .filter(|value| !value.trim().is_empty());

    match (name, key) {
        (Some(name), Some(key)) => Ok(Some(SecretKeyRef { name, key })),
        (None, None) => Ok(None),
        (Some(_), None) => Err(
            "FERRUM_INJECTOR_JWT_SECRET_REF_NAME requires FERRUM_INJECTOR_JWT_SECRET_REF_KEY"
                .to_string(),
        ),
        (None, Some(_)) => Err(
            "FERRUM_INJECTOR_JWT_SECRET_REF_KEY requires FERRUM_INJECTOR_JWT_SECRET_REF_NAME"
                .to_string(),
        ),
    }
}

fn default_sidecar_resources() -> ContainerResourceConfig {
    ContainerResourceConfig::new(
        DEFAULT_SIDECAR_CPU_REQUEST,
        DEFAULT_SIDECAR_MEMORY_REQUEST,
        DEFAULT_SIDECAR_CPU_LIMIT,
        DEFAULT_SIDECAR_MEMORY_LIMIT,
    )
}

fn default_init_resources() -> ContainerResourceConfig {
    ContainerResourceConfig::new(
        DEFAULT_INIT_CPU_REQUEST,
        DEFAULT_INIT_MEMORY_REQUEST,
        DEFAULT_INIT_CPU_LIMIT,
        DEFAULT_INIT_MEMORY_LIMIT,
    )
}

fn container_resources_from_runtime(
    key_prefix: &str,
    defaults: ContainerResourceConfig,
) -> Result<ContainerResourceConfig, String> {
    let cpu_request_key = format!("{key_prefix}_CPU_REQUEST");
    let memory_request_key = format!("{key_prefix}_MEMORY_REQUEST");
    let cpu_limit_key = format!("{key_prefix}_CPU_LIMIT");
    let memory_limit_key = format!("{key_prefix}_MEMORY_LIMIT");

    Ok(ContainerResourceConfig {
        cpu_request: resolve_resource_quantity(&cpu_request_key, &defaults.cpu_request)?,
        memory_request: resolve_resource_quantity(&memory_request_key, &defaults.memory_request)?,
        cpu_limit: resolve_resource_quantity(&cpu_limit_key, &defaults.cpu_limit)?,
        memory_limit: resolve_resource_quantity(&memory_limit_key, &defaults.memory_limit)?,
    })
}

fn resolve_resource_quantity(key: &str, default: &str) -> Result<String, String> {
    let value = resolve_ferrum_var(key)
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| default.to_string());
    if is_valid_kubernetes_quantity(&value) {
        Ok(value)
    } else {
        Err(format!(
            "Invalid {key}: '{value}' is not a valid Kubernetes resource quantity"
        ))
    }
}

fn is_valid_kubernetes_quantity(value: &str) -> bool {
    if value.is_empty() || value.starts_with('-') || value.starts_with('+') {
        return false;
    }

    let numeric = if let Some(prefix) = value.strip_suffix("Ki") {
        prefix
    } else if let Some(prefix) = value.strip_suffix("Mi") {
        prefix
    } else if let Some(prefix) = value.strip_suffix("Gi") {
        prefix
    } else if let Some(prefix) = value.strip_suffix("Ti") {
        prefix
    } else if let Some(prefix) = value.strip_suffix("Pi") {
        prefix
    } else if let Some(prefix) = value.strip_suffix("Ei") {
        prefix
    } else if let Some(last) = value.chars().last() {
        if matches!(
            last,
            'n' | 'u' | 'm' | 'k' | 'K' | 'M' | 'G' | 'T' | 'P' | 'E'
        ) {
            &value[..value.len() - last.len_utf8()]
        } else {
            value
        }
    } else {
        value
    };

    !numeric.is_empty() && numeric.parse::<f64>().is_ok_and(f64::is_finite)
}

fn sidecar_env_from_runtime() -> Vec<(String, String)> {
    SIDECAR_ENV_KEYS
        .iter()
        .filter_map(|key| {
            resolve_ferrum_var(key)
                .filter(|value| !value.trim().is_empty())
                .map(|value| ((*key).to_string(), value))
        })
        .collect()
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct JsonPatchOperation {
    pub op: &'static str,
    pub path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Value>,
}

#[derive(Debug, Deserialize)]
struct AdmissionReview {
    #[serde(rename = "apiVersion")]
    api_version: Option<String>,
    kind: Option<String>,
    request: Option<AdmissionRequest>,
}

#[derive(Debug, Deserialize)]
struct AdmissionRequest {
    uid: String,
    namespace: Option<String>,
    /// `GroupVersionKind` of the admitted object. Kubernetes always populates
    /// this for object-carrying admission requests. Optional here so a
    /// malformed/absent value is handled explicitly rather than failing
    /// deserialization of the whole review.
    #[serde(default)]
    kind: Option<GroupVersionKind>,
    /// `GroupVersionResource` of the admitted object. Used as a secondary
    /// confirmation that the request targets the core `pods` resource.
    #[serde(default)]
    resource: Option<GroupVersionResource>,
    /// When `true`, Kubernetes is performing a dry-run admission. A patch-only
    /// webhook has no side effects, so we return the identical patch; we honor
    /// the flag by never implying a side effect and by recording it for
    /// observability.
    #[serde(rename = "dryRun", default)]
    dry_run: Option<bool>,
    object: Value,
}

/// Kubernetes `meta/v1` GroupVersionKind. The core API group is the empty
/// string, so `group` defaults to empty when the field is absent.
#[derive(Debug, Default, Deserialize)]
struct GroupVersionKind {
    #[serde(default)]
    group: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    kind: String,
}

/// Kubernetes `meta/v1` GroupVersionResource. The core API group is the empty
/// string, so `group` defaults to empty when the field is absent.
#[derive(Debug, Default, Deserialize)]
struct GroupVersionResource {
    #[serde(default)]
    group: String,
    #[serde(default)]
    version: String,
    #[serde(default)]
    resource: String,
}

/// Outcome of validating that an `AdmissionRequest` targets a core-group Pod.
///
/// Any core-group (`apiGroup ""`) Pod version is accepted — the check is
/// intentionally version-agnostic for forward compatibility, not gated to `v1`.
enum PodKindCheck {
    /// The request targets a Pod and injection logic may proceed.
    Pod,
    /// The request targets something else (mis-scoped webhook). Carries a
    /// human-readable descriptor of the observed group/version/kind for logs.
    NotPod(String),
}

/// Validate that the admitted object is a core (`apiGroup ""`) Pod.
///
/// Kubernetes populates `request.kind` (a `GroupVersionKind`) for every
/// object-carrying admission request, and `request.resource` (a
/// `GroupVersionResource`) as well. A correctly-scoped `MutatingWebhookConfiguration`
/// only routes `pods` `CREATE`, but a mis-scoped configuration could send other
/// kinds. We accept the request only when the core group's `Pod` kind (or the
/// core `pods` resource) is present, and refuse to inject into anything else.
fn classify_pod_kind(request: &AdmissionRequest) -> PodKindCheck {
    // `kind` is authoritative when present. Core group is the empty string.
    if let Some(gvk) = &request.kind {
        if gvk.group.is_empty() && gvk.kind == "Pod" {
            return PodKindCheck::Pod;
        }
        // `kind` present but not a core Pod: this is a mis-scoped webhook.
        return PodKindCheck::NotPod(format!(
            "kind={{group:{:?},version:{:?},kind:{:?}}}",
            gvk.group, gvk.version, gvk.kind
        ));
    }

    // No `kind` block. Fall back to the `resource` block: core `pods`.
    if let Some(gvr) = &request.resource {
        if gvr.group.is_empty() && gvr.resource == "pods" {
            return PodKindCheck::Pod;
        }
        return PodKindCheck::NotPod(format!(
            "resource={{group:{:?},version:{:?},resource:{:?}}}",
            gvr.group, gvr.version, gvr.resource
        ));
    }

    // Neither `kind` nor `resource` present. A real Kubernetes apiserver always
    // sends at least one, so an admission request carrying neither is malformed
    // and we fail closed on injection (allow, but never inject).
    PodKindCheck::NotPod("no kind or resource metadata".to_string())
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let config = InjectorConfig::from_env_config(&env_config)
        .map_err(|e| anyhow::anyhow!("invalid injector configuration: {e}"))?;
    let tls_acceptor = build_tls_acceptor(&env_config, &config)?;
    let max_connections = env_config.max_connections;
    let shutdown_drain_seconds = env_config.shutdown_drain_seconds;
    let config = Arc::new(config);
    let connection_limiter = if max_connections > 0 {
        Some(Arc::new(Semaphore::new(max_connections)))
    } else {
        None
    };
    let listener = TcpListener::bind(config.listen_addr).await?;
    if tls_acceptor.is_none() {
        warn!(
            listen_addr = %config.listen_addr,
            "Ferrum injector serving PLAINTEXT HTTP (FERRUM_INJECTOR_ALLOW_PLAINTEXT=true). \
             Kubernetes requires HTTPS for admission webhooks; this is for local development only"
        );
    }
    info!(
        listen_addr = %config.listen_addr,
        namespace = %config.namespace,
        tls = tls_acceptor.is_some(),
        "Ferrum injector admission webhook listening"
    );
    let mut shutdown_rx = shutdown_tx.subscribe();
    let mut accept_backoff = crate::util::accept_backoff::AcceptBackoff::new();
    let mut accept_err_log = crate::util::accept_backoff::LogRateLimiter::new();
    let mut connections = JoinSet::new();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
                        accept_backoff.on_success();
                        let config = Arc::clone(&config);
                        let tls_acceptor = tls_acceptor.clone();
                        let connection_permit = match &connection_limiter {
                            Some(limiter) => {
                                let limiter = Arc::clone(limiter);
                                let Ok(connection_permit) = limiter.try_acquire_owned() else {
                                    warn!(
                                        remote_addr = %remote_addr,
                                        max_connections,
                                        "Injector connection rejected: max concurrent connections reached"
                                    );
                                    continue;
                                };
                                Some(connection_permit)
                            }
                            None => None,
                        };
                        connections.spawn(async move {
                            let _connection_permit = connection_permit;
                            if let Some(acceptor) = tls_acceptor {
                                match tls::accept_with_optional_timeout(
                                    &acceptor,
                                    stream,
                                    config.tls_handshake_timeout_seconds,
                                    &remote_addr,
                                    false,
                                )
                                .await
                                {
                                    Ok(tls_stream) => {
                                        serve_injector_connection(tls_stream, config, remote_addr)
                                            .await;
                                    }
                                    Err(e) => debug!(
                                        remote_addr = %remote_addr,
                                        error = %e,
                                        "Injector TLS handshake failed"
                                    ),
                                }
                            } else {
                                serve_injector_connection(stream, config, remote_addr).await;
                            }
                        });
                    }
                    Err(e) => {
                        // Bound the log rate independently of the backoff: an
                        // abort/reset flood is not backed off, so emit the
                        // first error then one summary per second with the
                        // suppressed count.
                        if let Some(suppressed) =
                            accept_err_log.on_event(crate::socket_opts::monotonic_now_ms())
                        {
                            error!(suppressed, "Failed to accept injector connection: {}", e);
                        }
                        // Back off on a sustained fd-exhaustion run so accept()
                        // cannot busy-spin a core.
                        if let Some(delay) = accept_backoff.on_error(e.kind()) {
                            tokio::time::sleep(delay).await;
                        }
                    }
                }
            }
            _ = shutdown_rx.changed() => {
                info!("Injector admission webhook shutting down");
                let drain = async {
                    while connections.join_next().await.is_some() {}
                };
                if tokio::time::timeout(
                    std::time::Duration::from_secs(shutdown_drain_seconds),
                    drain,
                )
                .await
                .is_err()
                {
                    warn!(
                        shutdown_drain_seconds,
                        remaining_connections = connections.len(),
                        "Injector shutdown drain timed out; aborting remaining connections"
                    );
                    connections.abort_all();
                    while connections.join_next().await.is_some() {}
                }
                return Ok(());
            }
            Some(result) = connections.join_next(), if !connections.is_empty() => {
                if let Err(error) = result
                    && !error.is_cancelled()
                {
                    warn!(%error, "Injector connection task failed");
                }
            }
        }
    }
}

fn build_tls_acceptor(
    env_config: &EnvConfig,
    config: &InjectorConfig,
) -> Result<Option<TlsAcceptor>, anyhow::Error> {
    let (Some(cert_path), Some(key_path)) = (&config.tls_cert_path, &config.tls_key_path) else {
        return Ok(None);
    };

    let tls_policy = TlsPolicy::from_env_config(env_config)?;
    let server_config = tls::load_tls_config_with_client_auth(
        cert_path,
        key_path,
        None,
        false,
        &tls_policy,
        env_config.tls_cert_expiry_warning_days,
        &[],
    )
    .map_err(|e| anyhow::anyhow!("Invalid injector TLS configuration: {}", e))?;
    // The shared TLS loader advertises `h2` before `http/1.1`, but every
    // injector connection is served by Hyper's HTTP/1-only builder. Drop `h2`
    // so an HTTP/2-capable Kubernetes API server can never negotiate it and
    // then send an HTTP/2 preface to the HTTP/1 parser.
    //
    // `acme-tls/1` is deliberately RETAINED. The shared loader installs
    // `AcmeTlsAlpnResolver` for every listener it builds, so this acceptor can
    // serve an RFC 8737 validation certificate from a pending order already in
    // the process-global ACME store — the resolver only does so for a
    // ClientHello that offers `acme-tls/1` ALONE with matching SNI, which no
    // Kubernetes API server sends. Dropping the protocol here would silently
    // break that externally orchestrated TLS-ALPN-01 path while leaving the
    // resolver in place, so the advertisement and serving path stay in
    // agreement. An `acme-tls/1` connection carries no HTTP, so handing the
    // post-handshake socket to the HTTP/1 builder is inert: the validator
    // closes it, or the header read timeout does.
    let mut server_config = Arc::unwrap_or_clone(server_config);
    server_config.alpn_protocols = vec![
        b"http/1.1".to_vec(),
        crate::tls::acme::TLS_ALPN01_PROTOCOL.to_vec(),
    ];
    Ok(Some(TlsAcceptor::from(Arc::new(server_config))))
}

async fn serve_injector_connection<S>(
    stream: S,
    config: Arc<InjectorConfig>,
    remote_addr: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let header_read_timeout_seconds = config.http_header_read_timeout_seconds;
    let svc = service_fn(move |req| {
        let config = Arc::clone(&config);
        async move { handle_injector_request(req, config, remote_addr).await }
    });
    // Match the proxy/admin listeners: bound the time a client may take to
    // send request headers so trickling connections cannot exhaust the
    // injector's connection budget. 0 is the documented opt-out.
    let mut builder = http1::Builder::new();
    if header_read_timeout_seconds > 0 {
        builder.timer(hyper_util::rt::TokioTimer::new());
        builder.header_read_timeout(std::time::Duration::from_secs(header_read_timeout_seconds));
    } else {
        // Pin the operator-facing `0 = disabled` contract explicitly. Hyper
        // has its own default timeout, which happens to be inactive without a
        // timer today; setting `None` prevents a future timer refactor from
        // silently enabling that default for injector connections.
        builder.header_read_timeout(None);
    }
    if let Err(e) = builder.serve_connection(io, svc).await {
        debug!(remote_addr = %remote_addr, error = %e, "Injector connection error");
    }
}

async fn handle_injector_request(
    req: Request<Incoming>,
    config: Arc<InjectorConfig>,
    remote_addr: SocketAddr,
) -> Result<Response<Full<Bytes>>, Infallible> {
    if req.method() != Method::POST || req.uri().path() != "/mutate" {
        return Ok(response(StatusCode::NOT_FOUND, "not found"));
    }

    let max_body_bytes = config.admission_review_max_body_bytes;
    let body = match Limited::new(req.into_body(), max_body_bytes)
        .collect()
        .await
    {
        Ok(collected) => collected.to_bytes(),
        Err(e) => {
            if is_length_limit_error(e.as_ref()) {
                let max_body_limit = admission_review_body_limit_display(max_body_bytes);
                warn!(
                    remote_addr = %remote_addr,
                    max_body_bytes,
                    max_body_limit = %max_body_limit,
                    "Injector AdmissionReview body exceeded configured limit"
                );
                return Ok(response(
                    StatusCode::PAYLOAD_TOO_LARGE,
                    format!("AdmissionReview body too large (max {max_body_limit})"),
                ));
            }
            warn!(
                remote_addr = %remote_addr,
                error = %e,
                "Injector failed to read AdmissionReview body"
            );
            return Ok(response(
                StatusCode::BAD_REQUEST,
                "failed to read AdmissionReview body",
            ));
        }
    };

    match admission_response(&body, &config) {
        Ok(value) => Ok(json_response(StatusCode::OK, value)),
        Err(e) => Ok(response(StatusCode::BAD_REQUEST, e)),
    }
}

fn admission_review_body_limit_display(max_body_bytes: usize) -> String {
    if max_body_bytes.is_multiple_of(MIB_BYTES) {
        format!("{} MiB", max_body_bytes / MIB_BYTES)
    } else {
        // Production env parsing is MiB-aligned, but tests and direct
        // InjectorConfig construction can still supply byte-granular caps.
        format!("{max_body_bytes} bytes")
    }
}

pub fn admission_response(body: &[u8], config: &InjectorConfig) -> Result<Value, String> {
    let review: AdmissionReview =
        serde_json::from_slice(body).map_err(|e| format!("invalid AdmissionReview JSON: {e}"))?;
    let api_version = review
        .api_version
        .unwrap_or_else(|| "admission.k8s.io/v1".to_string());
    let kind = review.kind.unwrap_or_else(|| "AdmissionReview".to_string());
    let Some(request) = review.request else {
        return Err("AdmissionReview.request is required".to_string());
    };
    // `dryRun` carries no side-effect semantics for a patch-only webhook: the
    // computed JSON patch is byte-for-byte identical whether or not the
    // apiserver is performing a dry run, and the webhook never mutates external
    // state. We still surface it for observability.
    let dry_run = request.dry_run.unwrap_or(false);
    let mut response = json!({
        "apiVersion": api_version,
        "kind": kind,
        "response": {
            "uid": request.uid,
            "allowed": true
        }
    });

    // Boundary validation: a mutating webhook scoped to `pods` must never inject
    // into a non-Pod object. A mis-scoped `MutatingWebhookConfiguration` could
    // route other kinds here; admit them (allowed=true) but emit no patch.
    if let PodKindCheck::NotPod(observed) = classify_pod_kind(&request) {
        warn!(
            uid = %request.uid,
            observed = %observed,
            dry_run,
            "Injector AdmissionReview targets a non-Pod object; admitting without injection (check MutatingWebhookConfiguration rules)"
        );
        return Ok(response);
    }

    debug!(
        uid = %request.uid,
        dry_run,
        "Injector processing Pod AdmissionReview"
    );

    let patches = match build_sidecar_patch_for_namespace(
        &request.object,
        config,
        request.namespace.as_deref(),
    ) {
        Ok(patches) => patches,
        Err(message) => {
            if let Some(resp) = response.get_mut("response").and_then(Value::as_object_mut) {
                resp.insert("allowed".to_string(), Value::Bool(false));
                resp.insert(
                    "status".to_string(),
                    json!({
                        "code": 400,
                        "message": message,
                    }),
                );
            }
            return Ok(response);
        }
    };

    if !patches.is_empty() {
        let patch_json =
            serde_json::to_vec(&patches).map_err(|e| format!("failed to serialize patch: {e}"))?;
        let patch = base64::engine::general_purpose::STANDARD.encode(patch_json);
        if let Some(resp) = response.get_mut("response").and_then(Value::as_object_mut) {
            resp.insert(
                "patchType".to_string(),
                Value::String("JSONPatch".to_string()),
            );
            resp.insert("patch".to_string(), Value::String(patch));
        }
    }

    Ok(response)
}

fn build_sidecar_patch_for_namespace(
    pod: &Value,
    config: &InjectorConfig,
    admission_namespace: Option<&str>,
) -> Result<Vec<JsonPatchOperation>, String> {
    match injection_decision(pod, config) {
        InjectionDecision::Inject => {}
        // A node-scoped skip is the one skip an operator must be able to see:
        // it is silent from the workload's point of view (the pod is admitted
        // unchanged) but it is also the difference between a meshed pod and a
        // blackholed node. Log it with enough identity to act on. The ordinary
        // opt-out / not-selected skips stay quiet -- they are the steady-state
        // outcome for most pods the webhook ever sees.
        InjectionDecision::SkipHostNetwork => {
            warn!(
                pod = %pod_display_name(pod),
                namespace = %pod_namespace(pod, admission_namespace, config),
                capture_mode = ?config.capture_mode,
                "Injector skipping pod with spec.hostNetwork=true: the pod shares the node's network namespace, so capture rules and sidecar listeners would apply node-wide; admitting the pod unmodified"
            );
            return Ok(Vec::new());
        }
        InjectionDecision::SkipNotSelected => return Ok(Vec::new()),
    }

    if injected_shape_matches(pod, config, admission_namespace)? {
        return Ok(Vec::new());
    }

    reject_reserved_name_conflicts(pod, config)?;
    require_application_containers(pod)?;

    let mut patch = Vec::new();
    let pod_namespace = pod_namespace(pod, admission_namespace, config);
    ensure_metadata_annotations(pod, &mut patch);
    patch.push(JsonPatchOperation {
        op: "add",
        path: "/metadata/annotations/ferrum.io~1injected".to_string(),
        value: Some(Value::String("true".to_string())),
    });
    // Native sidecar (Kubernetes 1.29+): insert Ferrum first in
    // initContainers with restartPolicy Always so later init containers
    // (including iptables capture) and application containers wait for
    // the startup probe. There is no ordinary-container fallback.
    ensure_init_containers(pod, &mut patch)?;
    patch.push(JsonPatchOperation {
        op: "add",
        path: NATIVE_SIDECAR_PATCH_PATH.to_string(),
        value: Some(sidecar_container(config, pod, &pod_namespace)),
    });

    if config.capture_mode == CaptureMode::Ebpf {
        patch.push(JsonPatchOperation {
            op: "add",
            path: "/metadata/annotations/ferrum.io~1capture-mode".to_string(),
            value: Some(Value::String("ebpf".to_string())),
        });
    }

    if config.capture_mode == CaptureMode::Iptables {
        patch.push(JsonPatchOperation {
            op: "add",
            path: IPTABLES_INIT_PATCH_PATH.to_string(),
            value: Some(init_container(config, pod)?),
        });
    }

    Ok(patch)
}

fn injected_shape_matches(
    pod: &Value,
    config: &InjectorConfig,
    admission_namespace: Option<&str>,
) -> Result<bool, String> {
    let Some(sidecar) = named_container(pod, "/spec/initContainers", SIDECAR_CONTAINER_NAME) else {
        return Ok(false);
    };
    let namespace = pod_namespace(pod, admission_namespace, config);
    if sidecar != &sidecar_container(config, pod, namespace.as_str()) {
        return Ok(false);
    }

    if config.capture_mode != CaptureMode::Iptables {
        return Ok(true);
    }
    let Some(init) = named_container(pod, "/spec/initContainers", INIT_CONTAINER_NAME) else {
        return Ok(false);
    };
    Ok(init == &init_container(config, pod)?)
}

/// Why the injector did or did not patch a pod.
///
/// The admission path needs more than a bool: a `hostNetwork` skip is a
/// node-safety refusal that has to be logged, while an opt-out or a
/// missing opt-in is the ordinary steady-state outcome and must stay silent.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InjectionDecision {
    /// Inject the native sidecar (and, in `CaptureMode::Iptables`, the
    /// iptables init container).
    Inject,
    /// `spec.hostNetwork: true` -- the pod shares the node's network namespace.
    SkipHostNetwork,
    /// Explicitly opted out, or never opted in under `require_annotation`.
    SkipNotSelected,
}

fn injection_decision(pod: &Value, config: &InjectorConfig) -> InjectionDecision {
    let annotations = pod
        .pointer("/metadata/annotations")
        .and_then(Value::as_object);
    let labels = pod.pointer("/metadata/labels").and_then(Value::as_object);

    if inject_annotation_blocks_injection(
        annotations
            .and_then(|m| m.get("sidecar.istio.io/inject"))
            .and_then(Value::as_str),
    ) {
        log_unrecognized_inject_annotation(annotations, "sidecar.istio.io/inject");
        return InjectionDecision::SkipNotSelected;
    }
    if inject_annotation_blocks_injection(
        annotations
            .and_then(|m| m.get("ferrum.io/inject"))
            .and_then(Value::as_str),
    ) {
        log_unrecognized_inject_annotation(annotations, "ferrum.io/inject");
        return InjectionDecision::SkipNotSelected;
    }
    if mesh_label_blocks_injection(
        labels
            .and_then(|m| m.get("ferrum.io/mesh"))
            .and_then(Value::as_str),
    ) {
        log_unrecognized_mesh_label(labels);
        return InjectionDecision::SkipNotSelected;
    }

    // A `hostNetwork: true` pod shares the NODE's network namespace, so every
    // pod-scoped mesh surface becomes node-scoped:
    //
    // * The `CaptureMode::Iptables` init container runs `IptablesPlan` with
    //   `NET_ADMIN`+`NET_RAW` and appends `nat/PREROUTING` + `nat/OUTPUT` jumps
    //   into what is really the node's own nat table, redirecting all node TCP
    //   at `127.0.0.1:15001`/`:15006`. That hijacks kubelet, CNI, DNS, every
    //   other host-network workload, and the node's egress -- and the init
    //   container installs no cleanup trap, so the outage outlives the pod.
    // * Even with capture off (`Ebpf`/`Explicit`), the sidecar's own listeners
    //   (15001/15006, and 15008 for HBONE) would bind on the NODE, colliding
    //   with host ports and exposing a mesh inbound listener node-wide, while
    //   having nothing captured to proxy.
    //
    // So skip the whole injection, not merely the capture half -- this matches
    // Istio's `injectRequired()` host-networking skip. Evaluated BEFORE the
    // opt-in gate so no opt-in spelling #4213 now accepts -- nor
    // `require_annotation=false` -- can re-enable it. (Opt-OUT is honored first
    // above only because it reaches the same skip outcome.)
    if pod_uses_host_network(pod) {
        return InjectionDecision::SkipHostNetwork;
    }

    if !config.require_annotation {
        return InjectionDecision::Inject;
    }

    let opted_in = inject_annotation_opts_in(
        annotations
            .and_then(|m| m.get("ferrum.io/inject"))
            .and_then(Value::as_str),
    ) || inject_annotation_opts_in(
        annotations
            .and_then(|m| m.get("sidecar.istio.io/inject"))
            .and_then(Value::as_str),
    ) || mesh_label_opts_in(
        labels
            .and_then(|m| m.get("ferrum.io/mesh"))
            .and_then(Value::as_str),
    );

    if opted_in {
        InjectionDecision::Inject
    } else {
        InjectionDecision::SkipNotSelected
    }
}

/// Whether the pod requests the node's network namespace.
///
/// The apiserver serializes `spec.hostNetwork` as a JSON boolean, but this
/// guard protects a node-wide outage, so the stringly-typed spelling is
/// accepted too: a hand-rolled or proxied AdmissionReview that sends
/// `"hostNetwork": "true"` must not slip past into the iptables path.
fn pod_uses_host_network(pod: &Value) -> bool {
    match pod.pointer("/spec/hostNetwork") {
        Some(Value::Bool(value)) => *value,
        Some(Value::String(value)) => value.eq_ignore_ascii_case("true"),
        _ => false,
    }
}

/// Best-effort pod identity for skip logs. Controller-created pods reach a
/// CREATE admission with only `generateName` set, so fall back to it before
/// giving up.
fn pod_display_name(pod: &Value) -> &str {
    pod.pointer("/metadata/name")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            pod.pointer("/metadata/generateName")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or("<unnamed>")
}

fn reject_reserved_name_conflicts(pod: &Value, config: &InjectorConfig) -> Result<(), String> {
    if named_container(pod, "/spec/containers", SIDECAR_CONTAINER_NAME).is_some() {
        return Err(
            "pod spec already defines reserved container name ferrum-edge in spec.containers; \
Ferrum now injects a Kubernetes native sidecar under spec.initContainers \
(restartPolicy: Always, Kubernetes 1.29+). Recreate the pod so the webhook \
can inject the new shape"
                .to_string(),
        );
    }

    if named_container(pod, "/spec/initContainers", SIDECAR_CONTAINER_NAME).is_some() {
        return Err(
            "pod spec already defines reserved init container name ferrum-edge; refusing injection"
                .to_string(),
        );
    }

    if config.capture_mode == CaptureMode::Iptables
        && named_container(pod, "/spec/initContainers", INIT_CONTAINER_NAME).is_some()
    {
        return Err(
            "pod spec already defines reserved init container name ferrum-edge-init; \
refusing injection"
                .to_string(),
        );
    }

    Ok(())
}

fn log_unrecognized_inject_annotation(
    annotations: Option<&serde_json::Map<String, Value>>,
    key: &str,
) {
    let raw = annotations.and_then(|m| m.get(key)).and_then(Value::as_str);
    if !inject_annotation_is_unrecognized(raw) {
        return;
    }
    warn!(
        annotation = key,
        value = raw,
        "Unrecognized inject annotation bool; refusing injection (fail closed)"
    );
}

fn log_unrecognized_mesh_label(labels: Option<&serde_json::Map<String, Value>>) {
    let raw = labels
        .and_then(|m| m.get("ferrum.io/mesh"))
        .and_then(Value::as_str);
    if !mesh_label_is_unrecognized(raw) {
        return;
    }
    warn!(
        label = "ferrum.io/mesh",
        value = raw,
        "Unrecognized mesh label; refusing injection (fail closed)"
    );
}

fn ensure_metadata_annotations(pod: &Value, patch: &mut Vec<JsonPatchOperation>) {
    if pod.pointer("/metadata/annotations").is_none() {
        patch.push(JsonPatchOperation {
            op: "add",
            path: "/metadata/annotations".to_string(),
            value: Some(json!({})),
        });
    }
}

fn require_application_containers(pod: &Value) -> Result<(), String> {
    match pod.pointer("/spec/containers") {
        Some(Value::Array(containers)) if !containers.is_empty() => Ok(()),
        Some(Value::Array(_)) | None => Err(
            "pod spec has no application containers; refusing to inject a native sidecar \
that Kubernetes would reject (a Pod must have at least one non-sidecar container)"
                .to_string(),
        ),
        Some(_) => Err(
            "pod spec.containers is not an array; refusing injection rather than emitting \
a patch Kubernetes would reject"
                .to_string(),
        ),
    }
}

fn ensure_init_containers(pod: &Value, patch: &mut Vec<JsonPatchOperation>) -> Result<(), String> {
    match pod.pointer("/spec/initContainers") {
        None => {
            patch.push(JsonPatchOperation {
                op: "add",
                path: "/spec/initContainers".to_string(),
                value: Some(json!([])),
            });
            Ok(())
        }
        Some(Value::Array(_)) => Ok(()),
        Some(_) => Err(
            "pod spec.initContainers is not an array; refusing injection rather than \
emitting a patch Kubernetes would reject"
                .to_string(),
        ),
    }
}

fn named_container<'a>(pod: &'a Value, pointer: &str, name: &str) -> Option<&'a Value> {
    pod.pointer(pointer)
        .and_then(Value::as_array)
        .and_then(|containers| {
            containers
                .iter()
                .find(|container| container.get("name").and_then(Value::as_str) == Some(name))
        })
}

fn pod_namespace(
    pod: &Value,
    admission_namespace: Option<&str>,
    config: &InjectorConfig,
) -> String {
    admission_namespace
        .filter(|value| !value.trim().is_empty())
        .or_else(|| {
            pod.pointer("/metadata/namespace")
                .and_then(Value::as_str)
                .filter(|value| !value.trim().is_empty())
        })
        .unwrap_or(&config.namespace)
        .to_string()
}

fn pod_service_account(pod: &Value) -> &str {
    pod.pointer("/spec/serviceAccountName")
        .and_then(Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .unwrap_or("default")
}

fn workload_spiffe_id(config: &InjectorConfig, pod: &Value, namespace: &str) -> String {
    format!(
        "spiffe://{}/ns/{namespace}/sa/{}",
        config.trust_domain,
        pod_service_account(pod)
    )
}

/// Whether the injected **Sidecar** should capture+relay UDP egress.
///
/// **Enabled (#1808).** The Sidecar mesh-mTLS datagram relay
/// (`MeshMtlsConnectionPool::open_datagram_tunnel`) makes Sidecar the FIRST
/// topology with a working end-to-end UDP path: the mesh runtime binds the UDP
/// capture listener for Sidecar (`MeshRuntime::udp_capture_listener` is gated to
/// Ambient OR Sidecar), the egress datapath relays each captured datagram over a
/// `udp`-marked mesh-mTLS CONNECT (`:15006`), and the destination unframes it
/// into a local `UdpSocket`. The injector only ever produces **Sidecar** pods
/// (`FERRUM_MESH_TOPOLOGY=sidecar`), so this central switch ENABLES the three
/// pod-side surfaces TOGETHER — the init container's UDP TPROXY rules, the
/// sidecar's runtime-enable env (`FERRUM_MESH_CAPTURE_UDP_ENABLED`/`_PORT`/
/// `_TPROXY_MARK`), and the transparent-bind capability (`NET_ADMIN`) — so an
/// injected Sidecar with `udp_capture_enabled` both binds the listener and
/// diverts UDP into it, matching the runtime listener gate. All three remain
/// behind the operator's `udp_capture_enabled` flag (default-off). (The
/// node-agent / ambient host-netns path installs no UDP TPROXY rules — see
/// `capture::udp_tproxy_commands_for_family`'s `host_netns` short-circuit — and
/// ambient's UDP producer is still deferred (F4.3 / #1803), so this gate does NOT
/// touch that path.)
const fn sidecar_udp_capture_supported() -> bool {
    true
}

/// Whether an injected Sidecar should ACTUALLY receive the pod-side UDP capture
/// surfaces (init TPROXY rules + runtime-enable env + `NET_ADMIN`). Beyond the
/// operator's `udp_capture_enabled` flag and the central
/// [`sidecar_udp_capture_supported`] switch, this REQUIRES `CaptureMode::Iptables`
/// (codex r1): the UDP TPROXY producer is the iptables init container, which
/// `build_sidecar_patch_for_namespace` only adds in `CaptureMode::Iptables`; the
/// eBPF path is TCP-only with no UDP producer, and `Explicit` mode installs no
/// init container at all. In those modes, enabling the flag would bind a
/// transparent UDP listener with NOTHING feeding it (UDP never captured/relayed
/// despite the opt-in), so gate the three surfaces on the iptables producer.
fn sidecar_udp_capture_active(config: &InjectorConfig) -> bool {
    config.udp_capture_enabled
        && sidecar_udp_capture_supported()
        && config.capture_mode == CaptureMode::Iptables
}

/// Whether this pod's rendered capture plan actually installs `ip6tables`
/// REDIRECT rules, so the sidecar must plan an IPv6-capable TCP capture
/// listener (issue #4271).
///
/// Gated on `CaptureMode::Iptables` for the same reason
/// [`sidecar_udp_capture_active`] is: the netfilter rules come from the iptables
/// init container, which `build_sidecar_patch_for_namespace` only adds in that
/// mode, so no other mode can produce the IPv6 REDIRECTs this flag describes.
///
/// A `capture_config` error resolves to `false` here rather than being
/// propagated: the same call inside [`init_container`] fails the whole
/// admission, so the sidecar env is never rendered from a config this rejects.
fn sidecar_capture_ipv6_active(config: &InjectorConfig, pod: &Value) -> bool {
    config.capture_mode == CaptureMode::Iptables
        && capture_config(config, pod)
            .map(|capture| !IptablesPlan::for_config(&capture).v6_commands.is_empty())
            .unwrap_or(false)
}

fn sidecar_env(config: &InjectorConfig, pod: &Value, namespace: &str) -> Vec<Value> {
    let mut env = vec![
        json!({"name": "FERRUM_MODE", "value": "mesh"}),
        json!({"name": "FERRUM_NAMESPACE", "value": namespace}),
        json!({"name": "FERRUM_MESH_TOPOLOGY", "value": "sidecar"}),
        json!({"name": "FERRUM_MESH_CAPTURE_MODE", "value": format!("{:?}", config.capture_mode).to_ascii_lowercase()}),
        json!({"name": "FERRUM_MESH_WORKLOAD_SPIFFE_ID", "value": workload_spiffe_id(config, pod, namespace)}),
    ];
    // Sidecar UDP capture is ENABLED (#1808): the init container installs the UDP
    // TPROXY rules (see `capture_config`) and the mesh runtime binds the UDP
    // listener for Sidecar, so push the runtime-enable env (and the TPROXY mark,
    // kept consistent with the init container's reinjection mark). Routed through
    // the same `sidecar_udp_capture_supported()` switch the rule emission uses so
    // the three pod-side surfaces stay consistent; all gated behind the operator's
    // `udp_capture_enabled` flag (default-off).
    if sidecar_udp_capture_active(config) {
        env.push(json!({"name": "FERRUM_MESH_CAPTURE_UDP_ENABLED", "value": "true"}));
        env.push(json!({
            "name": "FERRUM_MESH_CAPTURE_UDP_PORT",
            "value": config.udp_outbound_port.to_string()
        }));
        env.push(json!({
            "name": "FERRUM_MESH_TPROXY_MARK",
            "value": config.tproxy_mark.to_string()
        }));
    }
    // Tell the sidecar which address families its capture listeners must serve
    // (issue #4271). The init container emits `ip6tables` REDIRECT rules
    // whenever the pod's resolved capture scope carries an IPv6 CIDR; without
    // this signal the runtime would bind an IPv4-only listener and every
    // captured IPv6 connection would be refused with `ECONNREFUSED` while the
    // pod reports ready. Derived from the SAME rendered plan the init container
    // runs, so producer and consumer cannot disagree.
    if sidecar_capture_ipv6_active(config, pod) {
        env.push(json!({"name": "FERRUM_MESH_CAPTURE_IPV6_ENABLED", "value": "true"}));
    }
    env.extend(
        config
            .sidecar_env
            .iter()
            .map(|(name, value)| json!({"name": name, "value": value})),
    );
    if let Some(secret_ref) = &config.jwt_secret_ref {
        env.push(json!({
            "name": "FERRUM_CP_DP_GRPC_JWT_SECRET",
            "valueFrom": {
                "secretKeyRef": {
                    "name": secret_ref.name,
                    "key": secret_ref.key
                }
            }
        }));
    }
    env
}

fn sidecar_container(config: &InjectorConfig, pod: &Value, namespace: &str) -> Value {
    // The sidecar normally drops ALL capabilities (it runs as PROXY_UID). UDP
    // TPROXY capture is the exception (the capture listener binds an
    // `IP_TRANSPARENT` UDP socket, which on Linux needs `NET_ADMIN`). Sidecar UDP
    // capture is ENABLED (#1808): when `udp_capture_enabled` is on the runtime
    // binds the transparent UDP listener and the init container installs the UDP
    // rules, so authorize the transparent bind by adding `NET_ADMIN`. Gated on the
    // same `sidecar_udp_capture_supported()` switch as the listener + rules so the
    // capability appears together with them; otherwise keep the drop-ALL,
    // zero-capability posture.
    let capabilities = if sidecar_udp_capture_active(config) {
        json!({"drop": ["ALL"], "add": ["NET_ADMIN"]})
    } else {
        json!({"drop": ["ALL"]})
    };
    json!({
        "name": "ferrum-edge",
        "image": config.sidecar_image,
        "imagePullPolicy": "IfNotPresent",
        "args": ["run"],
        "securityContext": {
            "runAsUser": config.proxy_uid.unwrap_or(DEFAULT_PROXY_UID),
            "runAsNonRoot": true,
            "allowPrivilegeEscalation": false,
            "readOnlyRootFilesystem": true,
            "capabilities": capabilities,
            "seccompProfile": {"type": "RuntimeDefault"}
        },
        "resources": {
            "requests": {
                "cpu": config.sidecar_resources.cpu_request.as_str(),
                "memory": config.sidecar_resources.memory_request.as_str()
            },
            "limits": {
                "cpu": config.sidecar_resources.cpu_limit.as_str(),
                "memory": config.sidecar_resources.memory_limit.as_str()
            }
        },
        "ports": [
            {"containerPort": 15001, "name": "outbound"},
            {"containerPort": 15006, "name": "inbound"}
        ],
        "restartPolicy": "Always",
        "startupProbe": sidecar_exec_health_probe(
            SIDECAR_STARTUP_PROBE_PERIOD_SECONDS,
            SIDECAR_STARTUP_PROBE_FAILURE_THRESHOLD,
        ),
        "readinessProbe": sidecar_exec_health_probe(
            SIDECAR_READINESS_PROBE_PERIOD_SECONDS,
            SIDECAR_READINESS_PROBE_FAILURE_THRESHOLD,
        ),
        "env": sidecar_env(config, pod, namespace)
    })
}

/// Exec probe against loopback admin `/health` (not `/live`). Mesh sets
/// `startup_ready` only after the first admissible slice is applied and
/// capture listeners are bound, so this probe stays unready until traffic
/// can actually be served. Exec targets 127.0.0.1 inside the container and
/// therefore is not captured by inbound iptables redirect.
fn sidecar_exec_health_probe(period_seconds: u64, failure_threshold: u64) -> Value {
    json!({
        "exec": {
            "command": [
                SIDECAR_HEALTH_BINARY,
                "health",
                "-p",
                SIDECAR_HEALTH_ADMIN_PORT,
                "--host",
                "127.0.0.1"
            ]
        },
        "periodSeconds": period_seconds,
        "timeoutSeconds": 1,
        "failureThreshold": failure_threshold
    })
}

fn init_container(config: &InjectorConfig, pod: &Value) -> Result<Value, String> {
    let plan = IptablesPlan::for_config(&capture_config(config, pod)?);
    let script = plan.script();
    Ok(json!({
        "name": "ferrum-edge-init",
        "image": config.sidecar_image,
        "imagePullPolicy": "IfNotPresent",
        "securityContext": {
            "runAsUser": 0,
            "runAsNonRoot": false,
            "allowPrivilegeEscalation": false,
            // NET_ADMIN already covers everything UDP TPROXY capture needs
            // (the TPROXY + MARK targets, the owner-match, the fwmark `ip rule`,
            // and `ip route add local` into the dedicated table — including the
            // OUTPUT-MARK->lo-reroute->PREROUTING-TPROXY locally-generated egress
            // loop), so no extra capability is required when `udp_capture_enabled`
            // is on. NET_RAW remains for the TCP path.
            "capabilities": {
                "drop": ["ALL"],
                "add": ["NET_ADMIN", "NET_RAW"]
            },
            "seccompProfile": {"type": "RuntimeDefault"}
        },
        "resources": {
            "requests": {
                "cpu": config.init_resources.cpu_request.as_str(),
                "memory": config.init_resources.memory_request.as_str()
            },
            "limits": {
                "cpu": config.init_resources.cpu_limit.as_str(),
                "memory": config.init_resources.memory_limit.as_str()
            }
        },
        "env": [
            {"name": "FERRUM_MESH_CAPTURE_MODE", "value": "iptables"},
            {"name": "FERRUM_MESH_PROXY_UID", "value": config.proxy_uid.unwrap_or(DEFAULT_PROXY_UID).to_string()},
            {"name": "FERRUM_MESH_IP6TABLES_ENABLED", "value": config.ip6tables_mode.as_env_value()}
        ],
        "command": ["/bin/sh", "-c"],
        "args": [script]
    }))
}

fn capture_config(config: &InjectorConfig, pod: &Value) -> Result<CaptureConfig, String> {
    let annotations = pod
        .pointer("/metadata/annotations")
        .and_then(Value::as_object);

    let mut capture = CaptureConfig::explicit(15006, 15001);
    capture.mode = config.capture_mode;
    capture.proxy_uid = Some(config.proxy_uid.unwrap_or(DEFAULT_PROXY_UID));
    let include_outbound_ports = include_outbound_ports_for_pod(pod)?;
    capture.include_all_outbound_ports = include_outbound_ports.all_ports;
    capture.include_outbound_ports = include_outbound_ports.ports;
    capture.exclude_ports = exclude_outbound_ports_for_pod(config, pod)?;
    capture.exclude_inbound_ports = exclude_inbound_ports_for_pod(config, pod)?;
    capture.ip6tables_mode = config.ip6tables_mode;
    // UDP TPROXY capture (F3 §3.3 Stage 2), flag-gated default-off. When off the
    // emitted plan contains no mangle/TPROXY rules at all. Sidecar UDP egress is
    // ENABLED (#1808) and the injector only produces Sidecar pods, so the rules
    // are installed whenever the operator sets `udp_capture_enabled`: the mesh
    // runtime binds the Sidecar UDP listener and the egress datapath relays the
    // datagram over a mesh-mTLS CONNECT. Routed through the same
    // `sidecar_udp_capture_supported()` switch as the runtime-enable env and the
    // transparent-bind capability so the three pod-side surfaces stay consistent.
    capture.udp_capture_enabled = sidecar_udp_capture_active(config);
    capture.udp_outbound_port = config.udp_outbound_port;
    capture.tproxy_mark = config.tproxy_mark;

    // CIDR resolution layered on top of injector-level defaults:
    //   - `includeOutboundIPRanges` REPLACES the env-derived include list when
    //     present (Istio semantics: include-overrides-include).
    //   - `excludeOutboundIPRanges` APPENDS to the env-derived exclude list.
    //
    // An annotation that parses to zero CIDRs (e.g. `""`, `" , , "`, `","`) is
    // treated as absent and falls through to the env-derived include list.
    // Without this guard the catch-all `-d <cidr> -j REDIRECT` rules would not
    // be emitted at all and ALL outbound traffic would silently bypass the
    // proxy.
    let include_annotation = annotations
        .and_then(|m| m.get(ISTIO_INCLUDE_OUTBOUND_IP_RANGES_ANNOTATION))
        .and_then(Value::as_str);
    let include_annotation_cidrs = include_annotation.map(|raw| parse_cidr_list_env(Some(raw)));
    let (resolved_include, include_cidrs_explicit) = match include_annotation_cidrs {
        Some(cidrs) if !cidrs.is_empty() => {
            validate_cidr_list(&cidrs).map_err(|e| {
                format!("invalid {ISTIO_INCLUDE_OUTBOUND_IP_RANGES_ANNOTATION}: {e}")
            })?;
            (cidrs, true)
        }
        _ if !config.include_outbound_cidrs.is_empty() => {
            (config.include_outbound_cidrs.clone(), true)
        }
        _ => (vec!["0.0.0.0/0".to_string()], false),
    };
    capture.include_cidrs = resolved_include;
    capture.include_cidrs_explicit = include_cidrs_explicit;

    let mut resolved_exclude = config.exclude_outbound_cidrs.clone();
    if let Some(raw) = annotations
        .and_then(|m| m.get(ISTIO_EXCLUDE_OUTBOUND_IP_RANGES_ANNOTATION))
        .and_then(Value::as_str)
    {
        let annotation_cidrs = parse_cidr_list_env(Some(raw));
        if !annotation_cidrs.is_empty() {
            validate_cidr_list(&annotation_cidrs).map_err(|e| {
                format!("invalid {ISTIO_EXCLUDE_OUTBOUND_IP_RANGES_ANNOTATION}: {e}")
            })?;
            resolved_exclude.extend(annotation_cidrs);
        }
    }
    // Deduplicate while preserving order so iptables rule emission stays stable.
    let mut seen = std::collections::HashSet::new();
    resolved_exclude.retain(|cidr| seen.insert(cidr.clone()));
    capture.exclude_cidrs = resolved_exclude;

    Ok(capture)
}

// includeOutboundPorts is annotation-only: unlike excludeOutboundPorts, there
// is no injector-level/env default that seeds this list. The parser lives in
// `crate::capture` so the node-agent eBPF backend (`src/modes/node_agent.rs`)
// reads the same annotations through the same code path.
fn include_outbound_ports_for_pod(pod: &Value) -> Result<IncludeOutboundPorts, String> {
    let annotations = pod
        .pointer("/metadata/annotations")
        .and_then(Value::as_object);
    let lookup = |key: &'static str| -> (&'static str, Option<&str>) {
        let value = annotations
            .and_then(|annotations| annotations.get(key))
            .and_then(Value::as_str);
        (key, value)
    };
    include_outbound_ports_from_annotations([
        lookup(ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION),
        lookup(FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION),
    ])
}

fn exclude_outbound_ports_for_pod(
    config: &InjectorConfig,
    pod: &Value,
) -> Result<Vec<u16>, String> {
    let annotations = pod
        .pointer("/metadata/annotations")
        .and_then(Value::as_object);
    let mut ports = config.exclude_outbound_ports.clone();
    for key in [
        ISTIO_EXCLUDE_OUTBOUND_PORTS_ANNOTATION,
        FERRUM_EXCLUDE_OUTBOUND_PORTS_ANNOTATION,
    ] {
        let annotation_ports = parse_port_list(
            annotations
                .and_then(|annotations| annotations.get(key))
                .and_then(Value::as_str),
        )
        .map_err(|e| format!("invalid {key}: {e}"))?;
        ports.extend(annotation_ports);
    }
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

fn exclude_inbound_ports_for_pod(config: &InjectorConfig, pod: &Value) -> Result<Vec<u16>, String> {
    let annotations = pod
        .pointer("/metadata/annotations")
        .and_then(Value::as_object);
    let mut ports = config.exclude_inbound_ports.clone();
    for key in [
        ISTIO_EXCLUDE_INBOUND_PORTS_ANNOTATION,
        FERRUM_EXCLUDE_INBOUND_PORTS_ANNOTATION,
    ] {
        let annotation_ports = parse_port_list(
            annotations
                .and_then(|annotations| annotations.get(key))
                .and_then(Value::as_str),
        )
        .map_err(|e| format!("invalid {key}: {e}"))?;
        ports.extend(annotation_ports);
    }
    ports.extend(inbound_probe_ports_for_pod(pod)?);
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
}

/// HTTP `httpGet` and TCP `tcpSocket` probe ports on every container in the
/// pod, resolved against that container's named `ports` when the probe uses
/// a name. `exec` and `grpc` probes are skipped: they have no HTTP/TCP
/// kubelet port to exclude. Unresolved or ambiguous names fail admission
/// rather than leaving the probe captured by the inbound catch-all.
fn inbound_probe_ports_for_pod(pod: &Value) -> Result<Vec<u16>, String> {
    let mut ports = Vec::new();
    for pointer in POD_CONTAINER_LIST_POINTERS {
        let Some(containers) = pod.pointer(pointer).and_then(Value::as_array) else {
            continue;
        };
        for container in containers {
            collect_container_probe_ports(container, &mut ports)?;
        }
    }
    Ok(ports)
}

fn collect_container_probe_ports(container: &Value, ports: &mut Vec<u16>) -> Result<(), String> {
    let container_name = container_display_name(container);
    for probe_field in CONTAINER_PROBE_FIELDS {
        let Some(probe) = container.get(probe_field) else {
            continue;
        };
        if let Some(port) =
            inbound_exclusion_port_for_probe(container, container_name, probe_field, probe)?
        {
            ports.push(port);
        }
    }
    Ok(())
}

fn container_display_name(container: &Value) -> &str {
    container
        .get("name")
        .and_then(Value::as_str)
        .filter(|name| !name.trim().is_empty())
        .unwrap_or("<unnamed>")
}

fn inbound_exclusion_port_for_probe(
    container: &Value,
    container_name: &str,
    probe_field: &str,
    probe: &Value,
) -> Result<Option<u16>, String> {
    if let Some(http_get) = probe.get("httpGet") {
        return resolve_probe_handler_port(
            container,
            container_name,
            probe_field,
            "httpGet",
            http_get,
        )
        .map(Some);
    }
    if let Some(tcp_socket) = probe.get("tcpSocket") {
        return resolve_probe_handler_port(
            container,
            container_name,
            probe_field,
            "tcpSocket",
            tcp_socket,
        )
        .map(Some);
    }
    Ok(None)
}

fn resolve_probe_handler_port(
    container: &Value,
    container_name: &str,
    probe_field: &str,
    handler: &str,
    handler_value: &Value,
) -> Result<u16, String> {
    let Some(port) = handler_value.get("port") else {
        return Err(format!(
            "container '{container_name}' {probe_field}.{handler} is missing port; \
refusing injection"
        ));
    };
    match port {
        Value::Number(number) => json_u16_port(number).ok_or_else(|| {
            format!(
                "container '{container_name}' {probe_field}.{handler} port is not \
an integer in 1-65535; refusing injection"
            )
        }),
        Value::String(raw) => {
            let trimmed = raw.trim();
            if trimmed.is_empty() {
                return Err(format!(
                    "container '{container_name}' {probe_field}.{handler} port is \
empty; refusing injection"
                ));
            }
            if trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
                parse_numeric_probe_port(trimmed).ok_or_else(|| {
                    format!(
                        "container '{container_name}' {probe_field}.{handler} port \
'{trimmed}' is not an integer in 1-65535; refusing injection"
                    )
                })
            } else {
                resolve_named_container_port(container, container_name, probe_field, trimmed)
            }
        }
        _ => Err(format!(
            "container '{container_name}' {probe_field}.{handler} port must be a \
number or name; refusing injection"
        )),
    }
}

fn json_u16_port(number: &serde_json::Number) -> Option<u16> {
    number
        .as_u64()
        .and_then(|value| u16::try_from(value).ok())
        .filter(|port| *port != 0)
}

fn parse_numeric_probe_port(raw: &str) -> Option<u16> {
    raw.parse::<u16>().ok().filter(|port| *port != 0)
}

fn resolve_named_container_port(
    container: &Value,
    container_name: &str,
    probe_field: &str,
    port_name: &str,
) -> Result<u16, String> {
    let unresolved = || {
        format!(
            "container '{container_name}' {probe_field} names port '{port_name}' \
which is not declared in that container's ports; refusing injection so the \
kubelet probe is not captured by inbound mesh redirect"
        )
    };
    let Some(declared_ports) = container.get("ports").and_then(Value::as_array) else {
        return Err(unresolved());
    };
    let mut resolved = None;
    for declared in declared_ports {
        if declared.get("name").and_then(Value::as_str) != Some(port_name) {
            continue;
        }
        let Some(container_port) = declared
            .get("containerPort")
            .and_then(json_value_port_number)
        else {
            return Err(format!(
                "container '{container_name}' port '{port_name}' has a \
containerPort that is not an integer in 1-65535; refusing injection"
            ));
        };
        match resolved {
            Some(existing) if existing != container_port => {
                return Err(format!(
                    "container '{container_name}' declares port name '{port_name}' \
on more than one containerPort; refusing injection"
                ));
            }
            Some(_) => {}
            None => resolved = Some(container_port),
        }
    }
    resolved.ok_or_else(unresolved)
}

fn json_value_port_number(value: &Value) -> Option<u16> {
    match value {
        Value::Number(number) => json_u16_port(number),
        Value::String(raw) => parse_numeric_probe_port(raw.trim()),
        _ => None,
    }
}

fn json_response(status: StatusCode, value: Value) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(value.to_string())));
    *response.status_mut() = status;
    response.headers_mut().insert(
        hyper::header::CONTENT_TYPE,
        hyper::header::HeaderValue::from_static("application/json"),
    );
    response
}

fn response(status: StatusCode, body: impl Into<String>) -> Response<Full<Bytes>> {
    let mut response = Response::new(Full::new(Bytes::from(body.into())));
    *response.status_mut() = status;
    response
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::EnvConfig;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::task::JoinHandle;
    use tokio::time::{Duration, timeout};

    fn test_resources(
        cpu_request: &str,
        memory_request: &str,
        cpu_limit: &str,
        memory_limit: &str,
    ) -> ContainerResourceConfig {
        ContainerResourceConfig::new(cpu_request, memory_request, cpu_limit, memory_limit)
    }

    fn test_config(require_annotation: bool, capture_mode: CaptureMode) -> InjectorConfig {
        InjectorConfig {
            listen_addr: "127.0.0.1:9443".parse().expect("test addr"),
            namespace: "default".to_string(),
            sidecar_image: "ferrum-edge:test".to_string(),
            sidecar_env: vec![(
                "FERRUM_DP_CP_GRPC_URLS".to_string(),
                "http://cp:50051".to_string(),
            )],
            jwt_secret_ref: Some(SecretKeyRef {
                name: "ferrum-edge-secrets".to_string(),
                key: "cp-dp-grpc-jwt-secret".to_string(),
            }),
            sidecar_resources: default_sidecar_resources(),
            init_resources: default_init_resources(),
            require_annotation,
            capture_mode,
            proxy_uid: Some(1337),
            exclude_outbound_ports: Vec::new(),
            exclude_inbound_ports: Vec::new(),
            include_outbound_cidrs: Vec::new(),
            exclude_outbound_cidrs: Vec::new(),
            ip6tables_mode: Ip6TablesMode::Auto,
            udp_capture_enabled: false,
            udp_outbound_port: crate::capture::DEFAULT_UDP_OUTBOUND_PORT,
            tproxy_mark: crate::capture::DEFAULT_TPROXY_MARK,
            trust_domain: "cluster.local".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
            // Tests drive plaintext loopback servers; production fail-closed
            // behavior is covered separately via `from_env_config`.
            allow_plaintext: true,
            tls_handshake_timeout_seconds: 10,
            http_header_read_timeout_seconds: 10,
            admission_review_max_body_bytes: DEFAULT_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB
                * MIB_BYTES,
        }
    }

    // `from_env_config` reads process-global env vars via `resolve_ferrum_var`.
    // Tests that exercise it serialise through this lock and restore the prior
    // state so they do not race sibling tests in the same process.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Restores captured env state on drop so a panic inside the test body
    /// (e.g. a failing assertion) cannot leak process-global env into sibling
    /// tests. `ENV_LOCK` outlives this guard, so the restore stays serialised.
    struct EnvRestore(Vec<(String, Option<String>)>);

    impl Drop for EnvRestore {
        fn drop(&mut self) {
            for (key, value) in &self.0 {
                // SAFETY: ENV_LOCK is held for this guard's lifetime.
                unsafe {
                    match value {
                        Some(v) => std::env::set_var(key, v),
                        None => std::env::remove_var(key),
                    }
                }
            }
        }
    }

    fn with_injector_env_lock<F: FnOnce()>(vars: &[(&str, Option<&str>)], f: F) {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|p| p.into_inner());
        let _restore = EnvRestore(
            vars.iter()
                .map(|(key, _)| ((*key).to_string(), std::env::var(key).ok()))
                .collect(),
        );
        for (key, value) in vars {
            // SAFETY: ENV_LOCK serialises test access to the process-global env.
            unsafe {
                match value {
                    Some(v) => std::env::set_var(key, v),
                    None => std::env::remove_var(key),
                }
            }
        }
        f();
    }

    async fn spawn_injector_test_server(config: InjectorConfig) -> (SocketAddr, JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let config = Arc::new(config);
        let server = tokio::spawn(async move {
            let (stream, remote_addr) = listener.accept().await.unwrap();
            serve_injector_connection(stream, config, remote_addr).await;
        });
        (addr, server)
    }

    async fn read_raw_http_response(addr: SocketAddr, request: &[u8]) -> String {
        let mut stream = TcpStream::connect(addr).await.unwrap();
        stream.write_all(request).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        String::from_utf8(response).unwrap()
    }

    async fn assert_server_finished(server: JoinHandle<()>) {
        timeout(Duration::from_secs(5), server)
            .await
            .expect("injector test server timed out")
            .expect("injector test server panicked");
    }

    fn patch_named_container<'a>(patch: &'a [JsonPatchOperation], name: &str) -> Option<&'a Value> {
        patch.iter().find_map(|op| {
            op.value
                .as_ref()
                .filter(|value| value.get("name").and_then(Value::as_str) == Some(name))
        })
    }

    fn patch_has_named_container(patch: &[JsonPatchOperation], name: &str) -> bool {
        patch_named_container(patch, name).is_some()
    }

    #[test]
    fn patch_requires_opt_in_by_default() {
        let pod = json!({"metadata": {"labels": {}}, "spec": {"containers": []}});
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Explicit),
            None,
        )
        .expect("patch");
        assert!(patch.is_empty());
    }

    #[test]
    fn patch_opts_in_via_istio_inject_annotation_true() {
        // Workloads migrating from Istio carry `sidecar.istio.io/inject: "true"`.
        // The Ferrum injector honors this as opt-in alongside its native
        // `ferrum.io/inject: "true"` and the `ferrum.io/mesh: "enabled"` label.
        let pod = json!({
            "metadata": {
                "annotations": {"sidecar.istio.io/inject": "true"}
            },
            "spec": {
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        )
        .expect("patch");

        assert!(
            patch_has_named_container(&patch, "ferrum-edge"),
            "expected Ferrum native sidecar to be injected"
        );
    }

    #[test]
    fn patch_rejects_reserved_sidecar_name_conflict() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {"ferrum.io/injected": "true"}
            },
            "spec": {
                "containers": [{"name": "ferrum-edge", "image": "ferrum-edge:latest"}]
            }
        });
        let err = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        )
        .expect_err("reserved name conflict should be rejected");
        assert!(err.contains("reserved container name ferrum-edge"));
    }

    #[test]
    fn patch_is_idempotent_for_an_already_injected_pod() {
        let config = test_config(true, CaptureMode::Iptables);
        let mut pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {"ferrum.io/injected": "true"}
            },
            "spec": {
                "serviceAccountName": "default",
                "containers": [{"name": "app", "image": "app:test"}],
                "initContainers": []
            }
        });
        let namespace = pod_namespace(&pod, None, &config);
        let sidecar = sidecar_container(&config, &pod, &namespace);
        let init = init_container(&config, &pod).expect("init container");
        pod["spec"]["initContainers"]
            .as_array_mut()
            .unwrap()
            .push(sidecar);
        pod["spec"]["initContainers"]
            .as_array_mut()
            .unwrap()
            .push(init);
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None)
            .expect("reinvocation should be accepted");
        assert!(patch.is_empty());
    }

    #[test]
    fn patch_rejects_generated_sidecar_shape_with_extra_fields() {
        let config = test_config(true, CaptureMode::Iptables);
        let mut pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {"ferrum.io/injected": "true"}
            },
            "spec": {
                "serviceAccountName": "default",
                "containers": [{"name": "app", "image": "app:test"}],
                "initContainers": []
            }
        });
        let namespace = pod_namespace(&pod, None, &config);
        let mut sidecar = sidecar_container(&config, &pod, &namespace);
        sidecar["securityContext"]["privileged"] = Value::Bool(true);
        let init = init_container(&config, &pod).expect("init container");
        pod["spec"]["initContainers"]
            .as_array_mut()
            .unwrap()
            .push(sidecar);
        pod["spec"]["initContainers"]
            .as_array_mut()
            .unwrap()
            .push(init);

        let error = build_sidecar_patch_for_namespace(&pod, &config, None)
            .expect_err("extra sidecar fields must not pass reinvocation validation");
        assert!(error.contains("reserved init container name ferrum-edge"));
    }

    #[test]
    fn patch_rejects_injected_marker_with_fake_reserved_containers() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {"ferrum.io/injected": "true"}
            },
            "spec": {
                "containers": [{"name": "ferrum-edge", "image": "attacker/fake:latest"}],
                "initContainers": [{"name": "ferrum-edge-init", "image": "attacker/fake:latest"}]
            }
        });
        let error = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        )
        .expect_err("observability marker must not bypass reserved-name validation");
        assert!(error.contains("reserved container name ferrum-edge"));
    }

    #[test]
    fn patch_rejects_reserved_init_name_conflict_in_iptables_mode() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"}
            },
            "spec": {
                "containers": [{"name": "app", "image": "app:test"}],
                "initContainers": [{"name": "ferrum-edge-init", "image": "fake:init"}]
            }
        });
        let err = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        )
        .expect_err("reserved init name conflict should be rejected");
        assert!(err.contains("reserved init container name ferrum-edge-init"));
    }

    #[test]
    fn patch_does_not_trust_spoofed_injected_annotation() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {"ferrum.io/injected": "true"}
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        )
        .expect("patch");
        assert!(patch_has_named_container(&patch, "ferrum-edge"));
        assert!(patch_has_named_container(&patch, "ferrum-edge-init"));
    }

    #[test]
    fn patch_injects_sidecar_when_enabled() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        )
        .expect("patch");

        assert!(
            patch_has_named_container(&patch, "ferrum-edge"),
            "expected Ferrum native sidecar to be injected"
        );
        assert!(patch_has_named_container(&patch, "ferrum-edge-init"));
        assert!(
            !patch.iter().any(|op| op.path == "/spec/containers/-"),
            "native sidecar must not be appended as an ordinary container"
        );
        let sidecar = patch_named_container(&patch, "ferrum-edge").expect("sidecar container");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let env = sidecar
            .get("env")
            .and_then(Value::as_array)
            .expect("sidecar env");
        assert_eq!(sidecar.get("args"), Some(&json!(["run"])));
        assert_eq!(
            sidecar.get("restartPolicy"),
            Some(&Value::String("Always".to_string()))
        );
        assert_eq!(
            sidecar.pointer("/startupProbe/exec/command"),
            Some(&json!([
                "/app/ferrum-edge",
                "health",
                "-p",
                "9000",
                "--host",
                "127.0.0.1"
            ]))
        );
        assert!(
            sidecar
                .pointer("/startupProbe/exec/command")
                .and_then(Value::as_array)
                .is_some_and(|command| {
                    !command.iter().any(|part| part.as_str() == Some("--live"))
                }),
            "startupProbe must wait on /health readiness, not /live"
        );
        assert_eq!(
            sidecar.pointer("/readinessProbe/exec/command"),
            sidecar.pointer("/startupProbe/exec/command")
        );
        assert_eq!(
            patch
                .iter()
                .find(|op| op.value.as_ref() == Some(sidecar))
                .map(|op| op.path.as_str()),
            Some("/spec/initContainers/0"),
            "native sidecar must be inserted first so later inits wait on startupProbe"
        );
        assert_eq!(
            patch
                .iter()
                .find(|op| op.value.as_ref() == Some(init))
                .map(|op| op.path.as_str()),
            Some("/spec/initContainers/1"),
            "iptables init must run after the native sidecar is ready"
        );
        assert_eq!(
            sidecar.pointer("/securityContext/capabilities/drop"),
            Some(&json!(["ALL"]))
        );
        assert_eq!(
            sidecar.pointer("/securityContext/readOnlyRootFilesystem"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            sidecar.pointer("/securityContext/seccompProfile/type"),
            Some(&Value::String("RuntimeDefault".to_string()))
        );
        assert_eq!(
            sidecar.pointer("/resources/limits/memory"),
            Some(&Value::String("256Mi".to_string()))
        );
        assert_eq!(
            init.pointer("/securityContext/runAsNonRoot"),
            Some(&Value::Bool(false))
        );
        assert_eq!(
            init.pointer("/securityContext/capabilities/drop"),
            Some(&json!(["ALL"]))
        );
        assert_eq!(
            init.pointer("/securityContext/capabilities/add"),
            Some(&json!(["NET_ADMIN", "NET_RAW"]))
        );
        assert_eq!(
            init.pointer("/securityContext/seccompProfile/type"),
            Some(&Value::String("RuntimeDefault".to_string()))
        );
        assert_eq!(
            init.pointer("/resources/limits/memory"),
            Some(&Value::String("128Mi".to_string()))
        );
        assert!(env.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("FERRUM_DP_CP_GRPC_URLS")
                && entry.get("value").and_then(Value::as_str) == Some("http://cp:50051")
        }));
        assert!(env.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
                && entry.get("value").and_then(Value::as_str)
                    == Some("spiffe://cluster.local/ns/default/sa/api")
        }));
        let jwt_secret = env
            .iter()
            .find(|entry| {
                entry.get("name").and_then(Value::as_str) == Some("FERRUM_CP_DP_GRPC_JWT_SECRET")
            })
            .expect("jwt secret env");
        assert!(jwt_secret.get("value").is_none());
        assert_eq!(
            jwt_secret.pointer("/valueFrom/secretKeyRef/name"),
            Some(&Value::String("ferrum-edge-secrets".to_string()))
        );
        assert_eq!(
            jwt_secret.pointer("/valueFrom/secretKeyRef/key"),
            Some(&Value::String("cp-dp-grpc-jwt-secret".to_string()))
        );
    }

    #[test]
    fn patch_creates_missing_init_containers_array_before_inserting_sidecar() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Explicit),
            None,
        )
        .expect("patch");

        let init_list_index = patch
            .iter()
            .position(|op| op.path == "/spec/initContainers")
            .expect("initContainers array guard");
        let sidecar_index = patch
            .iter()
            .position(|op| op.path == "/spec/initContainers/0")
            .expect("native sidecar insert");
        assert!(
            init_list_index < sidecar_index,
            "initContainers array must exist before inserting the native sidecar"
        );
        assert!(patch_has_named_container(&patch, "ferrum-edge"));
        assert!(!patch_has_named_container(&patch, "ferrum-edge-init"));
    }

    #[test]
    fn patch_rejects_pod_with_no_application_containers() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {}
        });
        let err = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Explicit),
            None,
        )
        .expect_err("empty spec must not emit a native-sidecar-only pod");
        assert!(err.contains("no application containers"));
    }

    #[test]
    fn patch_rejects_empty_application_container_list() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {"containers": []}
        });
        let err = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Explicit),
            None,
        )
        .expect_err("empty containers must not emit a native-sidecar-only pod");
        assert!(err.contains("no application containers"));
    }

    #[test]
    fn istio_disabled_inject_annotation_fails_closed() {
        let pod = json!({
            "metadata": {
                "annotations": {"sidecar.istio.io/inject": "disabled"}
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(false, CaptureMode::Explicit),
            None,
        )
        .expect("patch");

        assert!(
            patch.is_empty(),
            "Unrecognized sidecar.istio.io/inject values must fail closed rather than inject"
        );
    }

    #[test]
    fn istio_false_inject_annotation_spellings_opt_out() {
        for value in ["false", "False", "FALSE", "0", "f", "F"] {
            let pod = json!({
                "metadata": {
                    "labels": {"ferrum.io/mesh": "enabled"},
                    "annotations": {"sidecar.istio.io/inject": value}
                },
                "spec": {"containers": [{"name": "app", "image": "app:test"}]}
            });
            let patch = build_sidecar_patch_for_namespace(
                &pod,
                &test_config(true, CaptureMode::Explicit),
                None,
            )
            .expect("patch");
            assert!(
                patch.is_empty(),
                "sidecar.istio.io/inject={value:?} must opt out"
            );
        }
    }

    #[test]
    fn inject_annotation_true_spellings_opt_in() {
        for value in ["true", "True", "TRUE", "1", "t", "T"] {
            let pod = json!({
                "metadata": {
                    "annotations": {"ferrum.io/inject": value}
                },
                "spec": {
                    "serviceAccountName": "api",
                    "containers": [{"name": "app", "image": "app:test"}]
                }
            });
            let patch = build_sidecar_patch_for_namespace(
                &pod,
                &test_config(true, CaptureMode::Iptables),
                None,
            )
            .expect("patch");
            assert!(
                patch_has_named_container(&patch, "ferrum-edge"),
                "ferrum.io/inject={value:?} must opt in"
            );
        }
    }

    #[test]
    fn mesh_label_false_spellings_opt_out() {
        for value in [
            "false", "False", "FALSE", "0", "f", "F", "disabled", "Disabled",
        ] {
            let pod = json!({
                "metadata": {"labels": {"ferrum.io/mesh": value}},
                "spec": {"containers": [{"name": "app", "image": "app:test"}]}
            });
            let patch = build_sidecar_patch_for_namespace(
                &pod,
                &test_config(false, CaptureMode::Explicit),
                None,
            )
            .expect("patch");
            assert!(patch.is_empty(), "ferrum.io/mesh={value:?} must opt out");
        }
    }

    #[test]
    fn mesh_label_enabled_spellings_opt_in() {
        for value in ["enabled", "Enabled", "ENABLED"] {
            let pod = json!({
                "metadata": {"labels": {"ferrum.io/mesh": value}},
                "spec": {
                    "serviceAccountName": "api",
                    "containers": [{"name": "app", "image": "app:test"}]
                }
            });
            let patch = build_sidecar_patch_for_namespace(
                &pod,
                &test_config(true, CaptureMode::Iptables),
                None,
            )
            .expect("patch");
            assert!(
                patch_has_named_container(&patch, "ferrum-edge"),
                "ferrum.io/mesh={value:?} must opt in"
            );
        }
    }

    #[test]
    fn ferrum_mesh_disabled_label_opts_out() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "disabled"}},
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(false, CaptureMode::Explicit),
            None,
        )
        .expect("patch");

        assert!(
            patch.is_empty(),
            "Ferrum-native disabled label remains opt-out"
        );
    }

    fn host_network_pod(host_network: Value) -> Value {
        json!({
            "metadata": {
                "name": "kube-proxy-abcde",
                "namespace": "payments",
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {"ferrum.io/inject": "true"}
            },
            "spec": {
                "hostNetwork": host_network,
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        })
    }

    #[test]
    fn host_network_pod_is_not_injected_even_with_explicit_opt_in() {
        // A `hostNetwork` pod shares the node's netns, so the iptables init
        // container would REDIRECT the NODE's TCP into a proxy that is not
        // listening. Explicit opt-in must not be able to buy that.
        let pod = host_network_pod(Value::Bool(true));
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            Some("payments"),
        )
        .expect("host-network pod is admitted, not rejected");

        assert!(
            patch.is_empty(),
            "hostNetwork pod must receive neither a sidecar nor an init container, got {patch:?}"
        );
    }

    #[test]
    fn host_network_pod_is_not_injected_when_annotation_is_not_required() {
        // The reachable-by-default shape: a namespace running
        // `require_annotation=false` injects every pod it sees, including the
        // host-network ones.
        let mut pod = host_network_pod(Value::Bool(true));
        pod["metadata"]["labels"] = json!({});
        pod["metadata"]["annotations"] = json!({});
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(false, CaptureMode::Iptables),
            Some("payments"),
        )
        .expect("host-network pod is admitted, not rejected");

        assert!(
            patch.is_empty(),
            "hostNetwork skip must hold with require_annotation=false, got {patch:?}"
        );
    }

    #[test]
    fn host_network_skip_covers_capture_modes_without_an_init_container() {
        // Even with no capture producer, the sidecar's 15001/15006 listeners
        // would bind on the NODE, so the skip is not iptables-specific.
        for mode in [CaptureMode::Ebpf, CaptureMode::Explicit] {
            let config = test_config(true, mode);
            let pod = host_network_pod(Value::Bool(true));
            let patch = build_sidecar_patch_for_namespace(&pod, &config, Some("payments"))
                .expect("host-network pod is admitted, not rejected");
            assert!(
                patch.is_empty(),
                "hostNetwork pod must not be injected in {mode:?} mode, got {patch:?}"
            );
        }
    }

    #[test]
    fn host_network_skip_accepts_the_stringly_typed_spelling() {
        let pod = host_network_pod(Value::String("True".to_string()));
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            Some("payments"),
        )
        .expect("host-network pod is admitted, not rejected");

        assert!(
            patch.is_empty(),
            "a non-apiserver AdmissionReview spelling hostNetwork as a string must not slip past"
        );
    }

    #[test]
    fn pod_without_host_network_is_still_injected() {
        // Control for the skip: identical metadata, pod-scoped netns.
        for host_network in [Value::Bool(false), Value::Null] {
            let mut pod = host_network_pod(Value::Bool(true));
            pod["spec"]["hostNetwork"] = host_network.clone();
            let patch = build_sidecar_patch_for_namespace(
                &pod,
                &test_config(true, CaptureMode::Iptables),
                Some("payments"),
            )
            .expect("patch");

            assert!(
                patch_has_named_container(&patch, "ferrum-edge"),
                "expected sidecar container for hostNetwork={host_network:?}"
            );
            assert!(
                patch_has_named_container(&patch, "ferrum-edge-init"),
                "expected iptables init container for hostNetwork={host_network:?}"
            );
        }
    }

    #[test]
    fn injection_decision_distinguishes_host_network_from_an_ordinary_skip() {
        // The reason is what makes the skip loggable; a bool would flatten the
        // node-safety refusal into the steady-state not-selected outcome.
        let config = test_config(true, CaptureMode::Iptables);
        assert_eq!(
            injection_decision(&host_network_pod(Value::Bool(true)), &config),
            InjectionDecision::SkipHostNetwork
        );

        let mut opted_out = host_network_pod(Value::Bool(true));
        opted_out["metadata"]["annotations"] = json!({"ferrum.io/inject": "false"});
        assert_eq!(
            injection_decision(&opted_out, &config),
            InjectionDecision::SkipNotSelected,
            "an explicit opt-out reaches the same skip and stays quiet"
        );

        let mut meshed = host_network_pod(Value::Bool(true));
        meshed["spec"]["hostNetwork"] = Value::Bool(false);
        assert_eq!(
            injection_decision(&meshed, &config),
            InjectionDecision::Inject
        );
    }

    #[test]
    fn admission_response_admits_host_network_pod_without_a_patch() {
        // The API server rejects a `patchType` with no `patch` (and an empty
        // patch document is pointless churn), so the skip path must emit
        // neither -- while still admitting the pod.
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "host-net-1",
                "namespace": "payments",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "object": host_network_pod(Value::Bool(true))
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(false, CaptureMode::Iptables),
        )
        .expect("admission response");

        assert_eq!(
            response.pointer("/response/allowed"),
            Some(&Value::Bool(true)),
            "a hostNetwork pod is admitted, never denied: denying would break \
             creation of host-network system pods in a meshed namespace"
        );
        assert_eq!(response.pointer("/response/patch"), None);
        assert_eq!(response.pointer("/response/patchType"), None);
        assert_eq!(response.pointer("/response/status"), None);
        assert_eq!(
            response.pointer("/response/uid"),
            Some(&Value::String("host-net-1".to_string()))
        );
    }

    #[test]
    fn sidecar_capabilities_track_udp_capture_flag() {
        // Sidecar UDP capture is ENABLED (#1808): with the flag OFF the sidecar
        // keeps the drop-ALL, zero-capability posture; with the flag ON the
        // transparent UDP bind needs NET_ADMIN, so the sidecar grants it. The two
        // surfaces (this capability + the init-container rules + the runtime env)
        // re-enable together via `sidecar_udp_capture_supported()`.
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });

        // Flag OFF: zero capability.
        let mut config = test_config(true, CaptureMode::Iptables);
        config.udp_capture_enabled = false;
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let sidecar = patch_named_container(&patch, "ferrum-edge").expect("sidecar container");
        assert_eq!(
            sidecar.pointer("/securityContext/capabilities/drop"),
            Some(&json!(["ALL"]))
        );
        assert_eq!(
            sidecar.pointer("/securityContext/capabilities/add"),
            None,
            "UDP capture off ⇒ no added capability"
        );

        // Flag ON: NET_ADMIN added for the transparent UDP bind.
        let mut config = test_config(true, CaptureMode::Iptables);
        config.udp_capture_enabled = true;
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let sidecar = patch_named_container(&patch, "ferrum-edge").expect("sidecar container");
        assert_eq!(
            sidecar.pointer("/securityContext/capabilities/drop"),
            Some(&json!(["ALL"]))
        );
        assert_eq!(
            sidecar.pointer("/securityContext/capabilities/add"),
            Some(&json!(["NET_ADMIN"])),
            "UDP capture on ⇒ NET_ADMIN for the transparent bind"
        );
    }

    #[test]
    fn injected_sidecar_installs_udp_tproxy_rules_when_enabled() {
        // With FERRUM_MESH_CAPTURE_UDP_ENABLED set, the injected init container
        // emits the UDP mangle/TPROXY rules and the sidecar carries the
        // runtime-enable env (#1808): Sidecar UDP relay is enabled (mesh-mTLS
        // datagram tunnel), so captured UDP is diverted into the bound listener.
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.udp_capture_enabled = true;
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");

        // Init container: UDP TPROXY/mangle rules ARE emitted.
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");
        assert!(
            commands.contains("-p udp"),
            "enabled Sidecar UDP must emit `-p udp` rules: {commands}"
        );
        assert!(
            commands.contains("TPROXY"),
            "enabled Sidecar UDP must emit the TPROXY target: {commands}"
        );
        assert!(
            commands.contains("mangle"),
            "enabled Sidecar UDP must use the mangle table: {commands}"
        );

        // Sidecar container: runtime UDP-enable env IS set.
        let sidecar = patch_named_container(&patch, "ferrum-edge").expect("sidecar container");
        let env = sidecar
            .pointer("/env")
            .and_then(Value::as_array)
            .cloned()
            .expect("sidecar env");
        let udp_enable = env.iter().find(|e| {
            e.pointer("/name").and_then(Value::as_str) == Some("FERRUM_MESH_CAPTURE_UDP_ENABLED")
        });
        assert_eq!(
            udp_enable.and_then(|e| e.pointer("/value")),
            Some(&json!("true")),
            "enabled Sidecar UDP must set FERRUM_MESH_CAPTURE_UDP_ENABLED=true"
        );
        // The capture port + TPROXY mark env ride alongside it.
        assert!(
            env.iter().any(|e| {
                e.pointer("/name").and_then(Value::as_str) == Some("FERRUM_MESH_CAPTURE_UDP_PORT")
            }),
            "enabled Sidecar UDP must set FERRUM_MESH_CAPTURE_UDP_PORT"
        );
        assert!(
            env.iter().any(|e| {
                e.pointer("/name").and_then(Value::as_str) == Some("FERRUM_MESH_TPROXY_MARK")
            }),
            "enabled Sidecar UDP must set FERRUM_MESH_TPROXY_MARK"
        );
    }

    #[test]
    fn injected_sidecar_omits_udp_rules_when_capture_disabled() {
        // With the flag OFF, no UDP rules and no runtime-enable env (default-off
        // posture preserved).
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.udp_capture_enabled = false;
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");
        assert!(
            !commands.contains("-p udp"),
            "UDP capture off must emit no `-p udp` rules: {commands}"
        );
        let sidecar = patch_named_container(&patch, "ferrum-edge").expect("sidecar container");
        if let Some(env) = sidecar.pointer("/env").and_then(Value::as_array) {
            assert!(
                !env.iter().any(|e| {
                    e.pointer("/name").and_then(Value::as_str)
                        == Some("FERRUM_MESH_CAPTURE_UDP_ENABLED")
                }),
                "UDP capture off must not set FERRUM_MESH_CAPTURE_UDP_ENABLED"
            );
        }
    }

    #[test]
    fn patch_excludes_configured_and_annotated_outbound_ports() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundPorts": "5432, 9092",
                    "ferrum.io/excludeOutboundPorts": "15020"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.exclude_outbound_ports = vec![3306, 5432];

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        for port in [3306, 5432, 9092, 15020] {
            assert!(commands.contains(&format!("--dport {port} -j RETURN")));
        }
    }

    #[test]
    fn patch_includes_annotated_outbound_ports() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundPorts": "5432, 9092",
                    "ferrum.io/includeOutboundPorts": "9092, 15090"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        for port in [5432, 9092, 15090] {
            assert!(
                commands.contains(&format!(
                    "-p tcp --dport {port} -j REDIRECT --to-ports 15001"
                )),
                "includeOutboundPorts REDIRECT missing for port {port}: {commands}"
            );
        }
        assert!(
            !commands.contains("-p tcp -d 0.0.0.0/0 -j REDIRECT --to-ports 15001"),
            "port-scoped include rules should replace the CIDR-only catch-all"
        );
    }

    #[test]
    fn patch_includes_outbound_ports_additive_to_explicit_outbound_ip_ranges() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": "10.0.0.0/8",
                    "traffic.sidecar.istio.io/includeOutboundPorts": "5432"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        assert!(
            commands.contains("-p tcp -d 10.0.0.0/8 -j REDIRECT --to-ports 15001"),
            "explicit includeOutboundIPRanges rule missing: {commands}"
        );
        assert!(
            commands.contains("-p tcp --dport 5432 -j REDIRECT --to-ports 15001"),
            "includeOutboundPorts rule missing: {commands}"
        );
        assert!(
            !commands.contains("-p tcp -d 10.0.0.0/8 --dport 5432 -j REDIRECT"),
            "includeOutboundPorts must not be intersected with includeOutboundIPRanges: {commands}"
        );
    }

    #[test]
    fn patch_accepts_include_outbound_ports_wildcard_as_all_ports() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundPorts": "*"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        assert!(
            commands.contains("-p tcp -j REDIRECT --to-ports 15001"),
            "wildcard includeOutboundPorts should capture all ports: {commands}"
        );
        assert!(
            !commands.contains("--dport"),
            "wildcard includeOutboundPorts should not emit port-narrowing rules: {commands}"
        );
    }

    #[test]
    fn patch_wildcard_include_outbound_ports_overrides_explicit_cidr_narrowing() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": "10.0.0.0/8",
                    "traffic.sidecar.istio.io/includeOutboundPorts": "*"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        assert!(
            commands.contains("-p tcp -j REDIRECT --to-ports 15001"),
            "wildcard includeOutboundPorts should capture all destinations even when includeOutboundIPRanges is explicit: {commands}"
        );
        assert!(
            !commands.contains("-p tcp -d 10.0.0.0/8 -j REDIRECT"),
            "wildcard includeOutboundPorts makes explicit CIDR-only redirect redundant: {commands}"
        );
        assert!(
            !commands.contains("--dport"),
            "wildcard includeOutboundPorts should not emit port-narrowing rules: {commands}"
        );
    }

    #[test]
    fn patch_rejects_invalid_include_outbound_ports_annotation() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundPorts": "not-a-port"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let err = build_sidecar_patch_for_namespace(&pod, &config, None)
            .expect_err("invalid annotation rejected");

        assert!(err.contains("traffic.sidecar.istio.io/includeOutboundPorts"));
    }

    #[test]
    fn patch_rejects_mixed_wildcard_include_outbound_ports_annotation() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundPorts": "*,not-a-port"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let err = build_sidecar_patch_for_namespace(&pod, &config, None)
            .expect_err("mixed wildcard annotation rejected");

        assert!(err.contains("traffic.sidecar.istio.io/includeOutboundPorts"));
        assert!(err.contains("wildcard '*' must be the only includeOutboundPorts token"));
    }

    #[test]
    fn patch_uses_configurable_container_resources() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.sidecar_resources = test_resources("5m", "16Mi", "50m", "96Mi");
        config.init_resources = test_resources("2m", "8Mi", "20m", "32Mi");

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let sidecar = patch_named_container(&patch, "ferrum-edge").expect("sidecar container");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");

        assert_eq!(
            sidecar.pointer("/resources/requests/cpu"),
            Some(&Value::String("5m".to_string()))
        );
        assert_eq!(
            sidecar.pointer("/resources/limits/memory"),
            Some(&Value::String("96Mi".to_string()))
        );
        assert_eq!(
            init.pointer("/resources/requests/memory"),
            Some(&Value::String("8Mi".to_string()))
        );
        assert_eq!(
            init.pointer("/resources/limits/cpu"),
            Some(&Value::String("20m".to_string()))
        );
    }

    #[test]
    fn patch_rejects_invalid_exclude_outbound_ports_annotation() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundPorts": "not-a-port"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let err = build_sidecar_patch_for_namespace(&pod, &config, None)
            .expect_err("invalid annotation rejected");

        assert!(err.contains("traffic.sidecar.istio.io/excludeOutboundPorts"));
        assert!(!err.contains(": invalid port exclusion"));
    }

    #[test]
    fn admission_response_denies_invalid_exclude_outbound_ports_annotation() {
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "bad-ports",
                "namespace": "payments",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "object": {
                    "metadata": {
                        "labels": {"ferrum.io/mesh": "enabled"},
                        "annotations": {
                            "traffic.sidecar.istio.io/excludeOutboundPorts": "not-a-port"
                        }
                    },
                    "spec": {"containers": [{"name": "app", "image": "app:test"}]}
                }
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(true, CaptureMode::Iptables),
        )
        .expect("admission denial");

        assert_eq!(
            response.pointer("/response/allowed"),
            Some(&Value::Bool(false))
        );
        assert_eq!(response.pointer("/response/patch"), None);
        let message = response
            .pointer("/response/status/message")
            .and_then(Value::as_str)
            .expect("denial message");
        assert!(message.contains("traffic.sidecar.istio.io/excludeOutboundPorts"));
        assert!(!message.contains(": invalid port exclusion"));
    }

    #[test]
    fn admission_response_denies_invalid_include_outbound_ports_annotation() {
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "bad-include-ports",
                "namespace": "payments",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "object": {
                    "metadata": {
                        "labels": {"ferrum.io/mesh": "enabled"},
                        "annotations": {
                            "traffic.sidecar.istio.io/includeOutboundPorts": "not-a-port"
                        }
                    },
                    "spec": {"containers": [{"name": "app", "image": "app:test"}]}
                }
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(true, CaptureMode::Iptables),
        )
        .expect("admission denial");

        assert_eq!(
            response.pointer("/response/allowed"),
            Some(&Value::Bool(false))
        );
        let message = response
            .pointer("/response/status/message")
            .and_then(Value::as_str)
            .expect("denial message");
        assert!(message.contains("traffic.sidecar.istio.io/includeOutboundPorts"));
    }

    #[tokio::test]
    async fn injector_request_rejects_oversized_admission_review_body() {
        let mut config = test_config(true, CaptureMode::Iptables);
        config.admission_review_max_body_bytes = 1024;
        let (addr, server) = spawn_injector_test_server(config).await;

        let body = vec![b'x'; 1040];
        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/mutate"))
            .header("connection", "close")
            .body(body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let text = resp.text().await.unwrap();
        assert!(text.contains("AdmissionReview body too large (max 1024 bytes)"));
        assert_server_finished(server).await;
    }

    #[tokio::test]
    async fn injector_request_accepts_body_exactly_at_limit() {
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc",
                "namespace": "payments",
                "object": {
                    "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                    "spec": {"containers": []}
                }
            }
        });
        let body = review.to_string();

        let mut config = test_config(true, CaptureMode::Explicit);
        config.admission_review_max_body_bytes = body.len();
        let (addr, server) = spawn_injector_test_server(config).await;

        let resp = reqwest::Client::new()
            .post(format!("http://{addr}/mutate"))
            .header("connection", "close")
            .body(body)
            .send()
            .await
            .unwrap();

        assert_eq!(resp.status(), StatusCode::OK);
        let text = resp.text().await.unwrap();
        assert!(text.contains(r#""allowed":true"#), "got: {text}");
        assert_server_finished(server).await;
    }

    #[tokio::test]
    async fn injector_request_rejects_truncated_admission_review_body() {
        let (addr, server) =
            spawn_injector_test_server(test_config(true, CaptureMode::Iptables)).await;
        let request = b"POST /mutate HTTP/1.1\r\nHost: localhost\r\nContent-Length: 100\r\nConnection: close\r\n\r\n{}";

        let response = read_raw_http_response(addr, request).await;

        assert!(
            response.starts_with("HTTP/1.1 400 Bad Request"),
            "response was {response:?}",
        );
        assert!(response.contains("failed to read AdmissionReview body"));
        assert_server_finished(server).await;
    }

    #[test]
    fn injector_admission_review_max_body_size_mib_defaults_and_validates() {
        assert_eq!(
            parse_injector_admission_review_max_body_bytes_from_mib(None).unwrap(),
            DEFAULT_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB * MIB_BYTES
        );
        assert_eq!(
            parse_injector_admission_review_max_body_bytes_from_mib(Some("")).unwrap(),
            DEFAULT_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB * MIB_BYTES
        );
        assert_eq!(
            parse_injector_admission_review_max_body_bytes_from_mib(Some("1")).unwrap(),
            MIB_BYTES
        );
        assert!(
            parse_injector_admission_review_max_body_bytes_from_mib(Some("0"))
                .unwrap_err()
                .contains("greater than zero")
        );
        assert!(
            parse_injector_admission_review_max_body_bytes_from_mib(Some("-1"))
                .unwrap_err()
                .contains("unsigned integer")
        );
        let overflow_mib = (MAX_INJECTOR_ADMISSION_REVIEW_BODY_SIZE_MIB + 1).to_string();
        assert!(
            parse_injector_admission_review_max_body_bytes_from_mib(Some(&overflow_mib))
                .unwrap_err()
                .contains("must be at most 64 MiB")
        );
    }

    #[test]
    fn admission_review_body_limit_display_formats_mib_when_aligned() {
        assert_eq!(
            admission_review_body_limit_display(4 * 1024 * 1024),
            "4 MiB"
        );
        assert_eq!(admission_review_body_limit_display(1024), "1024 bytes");
    }

    #[test]
    fn admission_response_encodes_json_patch() {
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc",
                "namespace": "payments",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "object": {
                    "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                    "spec": {"containers": [{"name": "app", "image": "app:1"}]}
                }
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(true, CaptureMode::Explicit),
        )
        .expect("admission response");

        assert_eq!(
            response.pointer("/response/allowed"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            response.pointer("/response/patchType"),
            Some(&Value::String("JSONPatch".to_string()))
        );
        let patch = response
            .pointer("/response/patch")
            .and_then(Value::as_str)
            .expect("encoded patch");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(patch)
            .expect("valid base64 patch");
        let operations: Vec<Value> = serde_json::from_slice(&decoded).expect("json patch");
        let sidecar = operations
            .iter()
            .find(|op| op.get("path").and_then(Value::as_str) == Some("/spec/initContainers/0"))
            .and_then(|op| op.get("value"))
            .expect("sidecar patch");
        let env = sidecar
            .get("env")
            .and_then(Value::as_array)
            .expect("sidecar env");
        assert!(env.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("FERRUM_NAMESPACE")
                && entry.get("value").and_then(Value::as_str) == Some("payments")
        }));
        assert!(env.iter().any(|entry| {
            entry.get("name").and_then(Value::as_str) == Some("FERRUM_MESH_WORKLOAD_SPIFFE_ID")
                && entry.get("value").and_then(Value::as_str)
                    == Some("spiffe://cluster.local/ns/payments/sa/default")
        }));
    }

    #[test]
    fn admission_response_includes_pod_gvk_and_still_injects() {
        // A correctly-scoped webhook sends `kind` + `resource` for a core Pod.
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc",
                "namespace": "payments",
                "kind": {"group": "", "version": "v1", "kind": "Pod"},
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "object": {
                    "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                    "spec": {"containers": [{"name": "app", "image": "app:1"}]}
                }
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(true, CaptureMode::Explicit),
        )
        .expect("admission response");

        assert_eq!(
            response.pointer("/response/allowed"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            response.pointer("/response/patchType"),
            Some(&Value::String("JSONPatch".to_string()))
        );
        assert!(
            response.pointer("/response/patch").is_some(),
            "a core v1 Pod must still be injected"
        );
    }

    #[test]
    fn admission_response_does_not_inject_non_pod_kind() {
        // Mis-scoped MutatingWebhookConfiguration routes a Deployment here. The
        // injector must admit it (allowed=true) without producing a patch.
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "deploy-1",
                "namespace": "payments",
                "kind": {"group": "apps", "version": "v1", "kind": "Deployment"},
                "resource": {"group": "apps", "version": "v1", "resource": "deployments"},
                "object": {
                    "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                    "spec": {"template": {"spec": {"containers": []}}}
                }
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(true, CaptureMode::Iptables),
        )
        .expect("admission response");

        assert_eq!(
            response.pointer("/response/allowed"),
            Some(&Value::Bool(true)),
            "non-Pod objects must be admitted, never blocked"
        );
        assert_eq!(
            response.pointer("/response/patch"),
            None,
            "non-Pod objects must never be patched/injected"
        );
        assert_eq!(response.pointer("/response/patchType"), None);
    }

    #[test]
    fn admission_response_injects_pod_when_only_resource_present() {
        // Some apiserver paths populate `resource` but not `kind`; the core
        // `pods` resource is sufficient to confirm a Pod.
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc",
                "namespace": "payments",
                "resource": {"group": "", "version": "v1", "resource": "pods"},
                "object": {
                    "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                    "spec": {"containers": [{"name": "app", "image": "app:1"}]}
                }
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(true, CaptureMode::Explicit),
        )
        .expect("admission response");

        assert!(
            response.pointer("/response/patch").is_some(),
            "core pods resource must be treated as a Pod"
        );
    }

    #[test]
    fn admission_response_does_not_inject_when_kind_and_resource_absent() {
        // A malformed request carrying neither `kind` nor `resource` must fail
        // closed on injection: admit, but never patch an unknown object.
        let review = json!({
            "apiVersion": "admission.k8s.io/v1",
            "kind": "AdmissionReview",
            "request": {
                "uid": "abc",
                "namespace": "payments",
                "object": {
                    "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
                    "spec": {"containers": []}
                }
            }
        });
        let response = admission_response(
            review.to_string().as_bytes(),
            &test_config(true, CaptureMode::Explicit),
        )
        .expect("admission response");

        assert_eq!(
            response.pointer("/response/allowed"),
            Some(&Value::Bool(true))
        );
        assert_eq!(
            response.pointer("/response/patch"),
            None,
            "object with no kind/resource metadata must not be injected"
        );
    }

    #[test]
    fn admission_response_honors_dry_run_with_identical_patch() {
        // A patch-only webhook has no side effects, so a dryRun request must
        // return the exact same patch as the non-dryRun request.
        let object = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let make_review = |dry_run: bool| {
            json!({
                "apiVersion": "admission.k8s.io/v1",
                "kind": "AdmissionReview",
                "request": {
                    "uid": "abc",
                    "namespace": "payments",
                    "kind": {"group": "", "version": "v1", "kind": "Pod"},
                    "resource": {"group": "", "version": "v1", "resource": "pods"},
                    "dryRun": dry_run,
                    "object": object.clone()
                }
            })
        };
        let config = test_config(true, CaptureMode::Iptables);

        let live = admission_response(make_review(false).to_string().as_bytes(), &config)
            .expect("live response");
        let dry = admission_response(make_review(true).to_string().as_bytes(), &config)
            .expect("dry-run response");

        // Both admit and carry a patch.
        assert_eq!(live.pointer("/response/allowed"), Some(&Value::Bool(true)));
        assert_eq!(dry.pointer("/response/allowed"), Some(&Value::Bool(true)));
        // The encoded patch is byte-for-byte identical and the response implies
        // no side effects beyond the returned patch in either case.
        assert_eq!(
            live.pointer("/response/patch"),
            dry.pointer("/response/patch"),
            "dryRun must not change the computed patch"
        );
        assert!(dry.pointer("/response/patch").is_some());
    }

    #[test]
    fn patch_ebpf_mode_skips_init_container() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "serviceAccountName": "api",
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let patch =
            build_sidecar_patch_for_namespace(&pod, &test_config(true, CaptureMode::Ebpf), None)
                .expect("patch");

        assert!(patch_has_named_container(&patch, "ferrum-edge"));
        assert!(
            !patch_has_named_container(&patch, "ferrum-edge-init"),
            "ebpf mode should not inject privileged init container"
        );
        assert_eq!(
            patch_named_container(&patch, "ferrum-edge")
                .and_then(|sidecar| sidecar.get("restartPolicy")),
            Some(&Value::String("Always".to_string())),
            "ebpf mode still emits the native sidecar"
        );
    }

    #[test]
    fn patch_explicit_mode_skips_init_container() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "containers": [{"name": "app", "image": "app:test"}]
            }
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Explicit),
            None,
        )
        .expect("patch");

        assert!(patch_has_named_container(&patch, "ferrum-edge"));
        assert!(!patch_has_named_container(&patch, "ferrum-edge-init"));
        assert_eq!(
            patch_named_container(&patch, "ferrum-edge")
                .and_then(|sidecar| sidecar.get("restartPolicy")),
            Some(&Value::String("Always".to_string()))
        );
    }

    #[test]
    fn injector_config_defaults_parse_from_env_config() {
        // No TLS material is configured here, so the dev-only plaintext opt-in
        // must be present for `from_env_config` to succeed (fail-closed default).
        with_injector_env_lock(
            &[
                ("FERRUM_INJECTOR_TLS_CERT_PATH", None),
                ("FERRUM_INJECTOR_TLS_KEY_PATH", None),
                ("FERRUM_INJECTOR_ALLOW_PLAINTEXT", Some("true")),
            ],
            || {
                let env = EnvConfig::default();
                let config = InjectorConfig::from_env_config(&env).expect("injector config");
                assert_eq!(config.listen_addr.port(), 9443);
                assert_eq!(config.capture_mode, CaptureMode::Explicit);
                assert_eq!(config.ip6tables_mode, Ip6TablesMode::Auto);
                assert_eq!(config.trust_domain, DEFAULT_INJECTOR_TRUST_DOMAIN);
                assert!(config.tls_cert_path.is_none());
                assert!(config.allow_plaintext);
            },
        );
    }

    #[test]
    fn injector_config_requires_tls_or_explicit_plaintext_opt_in() {
        // Fail-closed: no cert/key and no opt-in must refuse to start.
        with_injector_env_lock(
            &[
                ("FERRUM_INJECTOR_TLS_CERT_PATH", None),
                ("FERRUM_INJECTOR_TLS_KEY_PATH", None),
                ("FERRUM_INJECTOR_ALLOW_PLAINTEXT", None),
            ],
            || {
                let env = EnvConfig::default();
                let err = InjectorConfig::from_env_config(&env)
                    .expect_err("plaintext must be refused without explicit opt-in");
                assert!(err.contains("FERRUM_INJECTOR_TLS_CERT_PATH"));
                assert!(err.contains("FERRUM_INJECTOR_ALLOW_PLAINTEXT"));
            },
        );
    }

    #[test]
    fn injector_tls_serving_validation_is_fail_closed() {
        // cert + key present: TLS serving, always allowed.
        assert!(validate_injector_tls_serving(Some("/tls.crt"), Some("/tls.key"), false).is_ok());
        assert!(validate_injector_tls_serving(Some("/tls.crt"), Some("/tls.key"), true).is_ok());

        // Neither present: refused unless plaintext explicitly allowed.
        let err = validate_injector_tls_serving(None, None, false)
            .expect_err("plaintext refused by default");
        assert!(err.contains("injector requires TLS"));
        assert!(err.contains("FERRUM_INJECTOR_ALLOW_PLAINTEXT"));
        assert!(validate_injector_tls_serving(None, None, true).is_ok());

        // Half-configured TLS is always an error regardless of the opt-in.
        let cert_only = validate_injector_tls_serving(Some("/tls.crt"), None, true)
            .expect_err("cert without key is invalid");
        assert!(cert_only.contains("requires FERRUM_INJECTOR_TLS_KEY_PATH"));
        let key_only = validate_injector_tls_serving(None, Some("/tls.key"), true)
            .expect_err("key without cert is invalid");
        assert!(key_only.contains("requires FERRUM_INJECTOR_TLS_CERT_PATH"));
    }

    #[test]
    fn injector_config_rejects_invalid_trust_domain() {
        let err =
            validate_injector_trust_domain("CLUSTER.LOCAL").expect_err("invalid trust domain");
        assert!(err.contains("FERRUM_INJECTOR_TRUST_DOMAIN"));
    }

    #[test]
    fn injector_config_rejects_root_proxy_uid() {
        let err = parse_injector_proxy_uid(Some("0".to_string())).expect_err("root UID rejected");

        assert!(err.contains("FERRUM_MESH_PROXY_UID"));
        assert!(err.contains("non-zero"));
    }

    #[test]
    fn injector_config_rejects_invalid_resource_quantity() {
        let err =
            resolve_resource_quantity("FERRUM_INJECTOR_SIDECAR_CPU_REQUEST", "not-a-quantity")
                .expect_err("invalid quantity rejected");

        assert!(err.contains("FERRUM_INJECTOR_SIDECAR_CPU_REQUEST"));
    }

    #[test]
    fn injector_config_parses_non_root_proxy_uid() {
        let uid = parse_injector_proxy_uid(Some("1337".to_string())).expect("valid UID");

        assert_eq!(uid, Some(1337));
    }

    #[test]
    fn patch_excludes_configured_and_annotated_inbound_ports() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeInboundPorts": "8080, 9090",
                    "ferrum.io/excludeInboundPorts": "15090"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.exclude_inbound_ports = vec![22, 8080];

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        for port in [22, 8080, 9090, 15090] {
            assert!(
                commands.contains(&format!(
                    "FERRUM_MESH_INBOUND -p tcp --dport {port} -j RETURN"
                )) || commands.contains(&format!(
                    "-A FERRUM_MESH_INBOUND -p tcp --dport {port} -j RETURN"
                )),
                "inbound RETURN missing for port {port} in commands: {commands}"
            );
        }
        // CRITICAL: each inbound RETURN must precede the inbound REDIRECT to
        // 15006 — otherwise the catch-all REDIRECT fires first and exclusions
        // are silently bypassed.
        let redirect_pos = commands
            .find("REDIRECT --to-ports 15006")
            .expect("inbound REDIRECT");
        for port in [22, 8080, 9090, 15090] {
            let return_marker = format!("--dport {port} -j RETURN");
            let return_pos = commands
                .find(return_marker.as_str())
                .unwrap_or_else(|| panic!("RETURN for port {port} missing"));
            assert!(
                return_pos < redirect_pos,
                "inbound RETURN for port {port} must precede the REDIRECT"
            );
        }
    }

    #[test]
    fn patch_excludes_numeric_http_and_tcp_probe_ports() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "containers": [
                    {
                        "name": "app",
                        "image": "app:test",
                        "livenessProbe": {
                            "httpGet": {"path": "/livez", "port": 8080}
                        },
                        "readinessProbe": {
                            "httpGet": {"path": "/readyz", "port": 8081}
                        }
                    },
                    {
                        "name": "metrics",
                        "image": "metrics:test",
                        "startupProbe": {
                            "tcpSocket": {"port": 9090}
                        }
                    }
                ],
                "initContainers": [
                    {
                        "name": "migrate",
                        "image": "migrate:test",
                        "readinessProbe": {
                            "httpGet": {"path": "/healthz", "port": "9091"}
                        }
                    }
                ],
                "ephemeralContainers": [
                    {
                        "name": "debug",
                        "image": "debug:test",
                        "livenessProbe": {
                            "tcpSocket": {"port": 9092}
                        }
                    }
                ]
            }
        });
        let config = test_config(true, CaptureMode::Iptables);
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let commands = patch_named_container(&patch, "ferrum-edge-init")
            .expect("init container")
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");
        for port in [8080, 8081, 9090, 9091, 9092] {
            assert!(
                commands.contains(&format!("--dport {port} -j RETURN")),
                "probe port {port} must be excluded from inbound capture:\n{commands}"
            );
        }
    }

    #[test]
    fn patch_resolves_named_http_probe_ports_against_container_ports() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "app:test",
                    "ports": [
                        {"containerPort": 8080, "name": "http"},
                        {"containerPort": 9090, "name": "admin"}
                    ],
                    "livenessProbe": {
                        "httpGet": {"path": "/livez", "port": "http"}
                    },
                    "readinessProbe": {
                        "httpGet": {"path": "/readyz", "port": "admin"}
                    }
                }]
            }
        });
        let config = test_config(true, CaptureMode::Iptables);
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let commands = patch_named_container(&patch, "ferrum-edge-init")
            .expect("init container")
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");
        for port in [8080, 9090] {
            assert!(
                commands.contains(&format!("--dport {port} -j RETURN")),
                "named probe port must resolve to {port}:\n{commands}"
            );
        }
    }

    #[test]
    fn patch_does_not_exclude_exec_or_grpc_probe_ports() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "app:test",
                    "livenessProbe": {
                        "exec": {"command": ["true"]}
                    },
                    "readinessProbe": {
                        "grpc": {"port": 50051}
                    }
                }]
            }
        });
        let config = test_config(true, CaptureMode::Iptables);
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let commands = patch_named_container(&patch, "ferrum-edge-init")
            .expect("init container")
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");
        assert!(
            !commands.contains("--dport 50051 -j RETURN"),
            "gRPC probes are not HTTP/TCP kubelet ports and must not be excluded:\n{commands}"
        );
    }

    #[test]
    fn patch_unions_probe_ports_with_explicit_inbound_exclusions() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeInboundPorts": "22, 8080"
                }
            },
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "app:test",
                    "livenessProbe": {
                        "httpGet": {"path": "/livez", "port": 8080}
                    },
                    "readinessProbe": {
                        "httpGet": {"path": "/readyz", "port": 9090}
                    }
                }]
            }
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.exclude_inbound_ports = vec![22, 15090];
        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let commands = patch_named_container(&patch, "ferrum-edge-init")
            .expect("init container")
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");
        for port in [22, 8080, 9090, 15090] {
            assert!(
                commands.contains(&format!("--dport {port} -j RETURN")),
                "explicit and probe exclusions must both remain for {port}:\n{commands}"
            );
        }
    }

    #[test]
    fn patch_rejects_unresolved_named_probe_port() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "containers": [{
                    "name": "app",
                    "image": "app:test",
                    "ports": [{"containerPort": 8080, "name": "http"}],
                    "livenessProbe": {
                        "httpGet": {"path": "/livez", "port": "metrics"}
                    }
                }]
            }
        });
        let err = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        )
        .expect_err("unresolved named probe port must fail closed");
        assert!(
            err.contains("names port 'metrics'"),
            "error must name the unresolved probe port: {err}"
        );
        assert!(
            err.contains("refusing injection"),
            "unresolved names must fail admission, not capture the probe: {err}"
        );
    }

    #[test]
    fn patch_inserts_native_sidecar_before_existing_user_init_containers() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {
                "containers": [{"name": "app", "image": "app:test"}],
                "initContainers": [{"name": "migrate", "image": "migrate:test"}]
            }
        });
        let patch = build_sidecar_patch_for_namespace(
            &pod,
            &test_config(true, CaptureMode::Iptables),
            None,
        )
        .expect("patch");
        assert_eq!(
            patch
                .iter()
                .find(|op| {
                    op.value
                        .as_ref()
                        .and_then(|value| value.get("name"))
                        .and_then(Value::as_str)
                        == Some("ferrum-edge")
                })
                .map(|op| op.path.as_str()),
            Some("/spec/initContainers/0")
        );
        assert_eq!(
            patch
                .iter()
                .find(|op| {
                    op.value
                        .as_ref()
                        .and_then(|value| value.get("name"))
                        .and_then(Value::as_str)
                        == Some("ferrum-edge-init")
                })
                .map(|op| op.path.as_str()),
            Some("/spec/initContainers/1")
        );
        assert!(!patch.iter().any(|op| op.path == "/spec/initContainers"));
    }

    #[test]
    fn patch_rejects_invalid_exclude_inbound_ports_annotation() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeInboundPorts": "not-a-port"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let err = build_sidecar_patch_for_namespace(&pod, &config, None)
            .expect_err("invalid annotation rejected");

        assert!(
            err.contains("traffic.sidecar.istio.io/excludeInboundPorts"),
            "error must name the offending annotation: {err}"
        );
    }

    #[test]
    fn patch_appends_exclude_outbound_ip_ranges_annotation_to_env_defaults() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges":
                        "172.16.0.0/12, 192.168.0.0/16"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.exclude_outbound_cidrs = vec!["10.0.0.0/8".to_string()];

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        for cidr in ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"] {
            assert!(
                commands.contains(&format!("-d {cidr} -j RETURN")),
                "outbound exclude RETURN missing for {cidr}"
            );
        }
    }

    #[test]
    fn patch_include_outbound_ip_ranges_annotation_replaces_env_defaults() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": "10.0.0.0/8"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        // Env-derived default that MUST be overridden by the annotation.
        config.include_outbound_cidrs = vec!["172.16.0.0/12".to_string()];

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        assert!(
            commands.contains("-d 10.0.0.0/8 -j REDIRECT --to-ports 15001"),
            "annotation include CIDR must appear as REDIRECT target: {commands}"
        );
        assert!(
            !commands.contains("-d 172.16.0.0/12 -j REDIRECT"),
            "env-derived include CIDR must be REPLACED by annotation, not appended"
        );
    }

    #[test]
    fn patch_include_outbound_ip_ranges_falls_back_to_env_when_annotation_absent() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.include_outbound_cidrs = vec!["10.0.0.0/8".to_string()];

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        assert!(
            commands.contains("-d 10.0.0.0/8 -j REDIRECT --to-ports 15001"),
            "env-derived include CIDR must apply when annotation is absent"
        );
    }

    #[test]
    fn patch_rejects_invalid_exclude_outbound_ip_ranges_annotation() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges": "not-a-cidr"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let err = build_sidecar_patch_for_namespace(&pod, &config, None)
            .expect_err("invalid CIDR rejected");

        assert!(
            err.contains("traffic.sidecar.istio.io/excludeOutboundIPRanges"),
            "error must name the offending annotation: {err}"
        );
    }

    #[test]
    fn patch_rejects_invalid_include_outbound_ip_ranges_annotation() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": "10.0.0.0/64"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let err = build_sidecar_patch_for_namespace(&pod, &config, None)
            .expect_err("invalid CIDR rejected");

        assert!(
            err.contains("traffic.sidecar.istio.io/includeOutboundIPRanges"),
            "error must name the offending annotation: {err}"
        );
    }

    #[test]
    fn capture_config_defaults_include_to_zero_zero_when_env_and_annotation_unset() {
        let pod = json!({
            "metadata": {"labels": {"ferrum.io/mesh": "enabled"}},
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let capture = capture_config(&config, &pod).expect("capture config");

        assert_eq!(capture.include_cidrs, vec!["0.0.0.0/0".to_string()]);
        assert!(
            !capture.include_cidrs_explicit,
            "implicit catch-all include must be distinguishable from operator-provided CIDRs"
        );
        assert!(capture.exclude_cidrs.is_empty());
        assert!(capture.exclude_inbound_ports.is_empty());
    }

    // Regression: an `includeOutboundIPRanges` annotation that parses to zero
    // CIDRs (whitespace, comma-only, etc.) MUST fall through to the env-derived
    // include list. Earlier behavior treated `" , , "` as "present but empty"
    // and produced ZERO outbound REDIRECT rules — silently bypassing the proxy
    // for ALL outbound traffic.
    #[test]
    fn capture_config_falls_back_to_env_when_include_annotation_is_whitespace_only() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": "   "
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.include_outbound_cidrs = vec!["10.0.0.0/8".to_string()];

        let capture = capture_config(&config, &pod).expect("capture config");

        assert_eq!(
            capture.include_cidrs,
            vec!["10.0.0.0/8".to_string()],
            "whitespace-only annotation must fall through to env-derived value"
        );
        assert!(capture.include_cidrs_explicit);
    }

    #[test]
    fn capture_config_falls_back_to_env_when_include_annotation_is_commas_only() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": " , , "
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.include_outbound_cidrs = vec!["10.0.0.0/8".to_string()];

        let capture = capture_config(&config, &pod).expect("capture config");

        assert_eq!(
            capture.include_cidrs,
            vec!["10.0.0.0/8".to_string()],
            "comma-only annotation must fall through to env-derived value"
        );
        assert!(capture.include_cidrs_explicit);
    }

    #[test]
    fn capture_config_falls_back_to_default_when_include_annotation_empty_and_env_unset() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": ""
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let capture = capture_config(&config, &pod).expect("capture config");

        assert_eq!(
            capture.include_cidrs,
            vec!["0.0.0.0/0".to_string()],
            "empty annotation + empty env must default to 0.0.0.0/0 (must NOT produce zero include rules)"
        );
        assert!(!capture.include_cidrs_explicit);
    }

    // Same fall-through rule on the exclude path: a comma-only annotation must
    // not pollute the env-derived exclude list (no-op, not "extend with []").
    #[test]
    fn capture_config_exclude_annotation_whitespace_only_is_noop() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges": " , , "
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.exclude_outbound_cidrs = vec!["10.0.0.0/8".to_string()];

        let capture = capture_config(&config, &pod).expect("capture config");

        assert_eq!(
            capture.exclude_cidrs,
            vec!["10.0.0.0/8".to_string()],
            "whitespace/comma-only exclude annotation must be a no-op"
        );
    }

    // Deduplication: a port repeated across env + Istio annotation + Ferrum
    // annotation must collapse to a single RETURN rule.
    #[test]
    fn capture_config_deduplicates_inbound_ports_across_sources() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeInboundPorts": "22, 8080",
                    "ferrum.io/excludeInboundPorts": "22"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.exclude_inbound_ports = vec![22];

        let capture = capture_config(&config, &pod).expect("capture config");

        // 22 appears in env + both annotations, 8080 only in Istio annotation
        assert_eq!(
            capture.exclude_inbound_ports,
            vec![22, 8080],
            "duplicate ports across sources must collapse"
        );
    }

    #[test]
    fn capture_config_deduplicates_include_outbound_ports_across_aliases() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundPorts": "5432, 9092",
                    "ferrum.io/includeOutboundPorts": "5432, 15090"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let capture = capture_config(&config, &pod).expect("capture config");

        assert_eq!(
            capture.include_outbound_ports,
            vec![5432, 9092, 15090],
            "includeOutboundPorts aliases should merge and deduplicate"
        );
    }

    #[test]
    fn capture_config_include_outbound_ports_wildcard_clears_port_filter() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundPorts": "*"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let capture = capture_config(&config, &pod).expect("capture config");

        assert!(
            capture.include_all_outbound_ports,
            "wildcard includeOutboundPorts must stay distinct from absent includeOutboundPorts"
        );
        assert!(
            capture.include_outbound_ports.is_empty(),
            "wildcard includeOutboundPorts means all ports, so no port filter should be carried"
        );
    }

    #[test]
    fn capture_config_ferrum_include_outbound_ports_wildcard_clears_port_filter() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "ferrum.io/includeOutboundPorts": "*"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let capture = capture_config(&config, &pod).expect("capture config");

        assert!(
            capture.include_all_outbound_ports,
            "Ferrum wildcard includeOutboundPorts must stay distinct from absent includeOutboundPorts"
        );
        assert!(
            capture.include_outbound_ports.is_empty(),
            "Ferrum wildcard includeOutboundPorts means all ports, so no port filter should be carried"
        );
    }

    #[test]
    fn capture_config_accepts_duplicate_include_outbound_ports_wildcard_aliases() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundPorts": "*",
                    "ferrum.io/includeOutboundPorts": "*"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let capture = capture_config(&config, &pod).expect("duplicate wildcard aliases accepted");

        assert!(
            capture.include_all_outbound_ports,
            "duplicate wildcard aliases should preserve the all-ports marker"
        );
        assert!(
            capture.include_outbound_ports.is_empty(),
            "duplicate wildcard aliases should still mean all ports"
        );
    }

    #[test]
    fn capture_config_rejects_wildcard_include_outbound_ports_across_aliases() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/includeOutboundPorts": "*",
                    "ferrum.io/includeOutboundPorts": "5432"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let err = capture_config(&config, &pod).expect_err("mixed wildcard aliases rejected");

        assert!(err.contains("ferrum.io/includeOutboundPorts"));
        assert!(err.contains("traffic.sidecar.istio.io/includeOutboundPorts"));
        assert!(err.contains("cannot be combined with wildcard '*'"));
    }

    // Deduplication on the exclude-CIDR path: a CIDR repeated across env and
    // annotation must collapse to a single RETURN rule, with insertion order
    // preserved so iptables ruleset emission stays stable across reloads.
    #[test]
    fn capture_config_deduplicates_exclude_cidrs_preserving_order() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges":
                        "10.0.0.0/8, 192.168.0.0/16"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        // First entry repeats in the annotation; both must remain in the
        // env-first order (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16).
        config.exclude_outbound_cidrs = vec!["10.0.0.0/8".to_string(), "172.16.0.0/12".to_string()];

        let capture = capture_config(&config, &pod).expect("capture config");

        assert_eq!(
            capture.exclude_cidrs,
            vec![
                "10.0.0.0/8".to_string(),
                "172.16.0.0/12".to_string(),
                "192.168.0.0/16".to_string(),
            ],
            "duplicate CIDR must collapse and original insertion order must be preserved"
        );
    }

    // Localhost CIDR — Istio's iptables pipeline returns early for loopback
    // anyway, but the admission webhook still validates the CIDR shape.
    #[test]
    fn capture_config_accepts_localhost_cidr_in_exclude_annotation() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges": "127.0.0.0/8"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let capture = capture_config(&config, &pod).expect("capture config");

        assert!(
            capture.exclude_cidrs.iter().any(|c| c == "127.0.0.0/8"),
            "loopback CIDR must be accepted (no special-case rejection)"
        );
    }

    // IPv6 CIDR annotations pass admission (the validator checks shape and
    // prefix range, not a single address family) and survive into
    // `CaptureConfig` so the plan can fan them out to `ip6tables`.
    #[test]
    fn capture_config_accepts_ipv6_cidr_in_exclude_annotation_today() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges": "fd00::/8"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let capture = capture_config(&config, &pod).expect("IPv6 CIDR currently passes admission");
        assert!(capture.exclude_cidrs.iter().any(|c| c == "fd00::/8"));
    }

    #[test]
    fn patch_fans_out_ipv6_cidr_to_ip6tables_script() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges": "10.0.0.0/8, fd00::/8",
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": "172.16.0.0/12, 2001:db8::/32"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let config = test_config(true, CaptureMode::Iptables);

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        for ipv4 in ["10.0.0.0/8", "172.16.0.0/12"] {
            assert!(
                commands.contains(ipv4),
                "IPv4 CIDR {ipv4} must remain in the init script"
            );
        }
        for ipv6 in ["fd00::/8", "2001:db8::/32"] {
            assert!(
                commands.contains(ipv6),
                "IPv6 CIDR {ipv6} must appear in the ip6tables init script: {commands}"
            );
        }
        assert!(commands.contains("command -v ip6tables"));
        assert!(commands.contains("ip6tables -t nat"));
        assert!(commands.contains("skipping IPv6 mesh capture rules"));
    }

    #[test]
    fn patch_requires_ip6tables_when_configured_true() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges": "fd00::/8"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.ip6tables_mode = Ip6TablesMode::Required;

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        assert!(commands.contains("ip6tables is required for IPv6 mesh capture"));
        assert!(commands.contains("ip6tables nat table is required for IPv6 mesh capture"));
        assert!(commands.contains("ip6tables -t nat -w 5 -L"));
        assert!(commands.contains("exit 1"));
        assert!(commands.contains("ip6tables -t nat"));
    }

    #[test]
    fn patch_omits_ipv6_cidr_when_ip6tables_disabled() {
        let pod = json!({
            "metadata": {
                "labels": {"ferrum.io/mesh": "enabled"},
                "annotations": {
                    "traffic.sidecar.istio.io/excludeOutboundIPRanges": "10.0.0.0/8, fd00::/8",
                    "traffic.sidecar.istio.io/includeOutboundIPRanges": "172.16.0.0/12, 2001:db8::/32"
                }
            },
            "spec": {"containers": [{"name": "app", "image": "app:test"}]}
        });
        let mut config = test_config(true, CaptureMode::Iptables);
        config.ip6tables_mode = Ip6TablesMode::Disabled;

        let patch = build_sidecar_patch_for_namespace(&pod, &config, None).expect("patch");
        let init = patch_named_container(&patch, "ferrum-edge-init").expect("init container");
        let commands = init
            .pointer("/args/0")
            .and_then(Value::as_str)
            .expect("iptables plan");

        assert!(commands.contains("10.0.0.0/8"));
        assert!(commands.contains("172.16.0.0/12"));
        assert!(!commands.contains("fd00::/8"));
        assert!(!commands.contains("2001:db8::/32"));
        assert!(!commands.contains("ip6tables -t nat"));
    }
}
