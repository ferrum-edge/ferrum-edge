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
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

use crate::capture::{
    CaptureConfig, CaptureMode, DEFAULT_PROXY_UID, FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION,
    ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION, IncludeOutboundPorts, Ip6TablesMode, IptablesPlan,
    include_outbound_ports_from_annotations, validate_cidr_list,
};
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::identity::spiffe::TrustDomain;
use crate::tls::{self, TlsPolicy};
use crate::util::body_limit::is_length_limit_error;

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
    pub trust_domain: String,
    pub tls_cert_path: Option<String>,
    pub tls_key_path: Option<String>,
    pub tls_handshake_timeout_seconds: u64,
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
        match (&tls_cert_path, &tls_key_path) {
            (Some(_), Some(_)) | (None, None) => {}
            (Some(_), None) => {
                return Err(
                    "FERRUM_INJECTOR_TLS_CERT_PATH requires FERRUM_INJECTOR_TLS_KEY_PATH"
                        .to_string(),
                );
            }
            (None, Some(_)) => {
                return Err(
                    "FERRUM_INJECTOR_TLS_KEY_PATH requires FERRUM_INJECTOR_TLS_CERT_PATH"
                        .to_string(),
                );
            }
        }

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
            trust_domain,
            tls_cert_path,
            tls_key_path,
            tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
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
    object: Value,
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let config = InjectorConfig::from_env_config(&env_config)
        .map_err(|e| anyhow::anyhow!("invalid injector configuration: {e}"))?;
    let tls_acceptor = build_tls_acceptor(&env_config, &config)?;
    let max_connections = env_config.max_connections;
    let config = Arc::new(config);
    let connection_limiter = if max_connections > 0 {
        Some(Arc::new(Semaphore::new(max_connections)))
    } else {
        None
    };
    let listener = TcpListener::bind(config.listen_addr).await?;
    info!(
        listen_addr = %config.listen_addr,
        namespace = %config.namespace,
        tls = tls_acceptor.is_some(),
        "Ferrum injector admission webhook listening"
    );
    let mut shutdown_rx = shutdown_tx.subscribe();

    loop {
        tokio::select! {
            result = listener.accept() => {
                match result {
                    Ok((stream, remote_addr)) => {
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
                        tokio::spawn(async move {
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
                    Err(e) => error!("Failed to accept injector connection: {}", e),
                }
            }
            _ = shutdown_rx.changed() => {
                info!("Injector admission webhook shutting down");
                return Ok(());
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
    Ok(Some(TlsAcceptor::from(server_config)))
}

async fn serve_injector_connection<S>(
    stream: S,
    config: Arc<InjectorConfig>,
    remote_addr: SocketAddr,
) where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let io = TokioIo::new(stream);
    let svc = service_fn(move |req| {
        let config = Arc::clone(&config);
        async move { handle_injector_request(req, config, remote_addr).await }
    });
    if let Err(e) = http1::Builder::new().serve_connection(io, svc).await {
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
    let mut response = json!({
        "apiVersion": api_version,
        "kind": kind,
        "response": {
            "uid": request.uid,
            "allowed": true
        }
    });

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
    if !should_inject(pod, config) {
        return Ok(Vec::new());
    }

    reject_reserved_name_conflicts(pod, config)?;

    let mut patch = Vec::new();
    let pod_namespace = pod_namespace(pod, admission_namespace, config);
    ensure_metadata_annotations(pod, &mut patch);
    patch.push(JsonPatchOperation {
        op: "add",
        path: "/metadata/annotations/ferrum.io~1injected".to_string(),
        value: Some(Value::String("true".to_string())),
    });
    patch.push(JsonPatchOperation {
        op: "add",
        path: "/spec/containers/-".to_string(),
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
        ensure_init_containers(pod, &mut patch);
        patch.push(JsonPatchOperation {
            op: "add",
            path: "/spec/initContainers/-".to_string(),
            value: Some(init_container(config, pod)?),
        });
    }

    Ok(patch)
}

fn should_inject(pod: &Value, config: &InjectorConfig) -> bool {
    let annotations = pod
        .pointer("/metadata/annotations")
        .and_then(Value::as_object);
    let labels = pod.pointer("/metadata/labels").and_then(Value::as_object);

    if value_is_false(annotations.and_then(|m| m.get("sidecar.istio.io/inject")))
        || value_is_false(annotations.and_then(|m| m.get("ferrum.io/inject")))
        || value_is_false(labels.and_then(|m| m.get("ferrum.io/mesh")))
    {
        return false;
    }

    if !config.require_annotation {
        return true;
    }

    value_is_true(annotations.and_then(|m| m.get("ferrum.io/inject")))
        || value_is_true(annotations.and_then(|m| m.get("sidecar.istio.io/inject")))
        || labels
            .and_then(|m| m.get("ferrum.io/mesh"))
            .and_then(Value::as_str)
            .is_some_and(|value| value == "enabled")
}

fn reject_reserved_name_conflicts(pod: &Value, config: &InjectorConfig) -> Result<(), String> {
    if pod_has_ferrum_sidecar(pod) {
        return Err(
            "pod spec already defines reserved container name ferrum-edge; refusing injection"
                .to_string(),
        );
    }

    if config.capture_mode == CaptureMode::Iptables && pod_has_ferrum_init_container(pod) {
        return Err(
            "pod spec already defines reserved init container name ferrum-edge-init; refusing injection"
                .to_string(),
        );
    }

    Ok(())
}

fn value_is_true(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| value == "true")
}

fn value_is_false(value: Option<&Value>) -> bool {
    value
        .and_then(Value::as_str)
        .is_some_and(|value| matches!(value, "false" | "disabled"))
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

fn ensure_init_containers(pod: &Value, patch: &mut Vec<JsonPatchOperation>) {
    if pod.pointer("/spec/initContainers").is_none() {
        patch.push(JsonPatchOperation {
            op: "add",
            path: "/spec/initContainers".to_string(),
            value: Some(json!([])),
        });
    }
}

fn pod_has_ferrum_sidecar(pod: &Value) -> bool {
    pod.pointer("/spec/containers")
        .and_then(Value::as_array)
        .is_some_and(|containers| {
            containers.iter().any(|container| {
                container.get("name").and_then(Value::as_str) == Some("ferrum-edge")
            })
        })
}

fn pod_has_ferrum_init_container(pod: &Value) -> bool {
    pod.pointer("/spec/initContainers")
        .and_then(Value::as_array)
        .is_some_and(|containers| {
            containers.iter().any(|container| {
                container.get("name").and_then(Value::as_str) == Some("ferrum-edge-init")
            })
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

fn sidecar_env(config: &InjectorConfig, pod: &Value, namespace: &str) -> Vec<Value> {
    let mut env = vec![
        json!({"name": "FERRUM_MODE", "value": "mesh"}),
        json!({"name": "FERRUM_NAMESPACE", "value": namespace}),
        json!({"name": "FERRUM_MESH_TOPOLOGY", "value": "sidecar"}),
        json!({"name": "FERRUM_MESH_CAPTURE_MODE", "value": format!("{:?}", config.capture_mode).to_ascii_lowercase()}),
        json!({"name": "FERRUM_MESH_WORKLOAD_SPIFFE_ID", "value": workload_spiffe_id(config, pod, namespace)}),
    ];
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
            "capabilities": {"drop": ["ALL"]},
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
        "env": sidecar_env(config, pod, namespace)
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
    ports.sort_unstable();
    ports.dedup();
    Ok(ports)
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
            trust_domain: "cluster.local".to_string(),
            tls_cert_path: None,
            tls_key_path: None,
            tls_handshake_timeout_seconds: 10,
            admission_review_max_body_bytes: DEFAULT_INJECTOR_ADMISSION_REVIEW_MAX_BODY_SIZE_MIB
                * MIB_BYTES,
        }
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
            patch.iter().any(|op| op.path == "/spec/containers/-"),
            "expected sidecar container to be appended"
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
        assert!(patch.iter().any(|op| op.path == "/spec/containers/-"));
        assert!(patch.iter().any(|op| op.path == "/spec/initContainers/-"));
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

        assert!(patch.iter().any(|op| op.path == "/spec/containers/-"));
        assert!(patch.iter().any(|op| op.path == "/spec/initContainers/-"));
        let sidecar = patch
            .iter()
            .find(|op| op.path == "/spec/containers/-")
            .and_then(|op| op.value.as_ref())
            .expect("sidecar container");
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
        let env = sidecar
            .get("env")
            .and_then(Value::as_array)
            .expect("sidecar env");
        assert_eq!(sidecar.get("args"), Some(&json!(["run"])));
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let sidecar = patch
            .iter()
            .find(|op| op.path == "/spec/containers/-")
            .and_then(|op| op.value.as_ref())
            .expect("sidecar container");
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");

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
            .find(|op| op.get("path").and_then(Value::as_str) == Some("/spec/containers/-"))
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

        assert!(patch.iter().any(|op| op.path == "/spec/containers/-"));
        assert!(
            !patch.iter().any(|op| op.path == "/spec/initContainers/-"),
            "ebpf mode should not inject privileged init container"
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

        assert!(patch.iter().any(|op| op.path == "/spec/containers/-"));
        assert!(!patch.iter().any(|op| op.path == "/spec/initContainers/-"));
    }

    #[test]
    fn injector_config_defaults_parse_from_env_config() {
        let env = EnvConfig::default();
        let config = InjectorConfig::from_env_config(&env).expect("injector config");
        assert_eq!(config.listen_addr.port(), 9443);
        assert_eq!(config.capture_mode, CaptureMode::Explicit);
        assert_eq!(config.ip6tables_mode, Ip6TablesMode::Auto);
        assert_eq!(config.trust_domain, DEFAULT_INJECTOR_TRUST_DOMAIN);
        assert!(config.tls_cert_path.is_none());
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
        let init = patch
            .iter()
            .find(|op| op.path == "/spec/initContainers/-")
            .and_then(|op| op.value.as_ref())
            .expect("init container");
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
