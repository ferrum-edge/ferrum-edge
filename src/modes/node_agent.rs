//! Node agent mode — per-node eBPF capture manager for ambient mesh.
//!
//! `FERRUM_MODE=node_agent` runs as a DaemonSet companion alongside the
//! ambient mesh proxy. It attaches BPF programs to enrolled pods' cgroups
//! and veth interfaces to transparently redirect traffic to the co-located
//! Ferrum proxy.
//!
//! The node agent does NOT run proxy listeners. Traffic capture is its sole
//! responsibility.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};

use dashmap::DashMap;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::Pod;
use kube::api::Api;
use kube::runtime::watcher::{self as kube_watcher, Event};
use tracing::{debug, error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::capture::{
    CaptureConfig, FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION,
    ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION, IncludeOutboundPorts, Ip6TablesMode, IptablesPlan,
    XTABLES_LOCK_WAIT_SECONDS, include_outbound_ports_from_annotations,
};
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::ebpf::cgroup;
use crate::ebpf::kernel_probe::{self, KernelProbeResult};
use crate::ebpf::pod_watcher::{self, EnrollmentDecision};
use crate::ebpf::veth;
use crate::ebpf::{
    CaptureContract, DEFAULT_NODE_AGENT_SOCKET_PATH, EbpfBackend, FallbackMode, INCLUDE_PORTS_MAX,
    IncludePortsPolicy, NodeAgentMetrics, PodAttachmentState, PodInfo,
};

const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
const DEFAULT_BPF_FS_PATH: &str = "/sys/fs/bpf";
const DEFAULT_FALLBACK_MODE: &str = "iptables";

#[allow(dead_code)]
#[derive(Debug, Clone)]
pub struct NodeAgentConfig {
    pub node_name: String,
    pub capture_config: CaptureConfig,
    pub cgroup_root: String,
    pub bpf_fs_path: String,
    pub fallback_mode: FallbackMode,
    pub excluded_namespaces: HashSet<String>,
    pub capture_contract: CaptureContract,
}

impl NodeAgentConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Result<Self, String> {
        let node_name = resolve_ferrum_var("FERRUM_NODE_AGENT_NODE_NAME").ok_or(
            "FERRUM_NODE_AGENT_NODE_NAME is required in node_agent mode \
             (set via Kubernetes downward API: spec.nodeName)"
                .to_string(),
        )?;
        if node_name.trim().is_empty() {
            return Err("FERRUM_NODE_AGENT_NODE_NAME must not be empty".to_string());
        }

        let mut capture_config = CaptureConfig::from_env()?;
        capture_config.ensure_exclude_port(env_config.node_agent_hbone_redirect_port);
        let cgroup_root = resolve_ferrum_var("FERRUM_NODE_AGENT_CGROUP_ROOT")
            .unwrap_or_else(|| DEFAULT_CGROUP_ROOT.to_string());
        let bpf_fs_path = resolve_ferrum_var("FERRUM_NODE_AGENT_BPF_FS_PATH")
            .unwrap_or_else(|| DEFAULT_BPF_FS_PATH.to_string());
        let fallback_mode = FallbackMode::parse(
            &resolve_ferrum_var("FERRUM_NODE_AGENT_FALLBACK_MODE")
                .unwrap_or_else(|| DEFAULT_FALLBACK_MODE.to_string()),
        )?;

        let extra_excluded: Vec<String> =
            resolve_ferrum_var("FERRUM_NODE_AGENT_EXCLUDED_NAMESPACES")
                .map(|raw| {
                    raw.split(',')
                        .map(|s| s.trim().to_string())
                        .filter(|s| !s.is_empty())
                        .collect()
                })
                .unwrap_or_default();
        let excluded_namespaces = pod_watcher::build_excluded_namespaces(&extra_excluded);
        let capture_contract = CaptureContract::new(
            env_config.node_agent_proxy_mode,
            capture_config.outbound_port,
            env_config.node_agent_hbone_redirect_port,
            DEFAULT_NODE_AGENT_SOCKET_PATH,
        )?;

        Ok(Self {
            node_name,
            capture_config,
            cgroup_root,
            bpf_fs_path,
            fallback_mode,
            excluded_namespaces,
            capture_contract,
        })
    }
}

pub async fn run(
    env_config: EnvConfig,
    shutdown_tx: tokio::sync::watch::Sender<bool>,
) -> Result<(), anyhow::Error> {
    let config = NodeAgentConfig::from_env_config(&env_config).map_err(anyhow::Error::msg)?;
    let metrics = Arc::new(NodeAgentMetrics::default());
    crate::plugins::prometheus_metrics::global_registry().set_node_agent_metrics(metrics.clone());
    let startup_ready = Arc::new(AtomicBool::new(false));
    let admin_handles =
        start_node_agent_admin_listeners(&env_config, &shutdown_tx, startup_ready.clone()).await?;

    info!(
        node_name = %config.node_name,
        capture_mode = ?config.capture_config.mode,
        proxy_mode = %config.capture_contract.proxy_mode,
        outbound_capture_port = config.capture_contract.outbound_capture_port,
        hbone_redirect_port = config.capture_contract.hbone_redirect_port,
        cgroup_root = %config.cgroup_root,
        bpf_fs_path = %config.bpf_fs_path,
        fallback_mode = ?config.fallback_mode,
        "Starting node agent"
    );

    let probe = kernel_probe::probe_kernel(&config.cgroup_root, &config.bpf_fs_path);
    info!(
        kernel_release = %probe.kernel_release,
        meets_version = probe.meets_version_requirement,
        cgroup_v2 = probe.cgroup_v2_available,
        bpf_fs = probe.bpf_fs_available,
        "Kernel probe complete"
    );

    let result = if !probe.supports_ebpf() {
        handle_fallback(
            &config,
            &probe,
            metrics.as_ref(),
            &shutdown_tx,
            startup_ready,
        )
        .await
    } else {
        run_with_backend(
            create_backend(),
            &config,
            metrics,
            &shutdown_tx,
            startup_ready,
        )
        .await
    };

    let _ = shutdown_tx.send(true);
    for handle in admin_handles {
        if let Err(err) = handle.await {
            warn!(error = %err, "Node agent admin listener task failed");
        }
    }

    result
}

async fn start_node_agent_admin_listeners(
    env_config: &EnvConfig,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    startup_ready: Arc<AtomicBool>,
) -> Result<Vec<tokio::task::JoinHandle<()>>, anyhow::Error> {
    let mut handles = Vec::new();
    if !env_config.node_agent_admin_enabled {
        return Ok(handles);
    }
    if env_config.admin_http_port == 0 {
        return Ok(handles);
    }

    let admin_allowed_cidrs = Arc::new(
        crate::proxy::client_ip::TrustedProxies::parse_strict(&env_config.admin_allowed_cidrs)
            .map_err(|e| anyhow::anyhow!("FERRUM_ADMIN_ALLOWED_CIDRS: {}", e))?,
    );
    let jwt_manager = match create_jwt_manager_from_env() {
        Ok(manager) => manager,
        Err(err) => {
            warn!(
                "Admin JWT not configured for node_agent mode ({}), authenticated admin endpoints will reject operator tokens",
                err
            );
            let random_secret = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            crate::admin::jwt_auth::JwtManager::new(crate::admin::jwt_auth::JwtConfig {
                secret: random_secret,
                ..Default::default()
            })
        }
    };

    let admin_state = AdminState {
        db: None,
        jwt_manager,
        proxy_state: None,
        cached_config: None,
        mode: "node_agent".to_string(),
        read_only: true,
        admin_audit_enabled: env_config.admin_audit_enabled,
        startup_ready: Some(startup_ready),
        db_available: None,
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        admin_spec_max_body_size_mib: env_config.admin_spec_max_body_size_mib,
        reserved_ports: env_config.reserved_gateway_ports(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs,
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: env_config.http_header_read_timeout_seconds,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
    };

    // Safe-by-default bind: when the operator opts into the node-agent admin
    // listener but configures neither an explicit bind nor an allowlist, fall
    // back to loopback so unauthenticated `/metrics` and `/health` are not
    // exposed on the network. See `decide_admin_bind_address`.
    let signals = AdminBindSignals::from_env();
    let admin_http_addr = decide_admin_bind_address(
        &env_config.admin_bind_address,
        env_config.admin_http_port,
        &signals,
    )?;
    let shutdown = shutdown_tx.subscribe();
    let handle = tokio::spawn(async move {
        info!(
            "Starting node_agent admin HTTP listener on {}",
            admin_http_addr
        );
        if let Err(err) = admin::start_admin_listener(admin_http_addr, admin_state, shutdown).await
        {
            error!("Node agent admin HTTP listener error: {}", err);
        }
    });
    handles.push(handle);

    Ok(handles)
}

/// Operator signals that confirm the node-agent admin listener is intentionally
/// reachable beyond loopback. Captured at startup via `resolve_ferrum_var` so
/// the env > conf-file precedence chain matches the rest of the gateway.
#[derive(Debug, Clone)]
struct AdminBindSignals {
    /// `FERRUM_ADMIN_BIND_ADDRESS` set explicitly (env or ferrum.conf).
    bind_address_explicit: bool,
    /// `FERRUM_ADMIN_ALLOWED_CIDRS` set to a non-empty allowlist.
    allowed_cidrs_set: bool,
}

impl AdminBindSignals {
    fn from_env() -> Self {
        Self {
            bind_address_explicit: resolve_ferrum_var("FERRUM_ADMIN_BIND_ADDRESS")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false),
            allowed_cidrs_set: resolve_ferrum_var("FERRUM_ADMIN_ALLOWED_CIDRS")
                .map(|v| !v.trim().is_empty())
                .unwrap_or(false),
        }
    }
}

/// Pure helper: pick the admin listener bind address for node-agent mode.
///
/// When the operator opts in to the node-agent admin listener but has NOT
/// configured either network-exposure signal (`FERRUM_ADMIN_BIND_ADDRESS` or
/// `FERRUM_ADMIN_ALLOWED_CIDRS`) AND the resolved bind address is the
/// unspecified-default `0.0.0.0`, override it to `127.0.0.1` and emit a
/// `warn!` pointing operators at the escape hatches. This prevents accidentally
/// exposing unauthenticated `/metrics` and `/health` to the network when the
/// operator just flips
/// `FERRUM_NODE_AGENT_ADMIN_ENABLED=true` without further config.
fn decide_admin_bind_address(
    configured_bind: &str,
    port: u16,
    signals: &AdminBindSignals,
) -> Result<std::net::SocketAddr, anyhow::Error> {
    let configured_ip: std::net::IpAddr = configured_bind.parse().map_err(|_| {
        anyhow::anyhow!(
            "Invalid FERRUM_ADMIN_BIND_ADDRESS '{}' (expected a valid IP address)",
            configured_bind
        )
    })?;

    let any_signal_present = signals.bind_address_explicit || signals.allowed_cidrs_set;
    let is_default_unspecified = !signals.bind_address_explicit
        && (configured_ip.is_unspecified() || configured_bind == "0.0.0.0");

    if !any_signal_present && is_default_unspecified {
        warn!(
            "FERRUM_NODE_AGENT_ADMIN_ENABLED=true with no allowlist or explicit bind address configured; \
             defaulting node-agent admin listener to 127.0.0.1:{port} so unauthenticated /metrics and /health \
             are not exposed on the network. To bind elsewhere, set one of: \
             FERRUM_ADMIN_BIND_ADDRESS=<address> (e.g. 0.0.0.0 if intentional), \
             or FERRUM_ADMIN_ALLOWED_CIDRS=<cidr-list>"
        );
        let loopback: std::net::IpAddr = std::net::Ipv4Addr::LOCALHOST.into();
        return Ok(std::net::SocketAddr::new(loopback, port));
    }

    Ok(std::net::SocketAddr::new(configured_ip, port))
}

fn create_backend() -> Box<dyn EbpfBackend> {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        Box::new(crate::ebpf::AyaEbpfBackend::new())
    }
    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    {
        info!("ebpf feature not enabled, using mock backend");
        Box::new(crate::ebpf::MockEbpfBackend::default())
    }
}

async fn run_with_backend(
    mut backend: Box<dyn EbpfBackend>,
    config: &NodeAgentConfig,
    metrics: Arc<NodeAgentMetrics>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    startup_ready: Arc<AtomicBool>,
) -> Result<(), anyhow::Error> {
    initialize_backend(backend.as_mut(), config)?;

    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();

    let mut shutdown_rx = shutdown_tx.subscribe();
    let client = build_node_agent_kube_client().await?;
    let pods: Api<Pod> = Api::all(client);
    let watcher_config =
        kube_watcher::Config::default().fields(&format!("spec.nodeName={}", config.node_name));
    let mut pod_stream = Box::pin(kube_watcher::watcher(pods, watcher_config));
    let mut init_seen: Option<HashSet<String>> = None;

    info!(
        "Node agent initialized, watching pod events on node {}",
        config.node_name
    );

    loop {
        if *shutdown_rx.borrow() {
            break;
        }
        tokio::select! {
            changed = shutdown_rx.changed() => {
                if changed.is_err() || *shutdown_rx.borrow() {
                    break;
                }
            }
            event = pod_stream.next() => {
                match event {
                    Some(Ok(Event::Apply(pod))) => {
                        handle_kube_pod_applied(
                            backend.as_mut(),
                            &pod_states,
                            config,
                            metrics.as_ref(),
                            &pod,
                        );
                    }
                    Some(Ok(Event::Delete(pod))) => {
                        if let Some(uid) = pod_uid(&pod) {
                            handle_pod_removed(backend.as_mut(), &pod_states, metrics.as_ref(), &uid);
                        }
                    }
                    Some(Ok(Event::Init)) => {
                        init_seen = Some(HashSet::new());
                    }
                    Some(Ok(Event::InitApply(pod))) => {
                        if let Some(uid) = handle_kube_pod_applied(
                            backend.as_mut(),
                            &pod_states,
                            config,
                            metrics.as_ref(),
                            &pod,
                        ) && let Some(seen) = &mut init_seen {
                            seen.insert(uid);
                        }
                    }
                    Some(Ok(Event::InitDone)) => {
                        if let Some(seen) = init_seen.take() {
                            let stale_uids: Vec<String> = pod_states
                                .iter()
                                .filter(|entry| !seen.contains(entry.key().as_str()))
                                .map(|entry| entry.key().clone())
                                .collect();
                            for uid in stale_uids {
                                handle_pod_removed(backend.as_mut(), &pod_states, metrics.as_ref(), &uid);
                            }
                        }
                        startup_ready.store(true, Ordering::Release);
                        info!("Node agent initial pod sync complete; /health now reports ready");
                    }
                    Some(Err(e)) => {
                        warn!(error = %e, "Pod watcher error; kube-rs will retry");
                        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
                    }
                    None => {
                        warn!("Pod watcher ended unexpectedly");
                        break;
                    }
                }
            }
        }
    }

    info!(
        pods_enrolled = metrics.pods_enrolled.load(Ordering::Relaxed),
        pods_unenrolled = metrics.pods_unenrolled.load(Ordering::Relaxed),
        attach_errors = metrics.attach_errors.load(Ordering::Relaxed),
        attached_pods = pod_states.len(),
        "Node agent shutting down, detaching BPF programs"
    );
    cleanup_all_pods(backend.as_mut(), &pod_states);

    Ok(())
}

async fn wait_for_shutdown(shutdown_tx: &tokio::sync::watch::Sender<bool>) {
    let mut shutdown_rx = shutdown_tx.subscribe();
    if *shutdown_rx.borrow() {
        return;
    }
    while shutdown_rx.changed().await.is_ok() {
        if *shutdown_rx.borrow() {
            return;
        }
    }
}

async fn build_node_agent_kube_client() -> Result<kube::Client, anyhow::Error> {
    let config = match kube::Config::incluster() {
        Ok(config) => config,
        Err(in_cluster_err) => match kube::Config::infer().await {
            Ok(config) => config,
            Err(infer_err) => {
                anyhow::bail!(
                    "Failed to build Kubernetes client for node_agent mode: \
                     incluster={in_cluster_err}; inferred={infer_err}"
                );
            }
        },
    };
    Ok(kube::Client::try_from(config)?)
}

fn pod_uid(pod: &Pod) -> Option<String> {
    pod.metadata.uid.clone()
}

/// Parse the `includeOutboundPorts` annotations from a pod's annotation map.
/// Returns `None` when the pod has no relevant annotation (the BPF gate
/// fail-opens on missing entries, so absent annotation => capture
/// everything). Returns `Err` only when the annotation is structurally
/// invalid (mixed wildcard / explicit, malformed token, out-of-range port);
/// callers downgrade this to a `warn!` and leave the pod un-narrowed,
/// matching the injector's "reject at admission time, then continue" policy
/// for malformed values.
fn parse_pod_include_outbound_ports(
    annotations: &HashMap<String, String>,
) -> Result<Option<IncludeOutboundPorts>, String> {
    let lookup = |key: &'static str| -> (&'static str, Option<&str>) {
        (key, annotations.get(key).map(String::as_str))
    };
    let result = include_outbound_ports_from_annotations([
        lookup(ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION),
        lookup(FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION),
    ])?;
    if result.is_absent() {
        Ok(None)
    } else {
        Ok(Some(result))
    }
}

/// Read the cgroup id (kernel inode number, which is what
/// `bpf_get_current_cgroup_id` returns) for an enrolled pod's cgroup path.
/// Returns `None` on stat error so the node-agent can warn and continue
/// without aborting enrollment — losing per-pod narrowing is a graceful
/// degradation, not a fatal condition.
#[cfg(unix)]
fn read_cgroup_id_for_pod(cgroup_path: &str) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    match std::fs::metadata(cgroup_path) {
        Ok(meta) => Some(meta.ino()),
        Err(e) => {
            debug!(cgroup_path, error = %e, "Failed to stat cgroup for includeOutboundPorts; per-pod narrowing skipped");
            None
        }
    }
}

#[cfg(not(unix))]
fn read_cgroup_id_for_pod(_cgroup_path: &str) -> Option<u64> {
    // The node-agent only ships on Linux; this stub keeps non-Unix builds
    // (developer macOS / Windows for tests) compiling without pulling in
    // platform-specific deps.
    None
}

/// Convert a parsed pod-level [`IncludeOutboundPorts`] into the BPF wire
/// shape. Emits a `warn!` when the explicit-port list overflows the BPF
/// map's per-entry cap; the resulting policy still narrows traffic but to
/// the first `INCLUDE_PORTS_MAX` ports only. Operators that hit this cap
/// in practice should split annotations across multiple pods or revisit
/// `INCLUDE_PORTS_MAX`.
fn include_outbound_ports_to_policy(
    pod_uid: &str,
    include: &IncludeOutboundPorts,
) -> IncludePortsPolicy {
    if include.all_ports {
        return IncludePortsPolicy::all();
    }
    if include.ports.len() > INCLUDE_PORTS_MAX {
        warn!(
            pod_uid,
            requested = include.ports.len(),
            cap = INCLUDE_PORTS_MAX,
            "includeOutboundPorts annotation exceeds BPF map capacity; truncating to first {INCLUDE_PORTS_MAX} ports"
        );
    }
    IncludePortsPolicy::explicit(&include.ports)
}

/// Outcome of writing (or attempting to write) a pod's parsed
/// `includeOutboundPorts` annotation into the BPF map.
///
/// Carries both the cgroup id the entry is keyed on (so removal can use
/// it without re-statting the cgroup) and the [`IncludePortsPolicy`]
/// actually written, so the watcher can diff against this baseline on
/// the next Modified event and skip BPF map churn when the parsed value
/// has not changed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedIncludePorts {
    cgroup_id: u64,
    policy: IncludePortsPolicy,
}

/// Push the parsed per-pod include-port policy into the BPF map. Returns
/// the cgroup id and policy we wrote so callers can stash both on
/// `PodAttachmentState`: the cgroup id is the removal key, the policy is
/// the diff baseline for mid-life Modified events. Returns `None` when
/// there's nothing to write (no annotation, malformed annotation, or
/// cgroup-id stat failed) — none of which should abort enrollment.
fn apply_include_outbound_ports(
    backend: &mut dyn EbpfBackend,
    pod_uid: &str,
    cgroup_path: &str,
    annotations: &HashMap<String, String>,
) -> Option<AppliedIncludePorts> {
    let include = match parse_pod_include_outbound_ports(annotations) {
        Ok(Some(include)) => include,
        Ok(None) => return None,
        Err(e) => {
            warn!(
                pod_uid,
                error = %e,
                "Skipping includeOutboundPorts BPF narrowing; pod will capture all outbound ports"
            );
            return None;
        }
    };
    let cgroup_id = read_cgroup_id_for_pod(cgroup_path)?;
    let policy = include_outbound_ports_to_policy(pod_uid, &include);
    match backend.update_pod_include_ports(cgroup_id, &policy) {
        Ok(()) => {
            debug!(
                pod_uid,
                cgroup_id,
                all_ports = policy.is_all_ports(),
                port_count = policy.port_count,
                "Wrote per-pod includeOutboundPorts entry to BPF map"
            );
            Some(AppliedIncludePorts { cgroup_id, policy })
        }
        Err(e) => {
            warn!(
                pod_uid,
                cgroup_id,
                error = %e,
                "Failed to update FERRUM_INCLUDE_PORTS for pod; capture will not narrow"
            );
            None
        }
    }
}

fn handle_kube_pod_applied(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    pod: &Pod,
) -> Option<String> {
    let pod_uid = pod_uid(pod)?;
    let pod_name = pod.metadata.name.clone().unwrap_or_else(|| pod_uid.clone());
    let namespace = pod
        .metadata
        .namespace
        .clone()
        .unwrap_or_else(|| "default".to_string());
    let labels: HashMap<String, String> = pod
        .metadata
        .labels
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let annotations: HashMap<String, String> = pod
        .metadata
        .annotations
        .clone()
        .unwrap_or_default()
        .into_iter()
        .collect();
    let pod_ip = pod
        .status
        .as_ref()
        .and_then(|status| status.pod_ip.as_deref());
    let event = PodEvent {
        pod_uid: &pod_uid,
        pod_name: &pod_name,
        namespace: &namespace,
        labels: &labels,
        annotations: &annotations,
        pod_ip_str: pod_ip,
        pod_pid: None,
        veth_iface_override: None,
    };
    handle_pod_added(backend, pod_states, config, metrics, &event);
    Some(pod_uid)
}

/// Describes a pod event for enrollment processing.
pub struct PodEvent<'a> {
    pub pod_uid: &'a str,
    pub pod_name: &'a str,
    pub namespace: &'a str,
    pub labels: &'a HashMap<String, String>,
    pub annotations: &'a HashMap<String, String>,
    pub pod_ip_str: Option<&'a str>,
    pub pod_pid: Option<u32>,
    /// Pre-resolved host-side veth interface name for this pod, bypassing
    /// the production resolver. Production always sets this to `None` and
    /// relies on the procfs/sysfs probe from either the explicit pod PID or
    /// the resolved pod cgroup; tests set it to a synthetic interface name
    /// (e.g., `"veth-mock"`) to satisfy the post-`65606d87` enrollment
    /// invariant that requires an inbound tc attach before the pod is
    /// considered enrolled, without needing a real pod PID or a Linux kernel
    /// under test.
    pub veth_iface_override: Option<&'a str>,
}

pub fn handle_pod_added(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    event: &PodEvent<'_>,
) {
    let (pod_uid, pod_name, namespace) = (event.pod_uid, event.pod_name, event.namespace);
    let decision = pod_watcher::evaluate_enrollment(
        event.labels,
        event.annotations,
        namespace,
        &config.excluded_namespaces,
    );
    if decision != EnrollmentDecision::Enroll {
        if pod_states.contains_key(pod_uid) {
            handle_pod_removed(backend, pod_states, metrics, pod_uid);
        }
        debug!(
            pod_uid,
            pod_name, namespace, "Pod does not meet enrollment criteria"
        );
        return;
    }

    let pod_ip = event.pod_ip_str.and_then(pod_watcher::parse_pod_ip);
    let cgroup_path = cgroup::resolve_pod_cgroup_path(&config.cgroup_root, pod_uid)
        .map(|p| p.to_string_lossy().to_string());
    // Production: the kube-rs caller sets `veth_iface_override = None`; the
    // resolver first uses an explicit pod PID when available, then falls back
    // to the resolved pod cgroup to find a live process in that pod.
    // Tests supply a synthetic name so the post-65606d87 inbound-tc invariant
    // is satisfied without a real pod PID / Linux kernel.
    let veth_iface = event
        .veth_iface_override
        .map(|s| s.to_string())
        .or_else(|| veth::discover_veth_for_pod(event.pod_pid, cgroup_path.as_deref()));

    if let Some(mut state) = pod_states.get_mut(pod_uid) {
        let attachment_target_changed = state.cgroup_path != cgroup_path
            || veth_iface
                .as_ref()
                .is_some_and(|iface| state.veth_iface.as_ref() != Some(iface));
        if attachment_target_changed {
            drop(state);
            handle_pod_removed(backend, pod_states, metrics, pod_uid);
        } else {
            reconcile_existing_pod_ip(backend, config, metrics, pod_uid, pod_ip, &mut state);
            reconcile_existing_pod_include_ports(
                backend,
                metrics,
                pod_uid,
                event.annotations,
                &mut state,
            );
            debug!(pod_uid, pod_name, "Pod already enrolled, reconciled state");
            return;
        }
    }

    let mut state = PodAttachmentState {
        pod_uid: pod_uid.to_string(),
        pod_name: pod_name.to_string(),
        namespace: namespace.to_string(),
        pod_ip,
        cgroup_path: cgroup_path.clone(),
        veth_iface: veth_iface.clone(),
        attached: false,
        include_ports_cgroup_id: None,
        include_ports_policy: None,
    };

    if let Some(ref cgroup) = cgroup_path {
        let programs = [
            "ferrum_connect4",
            "ferrum_connect6",
            "ferrum_getpeername4",
            "ferrum_getpeername6",
        ];
        let mut attach_ok = true;
        for prog in &programs {
            if let Err(e) = backend.attach_cgroup(pod_uid, cgroup, prog) {
                warn!(pod_uid, program = prog, error = %e, "Failed to attach cgroup program");
                metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
                attach_ok = false;
                break;
            }
        }
        if attach_ok {
            let Some(ref iface) = veth_iface else {
                warn!(
                    pod_uid,
                    pod_name,
                    namespace,
                    "Could not resolve pod veth interface, skipping attachment"
                );
                metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
                if let Err(e) = backend.detach_pod(pod_uid) {
                    warn!(pod_uid, error = %e, "Failed to clean up partially attached pod");
                }
                return;
            };

            if let Err(e) = backend.attach_tc(pod_uid, iface, "ferrum_tc_inbound") {
                warn!(pod_uid, iface, error = %e, "Failed to attach tc program");
                metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
                if let Err(detach_err) = backend.detach_pod(pod_uid) {
                    warn!(pod_uid, error = %detach_err, "Failed to clean up partially attached pod");
                }
                return;
            }
            if let Some(ip) = pod_ip {
                let info = PodInfo {
                    proxy_port: config.capture_config.outbound_port,
                    cgroup_id: 0,
                };
                if let Err(e) = backend.update_pod_ip(ip, &info) {
                    warn!(pod_uid, %ip, error = %e, "Failed to update pod IP map");
                    metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
                    if let Err(detach_err) = backend.detach_pod(pod_uid) {
                        warn!(pod_uid, error = %detach_err, "Failed to clean up partially attached pod");
                    }
                    return;
                }
            }
            // Per-pod `includeOutboundPorts` narrowing. Best-effort: any
            // failure to parse or to write the BPF map leaves the pod
            // captured at the cgroup level without per-port narrowing
            // (which is the prior GAP-2K behavior). Enrollment itself
            // must not abort on this.
            if let Some(applied) =
                apply_include_outbound_ports(backend, pod_uid, cgroup, event.annotations)
            {
                state.include_ports_cgroup_id = Some(applied.cgroup_id);
                state.include_ports_policy = Some(applied.policy);
            }
            state.attached = true;
            metrics.pods_enrolled.fetch_add(1, Ordering::Relaxed);
            info!(
                pod_uid,
                pod_name,
                namespace,
                ?pod_ip,
                include_ports_narrowing = state.include_ports_cgroup_id.is_some(),
                "Pod enrolled for eBPF capture"
            );
        } else if let Err(e) = backend.detach_pod(pod_uid) {
            warn!(pod_uid, error = %e, "Failed to clean up partially attached pod");
        }
    } else {
        warn!(
            pod_uid,
            pod_name, "Could not resolve cgroup path, skipping attachment"
        );
        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }

    if state.attached {
        pod_states.insert(pod_uid.to_string(), state);
    }
}

fn reconcile_existing_pod_ip(
    backend: &mut dyn EbpfBackend,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    pod_ip: Option<std::net::Ipv4Addr>,
    state: &mut PodAttachmentState,
) {
    let Some(new_ip) = pod_ip else {
        return;
    };
    if state.pod_ip == Some(new_ip) {
        return;
    }

    let info = PodInfo {
        proxy_port: config.capture_config.outbound_port,
        cgroup_id: 0,
    };
    if let Err(e) = backend.update_pod_ip(new_ip, &info) {
        warn!(pod_uid, %new_ip, error = %e, "Failed to update pod IP map for existing pod");
        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
        return;
    }
    if let Some(old_ip) = state.pod_ip
        && let Err(e) = backend.remove_pod_ip(old_ip)
    {
        warn!(pod_uid, %old_ip, error = %e, "Failed to remove stale pod IP from map");
        metrics.attach_errors.fetch_add(1, Ordering::Relaxed);
    }
    state.pod_ip = Some(new_ip);
}

/// Re-evaluate the `includeOutboundPorts` annotations of an already-enrolled
/// pod (Kubernetes `Apply` events conflate "added" and "modified"), and
/// reprogram the BPF map if and only if the parsed policy differs from
/// the baseline stashed at enrollment time.
///
/// This is the GAP-2K mid-life update gap: prior to this hook, changing
/// `traffic.sidecar.istio.io/includeOutboundPorts` (or its Ferrum-native
/// alias) on a live pod was a no-op until the pod restarted, because the
/// node-agent only wrote the BPF map on first enrollment. With this hook,
/// a `kubectl annotate pod ...` reconciles within the watcher's normal
/// debounce window.
///
/// Diff-skip is load-bearing: pods receive `Modified` events for many
/// reasons (status updates, container restarts, condition flips). Writing
/// the BPF map on every Modified event would burn syscalls and produce
/// log noise. We compare the *parsed* policy (post-merge of Istio +
/// Ferrum aliases, post-sort, post-dedupe), not the raw annotation
/// strings — so re-ordering ports in the annotation is correctly a no-op.
///
/// Long-lived flow caveat: the BPF `connect4` / `connect6` programs run
/// on `connect(2)`, so the new policy takes effect only for *new* outbound
/// connections issued by the pod after this hook runs. Already-established
/// flows continue with the redirect their original connect saw — closing
/// them is a userspace concern outside this module.
fn reconcile_existing_pod_include_ports(
    backend: &mut dyn EbpfBackend,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    annotations: &HashMap<String, String>,
    state: &mut PodAttachmentState,
) {
    // Compute the desired policy (or None for absent annotation).
    let desired = match parse_pod_include_outbound_ports(annotations) {
        Ok(Some(include)) => Some(include_outbound_ports_to_policy(pod_uid, &include)),
        Ok(None) => None,
        Err(e) => {
            warn!(
                pod_uid,
                error = %e,
                "Mid-life pod annotation update failed to parse; keeping previous includeOutboundPorts policy"
            );
            metrics
                .pod_annotation_updates_failed
                .fetch_add(1, Ordering::Relaxed);
            return;
        }
    };

    // Hot-path diff-skip: most Modified events are unrelated to capture
    // annotations (status updates, container restart counts, etc.). The
    // `Option<IncludePortsPolicy>` derives `PartialEq`, so this is a
    // cheap structural compare — no allocations, no syscalls.
    if desired == state.include_ports_policy {
        return;
    }

    // Identity for removal/replace lookups. Prefer the cgroup id stashed
    // at enrollment (still valid even if the cgroup path was rotated
    // out from under us); fall back to re-statting the path only when
    // we have no prior id (the pod was previously unannotated and is
    // newly transitioning into having a policy).
    let cgroup_id_for_lookup = state.include_ports_cgroup_id.or_else(|| {
        state
            .cgroup_path
            .as_deref()
            .and_then(read_cgroup_id_for_pod)
    });

    match (desired, cgroup_id_for_lookup) {
        (Some(new_policy), Some(cgroup_id)) => {
            // Add or replace. `update_pod_include_ports` is an insert-or-
            // overwrite on the BPF HashMap; the kernel does not require
            // explicit removal before re-insertion.
            match backend.update_pod_include_ports(cgroup_id, &new_policy) {
                Ok(()) => {
                    let prev_summary = describe_policy(state.include_ports_policy.as_ref());
                    let new_summary = describe_policy(Some(&new_policy));
                    info!(
                        pod_uid,
                        cgroup_id,
                        prev_policy = %prev_summary,
                        new_policy = %new_summary,
                        "Re-applied mid-life pod includeOutboundPorts annotation update to BPF map"
                    );
                    state.include_ports_cgroup_id = Some(cgroup_id);
                    state.include_ports_policy = Some(new_policy);
                    metrics
                        .pod_annotation_updates_applied
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    warn!(
                        pod_uid,
                        cgroup_id,
                        error = %e,
                        "Failed to re-apply mid-life pod includeOutboundPorts update; keeping previous policy"
                    );
                    metrics
                        .pod_annotation_updates_failed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        (None, Some(cgroup_id)) => {
            // The pod removed its annotation entirely → drop the BPF
            // entry so the gate fail-opens back to "capture everything"
            // for this pod, matching pre-enrollment behavior.
            match backend.remove_pod_include_ports(cgroup_id) {
                Ok(()) => {
                    let prev_summary = describe_policy(state.include_ports_policy.as_ref());
                    info!(
                        pod_uid,
                        cgroup_id,
                        prev_policy = %prev_summary,
                        "Mid-life pod removed includeOutboundPorts annotation; dropped BPF map entry"
                    );
                    state.include_ports_cgroup_id = None;
                    state.include_ports_policy = None;
                    metrics
                        .pod_annotation_updates_applied
                        .fetch_add(1, Ordering::Relaxed);
                }
                Err(e) => {
                    warn!(
                        pod_uid,
                        cgroup_id,
                        error = %e,
                        "Failed to drop mid-life pod includeOutboundPorts BPF entry; keeping previous policy"
                    );
                    metrics
                        .pod_annotation_updates_failed
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
        }
        (Some(_), None) => {
            // We want to write a new entry but have no cgroup id — most
            // likely the pod was enrolled before its cgroup path
            // existed (Kubernetes Pod object reaches the watcher before
            // kubelet finishes creating the cgroup). Skip and let a
            // future event retry; do NOT count this as a failure because
            // it is operationally normal.
            debug!(
                pod_uid,
                "Mid-life includeOutboundPorts update deferred: cgroup id unavailable"
            );
        }
        (None, None) => {
            // Nothing to write and nothing to remove. Reachable only if
            // `desired` flipped from `None` to `None` in a way that
            // disagreed with `state.include_ports_policy` (e.g. the
            // baseline was `Some(_)` but the cgroup id was unknown when
            // it was stashed). Clear the baseline so future diffs are
            // consistent.
            state.include_ports_policy = None;
        }
    }
}

/// Render an `Option<&IncludePortsPolicy>` as a short structured string
/// for logging. Only invoked from the success/error arms of
/// `reconcile_existing_pod_include_ports` — never on the diff-skip
/// no-op path, which returns early before any formatting work runs.
fn describe_policy(policy: Option<&IncludePortsPolicy>) -> String {
    match policy {
        None => "none".to_string(),
        Some(p) if p.is_all_ports() => "all".to_string(),
        Some(p) => {
            let count = p.port_count as usize;
            let bounded = count.min(p.ports.len());
            format!("ports={:?}", &p.ports[..bounded])
        }
    }
}

#[allow(dead_code)]
pub fn handle_pod_removed(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
) {
    let removed = pod_states.remove(pod_uid);
    let Some((_, state)) = removed else {
        return;
    };

    if state.attached {
        if let Err(e) = backend.detach_pod(pod_uid) {
            warn!(pod_uid, error = %e, "Failed to detach BPF programs");
        }
        if let Some(ip) = state.pod_ip
            && let Err(e) = backend.remove_pod_ip(ip)
        {
            warn!(pod_uid, %ip, error = %e, "Failed to remove pod IP from map");
        }
        // Pair with `apply_include_outbound_ports` — only annotated pods
        // ever carried an entry. Use the stashed cgroup id so we don't
        // re-stat the cgroup path, which may already have been torn down
        // by kubelet.
        if let Some(cgroup_id) = state.include_ports_cgroup_id
            && let Err(e) = backend.remove_pod_include_ports(cgroup_id)
        {
            warn!(
                pod_uid,
                cgroup_id,
                error = %e,
                "Failed to remove pod includeOutboundPorts entry from BPF map"
            );
        }
        metrics.pods_unenrolled.fetch_add(1, Ordering::Relaxed);
        info!(pod_uid, pod_name = %state.pod_name, "Pod unenrolled from eBPF capture");
    }
}

async fn handle_fallback(
    config: &NodeAgentConfig,
    probe: &KernelProbeResult,
    metrics: &NodeAgentMetrics,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    startup_ready: Arc<AtomicBool>,
) -> Result<(), anyhow::Error> {
    handle_fallback_with(
        config,
        probe,
        metrics,
        shutdown_tx,
        |cmds, phase| async move { execute_iptables_commands(&cmds, phase).await },
        startup_ready,
    )
    .await
}

/// Test seam for [`handle_fallback`]. The production path passes
/// `execute_iptables_commands` (real `sh -c`); the unit test passes a no-op
/// closure so it can assert the control flow (setup → wait → cleanup) without
/// spawning ~11 subprocesses, which (a) is wall-clock expensive on a loaded
/// CI box and (b) drags real-time scheduling into a test that should be
/// purely deterministic.
async fn handle_fallback_with<F, Fut>(
    config: &NodeAgentConfig,
    probe: &KernelProbeResult,
    metrics: &NodeAgentMetrics,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    mut execute: F,
    startup_ready: Arc<AtomicBool>,
) -> Result<(), anyhow::Error>
where
    F: FnMut(Vec<String>, &'static str) -> Fut,
    Fut: std::future::Future<Output = Result<(), anyhow::Error>>,
{
    // Stamp the degradation reason on the shared metrics handle BEFORE the
    // warn/fallback decision so /metrics consistently reports `1` for the
    // exact reason that drove the fallback, even if iptables setup later
    // fails. `degradation_reason()` is `None` only when supports_ebpf() is
    // true — but we only reach this function when supports_ebpf() is false,
    // so the unwrap-or-fallback branch is purely defensive (e.g., a future
    // caller that probes more capability bits than the helper checks).
    let reason = probe.degradation_reason().unwrap_or("unknown");
    metrics.set_topology_degraded(reason);

    match config.fallback_mode {
        FallbackMode::Iptables => {
            warn!(
                kernel_release = %probe.kernel_release,
                meets_version = probe.meets_version_requirement,
                cgroup_v2 = probe.cgroup_v2_available,
                bpf_fs = probe.bpf_fs_available,
                degradation_reason = reason,
                "Kernel does not support eBPF capture, falling back to iptables mode. \
                 Remediation: upgrade kernel to >= 5.7 with cgroup v2 + bpffs mounted, \
                 or set FERRUM_NODE_AGENT_FALLBACK_MODE=fail to refuse startup on degraded nodes. \
                 Per-pod ambient capture remains available via iptables injection — \
                 configure the injector NodeSelector so pods on this node receive an iptables init container."
            );

            let plan = IptablesPlan::for_config(&config.capture_config);
            // Always try IPv6 cleanup: an earlier process/config may have
            // created ip6tables chains even when the current plan has none.
            let include_v6_cleanup = true;
            let setup = setup_commands_for_plan(&plan);
            if let Err(setup_err) = execute(setup, "setup").await {
                let cleanup = cleanup_commands_for_plan(include_v6_cleanup);
                if let Err(cleanup_err) = execute(cleanup, "cleanup").await {
                    warn!(
                        error = %cleanup_err,
                        "Failed to clean up iptables fallback rules after setup failure"
                    );
                }
                return Err(setup_err);
            }
            startup_ready.store(true, Ordering::Release);

            info!("Iptables fallback rules applied, awaiting shutdown signal");

            wait_for_shutdown(shutdown_tx).await;

            info!("Shutdown signal received, cleaning up iptables rules");
            let cleanup = cleanup_commands_for_plan(include_v6_cleanup);
            if let Err(e) = execute(cleanup, "cleanup").await {
                warn!(error = %e, "Failed to clean up iptables fallback rules");
            }

            Ok(())
        }
        FallbackMode::Fail => {
            error!(
                kernel_release = %probe.kernel_release,
                meets_version = probe.meets_version_requirement,
                cgroup_v2 = probe.cgroup_v2_available,
                bpf_fs = probe.bpf_fs_available,
                degradation_reason = reason,
                "Kernel does not support eBPF capture and fallback_mode=fail"
            );
            anyhow::bail!(
                "eBPF capture requires kernel >= 5.7 with cgroup v2 and bpffs. \
                 Detected: kernel={}, cgroup_v2={}, bpf_fs={}, reason={}. \
                 Set FERRUM_NODE_AGENT_FALLBACK_MODE=iptables to use iptables instead \
                 (default).",
                probe.kernel_release,
                probe.cgroup_v2_available,
                probe.bpf_fs_available,
                reason,
            );
        }
    }
}

fn setup_commands_for_plan(plan: &IptablesPlan) -> Vec<String> {
    let ip6tables_mode = plan.ip6tables_mode;
    let mut commands = Vec::with_capacity(
        plan.v4_commands.len() + plan.v6_commands.len() + usize::from(!plan.v6_commands.is_empty()),
    );

    if !plan.v6_commands.is_empty() && ip6tables_mode == Ip6TablesMode::Required {
        commands.push(format!(
            "command -v ip6tables >/dev/null 2>&1 || {{ echo \"ip6tables is required for IPv6 mesh capture\" >&2; exit 1; }}\n\
             ip6tables -t nat -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1 || {{ echo \"ip6tables nat table is required for IPv6 mesh capture\" >&2; exit 1; }}"
        ));
    }

    commands.extend(plan.v4_commands.iter().cloned());
    match ip6tables_mode {
        // The node agent runs commands one-by-one for clearer fallback errors, so
        // auto-mode probes are wrapped per command instead of batched like the init script.
        Ip6TablesMode::Auto => commands.extend(
            plan.v6_commands
                .iter()
                .map(|cmd| ip6tables_best_effort_wrapped_command(cmd)),
        ),
        Ip6TablesMode::Required => commands.extend(plan.v6_commands.iter().cloned()),
        Ip6TablesMode::Disabled => {}
    }
    commands
}

fn cleanup_commands_for_plan(include_v6: bool) -> Vec<String> {
    let mut commands = IptablesPlan::cleanup_commands();
    if include_v6 {
        // Keep cleanup best-effort per command; stale v6 chains from an earlier
        // config should not make node-agent fallback cleanup fail.
        commands.extend(
            IptablesPlan::cleanup_v6_commands()
                .iter()
                .map(|cmd| ip6tables_best_effort_wrapped_command(cmd)),
        );
    }
    commands
}

fn ip6tables_best_effort_wrapped_command(cmd: &str) -> String {
    format!(
        "if command -v ip6tables >/dev/null 2>&1; then\n  if ip6tables -t nat -w {XTABLES_LOCK_WAIT_SECONDS} -L >/dev/null 2>&1; then\n    {cmd}\n  else\n    echo \"ip6tables nat table unavailable; skipping IPv6 mesh capture rules\"\n  fi\nelse\n  echo \"ip6tables not found; skipping IPv6 mesh capture rules\"\nfi"
    )
}

/// Execute a list of shell commands (iptables/ip6tables setup or cleanup)
/// sequentially.
///
/// Each command is run via `sh -c` so that shell operators (`||`, `2>/dev/null`)
/// are interpreted correctly. Execution stops on the first command failure so
/// setup never reports success after a partially applied ruleset. Cleanup
/// commands include their own best-effort `|| true` guards where continuing
/// after an absent chain is safe.
///
/// Only invoked from `handle_fallback`, which is reached only on `node_agent`
/// mode after kernel-probe failure. The commands are formed from
/// `IptablesPlan::for_config` / `cleanup_commands`, both of which use
/// hardcoded chain names and operator inputs validated upstream
/// (`validate_cidr_list`, `parse_port_list`, `parse_proxy_uid`).
async fn execute_iptables_commands(commands: &[String], phase: &str) -> Result<(), anyhow::Error> {
    for cmd in commands {
        debug!(command = %cmd, phase, "Executing iptables command");
        match tokio::process::Command::new("sh")
            .arg("-c")
            .arg(cmd)
            .output()
            .await
        {
            Ok(output) => {
                if output.status.success() {
                    debug!(command = %cmd, phase, "iptables command succeeded");
                } else {
                    let stderr = String::from_utf8_lossy(&output.stderr);
                    let exit_code = output.status.code();
                    error!(
                        command = %cmd,
                        phase,
                        exit_code,
                        stderr = %stderr.trim(),
                        "iptables command failed"
                    );
                    anyhow::bail!(
                        "iptables {phase} command failed with exit code {:?}: {}",
                        exit_code,
                        stderr.trim()
                    );
                }
            }
            Err(e) => {
                error!(
                    command = %cmd,
                    phase,
                    error = %e,
                    "Failed to spawn iptables command"
                );
                return Err(anyhow::anyhow!(
                    "failed to spawn iptables {phase} command: {e}"
                ));
            }
        }
    }
    Ok(())
}

fn initialize_backend(
    backend: &mut dyn EbpfBackend,
    config: &NodeAgentConfig,
) -> Result<(), anyhow::Error> {
    backend.load_programs().map_err(anyhow::Error::msg)?;
    backend
        .update_capture_config(&config.capture_contract.bpf_capture_config())
        .map_err(anyhow::Error::msg)?;

    if let Some(uid) = config.capture_config.proxy_uid {
        backend.update_bypass_uid(uid).map_err(anyhow::Error::msg)?;
    }

    for cidr in &config.capture_config.include_cidrs {
        backend
            .update_cidr_include(cidr)
            .map_err(anyhow::Error::msg)?;
    }
    for cidr in &config.capture_config.exclude_cidrs {
        backend
            .update_cidr_exclude(cidr)
            .map_err(anyhow::Error::msg)?;
    }
    for port in &config.capture_config.exclude_ports {
        backend
            .update_port_exclude(*port)
            .map_err(anyhow::Error::msg)?;
    }
    // Per-pod `includeOutboundPorts` narrowing is applied later in
    // `handle_pod_added` via `apply_include_outbound_ports` because the
    // BPF map is keyed by per-pod cgroup id, not by the global
    // capture-config slot. `initialize_backend` only seeds the
    // node-global shape (CIDR includes/excludes, port excludes, proxy
    // UID bypass).

    // Best-effort SOCK_OPS attach at cgroup root for TCP-layer observability.
    // A failure here only loses telemetry; capture (cgroup_sockaddr / tc)
    // continues to operate.
    if let Err(e) = backend.attach_sock_ops(&config.cgroup_root) {
        warn!(
            cgroup_root = %config.cgroup_root,
            error = %e,
            "Failed to attach SOCK_OPS program; mesh-proxy will see zero TCP-layer counters"
        );
    }

    info!("BPF programs loaded and maps initialized");
    Ok(())
}

fn cleanup_all_pods(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
) {
    for entry in pod_states.iter() {
        let state = entry.value();
        if state.attached
            && let Err(e) = backend.detach_pod(&state.pod_uid)
        {
            warn!(pod_uid = %state.pod_uid, error = %e, "Failed to detach BPF programs during shutdown");
        }
    }
    if let Err(e) = backend.cleanup_all() {
        warn!(error = %e, "Failed to cleanup BPF state during shutdown");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capture::{CaptureMode, Ip6TablesMode};
    use crate::ebpf::MockEbpfBackend;

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn with_env_vars<T>(vars: &[(&str, &str)], f: impl FnOnce() -> T) -> T {
        let _guard = ENV_LOCK.lock().expect("env lock poisoned");
        let previous: Vec<(&str, Option<std::ffi::OsString>)> = vars
            .iter()
            .map(|(key, _)| (*key, std::env::var_os(key)))
            .collect();
        for (key, value) in vars {
            // SAFETY: this test helper serializes all env mutation in this module.
            unsafe { std::env::set_var(key, value) };
        }

        let result = f();

        for (key, value) in previous {
            // SAFETY: this test helper serializes all env mutation in this module.
            unsafe {
                match value {
                    Some(previous_value) => std::env::set_var(key, previous_value),
                    None => std::env::remove_var(key),
                }
            }
        }

        result
    }

    #[test]
    fn from_env_config_auto_excludes_configured_hbone_redirect_port() {
        let env_config = EnvConfig {
            node_agent_hbone_redirect_port: 16008,
            ..EnvConfig::default()
        };

        with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_NAME", "node-a"),
                (
                    "FERRUM_MESH_CAPTURE_EXCLUDE_PORTS",
                    "15001,15006,15008,15020",
                ),
            ],
            || {
                let config = NodeAgentConfig::from_env_config(&env_config)
                    .expect("node-agent config should parse");

                assert!(
                    config.capture_config.exclude_ports.contains(&16008),
                    "custom HBONE redirect port must bypass outbound capture"
                );
                assert_eq!(
                    config
                        .capture_config
                        .exclude_ports
                        .iter()
                        .filter(|&&port| port == 16008)
                        .count(),
                    1,
                    "auto-added HBONE redirect port should not duplicate"
                );
            },
        );
    }

    #[test]
    fn initialize_backend_populates_maps() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig {
                mode: CaptureMode::Ebpf,
                proxy_uid: Some(1337),
                inbound_port: 15006,
                outbound_port: 15001,
                include_cidrs: vec!["10.0.0.0/8".to_string()],
                include_cidrs_explicit: true,
                include_all_outbound_ports: false,
                include_outbound_ports: Vec::new(),
                exclude_cidrs: vec!["10.0.0.1/32".to_string()],
                exclude_ports: vec![15020],
                exclude_inbound_ports: Vec::new(),
                ip6tables_mode: Ip6TablesMode::Auto,
            },
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };

        let mut backend = MockEbpfBackend::default();
        initialize_backend(&mut backend, &config).unwrap();

        assert!(backend.programs_loaded);
        assert_eq!(backend.bypass_uids, vec![1337]);
        assert_eq!(backend.cidr_includes, vec!["10.0.0.0/8"]);
        assert_eq!(backend.cidr_excludes, vec!["10.0.0.1/32"]);
        assert_eq!(backend.port_excludes, vec![15020]);
        assert_eq!(
            backend.capture_config,
            Some(config.capture_contract.bpf_capture_config())
        );
    }

    #[test]
    fn initialize_backend_capture_config_failure_is_fatal() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let mut backend = MockEbpfBackend {
            fail_update_capture_config: true,
            ..MockEbpfBackend::default()
        };

        let err = initialize_backend(&mut backend, &config)
            .expect_err("capture-config failure should abort initialization");

        assert!(err.to_string().contains("capture config update failed"));
        assert!(backend.programs_loaded);
        assert!(backend.capture_config.is_none());
    }

    #[test]
    fn cleanup_all_pods_detaches_attached() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        pod_states.insert(
            "pod-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-1".to_string(),
                pod_name: "test-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_id: None,
                include_ports_policy: None,
            },
        );
        pod_states.insert(
            "pod-2".to_string(),
            PodAttachmentState {
                pod_uid: "pod-2".to_string(),
                pod_name: "skipped-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: None,
                veth_iface: None,
                attached: false,
                include_ports_cgroup_id: None,
                include_ports_policy: None,
            },
        );

        cleanup_all_pods(&mut backend, &pod_states);

        assert_eq!(backend.detached_pods.len(), 1);
        assert_eq!(backend.detached_pods[0], "pod-1");
        assert!(backend.cleaned_up);
    }

    // Verifies handle_fallback's control flow (setup → wait → cleanup → Ok)
    // without spawning real subprocesses. The earlier shape — invoking
    // `handle_fallback` directly on non-Linux so each `sh -c iptables …`
    // would fail fast — coupled a real-time sleep+signal race to ~11
    // fork/exec calls. Under CI contention either the subprocess storm or
    // the wall-clock race could push the test past its outer timeout.
    //
    // This version uses `handle_fallback_with` to inject a no-op runner and
    // pre-signals shutdown so `wait_for_shutdown`'s `borrow()` returns
    // immediately. End-to-end: no I/O, no real-time dependency, no flake.
    // The standalone `wait_for_shutdown_blocks_until_signal` test still
    // exercises the blocking path, and `IptablesPlan` has its own coverage
    // for command generation, so nothing of value is lost by mocking the
    // executor here.
    #[tokio::test]
    async fn handle_fallback_iptables_succeeds() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let probe = kernel_probe::KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx
            .send(true)
            .expect("watch channel should be open");
        let startup_ready = Arc::new(AtomicBool::new(false));
        let metrics = NodeAgentMetrics::default();

        let phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
        let phases_for_runner = std::sync::Arc::clone(&phases);
        let command_counts =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::<(&'static str, usize)>::new()));
        let command_counts_for_runner = std::sync::Arc::clone(&command_counts);

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle_fallback_with(
                &config,
                &probe,
                &metrics,
                &shutdown_tx,
                move |commands, phase| {
                    let phases = std::sync::Arc::clone(&phases_for_runner);
                    let command_counts = std::sync::Arc::clone(&command_counts_for_runner);
                    async move {
                        phases.lock().expect("phases mutex").push(phase);
                        command_counts
                            .lock()
                            .expect("command counts mutex")
                            .push((phase, commands.len()));
                        Ok(())
                    }
                },
                startup_ready.clone(),
            ),
        )
        .await
        .expect("handle_fallback should complete within timeout");
        assert!(result.is_ok());
        assert!(startup_ready.load(Ordering::Acquire));
        assert_eq!(
            *phases.lock().expect("phases mutex"),
            vec!["setup", "cleanup"]
        );
        // The degraded gauge must reflect the first-failing kernel
        // prerequisite even when iptables setup succeeded — operators rely
        // on it to filter dashboards by remediation type.
        assert_eq!(
            metrics.snapshot().topology_degraded_reason,
            Some("kernel_too_old"),
            "kernel-version failure should set the degraded gauge"
        );
    }

    #[tokio::test]
    async fn handle_fallback_iptables_setup_failure_is_not_ready() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let probe = kernel_probe::KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let startup_ready = Arc::new(AtomicBool::new(false));
        let metrics = NodeAgentMetrics::default();
        let phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
        let phases_for_runner = std::sync::Arc::clone(&phases);
        let command_counts =
            std::sync::Arc::new(std::sync::Mutex::new(Vec::<(&'static str, usize)>::new()));
        let command_counts_for_runner = std::sync::Arc::clone(&command_counts);

        let result = handle_fallback_with(
            &config,
            &probe,
            &metrics,
            &shutdown_tx,
            move |commands, phase| {
                let phases = std::sync::Arc::clone(&phases_for_runner);
                let command_counts = std::sync::Arc::clone(&command_counts_for_runner);
                async move {
                    phases.lock().expect("phases mutex").push(phase);
                    command_counts
                        .lock()
                        .expect("command counts mutex")
                        .push((phase, commands.len()));
                    anyhow::bail!("setup failed")
                }
            },
            startup_ready.clone(),
        )
        .await;

        assert!(result.is_err());
        assert!(!startup_ready.load(Ordering::Acquire));
        assert_eq!(
            *phases.lock().expect("phases mutex"),
            vec!["setup", "cleanup"]
        );
        let command_counts = command_counts.lock().expect("command counts mutex");
        assert!(
            command_counts
                .iter()
                .any(|(phase, count)| *phase == "setup" && *count > 1),
            "fallback setup should execute individual plan commands, got {command_counts:?}"
        );
        // Iptables setup failure does not erase the degraded gauge — the
        // node is still degraded, just also failed. Operators can read
        // both signals together: gauge=1 + missing pod-enrollment counts.
        assert_eq!(
            metrics.snapshot().topology_degraded_reason,
            Some("kernel_too_old"),
        );
    }

    #[test]
    fn cleanup_commands_try_ipv6_teardown_when_ip6tables_disabled() {
        let commands = cleanup_commands_for_plan(true);

        assert!(
            commands.iter().any(|cmd| cmd.contains("ip6tables")),
            "cleanup should remove stale IPv6 chains even when current config disables IPv6 capture"
        );
        assert!(
            commands
                .iter()
                .any(|cmd| cmd.contains("ip6tables -t nat -w 5 -L")),
            "disabled-mode IPv6 cleanup should remain best-effort behind the auto nat probe"
        );
    }

    #[test]
    fn cleanup_commands_wrap_required_ipv6_teardown_best_effort() {
        let commands = cleanup_commands_for_plan(true);

        assert!(
            commands
                .iter()
                .any(|cmd| cmd.contains("ip6tables -t nat -w 5 -L")),
            "required-mode cleanup should still probe ip6tables instead of emitting noisy bare commands"
        );
        assert!(
            commands
                .iter()
                .any(|cmd| cmd.contains("ip6tables not found; skipping IPv6 mesh capture rules")),
            "required-mode cleanup should remain best-effort when ip6tables is absent"
        );
    }

    #[test]
    fn setup_commands_wait_for_xtables_lock() {
        let plan = IptablesPlan::for_config(&CaptureConfig::explicit(15006, 15001));
        let commands = setup_commands_for_plan(&plan);

        assert!(
            commands.iter().all(|cmd| cmd.contains(" -w 5 ")),
            "setup commands should wait briefly for xtables lock: {commands:?}"
        );
    }

    #[tokio::test]
    async fn handle_fallback_iptables_setup_failure_is_fatal() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let probe = kernel_probe::KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        let startup_ready = Arc::new(AtomicBool::new(false));
        let metrics = NodeAgentMetrics::default();
        let phases = std::sync::Arc::new(std::sync::Mutex::new(Vec::<&'static str>::new()));
        let phases_for_runner = std::sync::Arc::clone(&phases);

        let result = handle_fallback_with(
            &config,
            &probe,
            &metrics,
            &shutdown_tx,
            move |commands, phase| {
                let phases = std::sync::Arc::clone(&phases_for_runner);
                async move {
                    if phase == "setup" {
                        assert!(
                            commands.len() > 1,
                            "setup should pass individual commands, got {commands:?}"
                        );
                        assert!(
                            commands.iter().all(|cmd| !cmd.contains('\n')),
                            "v4-only setup should not be collapsed into a shell script: {commands:?}"
                        );
                    }
                    phases.lock().expect("phases mutex").push(phase);
                    anyhow::bail!("setup failed")
                }
            },
            startup_ready.clone(),
        )
        .await;

        assert!(result.is_err());
        assert!(!startup_ready.load(Ordering::Acquire));
        assert_eq!(
            *phases.lock().expect("phases mutex"),
            vec!["setup", "cleanup"]
        );
    }

    #[test]
    fn handle_pod_added_enrolls_matching_pod() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(pod_states.contains_key("pod-uid-1"));
        assert_eq!(backend.cgroup_attachments.len(), 4);
        assert!(
            backend
                .pod_ips
                .contains_key(&std::net::Ipv4Addr::new(10, 0, 0, 5))
        );
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_added_missing_cgroup_does_not_poison_state() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-1"));
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_added_skips_non_matching() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let event = PodEvent {
            pod_uid: "pod-uid-2",
            pod_name: "no-mesh-pod",
            namespace: "default",
            labels: &HashMap::new(),
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-2"));
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handle_pod_added_unenrolls_existing_pod_when_labels_no_longer_match() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        pod_states.insert(
            "pod-uid-2".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-2".to_string(),
                pod_name: "mesh-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: Some("/sys/fs/cgroup/kubepods/poduid2".to_string()),
                veth_iface: None,
                attached: true,
                include_ports_cgroup_id: None,
                include_ports_policy: None,
            },
        );
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let event = PodEvent {
            pod_uid: "pod-uid-2",
            pod_name: "mesh-pod",
            namespace: "default",
            labels: &HashMap::new(),
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-2"));
        assert_eq!(backend.detached_pods, vec!["pod-uid-2"]);
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_added_skips_excluded_namespace() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let excluded = pod_watcher::build_excluded_namespaces(&[]);
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: excluded,
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-3",
            pod_name: "system-pod",
            namespace: "kube-system",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-3"));
    }

    #[test]
    fn handle_pod_removed_cleans_up_attached() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 5);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "test-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                cgroup_path: Some("/sys/fs/cgroup/kubepods/poduid1".to_string()),
                veth_iface: Some("veth123".to_string()),
                attached: true,
                include_ports_cgroup_id: None,
                include_ports_policy: None,
            },
        );
        backend
            .update_pod_ip(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    cgroup_id: 0,
                },
            )
            .unwrap();

        handle_pod_removed(&mut backend, &pod_states, &metrics, "pod-uid-1");

        assert!(!pod_states.contains_key("pod-uid-1"));
        assert_eq!(backend.detached_pods, vec!["pod-uid-1"]);
        assert!(!backend.pod_ips.contains_key(&ip));
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_removed_noop_for_unknown() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        handle_pod_removed(&mut backend, &pod_states, &metrics, "nonexistent");

        assert!(backend.detached_pods.is_empty());
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn handle_pod_added_skips_duplicate() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_id: None,
                include_ports_policy: None,
            },
        );

        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "duplicate",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert_eq!(pod_states.get("pod-uid-1").unwrap().pod_name, "existing");
    }

    #[test]
    fn handle_pod_added_reattaches_when_veth_changes_for_existing_pod() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup_path = cgroup_root.path().join("kubepods/podpod-uid-1");
        std::fs::create_dir_all(&cgroup_path).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: Some(cgroup_path.to_string_lossy().to_string()),
                veth_iface: Some("veth-old".to_string()),
                attached: true,
                include_ports_cgroup_id: None,
                include_ports_policy: None,
            },
        );

        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "sandbox-recreated",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.9"),
            pod_pid: None,
            veth_iface_override: Some("veth-new"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert_eq!(backend.detached_pods, vec!["pod-uid-1".to_string()]);
        assert!(
            backend
                .tc_attachments
                .iter()
                .any(|(iface, program)| iface == "veth-new" && program == "ferrum_tc_inbound")
        );
        let state = pod_states.get("pod-uid-1").unwrap();
        assert_eq!(state.pod_name, "sandbox-recreated");
        assert_eq!(state.veth_iface.as_deref(), Some("veth-new"));
    }

    #[test]
    fn handle_pod_added_updates_existing_pod_ip() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_id: None,
                include_ports_policy: None,
            },
        );

        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        assert_eq!(pod_states.get("pod-uid-1").unwrap().pod_ip, Some(ip));
        assert!(backend.pod_ips.contains_key(&ip));
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 0);
    }

    #[tokio::test]
    async fn handle_fallback_fail_returns_error() {
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let probe = kernel_probe::KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let startup_ready = Arc::new(AtomicBool::new(false));
        let metrics = NodeAgentMetrics::default();

        assert!(
            handle_fallback(
                &config,
                &probe,
                &metrics,
                &shutdown_tx,
                startup_ready.clone()
            )
            .await
            .is_err()
        );
        assert!(!startup_ready.load(Ordering::Acquire));
        // Even in fail mode the gauge briefly records the reason before
        // the process exits — operators scraping during the failure window
        // (or in tests like this) get a structured diagnostic.
        assert_eq!(
            metrics.snapshot().topology_degraded_reason,
            Some("kernel_too_old"),
        );
    }

    #[tokio::test]
    async fn handle_fallback_records_cgroup_v1_reason() {
        // Newer kernel but cgroup v2 unavailable — the gauge must report
        // cgroup_v1 so dashboards route the operator to remount the cgroup
        // hierarchy rather than to upgrade the kernel.
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let probe = kernel_probe::KernelProbeResult {
            kernel_release: "6.1.0".to_string(),
            meets_version_requirement: true,
            cgroup_v2_available: false,
            bpf_fs_available: true,
        };
        let (shutdown_tx, _shutdown_rx) = tokio::sync::watch::channel(false);
        shutdown_tx
            .send(true)
            .expect("watch channel should be open");
        let startup_ready = Arc::new(AtomicBool::new(false));
        let metrics = NodeAgentMetrics::default();

        let result = tokio::time::timeout(
            std::time::Duration::from_secs(1),
            handle_fallback_with(
                &config,
                &probe,
                &metrics,
                &shutdown_tx,
                |_cmds, _phase| async { Ok(()) },
                startup_ready.clone(),
            ),
        )
        .await
        .expect("handle_fallback should complete within timeout");

        assert!(result.is_ok());
        assert_eq!(
            metrics.snapshot().topology_degraded_reason,
            Some("cgroup_v1"),
        );
    }

    #[tokio::test]
    async fn wait_for_shutdown_blocks_until_signal() {
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let wait = wait_for_shutdown(&shutdown_tx);
        tokio::pin!(wait);

        tokio::select! {
            _ = &mut wait => panic!("wait_for_shutdown returned before shutdown was signalled"),
            _ = tokio::time::sleep(std::time::Duration::from_millis(25)) => {}
        }

        shutdown_tx
            .send(true)
            .expect("shutdown receiver should be live");
        tokio::time::timeout(std::time::Duration::from_secs(1), wait)
            .await
            .expect("shutdown wait should resolve after signal");
    }

    #[tokio::test]
    async fn admin_listener_http_port_zero_spawns_no_tasks() {
        let env_config = EnvConfig {
            node_agent_admin_enabled: true,
            admin_http_port: 0,
            ..EnvConfig::default()
        };
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let startup_ready = Arc::new(AtomicBool::new(false));

        let handles = start_node_agent_admin_listeners(&env_config, &shutdown_tx, startup_ready)
            .await
            .expect("port zero should be accepted");

        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn admin_listener_default_disabled_spawns_no_tasks() {
        let env_config = EnvConfig::default();
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let startup_ready = Arc::new(AtomicBool::new(false));

        let handles = start_node_agent_admin_listeners(&env_config, &shutdown_tx, startup_ready)
            .await
            .expect("disabled admin listener should be accepted");

        assert!(handles.is_empty());
    }

    #[tokio::test]
    async fn admin_listener_invalid_allowed_cidrs_returns_error() {
        let env_config = EnvConfig {
            node_agent_admin_enabled: true,
            admin_http_port: 18081,
            admin_allowed_cidrs: "not-a-cidr".to_string(),
            ..EnvConfig::default()
        };
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let startup_ready = Arc::new(AtomicBool::new(false));

        let err = start_node_agent_admin_listeners(&env_config, &shutdown_tx, startup_ready)
            .await
            .expect_err("invalid CIDR should fail before spawning");

        assert!(err.to_string().contains("FERRUM_ADMIN_ALLOWED_CIDRS"));
    }

    fn signals(bind_explicit: bool, cidrs: bool) -> AdminBindSignals {
        AdminBindSignals {
            bind_address_explicit: bind_explicit,
            allowed_cidrs_set: cidrs,
        }
    }

    #[test]
    fn decide_admin_bind_defaults_to_loopback_when_no_signals() {
        // Default unspecified bind + no auth, no allowlist, no explicit bind →
        // override to 127.0.0.1 to avoid exposing unauthenticated /metrics.
        let addr = decide_admin_bind_address("0.0.0.0", 9000, &signals(false, false))
            .expect("default 0.0.0.0 bind should be valid");
        assert_eq!(
            addr,
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9000)
        );
    }

    #[test]
    fn decide_admin_bind_respects_explicit_bind_address() {
        // Operator explicitly set FERRUM_ADMIN_BIND_ADDRESS=0.0.0.0 → respected.
        let addr = decide_admin_bind_address("0.0.0.0", 9000, &signals(true, false))
            .expect("explicit bind should be valid");
        assert_eq!(
            addr,
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 9000)
        );
    }

    #[test]
    fn decide_admin_bind_does_not_treat_jwt_secret_as_network_exposure_signal() {
        // /metrics and /health are unauthenticated, so JWT alone must not make
        // an unspecified listener network-reachable.
        let addr = decide_admin_bind_address("0.0.0.0", 9000, &signals(false, false))
            .expect("0.0.0.0 with only JWT should still be valid");
        assert_eq!(
            addr,
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9000)
        );
    }

    #[test]
    fn decide_admin_bind_respects_allowed_cidrs_signal() {
        // Allowlist configured → operator scoped network exposure, respect 0.0.0.0.
        let addr = decide_admin_bind_address("0.0.0.0", 9000, &signals(false, true))
            .expect("0.0.0.0 with allowed cidrs should be valid");
        assert_eq!(
            addr,
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 9000)
        );
    }

    #[test]
    fn decide_admin_bind_respects_explicit_loopback() {
        // Operator explicitly set FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 → respected.
        let addr = decide_admin_bind_address("127.0.0.1", 9000, &signals(true, false))
            .expect("loopback should be valid");
        assert_eq!(
            addr,
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9000)
        );
    }

    #[test]
    fn decide_admin_bind_respects_explicit_v6_unspecified() {
        // IPv6 :: with explicit-bind signal → respected (don't override).
        let addr = decide_admin_bind_address("::", 9000, &signals(true, false))
            .expect("explicit :: should be valid");
        assert_eq!(
            addr,
            std::net::SocketAddr::new(std::net::IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED), 9000)
        );
    }

    #[test]
    fn decide_admin_bind_overrides_v6_unspecified_with_no_signals() {
        // IPv6 :: with NO signals → also unsafe, override to loopback.
        let addr = decide_admin_bind_address("::", 9000, &signals(false, false))
            .expect("default :: bind should be valid");
        assert_eq!(
            addr,
            std::net::SocketAddr::new(std::net::Ipv4Addr::LOCALHOST.into(), 9000)
        );
    }

    #[test]
    fn decide_admin_bind_rejects_invalid_address() {
        let err = decide_admin_bind_address("not-an-ip", 9000, &signals(true, false))
            .expect_err("invalid IP should be rejected");
        assert!(err.to_string().contains("FERRUM_ADMIN_BIND_ADDRESS"));
    }

    // --- GAP-2K: per-pod includeOutboundPorts narrowing on eBPF capture ---

    fn annotations_with(pairs: &[(&str, &str)]) -> HashMap<String, String> {
        pairs
            .iter()
            .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
            .collect()
    }

    #[test]
    fn parse_pod_include_outbound_ports_absent_returns_none() {
        let result = parse_pod_include_outbound_ports(&HashMap::new())
            .expect("absent annotation must not error");
        assert!(result.is_none());
    }

    #[test]
    fn parse_pod_include_outbound_ports_wildcard() {
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "*")]);
        let result = parse_pod_include_outbound_ports(&annotations)
            .expect("wildcard annotation parses")
            .expect("wildcard is not absent");
        assert!(result.all_ports);
    }

    #[test]
    fn parse_pod_include_outbound_ports_explicit_ports() {
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "5432,8080")]);
        let result = parse_pod_include_outbound_ports(&annotations)
            .expect("explicit ports parse")
            .expect("explicit ports are not absent");
        assert!(!result.all_ports);
        assert_eq!(result.ports, vec![5432, 8080]);
    }

    #[test]
    fn parse_pod_include_outbound_ports_merges_alias() {
        let annotations = annotations_with(&[
            ("traffic.sidecar.istio.io/includeOutboundPorts", "80"),
            ("ferrum.io/includeOutboundPorts", "443"),
        ]);
        let result = parse_pod_include_outbound_ports(&annotations)
            .expect("aliases merge")
            .expect("merged is not absent");
        assert_eq!(result.ports, vec![80, 443]);
    }

    #[test]
    fn parse_pod_include_outbound_ports_surfaces_errors() {
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "0")]);
        let err =
            parse_pod_include_outbound_ports(&annotations).expect_err("port 0 must be rejected");
        assert!(err.contains("includeOutboundPorts"));
    }

    #[test]
    fn include_outbound_ports_to_policy_wildcard() {
        let include = IncludeOutboundPorts {
            all_ports: true,
            ports: Vec::new(),
        };
        let policy = include_outbound_ports_to_policy("pod-uid", &include);
        assert!(policy.is_all_ports());
    }

    #[test]
    fn include_outbound_ports_to_policy_explicit() {
        let include = IncludeOutboundPorts {
            all_ports: false,
            ports: vec![80, 443, 5432],
        };
        let policy = include_outbound_ports_to_policy("pod-uid", &include);
        assert!(!policy.is_all_ports());
        assert_eq!(policy.port_count, 3);
        assert_eq!(&policy.ports[..3], &[80, 443, 5432]);
    }

    #[test]
    fn include_outbound_ports_to_policy_truncates_when_over_cap() {
        // Build a port list one element larger than the cap so the warn-and-truncate
        // path is exercised. The resulting policy still narrows, just to the first
        // INCLUDE_PORTS_MAX ports.
        let mut ports = Vec::with_capacity(INCLUDE_PORTS_MAX + 1);
        for i in 0..(INCLUDE_PORTS_MAX as u16 + 1) {
            ports.push(1000 + i);
        }
        let include = IncludeOutboundPorts {
            all_ports: false,
            ports: ports.clone(),
        };
        let policy = include_outbound_ports_to_policy("pod-uid", &include);
        assert_eq!(policy.port_count as usize, INCLUDE_PORTS_MAX);
        for (policy_port, requested_port) in policy
            .ports
            .iter()
            .zip(ports.iter())
            .take(INCLUDE_PORTS_MAX)
        {
            assert_eq!(policy_port, requested_port);
        }
    }

    #[cfg(unix)]
    #[test]
    fn read_cgroup_id_returns_inode_for_real_path() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().to_string_lossy().to_string();
        // Both calls should return the same value because the directory is
        // the same; we only assert the helper returns *something* truthy and
        // is stable across reads. Exact inode value depends on filesystem.
        let id1 = read_cgroup_id_for_pod(&path).expect("real path stats");
        let id2 = read_cgroup_id_for_pod(&path).expect("repeat stats");
        assert_eq!(id1, id2);
        assert!(id1 > 0);
    }

    #[test]
    fn read_cgroup_id_returns_none_on_missing_path() {
        assert!(read_cgroup_id_for_pod("/nonexistent/cgroup/path/here").is_none());
    }

    #[test]
    fn handle_pod_added_writes_include_ports_for_annotated_pod() {
        // End-to-end happy path: an annotated pod gets a per-cgroup
        // includeOutboundPorts entry in the mock BPF backend keyed by the
        // resolved cgroup's inode (since this test uses a real tempdir for
        // the cgroup path, the inode is deterministic per-run via stat()).
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup_path = cgroup_root.path().join("kubepods/podpod-uid-1");
        std::fs::create_dir_all(&cgroup_path).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "5432,8080")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state = pod_states.get("pod-uid-1").expect("pod enrolled");
        let cgroup_id = state
            .include_ports_cgroup_id
            .expect("cgroup id stashed for annotated pod");
        let policy = backend
            .include_ports
            .get(&cgroup_id)
            .expect("BPF map populated for annotated pod");
        assert!(!policy.is_all_ports());
        assert_eq!(policy.port_count, 2);
        assert_eq!(&policy.ports[..2], &[5432, 8080]);
    }

    #[test]
    fn handle_pod_added_wildcard_annotation_writes_all_ports() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "*")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state = pod_states.get("pod-uid-1").expect("pod enrolled");
        let cgroup_id = state
            .include_ports_cgroup_id
            .expect("cgroup id stashed for wildcard annotation");
        let policy = backend
            .include_ports
            .get(&cgroup_id)
            .expect("BPF map populated for wildcard annotation");
        assert!(policy.is_all_ports());
    }

    #[test]
    fn handle_pod_added_unannotated_skips_include_ports_map() {
        // No annotation → no BPF map entry → no cgroup_id stashed. This is
        // the regression guard for the BPF fail-open path: pods without
        // includeOutboundPorts must remain captured exactly as they were
        // before GAP-2K.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state = pod_states.get("pod-uid-1").expect("pod enrolled");
        assert!(
            state.include_ports_cgroup_id.is_none(),
            "unannotated pod must not stash a cgroup id"
        );
        assert!(
            backend.include_ports.is_empty(),
            "unannotated pod must not write to FERRUM_INCLUDE_PORTS"
        );
    }

    #[test]
    fn handle_pod_added_malformed_annotation_does_not_block_enrollment() {
        // Malformed annotation → log a warning, leave the pod un-narrowed,
        // continue enrolling it. This matches the rest of the
        // node-agent's "degrade gracefully" policy.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "bogus")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state = pod_states.get("pod-uid-1").expect("pod still enrolls");
        assert!(state.attached);
        assert!(
            state.include_ports_cgroup_id.is_none(),
            "malformed annotation must not write a BPF entry"
        );
        assert!(backend.include_ports.is_empty());
    }

    #[test]
    fn handle_pod_removed_removes_include_ports_entry() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "5432")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        assert_eq!(backend.include_ports.len(), 1, "entry must be written");

        handle_pod_removed(&mut backend, &pod_states, &metrics, "pod-uid-1");
        assert!(
            backend.include_ports.is_empty(),
            "removal must drop the include-ports entry"
        );
        assert!(!pod_states.contains_key("pod-uid-1"));
    }

    // --- T4-B: mid-life pod annotation updates (extends GAP-2K) ---
    //
    // `Event::Apply` from kube-rs covers both newly-added and modified pods,
    // so `handle_pod_added` is the watcher's single entry point for both.
    // The tests below exercise the diff-and-apply path inside the
    // "already enrolled" branch (`reconcile_existing_pod_include_ports`)
    // by calling `handle_pod_added` twice with the same `pod_uid` but
    // different annotations, simulating what kube-rs would emit for a
    // `kubectl annotate pod ...` against a live pod.

    /// Build the standard test config + cgroup tempdir layout used by
    /// every T4-B handle_pod_added round-trip test. Returns the tempdir
    /// (so the test scope keeps it alive), the resolved cgroup root
    /// path, and a `NodeAgentConfig` pointing at it.
    fn t4b_test_config(pod_uid: &str) -> (tempfile::TempDir, NodeAgentConfig) {
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join(format!("kubepods/pod{pod_uid}"))).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
        };
        (cgroup_root, config)
    }

    /// Build a `PodEvent` referencing the supplied labels/annotations.
    /// Encapsulated so each T4-B test reads as "annotate this pod and
    /// run handle_pod_added" without inlining the same struct literal
    /// every time.
    fn t4b_pod_event<'a>(
        pod_uid: &'a str,
        labels: &'a HashMap<String, String>,
        annotations: &'a HashMap<String, String>,
    ) -> PodEvent<'a> {
        PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            labels,
            annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        }
    }

    fn t4b_mesh_labels() -> HashMap<String, String> {
        HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())])
    }

    #[test]
    fn handle_pod_updated_with_same_annotation_is_no_op() {
        // Diff-skip regression guard: Modified events fire many times
        // for unrelated reasons (status updates, condition flips, image
        // pull progress). If we wrote the BPF map on every Modified
        // event we'd burn syscalls and produce log noise.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let (_cgroup_root, config) = t4b_test_config("pod-uid-1");
        let labels = t4b_mesh_labels();
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "80")]);

        // First Apply (the "added" event).
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &annotations),
        );
        assert_eq!(backend.include_ports.len(), 1, "initial write must occur");
        let snapshot_before = backend.include_ports.clone();

        // Second Apply with identical annotations (the "modified-but-
        // unchanged" event).
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &annotations),
        );

        assert_eq!(
            backend.include_ports, snapshot_before,
            "identical annotations must not mutate the BPF map"
        );
        assert_eq!(
            metrics
                .pod_annotation_updates_applied
                .load(Ordering::Relaxed),
            0,
            "no-op diff must not bump the applied counter"
        );
        assert_eq!(
            metrics
                .pod_annotation_updates_failed
                .load(Ordering::Relaxed),
            0
        );
    }

    #[test]
    fn handle_pod_updated_explicit_to_explicit_writes_new_ports() {
        // `80` → `80,443`: the parser sorts/dedupes, so the second policy
        // genuinely differs. The mock backend's HashMap-shaped
        // `include_ports` overwrites on insert, so we expect the entry
        // for this pod's cgroup id to reflect the NEW port set.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let (_cgroup_root, config) = t4b_test_config("pod-uid-1");
        let labels = t4b_mesh_labels();

        let initial = annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "80")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &initial),
        );
        let cgroup_id = pod_states
            .get("pod-uid-1")
            .expect("pod enrolled")
            .include_ports_cgroup_id
            .expect("cgroup id stashed");
        assert_eq!(backend.include_ports.get(&cgroup_id).unwrap().port_count, 1);

        let updated =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "80,443")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &updated),
        );

        // The entry for this pod's cgroup is replaced — same key, new
        // value — exactly the contract `update_pod_include_ports`
        // guarantees on the kernel side.
        let entry = backend
            .include_ports
            .get(&cgroup_id)
            .expect("entry replaced under same cgroup key");
        assert!(!entry.is_all_ports());
        assert_eq!(entry.port_count, 2);
        assert_eq!(&entry.ports[..2], &[80, 443]);
        let state = pod_states.get("pod-uid-1").unwrap();
        assert_eq!(
            state.include_ports_policy.as_ref().unwrap().port_count,
            2,
            "baseline must advance to the new policy for the next diff"
        );
        assert_eq!(
            metrics
                .pod_annotation_updates_applied
                .load(Ordering::Relaxed),
            1,
            "successful mid-life update must bump the applied counter"
        );
    }

    #[test]
    fn handle_pod_updated_explicit_to_wildcard_writes_all_ports_sentinel() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let (_cgroup_root, config) = t4b_test_config("pod-uid-1");
        let labels = t4b_mesh_labels();

        let initial = annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "80")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &initial),
        );

        let updated = annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "*")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &updated),
        );

        let cgroup_id = pod_states
            .get("pod-uid-1")
            .unwrap()
            .include_ports_cgroup_id
            .unwrap();
        let entry = backend.include_ports.get(&cgroup_id).unwrap();
        assert!(
            entry.is_all_ports(),
            "wildcard transition must write the all-ports sentinel"
        );
        assert_eq!(
            metrics
                .pod_annotation_updates_applied
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn handle_pod_updated_explicit_to_absent_removes_bpf_entry() {
        // When an operator removes the annotation entirely (e.g.
        // `kubectl annotate pod foo traffic.sidecar.istio.io/includeOutboundPorts-`),
        // the BPF gate should fail-open back to "capture everything"
        // for that pod. That's encoded by removing the map entry.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let (_cgroup_root, config) = t4b_test_config("pod-uid-1");
        let labels = t4b_mesh_labels();

        let initial = annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "80")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &initial),
        );
        let cgroup_id_before = pod_states
            .get("pod-uid-1")
            .unwrap()
            .include_ports_cgroup_id
            .unwrap();
        assert!(backend.include_ports.contains_key(&cgroup_id_before));

        // Apply with empty annotations — the operator stripped the
        // includeOutboundPorts key.
        let empty = HashMap::new();
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &empty),
        );

        assert!(
            !backend.include_ports.contains_key(&cgroup_id_before),
            "removed annotation must drop the BPF entry"
        );
        let state = pod_states.get("pod-uid-1").unwrap();
        assert!(
            state.include_ports_cgroup_id.is_none(),
            "state must forget the cgroup id when the entry is removed"
        );
        assert!(state.include_ports_policy.is_none());
        assert_eq!(
            metrics
                .pod_annotation_updates_applied
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn handle_pod_updated_unannotated_to_explicit_enrolls_new_policy() {
        // The pod was originally unannotated → no BPF entry. Operator
        // adds `includeOutboundPorts: 80` → BPF entry should appear.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let (_cgroup_root, config) = t4b_test_config("pod-uid-1");
        let labels = t4b_mesh_labels();

        let empty = HashMap::new();
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &empty),
        );
        assert!(
            backend.include_ports.is_empty(),
            "unannotated pod has no BPF entry initially"
        );

        let annotated =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "80")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &annotated),
        );

        let state = pod_states.get("pod-uid-1").unwrap();
        let cgroup_id = state
            .include_ports_cgroup_id
            .expect("mid-life add must stash a cgroup id");
        let entry = backend
            .include_ports
            .get(&cgroup_id)
            .expect("mid-life add must populate the BPF map");
        assert!(!entry.is_all_ports());
        assert_eq!(entry.port_count, 1);
        assert_eq!(entry.ports[0], 80);
        assert_eq!(
            metrics
                .pod_annotation_updates_applied
                .load(Ordering::Relaxed),
            1
        );
    }

    #[test]
    fn handle_pod_updated_opt_out_to_opt_in_re_enrolls() {
        // `ferrum.io/inject: false` → `ferrum.io/inject: true`. This is
        // handled by the existing enrollment-decision path (the
        // un-enrolled pod is not in `pod_states`, so the second Apply
        // hits the cold enrollment branch). The point of this test is
        // to confirm the watcher doesn't get stuck on a stale "skip"
        // decision once the operator flips opt-out off.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let (_cgroup_root, config) = t4b_test_config("pod-uid-1");

        let opt_out_labels = t4b_mesh_labels();
        let opt_out_annotations = annotations_with(&[("ferrum.io/inject", "false")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &opt_out_labels, &opt_out_annotations),
        );
        assert!(
            !pod_states.contains_key("pod-uid-1"),
            "opt-out annotation must skip enrollment"
        );

        let opt_in_annotations = annotations_with(&[("ferrum.io/inject", "true")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &opt_out_labels, &opt_in_annotations),
        );

        let state = pod_states
            .get("pod-uid-1")
            .expect("opt-in flip must enroll the pod");
        assert!(state.attached);
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_updated_opt_in_to_opt_out_unenrolls() {
        // The opposite: a previously enrolled pod gets `ferrum.io/inject:
        // false` mid-life. The watcher must call the un-enroll path
        // (which is what `evaluate_enrollment` returning `Skip` for an
        // already-tracked pod_uid triggers in `handle_pod_added`).
        //
        // Long-lived-flow caveat: this test asserts the BPF map and
        // pod_states are cleaned up. It does NOT assert anything about
        // already-established TCP connections — those keep flowing
        // through the rewrite chosen at their original connect(2) call,
        // because BPF cgroup_sockaddr only runs on new connects.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let (_cgroup_root, config) = t4b_test_config("pod-uid-1");

        let labels = t4b_mesh_labels();
        let opt_in_annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "80")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &opt_in_annotations),
        );
        assert!(pod_states.contains_key("pod-uid-1"));
        assert_eq!(backend.include_ports.len(), 1);

        let opt_out_annotations = annotations_with(&[("ferrum.io/inject", "false")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &opt_out_annotations),
        );

        assert!(
            !pod_states.contains_key("pod-uid-1"),
            "opt-out flip must un-enroll the pod"
        );
        assert!(
            backend.include_ports.is_empty(),
            "un-enrollment must drop the BPF includeOutboundPorts entry"
        );
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_updated_malformed_annotation_keeps_previous_policy() {
        // The pod was enrolled with a valid `80` policy. Operator then
        // applies a malformed annotation (e.g. typo in port number).
        // The previous policy MUST be retained — silently widening
        // capture to "all ports" on a typo would be a surprise.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let (_cgroup_root, config) = t4b_test_config("pod-uid-1");
        let labels = t4b_mesh_labels();

        let good = annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "80")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &good),
        );
        let cgroup_id = pod_states
            .get("pod-uid-1")
            .unwrap()
            .include_ports_cgroup_id
            .unwrap();
        let before = *backend.include_ports.get(&cgroup_id).unwrap();

        let bad = annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "bogus")]);
        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &t4b_pod_event("pod-uid-1", &labels, &bad),
        );

        let after = *backend.include_ports.get(&cgroup_id).unwrap();
        assert_eq!(
            before, after,
            "malformed annotation must NOT rewrite the BPF entry"
        );
        let state = pod_states.get("pod-uid-1").unwrap();
        assert_eq!(
            state.include_ports_cgroup_id,
            Some(cgroup_id),
            "previous cgroup id must be retained"
        );
        assert!(state.include_ports_policy.is_some());
        assert_eq!(
            metrics
                .pod_annotation_updates_failed
                .load(Ordering::Relaxed),
            1,
            "parse failure must bump the failed counter"
        );
        assert_eq!(
            metrics
                .pod_annotation_updates_applied
                .load(Ordering::Relaxed),
            0
        );
    }
}
