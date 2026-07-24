//! Node agent mode — per-node eBPF capture manager for ambient mesh.
//!
//! `FERRUM_MODE=node_agent` runs as a DaemonSet companion alongside the
//! ambient mesh proxy. It attaches BPF programs to enrolled pods' cgroups
//! and veth interfaces to transparently redirect traffic to the co-located
//! Ferrum proxy.
//!
//! The node agent does NOT run proxy listeners. Traffic capture is its sole
//! responsibility.

use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::hash::{Hash, Hasher};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, LazyLock};
use std::time::{Duration, Instant};

use dashmap::DashMap;
use futures_util::StreamExt;
use k8s_openapi::api::core::v1::{Container, Pod, PodSpec, PodStatus, Probe};
use k8s_openapi::apimachinery::pkg::util::intstr::IntOrString;
use kube::runtime::watcher::{self as kube_watcher, Event};
use kube::{Client, api::Api};
use tracing::{debug, error, info, warn};

use crate::admin::jwt_auth::create_jwt_manager_from_env;
use crate::admin::{self, AdminState};
use crate::capture::{
    CaptureConfig, CaptureMode, FERRUM_INCLUDE_OUTBOUND_PORTS_ANNOTATION,
    ISTIO_INCLUDE_OUTBOUND_PORTS_ANNOTATION, IncludeOutboundPorts, Ip6TablesMode, IptablesPlan,
    XTABLES_LOCK_WAIT_SECONDS, include_outbound_ports_from_annotations,
};
use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
use crate::config::EnvConfig;
use crate::config::conf_file::resolve_ferrum_var;
use crate::ebpf::cgroup;
use crate::ebpf::kernel_probe::{self, KernelProbeResult};
use crate::ebpf::pod_watcher::{self, EnrollmentDecision};
use crate::ebpf::veth;
use crate::ebpf::{
    CaptureContract, DEFAULT_NODE_AGENT_SOCKET_PATH, EbpfBackend, FallbackMode, INCLUDE_PORTS_MAX,
    IncludePortsPolicy, NODE_AGENT_CAPTURE_STATE_IDENTITY_BRIDGE_UNAVAILABLE,
    NODE_AGENT_CAPTURE_STATE_NODE_GLOBAL_FALLBACK, NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED,
    NODE_AGENT_CAPTURE_STATE_READY, NODE_AGENT_CAPTURE_STATE_UNAVAILABLE, NodeAgentMetrics,
    NodeAgentProxyMode, PodAttachmentState, PodInfo, TcAttachDirection,
};
use crate::modes::node_agent_cni_server::{
    self, CniWorkItem, CniWorkReceiver, cni_work_channel, spawn_cni_listener,
};

const DEFAULT_CGROUP_ROOT: &str = "/sys/fs/cgroup";
const DEFAULT_BPF_FS_PATH: &str = "/sys/fs/bpf";
const DEFAULT_FALLBACK_MODE: &str = "fail";
const CNI_METADATA_FETCH_TIMEOUT: Duration = Duration::from_millis(750);
const POD_ENROLLMENT_RETRY_BACKOFF: Duration = Duration::from_secs(30);
const UDP_CAPTURE_READINESS_POLL: Duration = Duration::from_millis(250);
const UDP_HANDSHAKE_ORPHAN_GRACE: Duration = Duration::from_secs(30);
// Verified handshakes need longer than the ordinary orphan grace for producer
// polling, bounded responder batches, and process restarts, but cannot live
// forever after their producer exits. 20 * the 30s grace gives those paths ten
// minutes in production while keeping the test helper's age injectable.
const VERIFIED_UDP_HANDSHAKE_RETENTION_MULTIPLIER: u32 = 20;

static FAILED_POD_ENROLLMENT_ATTEMPTS: LazyLock<DashMap<String, FailedPodEnrollmentAttempt>> =
    LazyLock::new(DashMap::new);
static PENDING_CAPTURE_FAILURES: LazyLock<DashMap<String, ()>> = LazyLock::new(DashMap::new);

const CAPTURE_FAILURE_POD_IP_UPDATE: &str = "pod_ip_update";
const CAPTURE_FAILURE_POD_IP_REMOVE: &str = "pod_ip_remove";
const CAPTURE_FAILURE_POD_DETACH: &str = "pod_detach";
const CAPTURE_FAILURE_NODE_PROBE_PORT_UPDATE: &str = "node_probe_port_update";
const CAPTURE_FAILURE_NODE_PROBE_PORT_REMOVE: &str = "node_probe_port_remove";
const CAPTURE_FAILURE_INCLUDE_PORTS_REMOVE: &str = "include_ports_remove";
const CAPTURE_FAILURE_WORKLOAD_IDENTITY_REMOVE: &str = "workload_identity_remove";
const CAPTURE_FAILURE_UDP_READINESS: &str = "udp_readiness";
const CAPTURE_FAILURE_DETAIL_POD_IP: &str = "pod_ip";
const CAPTURE_FAILURE_DETAIL_POD_IP6: &str = "pod_ip6";
const CAPTURE_FAILURE_DETAIL_POD_DETACH: &str = "pod_detach";
const CAPTURE_FAILURE_DETAIL_NODE_PROBE_PORTS: &str = "node_probe_ports";
const CAPTURE_FAILURE_DETAIL_UDP_READINESS: &str = "udp_readiness";

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
    /// SPIFFE trust domain used to derive each enrolled pod's workload SPIFFE
    /// ID (`spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}`) for
    /// the `FERRUM_WORKLOAD_IDENTITY` map (GAP-1b). Sourced from
    /// `FERRUM_K8S_TRUST_DOMAIN` (default `cluster.local`) so it matches the
    /// CP-side SPIFFE format that the node-waypoint resolver enrolls.
    pub trust_domain: String,
    /// Directory under which the node-agent publishes a per-pod registry file
    /// (`<dir>/<pod_uid>` containing the pod cgroup path plus optional
    /// `ipv4=`/`ipv6=` source-IP lines) for the mesh proxy's in-netns capture
    /// listeners or Ambient UDP producer to consume. `Some` when NodeWaypoint
    /// in-netns TCP capture or Ambient UDP capture needs the registry; `None`
    /// disables publishing entirely. Sourced from
    /// `FERRUM_MESH_NODE_WAYPOINT_POD_REGISTRY_DIR`.
    pub node_waypoint_pod_registry_dir: Option<std::path::PathBuf>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Default)]
pub struct PodSourceIps {
    pub ipv4: Option<std::net::Ipv4Addr>,
    pub ipv6: Option<std::net::Ipv6Addr>,
}

impl PodSourceIps {
    #[cfg(test)]
    fn from_primary_str(ip: Option<&str>) -> Self {
        let mut ips = Self::default();
        if let Some(ip) = ip {
            ips.insert_str(ip);
        }
        ips
    }

    fn from_status(status: Option<&PodStatus>) -> Self {
        let mut ips = Self::default();
        let Some(status) = status else {
            return ips;
        };
        if let Some(primary) = status.pod_ip.as_deref() {
            ips.insert_str(primary);
        }
        if let Some(pod_ips) = &status.pod_ips {
            for pod_ip in pod_ips {
                ips.insert_str(&pod_ip.ip);
            }
        }
        ips
    }

    fn insert_str(&mut self, ip: &str) {
        match ip.parse::<std::net::IpAddr>() {
            Ok(std::net::IpAddr::V4(ip)) => {
                if self.ipv4.is_none() {
                    self.ipv4 = Some(ip);
                }
            }
            Ok(std::net::IpAddr::V6(ip)) => {
                if self.ipv6.is_none() {
                    self.ipv6 = Some(ip);
                }
            }
            Err(_) => {}
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
struct NodeSourceIps {
    ipv4: Vec<std::net::Ipv4Addr>,
    ipv6: Vec<std::net::Ipv6Addr>,
}

impl NodeSourceIps {
    fn is_empty(&self) -> bool {
        self.ipv4.is_empty() && self.ipv6.is_empty()
    }

    fn insert(&mut self, ip: std::net::IpAddr) {
        match ip {
            std::net::IpAddr::V4(ip) => {
                if !self.ipv4.contains(&ip) {
                    self.ipv4.push(ip);
                }
            }
            std::net::IpAddr::V6(ip) => {
                if !self.ipv6.contains(&ip) {
                    self.ipv6.push(ip);
                }
            }
        }
    }

    #[cfg(test)]
    fn extend(&mut self, other: NodeSourceIps) {
        for ip in other.ipv4 {
            self.insert(std::net::IpAddr::V4(ip));
        }
        for ip in other.ipv6 {
            self.insert(std::net::IpAddr::V6(ip));
        }
    }
}

/// CNI plugin listener configuration. Resolved from the env config in
/// `run` so the eBPF path and the fallback path agree on whether the
/// listener should come up. Empty `socket_path` is normalized to the
/// default in `EnvConfig`; the boolean `enabled` is the operator switch
/// that flips the entire CNI hot path on or off.
#[derive(Debug, Clone)]
pub struct CniListenerConfig {
    pub enabled: bool,
    pub socket_path: String,
}

impl CniListenerConfig {
    pub fn from_env_config(env_config: &EnvConfig) -> Self {
        Self {
            enabled: env_config.node_agent_cni_enabled,
            socket_path: env_config.node_agent_cni_socket_path.clone(),
        }
    }
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
        // The node-agent DaemonSet runs `hostNetwork: true` (host netns), so the
        // UDP TPROXY `addrtype --dst-type LOCAL` direction split (valid only in a
        // pod netns) is suppressed for the iptables fallback — see
        // `CaptureConfig::host_netns` and `udp_tproxy_commands_for_family`.
        // Node-agent host-netns UDP capture is unsupported in this stage; eBPF does
        // not cover UDP either (TCP-only connect()-cgroup hooks). UDP capture lives
        // in the injector's pod-netns path (node-agent/node-waypoint UDP is a future
        // stage).
        capture_config.host_netns = true;
        // Both the node-agent and the mesh proxy read FERRUM_MESH_OUTBOUND_LISTEN_ADDR
        // (default 127.0.0.1:15001), so the eBPF connect4 rewrite port and the
        // proxy's in-netns listener stay aligned — co-deployed node-waypoint
        // node-agent + proxy must set this env consistently. Port 0 means the
        // proxy disables its outbound listener, so disable outbound capture here
        // too (no connect4/connect6, no in-netns registry) rather than rewrite
        // egress to a dead loopback port; inbound capture is unaffected.
        match resolve_ferrum_var("FERRUM_MESH_OUTBOUND_LISTEN_ADDR")
            .and_then(|raw| raw.trim().parse::<std::net::SocketAddr>().ok())
        {
            Some(addr) if addr.port() == 0 => capture_config.outbound_capture_enabled = false,
            Some(addr) => capture_config.outbound_port = addr.port(),
            None => {}
        }
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
        let mut capture_contract = CaptureContract::new(
            env_config.node_agent_proxy_mode,
            capture_config.outbound_port,
            env_config.node_agent_hbone_redirect_port,
            DEFAULT_NODE_AGENT_SOCKET_PATH,
        )?;

        // In-netns capture is the default for NodeWaypoint: publish the per-pod
        // registry whenever the node-agent runs in NodeWaypoint proxy mode with
        // outbound capture enabled. Other proxy modes have no in-netns listener
        // consumer, so leave it `None` and skip all the filesystem work on the
        // hot paths.
        let node_waypoint_in_netns = env_config.node_agent_proxy_mode
            == NodeAgentProxyMode::NodeWaypoint
            && capture_config.outbound_capture_enabled;
        // NodeWaypoint in-netns capture now binds both pod-loopback families.
        // Keep the global IPv6 include so dual-stack destinations are captured
        // instead of bypassing `mesh_authz`; if a pod's IPv6 listener is not
        // ready yet, connect6 redirects to `[::1]:<port>` and fails closed by
        // connection refusal until the proxy publishes `.ready6`.
        capture_contract.ipv6_outbound_deny = false;
        if node_waypoint_in_netns
            && !capture_config
                .include_cidrs
                .iter()
                .any(|cidr| cidr_is_ipv6(cidr))
        {
            capture_config.include_cidrs.push("::/0".to_string());
        }
        // Publish the per-pod registry (uid → cgroup) when EITHER the NodeWaypoint
        // TCP in-netns capture path needs it (the historical consumer) OR the
        // topology is Ambient. Ambient's mesh proxy consumes the same registry
        // for both the enabled `NetnsUdpCaptureManager` producer and the disabled
        // `NetnsUdpCleanupManager`; suppressing publication when UDP is disabled
        // would make an enabled-to-disabled rollout unable to visit pod netns and
        // reap stale rules from the prior producer (#2013, codex). The registry
        // is a generic per-pod map; publishing it does NOT change eBPF/redirect
        // behavior — that stays gated on `node_waypoint_in_netns` via the capture
        // contract, so a plain Ambient (LocalPod) deployment gets the registry for
        // the UDP producer WITHOUT the NodeWaypoint ipv6-deny / connect4-deferral
        // posture. The UDP gate is `udp_capture_enabled && topology == ambient`,
        // but is NOT anded with `outbound_capture_enabled`: the producer binds its own
        // `FERRUM_MESH_CAPTURE_UDP_PORT` inside each pod netns and does not use the
        // TCP `FERRUM_MESH_OUTBOUND_LISTEN_ADDR` listener at all, so a port-0
        // outbound listener (which clears `outbound_capture_enabled` for the TCP
        // connect4/connect6 redirect path) MUST NOT suppress UDP registry
        // publication — doing so would leave the producer polling an empty
        // directory while pod UDP egress bypasses capture/authz (fail-open, #2013
        // codex). The node-agent writes the pod-IP map with UDP readiness closed
        // before publishing this entry. The host-veth tc guard drops pod UDP until
        // the producer installs its guard/socket/rules and publishes
        // `.udp-ready/<uid>`.
        let mesh_topology =
            resolve_ferrum_var("FERRUM_MESH_TOPOLOGY").unwrap_or_else(|| "sidecar".to_string());
        let ambient_topology = mesh_topology.trim().eq_ignore_ascii_case("ambient");
        let udp_capture_requested = capture_config.udp_capture_enabled;
        if udp_capture_requested && !ambient_topology {
            warn!(
                mesh_topology = mesh_topology.trim(),
                "FERRUM_MESH_CAPTURE_UDP_ENABLED=true requires FERRUM_MESH_TOPOLOGY=ambient; the Ambient UDP readiness guard is disabled and registry publication remains topology-dependent"
            );
        }
        let ambient_udp_producer = udp_capture_requested && ambient_topology;
        // The node-agent readiness guard is meaningful only when the Ambient
        // mesh runtime starts `NetnsUdpCaptureManager`. Other topologies keep
        // their documented unsupported/pass-through posture.
        capture_config.udp_capture_enabled = ambient_udp_producer;
        let should_publish_registry = node_waypoint_in_netns || ambient_topology;
        let node_waypoint_pod_registry_dir = if should_publish_registry {
            Some(std::path::PathBuf::from(
                &env_config.mesh_node_waypoint_pod_registry_dir,
            ))
        } else {
            None
        };

        Ok(Self {
            node_name,
            capture_config,
            cgroup_root,
            bpf_fs_path,
            fallback_mode,
            excluded_namespaces,
            capture_contract,
            trust_domain: env_config.k8s_trust_domain.clone(),
            node_waypoint_pod_registry_dir,
        })
    }
}

fn cidr_is_ipv6(cidr: &str) -> bool {
    let Some((addr, _prefix)) = cidr.split_once('/') else {
        return false;
    };
    addr.parse::<std::net::IpAddr>()
        .map(|ip| ip.is_ipv6())
        .unwrap_or(false)
}

fn node_agent_node_source_ips_from_env() -> Result<NodeSourceIps, String> {
    let mut ips = NodeSourceIps::default();
    if let Some(raw) = resolve_ferrum_var("FERRUM_NODE_AGENT_NODE_IP") {
        insert_node_source_ip(&mut ips, "FERRUM_NODE_AGENT_NODE_IP", raw.trim())?;
    }
    if let Some(raw) = resolve_ferrum_var("FERRUM_NODE_AGENT_NODE_IPS") {
        for raw_ip in raw.split(',') {
            insert_node_source_ip(&mut ips, "FERRUM_NODE_AGENT_NODE_IPS", raw_ip.trim())?;
        }
    }
    Ok(ips)
}

fn insert_node_source_ip(ips: &mut NodeSourceIps, var_name: &str, raw: &str) -> Result<(), String> {
    if raw.is_empty() {
        return Ok(());
    }
    match raw.parse::<std::net::IpAddr>() {
        Ok(ip) => {
            ips.insert(ip);
            Ok(())
        }
        Err(e) => Err(format!(
            "{var_name} contains invalid IP address '{raw}': {e}"
        )),
    }
}

fn pod_probe_ports_from_spec(spec: Option<&PodSpec>) -> Vec<u16> {
    let Some(spec) = spec else {
        return Vec::new();
    };
    let mut ports = Vec::new();
    for container in &spec.containers {
        for probe in [
            container.liveness_probe.as_ref(),
            container.readiness_probe.as_ref(),
            container.startup_probe.as_ref(),
        ]
        .into_iter()
        .flatten()
        {
            collect_probe_ports(&mut ports, probe, container);
        }
    }
    ports.sort_unstable();
    ports.dedup();
    ports
}

fn collect_probe_ports(ports: &mut Vec<u16>, probe: &Probe, container: &Container) {
    if let Some(http_get) = &probe.http_get
        && let Some(port) = resolve_probe_port(&http_get.port, container)
    {
        ports.push(port);
    }
    if let Some(tcp_socket) = &probe.tcp_socket
        && let Some(port) = resolve_probe_port(&tcp_socket.port, container)
    {
        ports.push(port);
    }
    if let Some(grpc) = &probe.grpc
        && let Some(port) = valid_probe_port(grpc.port)
    {
        ports.push(port);
    }
}

fn resolve_probe_port(port: &IntOrString, container: &Container) -> Option<u16> {
    match port {
        IntOrString::Int(port) => valid_probe_port(*port),
        IntOrString::String(name) => container.ports.as_ref()?.iter().find_map(|candidate| {
            if candidate.name.as_deref() != Some(name.as_str()) {
                return None;
            }
            if candidate
                .protocol
                .as_deref()
                .is_some_and(|protocol| !protocol.eq_ignore_ascii_case("TCP"))
            {
                return None;
            }
            valid_probe_port(candidate.container_port)
        }),
    }
}

fn valid_probe_port(port: i32) -> Option<u16> {
    u16::try_from(port).ok().filter(|port| *port != 0)
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

    let cni_config = CniListenerConfig::from_env_config(&env_config);

    // Fail closed when Ambient UDP capture needs the per-pod registry but the
    // node would take the iptables `handle_fallback()` path (#2013). The
    // `NetnsUdpCaptureManager` producer and disabled `NetnsUdpCleanupManager`
    // on the mesh proxy poll the per-pod
    // registry (`node_waypoint_pod_registry_dir`) as its ONLY source of enrolled
    // pods, and that registry is populated exclusively by the eBPF-backed pod
    // watcher (`run_with_backend` → `handle_kube_pod_applied` → `publish_pod_
    // registry`). `handle_fallback()` only applies host-netns iptables and never
    // runs the pod watcher, so it would leave the producer polling an empty
    // directory while enabled capture bypasses authz or disabled cleanup strands
    // stale fail-closed guards. Host-netns iptables also cannot install pod-netns UDP TPROXY
    // rules at all (the `addrtype --dst-type LOCAL` direction split is
    // pod-netns-only; see `handle_fallback_with`). Refuse startup with an
    // actionable error rather than silently break either lifecycle phase,
    // mirroring `create_backend`'s refusal to no-op when eBPF is unavailable.
    let ambient_topology = resolve_ferrum_var("FERRUM_MESH_TOPOLOGY")
        .is_some_and(|topology| topology.trim().eq_ignore_ascii_case("ambient"));
    if ambient_udp_registry_requires_ebpf(
        probe.supports_ebpf(),
        ambient_topology,
        config.node_waypoint_pod_registry_dir.is_some(),
    ) {
        metrics.set_topology_degraded(probe.degradation_reason().unwrap_or("unknown"));
        metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
        let _ = shutdown_tx.send(true);
        for handle in admin_handles {
            if let Err(err) = handle.await {
                warn!(error = %err, "Node agent admin listener task failed");
            }
        }
        anyhow::bail!(
            "Ambient UDP lifecycle cleanup requires the per-pod registry, but this node \
             cannot run eBPF capture (kernel_release={}, cgroup_v2={}, bpf_fs={}, reason={}), so the \
             node-agent would fall back to host-netns iptables — which never runs the pod watcher \
             that publishes the per-pod registry the mesh proxy's UDP capture producer polls, and \
             cannot install pod-netns UDP TPROXY rules from the host netns. Continuing would leave \
             pod UDP egress uncaptured and unauthorized (fail-open). Remediation: upgrade this node \
             to kernel >= 5.7 with cgroup v2 + bpffs mounted (use the -ebpf image variant), or \
             disable the Ambient topology on this node. FERRUM_NODE_AGENT_FALLBACK_MODE=iptables \
             does not support the Ambient UDP producer or its disabled stale-rule cleanup.",
            probe.kernel_release,
            probe.cgroup_v2_available,
            probe.bpf_fs_available,
            probe.degradation_reason().unwrap_or("unknown"),
        );
    }

    let result = if !probe.supports_ebpf() {
        handle_fallback(
            &config,
            &probe,
            metrics.clone(),
            &shutdown_tx,
            startup_ready,
            cni_config,
        )
        .await
    } else {
        let backend = create_backend(&config, &metrics)?;
        run_with_backend(
            backend,
            &config,
            metrics,
            &shutdown_tx,
            startup_ready,
            cni_config,
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

/// Pure predicate: does this node need to refuse startup because Ambient UDP
/// capture depends on the per-pod registry, but the node cannot run the eBPF
/// pod watcher that populates it?
///
/// Returns `true` when ALL hold:
/// - `supports_ebpf` is `false` (the node would take the `handle_fallback()`
///   iptables path, which never runs the pod watcher / `publish_pod_registry`),
/// - `ambient_topology` is `true` (the registry is needed for the Ambient UDP
///   producer or disabled stale-rule cleanup), and
/// - `registry_dir_configured` is `true` (a registry directory is actually set,
///   so either the producer or disabled cleanup manager has somewhere to poll).
///
/// When `true`, the node-agent must fail startup rather than silently run in a
/// state where pod UDP egress bypasses capture/authz (fail-open, #2013). This is
/// split out as a pure function so the fail-closed decision is unit-testable
/// without the Linux-gated capture path.
fn ambient_udp_registry_requires_ebpf(
    supports_ebpf: bool,
    ambient_topology: bool,
    registry_dir_configured: bool,
) -> bool {
    !supports_ebpf && ambient_topology && registry_dir_configured
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
    let metrics_auth = Arc::new(
        crate::admin::MetricsAuthPolicy::from_env(env_config).map_err(|e| anyhow::anyhow!(e))?,
    );
    let jwt_manager = match create_jwt_manager_from_env() {
        Ok(manager) => manager,
        Err(crate::admin::jwt_auth::JwtError::NotConfigured) => {
            warn!(
                "Admin JWT secret not set for node_agent mode; generating a random read-only secret \
                 (authenticated admin endpoints will reject externally minted tokens)"
            );
            let random_secret = format!("{}{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4());
            crate::admin::jwt_auth::JwtManager::new(crate::admin::jwt_auth::JwtConfig {
                secret: random_secret,
                ..Default::default()
            })
        }
        Err(err) => {
            return Err(anyhow::anyhow!(
                "Invalid admin JWT configuration for node_agent mode: {err}. \
                 node_agent generates a random secret only when FERRUM_ADMIN_JWT_SECRET \
                 is unset; a configured-but-invalid secret or TTL must be fixed."
            ));
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
        admin_require_namespace_claim: env_config.admin_require_namespace_claim,
        startup_ready: Some(startup_ready),
        // node_agent mode has no post-start listener supervision that flips
        // readiness; readiness is governed by `startup_ready` alone.
        serving_degraded: None,
        serving_listener_failures: None,
        db_available: None,
        config_rejected: None,
        admin_restore_max_body_size_mib: env_config.admin_restore_max_body_size_mib,
        admin_spec_max_body_size_mib: env_config.admin_spec_max_body_size_mib,
        reserved_ports: env_config.reserved_gateway_ports(),
        stream_proxy_bind_address: env_config.stream_proxy_bind_address.clone(),
        admin_allowed_cidrs,
        metrics_auth,
        cached_db_health: Arc::new(arc_swap::ArcSwap::new(Arc::new(None))),
        db_health_refresh: Arc::new(tokio::sync::Mutex::new(())),
        dp_registry: None,
        mesh_registry: None,
        cp_connection_state: None,
        admin_http_header_read_timeout_seconds: env_config.http_header_read_timeout_seconds,
        mesh_runtime_state: None,
        admin_tls_handshake_timeout_seconds: env_config.frontend_tls_handshake_timeout_seconds,
        backend_allow_ips: env_config.backend_allow_ips.clone(),
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
    let admin_conn_limiter = Arc::new(admin::AdminConnLimiter::new(
        env_config.admin_max_connections,
        env_config.admin_max_connections_per_ip,
    ));
    let shutdown = shutdown_tx.subscribe();
    let (started_tx, started_rx) = tokio::sync::oneshot::channel();
    let handle = tokio::spawn(async move {
        info!(
            "Starting node_agent admin HTTP listener on {}",
            crate::secrets::report_listener_addr(
                "FERRUM_ADMIN_BIND_ADDRESS",
                "FERRUM_ADMIN_HTTP_PORT",
                &admin_http_addr.to_string()
            )
        );
        if let Err(err) = admin::start_admin_listener_with_tls_and_signal(
            admin_http_addr,
            admin_state,
            shutdown,
            None,
            Some(started_tx),
            admin_conn_limiter,
        )
        .await
        {
            error!("Node agent admin HTTP listener error: {}", err);
        }
    });
    handles.push(handle);

    crate::startup::wait_for_start_signals(
        vec![("Node agent admin HTTP listener".to_string(), started_rx)],
        Duration::from_secs(10),
    )
    .await?;

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
/// The admin bind defaults to loopback (`127.0.0.1`), keeping unauthenticated
/// `/metrics` and `/health` off the network unless the operator opts in. Two
/// opt-in signals are honored:
///
/// - An explicit `FERRUM_ADMIN_BIND_ADDRESS` is used verbatim.
/// - `FERRUM_ADMIN_ALLOWED_CIDRS` with no explicit bind binds to `0.0.0.0` so
///   cluster scraping can reach the listener — restricted by that allowlist.
///   Because the bind now defaults to loopback, an allowlist alone could not
///   otherwise make `/metrics` reachable, so this restores that documented
///   contract.
///
/// With neither signal the listener is pinned to `127.0.0.1` (with a `warn!`
/// pointing operators at the opt-ins) even if a stale `0.0.0.0`/`::` is passed,
/// so it is never silently exposed.
fn decide_admin_bind_address(
    configured_bind: &str,
    port: u16,
    signals: &AdminBindSignals,
) -> Result<std::net::SocketAddr, anyhow::Error> {
    let configured_ip: std::net::IpAddr = configured_bind.parse().map_err(|_| {
        anyhow::anyhow!(
            "Invalid FERRUM_ADMIN_BIND_ADDRESS {} (expected a valid IP address)",
            crate::secrets::quoted_env_value("FERRUM_ADMIN_BIND_ADDRESS", configured_bind)
        )
    })?;

    // An explicit bind address always wins.
    if signals.bind_address_explicit {
        return Ok(std::net::SocketAddr::new(configured_ip, port));
    }

    // Allowlist-only opt-in: bind to all interfaces (restricted by the
    // allowlist) so cluster scraping reaches /metrics and /health. The bind
    // otherwise defaults to loopback, which the allowlist alone cannot override.
    if signals.allowed_cidrs_set {
        warn!(
            "FERRUM_NODE_AGENT_ADMIN_ENABLED=true with FERRUM_ADMIN_ALLOWED_CIDRS and no explicit \
             FERRUM_ADMIN_BIND_ADDRESS; binding node-agent admin to 0.0.0.0:{port} (restricted by the \
             allowlist) so unauthenticated /metrics and /health are reachable for cluster scraping. \
             Set FERRUM_ADMIN_BIND_ADDRESS to pin a specific address."
        );
        return Ok(std::net::SocketAddr::new(
            std::net::Ipv4Addr::UNSPECIFIED.into(),
            port,
        ));
    }

    // No opt-in signal: keep the safe loopback default, pinning 127.0.0.1 even
    // if a non-loopback bind was passed without a signal so /metrics is never
    // silently exposed.
    if !configured_ip.is_loopback() {
        warn!(
            "FERRUM_NODE_AGENT_ADMIN_ENABLED=true with no allowlist or explicit bind address configured; \
             defaulting node-agent admin listener to 127.0.0.1:{port} so unauthenticated /metrics and /health \
             are not exposed on the network. To expose it, set FERRUM_ADMIN_ALLOWED_CIDRS=<cidr-list> \
             or FERRUM_ADMIN_BIND_ADDRESS=<address>."
        );
        return Ok(std::net::SocketAddr::new(
            std::net::Ipv4Addr::LOCALHOST.into(),
            port,
        ));
    }

    Ok(std::net::SocketAddr::new(configured_ip, port))
}

fn create_backend(
    config: &NodeAgentConfig,
    metrics: &Arc<NodeAgentMetrics>,
) -> Result<Box<dyn EbpfBackend>, anyhow::Error> {
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    {
        let _ = (config, metrics);
        Ok(Box::new(crate::ebpf::AyaEbpfBackend::new()))
    }
    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    {
        // The kernel probe said this node CAN run eBPF capture, but THIS
        // binary was built without the `ebpf` feature (or for a non-Linux
        // target), so the mock backend would attach nothing. Refuse startup
        // and set observable degraded state instead of silently no-op'ing as
        // if the node were healthy.
        let _ = config;
        metrics.set_topology_degraded("ebpf_feature_disabled");
        metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
        anyhow::bail!(
            "node-agent eBPF capture requires a Linux binary built with --features ebpf. \
             This binary would select the mock backend, which attaches nothing and captures \
             no traffic. Use the -ebpf image variant or rebuild with FEATURES=cloud-secrets,ebpf."
        );
    }
}

async fn run_with_backend(
    mut backend: Box<dyn EbpfBackend>,
    config: &NodeAgentConfig,
    metrics: Arc<NodeAgentMetrics>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    startup_ready: Arc<AtomicBool>,
    cni_config: CniListenerConfig,
) -> Result<(), anyhow::Error> {
    initialize_backend(backend.as_mut(), config, metrics.as_ref())?;

    let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();

    let mut shutdown_rx = shutdown_tx.subscribe();
    let client = build_node_agent_kube_client().await?;
    let pods: Api<Pod> = Api::all(client.clone());
    let watcher_config =
        kube_watcher::Config::default().fields(&format!("spec.nodeName={}", config.node_name));
    let mut pod_stream = Box::pin(kube_watcher::watcher(pods, watcher_config));
    let mut init_seen: Option<HashSet<String>> = None;

    // Optional CNI plugin listener: when enabled, spawns a UDS server that
    // funnels ADD/DEL/CHECK calls from the `ferrum-cni` binary into this
    // loop via the `cni_work_rx` channel. When disabled (the default), the
    // channel stays empty and the receiver in the select! arm parks
    // forever — the kube-rs watcher remains the sole enrollment driver.
    let (cni_work_tx, mut cni_work_rx): (_, CniWorkReceiver) = cni_work_channel();
    let cni_listener_handle = if cni_config.enabled {
        Some(spawn_cni_listener(
            cni_config.socket_path.clone(),
            cni_work_tx.clone(),
            metrics.clone(),
            shutdown_tx.subscribe(),
        ))
    } else {
        info!("CNI plugin listener disabled; kube-rs watcher is the sole enrollment path");
        None
    };
    // Drop the local sender so the receiver closes cleanly when the
    // listener task exits — otherwise the select! would park forever on
    // the receiver during shutdown.
    drop(cni_work_tx);
    let mut cni_work_open = true;

    info!(
        "Node agent initialized, watching pod events on node {}",
        config.node_name
    );

    // Periodic re-drive of transiently-failed enrollments. Failed pods are not
    // in `pod_states`, and the watcher/CNI arms only enroll on fresh events, so
    // without this a transient eBPF attach/map failure (after cgroup+veth
    // resolved) would become an indefinite capture gap until the next pod event.
    // `retry_backed_off_pod_enrollments` is a cheap no-op when no failures are
    // pending. Consume the immediate first tick that `interval` fires so the
    // first real pass waits a full backoff window rather than firing instantly.
    let mut retry_interval = tokio::time::interval(POD_ENROLLMENT_RETRY_BACKOFF);
    retry_interval.tick().await;
    let mut udp_readiness_interval = tokio::time::interval(UDP_CAPTURE_READINESS_POLL);
    udp_readiness_interval.tick().await;
    let mut udp_ready_uids = HashSet::new();

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
                            handle_pod_removed(backend.as_mut(), &pod_states, config, metrics.as_ref(), &uid);
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
                            let stale_uids = watcher_init_stale_uids(&pod_states, &seen);
                            for uid in stale_uids {
                                handle_pod_removed(backend.as_mut(), &pod_states, config, metrics.as_ref(), &uid);
                            }
                            // Also remove pods whose owned failure snapshots
                            // vanished across the relist; otherwise the retry
                            // loop replays them indefinitely (see helper docs).
                            prune_failed_enrollments_from_relist(
                                backend.as_mut(),
                                &pod_states,
                                config,
                                &metrics,
                                &seen,
                            );
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
            cni_work = cni_work_rx.recv(), if cni_work_open => {
                match cni_work {
                    Some(work) => {
                        let enrolled_uid = process_cni_work_item(
                            backend.as_mut(),
                            &pod_states,
                            config,
                            metrics.as_ref(),
                            &client,
                            work,
                        ).await;
                        mark_relist_seen_from_cni_add(&mut init_seen, enrolled_uid.as_deref());
                    }
                    None => {
                        // Channel closed — listener task exited. Disable this
                        // select arm so the watcher keeps running instead of
                        // spinning on an immediately-ready closed receiver.
                        cni_work_open = false;
                        debug!("CNI work queue closed; CNI plugin path inactive for the remainder of this run");
                    }
                }
            }
            _ = retry_interval.tick() => {
                // Re-drive any pod whose transient enrollment failure has aged
                // past the backoff window, and retry stale detach/map cleanup
                // that would otherwise keep capture partially attached. Cheap
                // no-ops when none are pending.
                retry_backed_off_pod_enrollments(
                    backend.as_mut(),
                    &pod_states,
                    config,
                    metrics.as_ref(),
                    false,
                );
                retry_pending_pod_detaches(
                    backend.as_mut(),
                    &pod_states,
                    config,
                    metrics.as_ref(),
                );
                retry_pending_pod_ip_removals(
                    backend.as_mut(),
                    &pod_states,
                    config,
                    metrics.as_ref(),
                );
                retry_pending_node_probe_port_updates(
                    backend.as_mut(),
                    &pod_states,
                    metrics.as_ref(),
                );
                retry_pending_node_probe_port_removals(
                    backend.as_mut(),
                    &pod_states,
                    config,
                    metrics.as_ref(),
                );
                retry_pending_cgroup_map_removals(
                    backend.as_mut(),
                    &pod_states,
                    config,
                    metrics.as_ref(),
                );
            }
            _ = udp_readiness_interval.tick(), if udp_readiness_reconcile_enabled(config) => {
                reconcile_udp_capture_readiness_with_sync_state(
                    backend.as_mut(),
                    &pod_states,
                    config,
                    metrics.as_ref(),
                    &mut udp_ready_uids,
                    startup_ready.load(Ordering::Acquire),
                );
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
    cleanup_all_pods(backend.as_mut(), &pod_states, config);

    if let Some(handle) = cni_listener_handle
        && let Err(err) = handle.await
    {
        warn!(error = %err, "Node agent CNI listener task panicked");
    }

    Ok(())
}

fn watcher_init_stale_uids(
    pod_states: &DashMap<String, PodAttachmentState>,
    seen: &HashSet<String>,
) -> Vec<String> {
    pod_states
        .iter()
        .filter(|entry| !seen.contains(entry.key().as_str()))
        .map(|entry| entry.key().clone())
        .collect()
}

/// Remove transiently-failed pods (in `FAILED_POD_ENROLLMENT_ATTEMPTS`) that
/// vanished across a watcher reconnect/relist. The InitDone stale sweep only
/// reconciles enrolled pods (`watcher_init_stale_uids` walks `pod_states`), but a
/// pod that failed enrollment before it was inserted into `pod_states` keeps an
/// owned snapshot *outside* `pod_states`. If that pod is gone after the relist,
/// nothing else clears the record, so the periodic retry loop would replay it
/// forever — warning and bumping `attach_errors` every ~30s for a UID the API no
/// longer reports. Routing it through `handle_pod_removed` consumes any partial
/// BPF cleanup evidence before clearing the retry record.
///
/// Records are scoped by the `pod_states` key prefix so a sibling node-agent
/// runtime (or, under `cargo test`, another test's pods) is never pruned.
fn has_failed_pod_enrollments(pod_states: &DashMap<String, PodAttachmentState>) -> bool {
    if FAILED_POD_ENROLLMENT_ATTEMPTS.is_empty() {
        return false;
    }

    let key_prefix = pod_state_key_prefix(pod_states);
    FAILED_POD_ENROLLMENT_ATTEMPTS
        .iter()
        .any(|entry| entry.key().starts_with(&key_prefix))
}

fn has_pending_capture_failures(pod_states: &DashMap<String, PodAttachmentState>) -> bool {
    if PENDING_CAPTURE_FAILURES.is_empty() {
        return false;
    }

    let key_prefix = pod_state_key_prefix(pod_states);
    PENDING_CAPTURE_FAILURES
        .iter()
        .any(|entry| entry.key().starts_with(&key_prefix))
}

fn clear_partial_capture_state_if_recovered(
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
) {
    if !has_failed_pod_enrollments(pod_states)
        && !has_pending_capture_failures(pod_states)
        && metrics.snapshot().capture_state == NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
    {
        metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_READY);
    }
}

fn prune_failed_enrollments_from_relist(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    seen: &HashSet<String>,
) {
    if FAILED_POD_ENROLLMENT_ATTEMPTS.is_empty() {
        return;
    }

    let key_prefix = pod_state_key_prefix(pod_states);
    // Collect first so we never remove while iterating the same DashMap.
    let stale_keys: Vec<String> = FAILED_POD_ENROLLMENT_ATTEMPTS
        .iter()
        .filter_map(|entry| {
            let pod_uid = entry.key().strip_prefix(&key_prefix)?;
            (!seen.contains(pod_uid)).then(|| entry.key().clone())
        })
        .collect();

    for state_key in stale_keys {
        let Some(pod_uid) = state_key.strip_prefix(&key_prefix) else {
            continue;
        };
        handle_pod_removed(backend, pod_states, config, metrics, pod_uid);
    }
    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

fn mark_relist_seen_from_cni_add(
    init_seen: &mut Option<HashSet<String>>,
    enrolled_uid: Option<&str>,
) {
    if let (Some(seen), Some(uid)) = (init_seen.as_mut(), enrolled_uid) {
        seen.insert(uid.to_string());
    }
}

/// Apply one CNI plugin RPC to the same state the kube-rs watcher
/// manipulates. The watcher arm and this arm of the select! loop share
/// `backend` ownership exclusively — no `Mutex`. Idempotency is
/// inherited from `handle_pod_added` / `handle_pod_removed`: repeat
/// calls with the same identity are no-ops.
///
/// The production ADD path first fetches pod metadata from the Kubernetes API
/// in [`apply_cni_request_with_kube_metadata`]. This pure helper keeps the
/// no-metadata fallback behavior testable: if that API GET fails, ADD is
/// acknowledged without BPF attachment and the kube-rs watcher reconciles when
/// its event arrives.
///
/// On the DEL path: when we already have a pod-state entry, we tear
/// down BPF attachment immediately — the CNI DEL is a strong signal
/// that the sandbox is going away, and waiting for the watcher's
/// `Delete` event would leave stale BPF state for the gap.
async fn process_cni_work_item(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    kube_client: &Client,
    work: CniWorkItem,
) -> Option<String> {
    let CniWorkItem { request, respond } = work;
    let (response, enrolled_uid) = apply_cni_request_with_kube_metadata(
        backend,
        pod_states,
        config,
        metrics,
        kube_client,
        &request,
    )
    .await;
    // The remote receiver may have been dropped (CNI client timed out or
    // the listener task is shutting down); that's fine — we still
    // applied the side-effect. The metric/log already reflect the
    // outcome from the server's side.
    let _ = respond.send(response);
    enrolled_uid
}

async fn apply_cni_request_with_kube_metadata(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    kube_client: &Client,
    request: &CniRpcRequest,
) -> (CniRpcResponse, Option<String>) {
    if request.verb != RpcVerb::Add {
        return (
            apply_cni_request(backend, pod_states, config, metrics, request),
            None,
        );
    }

    let pod_api: Api<Pod> = Api::namespaced(kube_client.clone(), &request.pod_namespace);
    match tokio::time::timeout(CNI_METADATA_FETCH_TIMEOUT, pod_api.get(&request.pod_name)).await {
        Ok(Ok(pod)) => apply_cni_add_from_pod(backend, pod_states, config, metrics, request, &pod),
        Ok(Err(err)) => {
            debug!(
                namespace = %request.pod_namespace,
                pod_name = %request.pod_name,
                error = %err,
                "CNI ADD could not fetch pod metadata; kube-rs watcher will reconcile"
            );
            (
                apply_cni_request(backend, pod_states, config, metrics, request),
                None,
            )
        }
        Err(_elapsed) => {
            debug!(
                namespace = %request.pod_namespace,
                pod_name = %request.pod_name,
                timeout_ms = CNI_METADATA_FETCH_TIMEOUT.as_millis(),
                "CNI ADD pod metadata fetch timed out; kube-rs watcher will reconcile"
            );
            (
                apply_cni_request(backend, pod_states, config, metrics, request),
                None,
            )
        }
    }
}

fn apply_cni_add_from_pod(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    request: &CniRpcRequest,
    pod: &Pod,
) -> (CniRpcResponse, Option<String>) {
    let Some(api_uid) = pod_uid(pod) else {
        return (
            CniRpcResponse::Rejected {
                reason:
                    "Kubernetes API pod is missing metadata.uid; kube-rs watcher will reconcile"
                        .to_string(),
            },
            None,
        );
    };
    if let Some(request_uid) = request.pod_uid.as_deref()
        && request_uid != api_uid
    {
        return (
            CniRpcResponse::Rejected {
                reason: format!(
                    "CNI pod UID {request_uid} does not match Kubernetes API pod UID {api_uid}; kube-rs watcher will reconcile"
                ),
            },
            None,
        );
    }

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
    let pod_name = pod
        .metadata
        .name
        .as_deref()
        .unwrap_or(request.pod_name.as_str());
    let namespace = pod
        .metadata
        .namespace
        .as_deref()
        .unwrap_or(request.pod_namespace.as_str());
    let status = pod.status.as_ref();
    let pod_ip = status.and_then(|status| status.pod_ip.as_deref());
    let pod_source_ips = PodSourceIps::from_status(status);
    let node_probe_ports = pod_probe_ports_from_spec(pod.spec.as_ref());
    let service_account = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.service_account_name.as_deref());
    let event = PodEvent {
        pod_uid: &api_uid,
        pod_name,
        namespace,
        service_account,
        labels: &labels,
        annotations: &annotations,
        pod_ip_str: pod_ip,
        pod_source_ips,
        node_probe_ports,
        pod_pid: None,
        veth_iface_override: None,
    };
    handle_pod_added(backend, pod_states, config, metrics, &event);
    // Surface the UID that was actually inserted into `pod_states` (the
    // Kubernetes API `metadata.uid`, which may differ from — or be present when
    // the CRI omitted — `request.pod_uid`) so a CNI ADD during the watcher
    // Init/InitDone relist window marks the enrolled pod seen and survives the
    // stale sweep. `None` when enrollment did not land (e.g. attach failure).
    let enrolled_uid = if pod_states.contains_key(api_uid.as_str()) {
        Some(api_uid)
    } else {
        None
    };
    (CniRpcResponse::Ok, enrolled_uid)
}

/// Pure-function core of [`process_cni_work_item`] so tests can drive
/// it without an `mpsc` round-trip.
pub fn apply_cni_request(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    request: &CniRpcRequest,
) -> CniRpcResponse {
    let labels: HashMap<String, String> = HashMap::new();
    let annotations: HashMap<String, String> = HashMap::new();
    let event = node_agent_cni_server::pod_event_from_request(request, &labels, &annotations);
    match request.verb {
        RpcVerb::Add => {
            // Metadata-free ADD requests must not drive enrollment
            // decisions. They arrive before we can reliably evaluate
            // labels/annotations, so we acknowledge and let either
            // `apply_cni_request_with_kube_metadata` (when available)
            // or the kube-rs watcher perform authoritative reconcile.
            if event.pod_uid.is_empty() {
                return CniRpcResponse::Rejected {
                    reason: "missing K8S_POD_UID in CNI args; kube-rs watcher will reconcile"
                        .to_string(),
                };
            }
            CniRpcResponse::Ok
        }
        RpcVerb::Del => {
            if event.pod_uid.is_empty() {
                return CniRpcResponse::Rejected {
                    reason: "missing K8S_POD_UID in CNI args; kube-rs watcher will reconcile"
                        .to_string(),
                };
            }
            handle_pod_removed(backend, pod_states, config, metrics, event.pod_uid);
            CniRpcResponse::Ok
        }
        RpcVerb::Check => {
            if event.pod_uid.is_empty() {
                return CniRpcResponse::Rejected {
                    reason: "missing K8S_POD_UID in CNI args".to_string(),
                };
            }
            // CHECK is best-effort verification: report Ok when we have
            // a pod-state entry, Rejected otherwise. kubelet treats
            // Rejected as a hint that ADD needs replaying.
            if pod_states.contains_key(event.pod_uid) {
                CniRpcResponse::Ok
            } else {
                CniRpcResponse::Rejected {
                    reason: "pod not currently enrolled".to_string(),
                }
            }
        }
    }
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
/// Carries the cgroup ids the entry was written under — the pod cgroup inode
/// plus every descendant container-cgroup inode (`connect4`/`connect6` look up
/// `FERRUM_INCLUDE_PORTS` by the *leaf* cgroup, so the policy must live under
/// the whole subtree, not just the pod inode) — so removal can drop every entry
/// without re-statting the cgroup tree, and the [`IncludePortsPolicy`] actually
/// written, so the watcher can diff against this baseline on the next Modified
/// event and skip BPF map churn when the parsed value has not changed.
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedIncludePorts {
    cgroup_ids: Vec<u64>,
    policy: IncludePortsPolicy,
}

/// Push the parsed per-pod include-port policy into the BPF map. Returns the
/// cgroup ids and policy we wrote so callers can stash both on
/// `PodAttachmentState`: the ids are the removal keys, the policy is the diff
/// baseline for mid-life Modified events. The policy is written under the pod
/// cgroup inode AND every descendant container-cgroup inode, because the
/// `connect4`/`connect6` gate keys `FERRUM_INCLUDE_PORTS` by
/// `bpf_get_current_cgroup_id()` (the container leaf cgroup) — writing only the
/// pod inode would never match the hook's key and the narrowing would silently
/// not engage. Returns `None` when there's nothing to write (no annotation,
/// malformed annotation, no readable cgroup inode, or every write failing) —
/// none of which should abort enrollment.
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
    let cgroup_ids = cgroup::collect_cgroup_tree_inodes(std::path::Path::new(cgroup_path));
    if cgroup_ids.is_empty() {
        warn!(
            pod_uid,
            cgroup_path,
            "Could not read any cgroup inode for pod; includeOutboundPorts narrowing will not engage"
        );
        return None;
    }
    let policy = include_outbound_ports_to_policy(pod_uid, &include);
    let mut written = Vec::with_capacity(cgroup_ids.len());
    for cgroup_id in cgroup_ids {
        match backend.update_pod_include_ports(cgroup_id, &policy) {
            Ok(()) => written.push(cgroup_id),
            Err(e) => {
                warn!(
                    pod_uid,
                    cgroup_id,
                    error = %e,
                    "Failed to write FERRUM_INCLUDE_PORTS for a pod cgroup inode; that cgroup's capture will not narrow"
                );
            }
        }
    }
    if written.is_empty() {
        warn!(
            pod_uid,
            "No FERRUM_INCLUDE_PORTS entries written for pod; capture will not narrow"
        );
        return None;
    }
    debug!(
        pod_uid,
        cgroup_ids = written.len(),
        all_ports = policy.is_all_ports(),
        port_count = policy.port_count,
        "Wrote per-pod includeOutboundPorts entries across pod cgroup tree"
    );
    Some(AppliedIncludePorts {
        cgroup_ids: written,
        policy,
    })
}

/// Build the source workload identity for a pod and write it into the
/// `FERRUM_WORKLOAD_IDENTITY` map (GAP-1b) so the connect hooks can stamp
/// orig-dst records with it. The SPIFFE ID is
/// `spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}`, matching the
/// CP-side format the node-waypoint resolver enrolls; the hash uses the same
/// `workload_spiffe_hash` algorithm as the resolver so the two agree.
///
/// The identity is written under the pod cgroup inode AND every descendant
/// container-cgroup inode (`cgroup::collect_cgroup_tree_inodes`). The connect
/// hooks look the identity up by `bpf_get_current_cgroup_id()`, which is the
/// *container* leaf cgroup — a child of the pod cgroup on every Kubernetes
/// cgroup driver — so writing only the pod inode would never match the hook's
/// key and resolution would silently fail closed in real pods.
///
/// Returns the cgroup inodes successfully written (the un-enrollment keys), or
/// an empty Vec on any total failure (bad pod UID, un-buildable SPIFFE ID, no
/// readable cgroup inode, or every BPF write failing). Best-effort: an empty
/// return logs and does not abort enrollment — the connect hooks then fall back
/// to the all-zero sentinel and node-waypoint resolution fails closed for that
/// pod, the same posture as before identity stamping existed.
fn apply_workload_identity(
    backend: &mut dyn EbpfBackend,
    config: &NodeAgentConfig,
    pod_uid: &str,
    namespace: &str,
    service_account: Option<&str>,
    cgroup_path: &str,
) -> Vec<u64> {
    let Some(identity) = build_workload_identity(
        pod_uid,
        namespace,
        service_account.unwrap_or("default"),
        &config.trust_domain,
    ) else {
        return Vec::new();
    };
    let cgroup_ids = cgroup::collect_cgroup_tree_inodes(std::path::Path::new(cgroup_path));
    if cgroup_ids.is_empty() {
        warn!(
            pod_uid,
            cgroup_path,
            "Could not read any cgroup inode for pod; node-waypoint identity resolution will \
             fail closed for traffic from this pod"
        );
        return Vec::new();
    }

    let mut written = Vec::with_capacity(cgroup_ids.len());
    for cgroup_id in cgroup_ids {
        match backend.update_workload_identity(cgroup_id, &identity) {
            Ok(()) => written.push(cgroup_id),
            Err(e) => {
                warn!(
                    pod_uid,
                    cgroup_id,
                    error = %e,
                    "Failed to write FERRUM_WORKLOAD_IDENTITY for a pod cgroup inode; \
                     traffic from that cgroup will fail closed"
                );
            }
        }
    }
    if written.is_empty() {
        warn!(
            pod_uid,
            "No FERRUM_WORKLOAD_IDENTITY entries written for pod; node-waypoint identity \
             resolution will fail closed for traffic from this pod"
        );
    } else {
        debug!(
            pod_uid,
            cgroup_ids = written.len(),
            "Wrote source workload identity to FERRUM_WORKLOAD_IDENTITY across pod cgroup tree"
        );
    }
    written
}

fn cleanup_pre_enrollment_maps(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    state: &PodAttachmentState,
) {
    cleanup_pre_enrollment_node_probe_ports(backend, pod_states, metrics, pod_uid, state);
    if let Some(ip) = state.pod_ip {
        remove_pre_enrollment_pod_ip_if_unowned(
            backend,
            pod_states,
            metrics,
            pod_uid,
            ip,
            "pre-enrollment cleanup",
        );
    }
    if let Some(ip) = state.pod_ip6 {
        remove_pre_enrollment_pod_ip6_if_unowned(
            backend,
            pod_states,
            metrics,
            pod_uid,
            ip,
            "pre-enrollment cleanup",
        );
    }
    for cgroup_id in &state.include_ports_cgroup_ids {
        if let Err(e) = backend.remove_pod_include_ports(*cgroup_id) {
            warn!(
                pod_uid,
                cgroup_id = *cgroup_id,
                error = %e,
                "Failed to remove pre-enrollment includeOutboundPorts entry from BPF map"
            );
        }
    }
    for cgroup_id in &state.workload_identity_cgroup_ids {
        if let Err(e) = backend.remove_workload_identity(*cgroup_id) {
            warn!(
                pod_uid,
                cgroup_id = *cgroup_id,
                error = %e,
                "Failed to remove pre-enrollment workload-identity entry from BPF map"
            );
        }
    }
}

fn cleanup_pre_enrollment_node_probe_ports(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    state: &PodAttachmentState,
) {
    if state.node_probe_ports.is_empty() {
        return;
    }
    if let Some(ip) = state.pod_ip {
        for port in &state.node_probe_ports {
            remove_node_probe_port_if_unowned(
                backend,
                pod_states,
                metrics,
                NodeProbePortRemoval {
                    pod_uid,
                    ip: std::net::IpAddr::V4(ip),
                    port: *port,
                    reason: "pre-enrollment cleanup",
                    clear_recovered_state: false,
                },
            );
        }
    }
    if let Some(ip) = state.pod_ip6 {
        for port in &state.node_probe_ports {
            remove_node_probe_port_if_unowned(
                backend,
                pod_states,
                metrics,
                NodeProbePortRemoval {
                    pod_uid,
                    ip: std::net::IpAddr::V6(ip),
                    port: *port,
                    reason: "pre-enrollment cleanup",
                    clear_recovered_state: false,
                },
            );
        }
    }
}

#[derive(Debug)]
struct NodeProbePortApplyError {
    message: String,
    applied_ports: Vec<u16>,
}

fn remember_applied_node_probe_port(applied_ports: &mut Vec<u16>, port: u16) {
    if !applied_ports.contains(&port) {
        applied_ports.push(port);
    }
}

fn apply_node_probe_ports_collecting(
    backend: &mut dyn EbpfBackend,
    pod_uid: &str,
    state: &PodAttachmentState,
) -> Result<Vec<u16>, NodeProbePortApplyError> {
    let mut applied_ports = Vec::new();
    for port in &state.node_probe_ports {
        if let Some(ip) = state.pod_ip {
            if let Err(e) = backend.update_node_probe_port(ip, *port) {
                return Err(NodeProbePortApplyError {
                    message: format!("failed to write IPv4 node probe port {ip}:{port}: {e}"),
                    applied_ports,
                });
            }
            remember_applied_node_probe_port(&mut applied_ports, *port);
        }
        if let Some(ip) = state.pod_ip6 {
            if let Err(e) = backend.update_node_probe_port6(ip, *port) {
                return Err(NodeProbePortApplyError {
                    message: format!("failed to write IPv6 node probe port {ip}:{port}: {e}"),
                    applied_ports,
                });
            }
            remember_applied_node_probe_port(&mut applied_ports, *port);
        }
    }
    if !state.node_probe_ports.is_empty() {
        debug!(
            pod_uid,
            ?state.node_probe_ports,
            "Wrote node-source probe-port exemptions for enrolled pod"
        );
    }
    Ok(applied_ports)
}

fn apply_node_probe_ports(
    backend: &mut dyn EbpfBackend,
    pod_uid: &str,
    state: &PodAttachmentState,
) -> Result<(), String> {
    apply_node_probe_ports_collecting(backend, pod_uid, state)
        .map(|_| ())
        .map_err(|e| e.message)
}

fn cleanup_node_probe_ports(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    state: &PodAttachmentState,
) {
    if state.node_probe_ports.is_empty() {
        return;
    }
    if let Some(ip) = state.pod_ip {
        for port in &state.node_probe_ports {
            remove_node_probe_port_if_unowned(
                backend,
                pod_states,
                metrics,
                NodeProbePortRemoval {
                    pod_uid,
                    ip: std::net::IpAddr::V4(ip),
                    port: *port,
                    reason: "pod cleanup",
                    clear_recovered_state: true,
                },
            );
        }
    }
    if let Some(ip) = state.pod_ip6 {
        for port in &state.node_probe_ports {
            remove_node_probe_port_if_unowned(
                backend,
                pod_states,
                metrics,
                NodeProbePortRemoval {
                    pod_uid,
                    ip: std::net::IpAddr::V6(ip),
                    port: *port,
                    reason: "pod cleanup",
                    clear_recovered_state: true,
                },
            );
        }
    }
}

struct NodeProbePortRemoval<'a> {
    pod_uid: &'a str,
    ip: std::net::IpAddr,
    port: u16,
    reason: &'static str,
    clear_recovered_state: bool,
}

fn remove_node_probe_port_if_unowned(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    removal: NodeProbePortRemoval<'_>,
) {
    let state_key = pod_state_key(pod_states, removal.pod_uid);
    let detail = node_probe_port_failure_detail(removal.ip, removal.port);
    if let Some(owner_pod_uid) =
        other_pod_owning_probe_port_addr(pod_states, removal.pod_uid, removal.ip, removal.port)
    {
        debug!(
            pod_uid = removal.pod_uid,
            owner_pod_uid,
            ip = %removal.ip,
            port = removal.port,
            removal_reason = removal.reason,
            "Skipping node probe-port map removal; key is owned by another tracked pod"
        );
        forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_NODE_PROBE_PORT_REMOVE, &detail);
        forget_pending_node_probe_port_remove_failures_for_key(
            pod_states,
            removal.ip,
            removal.port,
        );
        if removal.clear_recovered_state {
            clear_partial_capture_state_if_recovered(pod_states, metrics);
        }
        return;
    }

    let result = match removal.ip {
        std::net::IpAddr::V4(ip) => backend.remove_node_probe_port(ip, removal.port),
        std::net::IpAddr::V6(ip) => backend.remove_node_probe_port6(ip, removal.port),
    };
    if let Err(e) = result {
        warn!(
            pod_uid = removal.pod_uid,
            ip = %removal.ip,
            port = removal.port,
            error = %e,
            removal_reason = removal.reason,
            "Failed to remove node probe-port entry from BPF map"
        );
        metrics.record_attach_error();
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_NODE_PROBE_PORT_REMOVE,
            &detail,
        );
        return;
    }

    forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_NODE_PROBE_PORT_REMOVE, &detail);
    if removal.clear_recovered_state {
        clear_partial_capture_state_if_recovered(pod_states, metrics);
    }
}

fn remove_node_probe_ports_for_ip(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    ip: std::net::IpAddr,
    ports: &[u16],
    removal_reason: &'static str,
) {
    for port in ports {
        remove_node_probe_port_if_unowned(
            backend,
            pod_states,
            metrics,
            NodeProbePortRemoval {
                pod_uid,
                ip,
                port: *port,
                reason: removal_reason,
                clear_recovered_state: true,
            },
        );
    }
}

fn cleanup_partial_pod_enrollment(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    state: &PodAttachmentState,
) {
    if let Err(e) = backend.detach_pod(pod_uid) {
        warn!(pod_uid, error = %e, "Failed to clean up partially attached pod");
    }
    cleanup_pre_enrollment_maps(backend, pod_states, metrics, pod_uid, state);
}

fn build_workload_spiffe_id(
    namespace: &str,
    service_account: &str,
    trust_domain: &str,
) -> Option<crate::identity::SpiffeId> {
    let trust_domain = match crate::identity::spiffe::TrustDomain::new(trust_domain) {
        Ok(td) => td,
        Err(e) => {
            warn!(trust_domain, error = %e, "Cannot derive workload identity: invalid trust domain");
            return None;
        }
    };
    let path = format!("ns/{namespace}/sa/{service_account}");
    match crate::identity::spiffe::SpiffeId::from_parts(&trust_domain, &path) {
        Ok(id) => Some(id),
        Err(e) => {
            warn!(
                namespace,
                service_account,
                error = %e,
                "Cannot derive workload identity: invalid SPIFFE components"
            );
            None
        }
    }
}

/// Construct the `WorkloadIdentity` for a pod from its UID and the derived
/// SPIFFE ID. Returns `None` when the pod UID is not a valid UUID or the
/// SPIFFE components are unusable.
fn build_workload_identity(
    pod_uid: &str,
    namespace: &str,
    service_account: &str,
    trust_domain: &str,
) -> Option<crate::ebpf::WorkloadIdentity> {
    let uid_bytes = match crate::modes::mesh::node_waypoint::parse_pod_uid(pod_uid) {
        Ok(bytes) => bytes,
        Err(e) => {
            warn!(pod_uid, error = %e, "Cannot derive workload identity: invalid pod UID");
            return None;
        }
    };
    let spiffe_id = build_workload_spiffe_id(namespace, service_account, trust_domain)?;
    let hash = crate::modes::mesh::node_waypoint::workload_spiffe_hash(&spiffe_id);
    Some(crate::ebpf::WorkloadIdentity::new(uid_bytes, hash))
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
    let status = pod.status.as_ref();
    let pod_ip = status.and_then(|status| status.pod_ip.as_deref());
    let pod_source_ips = PodSourceIps::from_status(status);
    let node_probe_ports = pod_probe_ports_from_spec(pod.spec.as_ref());
    let service_account = pod
        .spec
        .as_ref()
        .and_then(|spec| spec.service_account_name.as_deref());
    let event = PodEvent {
        pod_uid: &pod_uid,
        pod_name: &pod_name,
        namespace: &namespace,
        service_account,
        labels: &labels,
        annotations: &annotations,
        pod_ip_str: pod_ip,
        pod_source_ips,
        node_probe_ports,
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
    /// Kubernetes `spec.serviceAccountName`. Used to derive the workload
    /// SPIFFE ID for the `FERRUM_WORKLOAD_IDENTITY` map (GAP-1b). `None` (or
    /// the kube default) maps to the `default` service account.
    pub service_account: Option<&'a str>,
    pub labels: &'a HashMap<String, String>,
    pub annotations: &'a HashMap<String, String>,
    pub pod_ip_str: Option<&'a str>,
    pub pod_source_ips: PodSourceIps,
    pub node_probe_ports: Vec<u16>,
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

#[derive(Debug, Clone, PartialEq, Eq)]
struct PodEnrollmentAttemptSignature {
    namespace: String,
    service_account: Option<String>,
    pod_ip: Option<std::net::Ipv4Addr>,
    pod_source_ips: PodSourceIps,
    node_probe_ports: Vec<u16>,
    cgroup_path: Option<String>,
    veth_iface: Option<String>,
    labels_fingerprint: u64,
    annotations_fingerprint: u64,
}

/// Owned snapshot of everything needed to rebuild a `PodEvent` and re-drive
/// `handle_pod_added` for a pod whose enrollment failed transiently. A failed
/// enrollment is suppressed for `POD_ENROLLMENT_RETRY_BACKOFF` to avoid the
/// per-Apply churn that issue #1733 fixed, but failed pods are NOT inserted
/// into `pod_states` (insertion only happens once `state.attached` is true), so
/// they cannot be reconciled from `pod_states`. Without an owned record, a
/// transient eBPF attach/map failure that lands *after* the cgroup and veth
/// resolved would become an indefinite capture gap whenever no further pod
/// event arrives for that pod. We keep this snapshot so the periodic retry loop
/// in `run_with_backend` can rebuild the event and try again every ~30s until
/// it succeeds (or the pod is removed / no longer matches enrollment).
///
/// `veth_iface_override` is intentionally not captured: production always sets
/// it to `None` and relies on the live procfs/sysfs resolver, so the rebuilt
/// `PodEvent` re-resolves the interface on each retry.
#[derive(Debug, Clone)]
struct RetryablePodEnrollment {
    pod_uid: String,
    pod_name: String,
    namespace: String,
    service_account: Option<String>,
    labels: HashMap<String, String>,
    annotations: HashMap<String, String>,
    pod_ip: Option<String>,
    pod_source_ips: PodSourceIps,
    node_probe_ports: Vec<u16>,
    pod_pid: Option<u32>,
}

impl RetryablePodEnrollment {
    fn from_event(event: &PodEvent<'_>) -> Self {
        Self {
            pod_uid: event.pod_uid.to_string(),
            pod_name: event.pod_name.to_string(),
            namespace: event.namespace.to_string(),
            service_account: event.service_account.map(ToOwned::to_owned),
            labels: event.labels.clone(),
            annotations: event.annotations.clone(),
            pod_ip: event.pod_ip_str.map(ToOwned::to_owned),
            pod_source_ips: event.pod_source_ips,
            node_probe_ports: event.node_probe_ports.clone(),
            pod_pid: event.pod_pid,
        }
    }

    /// Reconstruct a borrowed `PodEvent` from this owned snapshot for replaying
    /// through `handle_pod_added`. The returned event borrows from `self`, so
    /// `self` must outlive the event.
    fn as_event(&self) -> PodEvent<'_> {
        PodEvent {
            pod_uid: &self.pod_uid,
            pod_name: &self.pod_name,
            namespace: &self.namespace,
            service_account: self.service_account.as_deref(),
            labels: &self.labels,
            annotations: &self.annotations,
            pod_ip_str: self.pod_ip.as_deref(),
            pod_source_ips: self.pod_source_ips,
            node_probe_ports: self.node_probe_ports.clone(),
            pod_pid: self.pod_pid,
            // Production always re-resolves the veth on retry (see struct docs).
            veth_iface_override: None,
        }
    }
}

#[derive(Debug, Clone)]
struct FailedPodEnrollmentAttempt {
    signature: PodEnrollmentAttemptSignature,
    last_attempt: Instant,
    /// Owned snapshot used to re-drive enrollment after the backoff window
    /// expires. `Some` for every real failure recorded by `handle_pod_added`;
    /// the periodic retry loop skips records that lack a snapshot.
    snapshot: Option<RetryablePodEnrollment>,
    /// Exact BPF keys that may have been written before enrollment failed.
    /// Removal cannot reconstruct cgroup inode keys after the sandbox dies, so
    /// retain the partial state until a genuine pod removal verifies cleanup.
    cleanup_state: Option<PodAttachmentState>,
}

/// Prefix shared by every `FAILED_POD_ENROLLMENT_ATTEMPTS` key belonging to a
/// given `pod_states`. The map is a process-global static; including the
/// `pod_states` pointer scopes records to the owning node-agent runtime so the
/// periodic retry loop never re-drives another runtime's (or, under `cargo
/// test`, another test's) pods.
fn pod_state_key_prefix(pod_states: &DashMap<String, PodAttachmentState>) -> String {
    format!("{:p}:", pod_states)
}

fn pod_state_key(pod_states: &DashMap<String, PodAttachmentState>, pod_uid: &str) -> String {
    format!("{}{pod_uid}", pod_state_key_prefix(pod_states))
}

fn pending_capture_failure_key(state_key: &str, operation: &str, detail: &str) -> String {
    format!(
        "{state_key}:{operation}:{}",
        encode_pending_capture_detail(detail)
    )
}

fn encode_pending_capture_detail(detail: &str) -> String {
    detail.replace('%', "%25").replace(':', "%3A")
}

fn decode_pending_capture_detail(detail: &str) -> String {
    detail.replace("%3A", ":").replace("%25", "%")
}

#[derive(Debug, Clone)]
struct PendingCaptureFailure {
    key: String,
    state_key: String,
    operation: String,
    detail: String,
}

fn parse_pending_capture_failure_key(key: &str) -> Option<PendingCaptureFailure> {
    let mut parts = key.rsplitn(3, ':');
    let detail = decode_pending_capture_detail(parts.next()?);
    let operation = parts.next()?;
    let state_key = parts.next()?;
    if state_key.is_empty() || operation.is_empty() || detail.is_empty() {
        return None;
    }
    Some(PendingCaptureFailure {
        key: key.to_string(),
        state_key: state_key.to_string(),
        operation: operation.to_string(),
        detail,
    })
}

#[cfg(test)]
fn pending_capture_failure_prefix(state_key: &str) -> String {
    format!("{state_key}:")
}

fn remember_pending_capture_failure(state_key: &str, operation: &str, detail: &str) {
    PENDING_CAPTURE_FAILURES.insert(
        pending_capture_failure_key(state_key, operation, detail),
        (),
    );
}

fn forget_pending_capture_failure(state_key: &str, operation: &str, detail: &str) -> bool {
    PENDING_CAPTURE_FAILURES
        .remove(&pending_capture_failure_key(state_key, operation, detail))
        .is_some()
}

fn node_probe_port_failure_detail(ip: std::net::IpAddr, port: u16) -> String {
    format!("{ip},{port}")
}

fn parse_node_probe_port_failure_detail(detail: &str) -> Option<(std::net::IpAddr, u16)> {
    let (ip, port) = detail.split_once(',')?;
    Some((ip.parse().ok()?, port.parse().ok()?))
}

fn node_probe_port_update_failure_detail(ports: &[u16]) -> String {
    let mut ports = ports.to_vec();
    ports.sort_unstable();
    ports.dedup();
    let ports = ports
        .iter()
        .map(u16::to_string)
        .collect::<Vec<_>>()
        .join(",");
    format!("{CAPTURE_FAILURE_DETAIL_NODE_PROBE_PORTS}={ports}")
}

fn parse_node_probe_port_update_failure_detail(detail: &str) -> Option<Vec<u16>> {
    let ports = detail.strip_prefix(CAPTURE_FAILURE_DETAIL_NODE_PROBE_PORTS)?;
    let ports = ports.strip_prefix('=')?;
    if ports.is_empty() {
        return Some(Vec::new());
    }
    let mut parsed = Vec::new();
    for port in ports.split(',') {
        parsed.push(port.parse().ok()?);
    }
    parsed.sort_unstable();
    parsed.dedup();
    Some(parsed)
}

fn forget_pending_node_probe_port_remove_failures_for_key(
    pod_states: &DashMap<String, PodAttachmentState>,
    ip: std::net::IpAddr,
    port: u16,
) -> usize {
    let key_prefix = pod_state_key_prefix(pod_states);
    let detail = node_probe_port_failure_detail(ip, port);
    let keys: Vec<String> = PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            let failure = parse_pending_capture_failure_key(entry.key())?;
            (failure.state_key.starts_with(&key_prefix)
                && failure.operation == CAPTURE_FAILURE_NODE_PROBE_PORT_REMOVE
                && failure.detail == detail)
                .then_some(failure.key)
        })
        .collect();
    let removed = keys.len();
    for key in keys {
        PENDING_CAPTURE_FAILURES.remove(&key);
    }
    removed
}

fn forget_pending_node_probe_port_update_failures_for_state(state_key: &str) -> usize {
    let keys: Vec<String> = PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            let failure = parse_pending_capture_failure_key(entry.key())?;
            (failure.state_key == state_key
                && failure.operation == CAPTURE_FAILURE_NODE_PROBE_PORT_UPDATE)
                .then_some(failure.key)
        })
        .collect();
    let removed = keys.len();
    for key in keys {
        PENDING_CAPTURE_FAILURES.remove(&key);
    }
    removed
}

fn forget_pending_pod_ip_remove_failures_for_ip(
    pod_states: &DashMap<String, PodAttachmentState>,
    ip: impl std::fmt::Display,
) -> usize {
    let key_prefix = pod_state_key_prefix(pod_states);
    let detail = ip.to_string();
    let keys: Vec<String> = PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            let failure = parse_pending_capture_failure_key(entry.key())?;
            (failure.state_key.starts_with(&key_prefix)
                && failure.operation == CAPTURE_FAILURE_POD_IP_REMOVE
                && failure.detail == detail)
                .then_some(failure.key)
        })
        .collect();
    let removed = keys.len();
    for key in keys {
        PENDING_CAPTURE_FAILURES.remove(&key);
    }
    removed
}

#[cfg(test)]
fn forget_pending_capture_failures_for_pod(state_key: &str) {
    let prefix = pending_capture_failure_prefix(state_key);
    let keys: Vec<String> = PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            entry
                .key()
                .starts_with(&prefix)
                .then(|| entry.key().clone())
        })
        .collect();
    for key in keys {
        PENDING_CAPTURE_FAILURES.remove(&key);
    }
}

fn map_fingerprint(map: &HashMap<String, String>) -> u64 {
    let mut entries: Vec<_> = map.iter().collect();
    entries.sort_unstable_by_key(|(left_key, _)| *left_key);
    let mut hasher = DefaultHasher::new();
    for (key, value) in entries {
        key.hash(&mut hasher);
        value.hash(&mut hasher);
    }
    hasher.finish()
}

fn pod_enrollment_attempt_signature(
    event: &PodEvent<'_>,
    pod_ip: Option<std::net::Ipv4Addr>,
    cgroup_path: &Option<String>,
    veth_iface: &Option<String>,
) -> PodEnrollmentAttemptSignature {
    PodEnrollmentAttemptSignature {
        namespace: event.namespace.to_string(),
        service_account: event.service_account.map(ToOwned::to_owned),
        pod_ip,
        pod_source_ips: event.pod_source_ips,
        node_probe_ports: event.node_probe_ports.clone(),
        cgroup_path: cgroup_path.clone(),
        veth_iface: veth_iface.clone(),
        labels_fingerprint: map_fingerprint(event.labels),
        annotations_fingerprint: map_fingerprint(event.annotations),
    }
}

fn recently_failed_pod_enrollment(
    state_key: &str,
    signature: &PodEnrollmentAttemptSignature,
) -> bool {
    let Some(previous) = FAILED_POD_ENROLLMENT_ATTEMPTS.get(state_key) else {
        return false;
    };
    if &previous.value().signature != signature {
        return false;
    }
    if previous.last_attempt.elapsed() >= POD_ENROLLMENT_RETRY_BACKOFF {
        drop(previous);
        FAILED_POD_ENROLLMENT_ATTEMPTS.remove(state_key);
        return false;
    }
    true
}

#[cfg(test)]
fn remember_failed_pod_enrollment(
    state_key: &str,
    signature: PodEnrollmentAttemptSignature,
    snapshot: RetryablePodEnrollment,
) {
    let prior_cleanup_state = FAILED_POD_ENROLLMENT_ATTEMPTS
        .get(state_key)
        .and_then(|attempt| attempt.cleanup_state.clone());
    remember_failed_pod_enrollment_preserving_cleanup(
        state_key,
        signature,
        snapshot,
        prior_cleanup_state.as_ref(),
    );
}

fn remember_failed_pod_enrollment_preserving_cleanup(
    state_key: &str,
    signature: PodEnrollmentAttemptSignature,
    snapshot: RetryablePodEnrollment,
    prior_cleanup_state: Option<&PodAttachmentState>,
) {
    FAILED_POD_ENROLLMENT_ATTEMPTS.insert(
        state_key.to_string(),
        FailedPodEnrollmentAttempt {
            signature,
            last_attempt: Instant::now(),
            snapshot: Some(snapshot),
            cleanup_state: prior_cleanup_state.cloned(),
        },
    );
}

#[cfg(test)]
fn remember_failed_pod_enrollment_with_cleanup_state(
    state_key: &str,
    signature: PodEnrollmentAttemptSignature,
    snapshot: RetryablePodEnrollment,
    cleanup_state: &PodAttachmentState,
) {
    let prior_cleanup_state = FAILED_POD_ENROLLMENT_ATTEMPTS
        .get(state_key)
        .and_then(|attempt| attempt.cleanup_state.clone());
    remember_failed_pod_enrollment_with_merged_cleanup_state(
        state_key,
        signature,
        snapshot,
        prior_cleanup_state.as_ref(),
        cleanup_state,
    );
}

fn extend_unique_cgroup_ids(target: &mut Vec<u64>, source: &[u64]) {
    for cgroup_id in source {
        if !target.contains(cgroup_id) {
            target.push(*cgroup_id);
        }
    }
}

fn merge_failed_enrollment_cleanup_state(
    prior: Option<&PodAttachmentState>,
    current: &PodAttachmentState,
) -> PodAttachmentState {
    let Some(prior) = prior else {
        return current.clone();
    };
    let mut merged = current.clone();
    extend_unique_cgroup_ids(
        &mut merged.include_ports_cgroup_ids,
        &prior.include_ports_cgroup_ids,
    );
    extend_unique_cgroup_ids(
        &mut merged.workload_identity_cgroup_ids,
        &prior.workload_identity_cgroup_ids,
    );
    for port in &prior.node_probe_ports {
        if !merged.node_probe_ports.contains(port) {
            merged.node_probe_ports.push(*port);
        }
    }
    merged.pod_ip = merged.pod_ip.or(prior.pod_ip);
    merged.pod_ip6 = merged.pod_ip6.or(prior.pod_ip6);
    if merged.cgroup_path.is_none() {
        merged.cgroup_path.clone_from(&prior.cgroup_path);
    }
    if merged.veth_iface.is_none() {
        merged.veth_iface.clone_from(&prior.veth_iface);
    }
    if merged.include_ports_policy.is_none() {
        merged.include_ports_policy = prior.include_ports_policy;
    }
    merged.attached |= prior.attached;
    merged
}

fn remember_failed_pod_enrollment_with_merged_cleanup_state(
    state_key: &str,
    signature: PodEnrollmentAttemptSignature,
    snapshot: RetryablePodEnrollment,
    prior_cleanup_state: Option<&PodAttachmentState>,
    cleanup_state: &PodAttachmentState,
) {
    FAILED_POD_ENROLLMENT_ATTEMPTS.insert(
        state_key.to_string(),
        FailedPodEnrollmentAttempt {
            signature,
            last_attempt: Instant::now(),
            snapshot: Some(snapshot),
            cleanup_state: Some(merge_failed_enrollment_cleanup_state(
                prior_cleanup_state,
                cleanup_state,
            )),
        },
    );
}

fn forget_failed_pod_enrollment(state_key: &str) {
    FAILED_POD_ENROLLMENT_ATTEMPTS.remove(state_key);
}

fn has_failed_pod_enrollment_attempt(state_key: &str) -> bool {
    FAILED_POD_ENROLLMENT_ATTEMPTS.contains_key(state_key)
}

fn forget_pod_enrollment_attempt(state_key: &str) {
    FAILED_POD_ENROLLMENT_ATTEMPTS.remove(state_key);
}

/// Re-drive enrollment for every pod that failed transiently and whose backoff
/// window has elapsed.
///
/// Failed enrollments are remembered in `FAILED_POD_ENROLLMENT_ATTEMPTS` and
/// suppressed for `POD_ENROLLMENT_RETRY_BACKOFF` so we don't churn on every
/// Apply (issue #1733). But failed pods are never inserted into `pod_states`
/// (insertion only happens once `state.attached` is true), so nothing
/// reconciles them from `pod_states`. Before this loop, a transient eBPF
/// attach/map failure that struck *after* the cgroup and veth resolved became
/// an indefinite capture gap if no further pod/CNI event arrived for that pod.
///
/// This helper closes that gap. It collects the eligible `(state_key,
/// snapshot)` pairs *first* (an owned `Vec`) so we never mutate
/// `FAILED_POD_ENROLLMENT_ATTEMPTS` while iterating it, then replays each
/// snapshot through the backoff-bypassing entry point. That entry point captures
/// retained cleanup evidence before removing the stale attempt, so a repeated
/// pre-mutation failure cannot erase keys written by an earlier partial attempt.
/// On repeated failure it re-remembers with a fresh `last_attempt`, so the pod
/// keeps retrying roughly every `POD_ENROLLMENT_RETRY_BACKOFF` until it enrolls,
/// is removed, or no longer matches enrollment criteria — strictly
/// better-bounded than the pre-#1733 every-Apply churn.
///
/// `force` bypasses the elapsed-time gate; production passes `false`. Tests pass
/// `true` to exercise the replay deterministically without real sleeps (the
/// 30-second window is otherwise unreachable without wall-clock time).
fn retry_backed_off_pod_enrollments(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    force: bool,
) {
    if FAILED_POD_ENROLLMENT_ATTEMPTS.is_empty() {
        return;
    }

    // Only re-drive records owned by *this* `pod_states`. The map is a global
    // static, so without scoping a node-agent runtime (or a sibling test) would
    // replay another runtime's pods against the wrong state map.
    let key_prefix = pod_state_key_prefix(pod_states);

    // Collect (state_key, snapshot) first so we never hold DashMap shard guards
    // across the replay (which itself mutates FAILED_POD_ENROLLMENT_ATTEMPTS via
    // handle_pod_added). `force` bypasses the elapsed gate for tests.
    let due: Vec<(String, RetryablePodEnrollment)> = FAILED_POD_ENROLLMENT_ATTEMPTS
        .iter()
        .filter(|entry| entry.key().starts_with(&key_prefix))
        .filter(|entry| {
            force || entry.value().last_attempt.elapsed() >= POD_ENROLLMENT_RETRY_BACKOFF
        })
        .filter_map(|entry| {
            entry
                .value()
                .snapshot
                .clone()
                .map(|snapshot| (entry.key().clone(), snapshot))
        })
        .collect();

    for (_state_key, snapshot) in due {
        let event = snapshot.as_event();
        debug!(
            pod_uid = event.pod_uid,
            pod_name = event.pod_name,
            namespace = event.namespace,
            "Re-driving backed-off pod enrollment after retry window"
        );
        handle_pod_added_after_backoff(backend, pod_states, config, metrics, &event);
    }
}

fn pending_pod_ip_removal_failures(
    pod_states: &DashMap<String, PodAttachmentState>,
) -> Vec<(String, String, String, std::net::IpAddr)> {
    if PENDING_CAPTURE_FAILURES.is_empty() {
        return Vec::new();
    }

    let key_prefix = pod_state_key_prefix(pod_states);
    PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            let failure = parse_pending_capture_failure_key(entry.key())?;
            if !failure.state_key.starts_with(&key_prefix)
                || failure.operation != CAPTURE_FAILURE_POD_IP_REMOVE
            {
                return None;
            }
            let pod_uid = failure.state_key.strip_prefix(&key_prefix)?.to_string();
            let ip = failure.detail.parse().ok()?;
            Some((failure.key, failure.state_key, pod_uid, ip))
        })
        .collect()
}

fn pending_pod_detach_failures(
    pod_states: &DashMap<String, PodAttachmentState>,
) -> Vec<(String, String, String)> {
    if PENDING_CAPTURE_FAILURES.is_empty() {
        return Vec::new();
    }

    let key_prefix = pod_state_key_prefix(pod_states);
    PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            let failure = parse_pending_capture_failure_key(entry.key())?;
            if !failure.state_key.starts_with(&key_prefix)
                || failure.operation != CAPTURE_FAILURE_POD_DETACH
                || failure.detail != CAPTURE_FAILURE_DETAIL_POD_DETACH
            {
                return None;
            }
            let pod_uid = failure.state_key.strip_prefix(&key_prefix)?.to_string();
            Some((failure.key, failure.state_key, pod_uid))
        })
        .collect()
}

fn pending_node_probe_port_removal_failures(
    pod_states: &DashMap<String, PodAttachmentState>,
) -> Vec<(String, String, String, std::net::IpAddr, u16)> {
    if PENDING_CAPTURE_FAILURES.is_empty() {
        return Vec::new();
    }

    let key_prefix = pod_state_key_prefix(pod_states);
    PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            let failure = parse_pending_capture_failure_key(entry.key())?;
            if !failure.state_key.starts_with(&key_prefix)
                || failure.operation != CAPTURE_FAILURE_NODE_PROBE_PORT_REMOVE
            {
                return None;
            }
            let (ip, port) = parse_node_probe_port_failure_detail(&failure.detail)?;
            let pod_uid = failure.state_key.strip_prefix(&key_prefix)?.to_string();
            Some((failure.key, failure.state_key, pod_uid, ip, port))
        })
        .collect()
}

fn pending_cgroup_map_removal_failures(
    pod_states: &DashMap<String, PodAttachmentState>,
    operation: &str,
) -> Vec<(String, String, String, u64)> {
    if PENDING_CAPTURE_FAILURES.is_empty() {
        return Vec::new();
    }

    let key_prefix = pod_state_key_prefix(pod_states);
    PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            let failure = parse_pending_capture_failure_key(entry.key())?;
            if !failure.state_key.starts_with(&key_prefix) || failure.operation != operation {
                return None;
            }
            let pod_uid = failure.state_key.strip_prefix(&key_prefix)?.to_string();
            let cgroup_id = failure.detail.parse().ok()?;
            Some((failure.key, failure.state_key, pod_uid, cgroup_id))
        })
        .collect()
}

fn pending_node_probe_port_update_failures(
    pod_states: &DashMap<String, PodAttachmentState>,
) -> Vec<(String, String, Vec<u16>)> {
    if PENDING_CAPTURE_FAILURES.is_empty() {
        return Vec::new();
    }

    let key_prefix = pod_state_key_prefix(pod_states);
    PENDING_CAPTURE_FAILURES
        .iter()
        .filter_map(|entry| {
            let failure = parse_pending_capture_failure_key(entry.key())?;
            if !failure.state_key.starts_with(&key_prefix)
                || failure.operation != CAPTURE_FAILURE_NODE_PROBE_PORT_UPDATE
            {
                return None;
            }
            let pod_uid = failure.state_key.strip_prefix(&key_prefix)?.to_string();
            let desired_ports = parse_node_probe_port_update_failure_detail(&failure.detail)?;
            Some((failure.key, pod_uid, desired_ports))
        })
        .collect()
}

fn retry_pending_node_probe_port_updates(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
) {
    let pending = pending_node_probe_port_update_failures(pod_states);
    if pending.is_empty() {
        return;
    }

    for (failure_key, pod_uid, desired_ports) in pending {
        if !PENDING_CAPTURE_FAILURES.contains_key(&failure_key) {
            continue;
        }
        let Some(mut state) = pod_states.get_mut(&pod_uid) else {
            PENDING_CAPTURE_FAILURES.remove(&failure_key);
            debug!(
                pod_uid,
                "Cleared pending node probe-port update because the pod is no longer tracked"
            );
            continue;
        };

        let previous_ports = state.node_probe_ports.clone();
        let mut desired_state = state.clone();
        desired_state.node_probe_ports = desired_ports.clone();
        match apply_node_probe_ports_collecting(backend, &pod_uid, &desired_state) {
            Ok(_) => {
                state.node_probe_ports = desired_ports.clone();
                let stale_ports: Vec<u16> = previous_ports
                    .iter()
                    .copied()
                    .filter(|port| !desired_ports.contains(port))
                    .collect();
                let pod_ip = state.pod_ip;
                let pod_ip6 = state.pod_ip6;
                drop(state);

                PENDING_CAPTURE_FAILURES.remove(&failure_key);
                if let Some(ip) = pod_ip {
                    remove_node_probe_ports_for_ip(
                        backend,
                        pod_states,
                        metrics,
                        &pod_uid,
                        std::net::IpAddr::V4(ip),
                        &stale_ports,
                        "probe ports update retry",
                    );
                }
                if let Some(ip) = pod_ip6 {
                    remove_node_probe_ports_for_ip(
                        backend,
                        pod_states,
                        metrics,
                        &pod_uid,
                        std::net::IpAddr::V6(ip),
                        &stale_ports,
                        "probe ports update retry",
                    );
                }
                forget_pending_node_probe_port_update_failures_for_state(&pod_state_key(
                    pod_states, &pod_uid,
                ));
                debug!(
                    pod_uid,
                    ?desired_ports,
                    "Recovered pending node probe-port map update failure"
                );
            }
            Err(e) => {
                for port in e.applied_ports {
                    remember_applied_node_probe_port(&mut state.node_probe_ports, port);
                }
                warn!(
                    pod_uid,
                    error = %e.message,
                    "Retrying pending node probe-port map update failed; keeping capture state degraded"
                );
            }
        }
    }

    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

fn retry_pending_node_probe_port_removals(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
) {
    let pending = pending_node_probe_port_removal_failures(pod_states);
    if pending.is_empty() {
        return;
    }

    for (failure_key, state_key, pod_uid, ip, port) in pending {
        if let Some(owner_pod_uid) = pod_owning_probe_port_addr(pod_states, ip, port) {
            PENDING_CAPTURE_FAILURES.remove(&failure_key);
            debug!(
                owner_pod_uid,
                %ip,
                port,
                "Cleared pending node probe-port removal because another tracked pod owns the key"
            );
            complete_removed_udp_close_handoff(pod_states, config, &state_key, &pod_uid);
            continue;
        }

        let result = match ip {
            std::net::IpAddr::V4(ip) => backend.remove_node_probe_port(ip, port),
            std::net::IpAddr::V6(ip) => backend.remove_node_probe_port6(ip, port),
        };
        match result {
            Ok(()) => {
                PENDING_CAPTURE_FAILURES.remove(&failure_key);
                debug!(%ip, port, "Recovered pending node probe-port map removal failure");
                complete_removed_udp_close_handoff(pod_states, config, &state_key, &pod_uid);
            }
            Err(e) => {
                warn!(
                    %ip,
                    port,
                    error = %e,
                    "Retrying pending node probe-port map removal failed; keeping capture state degraded"
                );
            }
        }
    }

    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

fn retry_pending_cgroup_map_removals(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
) {
    for operation in [
        CAPTURE_FAILURE_INCLUDE_PORTS_REMOVE,
        CAPTURE_FAILURE_WORKLOAD_IDENTITY_REMOVE,
    ] {
        for (failure_key, state_key, pod_uid, cgroup_id) in
            pending_cgroup_map_removal_failures(pod_states, operation)
        {
            let live_owner = pod_states.iter().find_map(|entry| {
                let owns_key = if operation == CAPTURE_FAILURE_INCLUDE_PORTS_REMOVE {
                    entry.value().include_ports_cgroup_ids.contains(&cgroup_id)
                } else {
                    entry
                        .value()
                        .workload_identity_cgroup_ids
                        .contains(&cgroup_id)
                };
                owns_key.then(|| entry.key().clone())
            });
            if let Some(owner_pod_uid) = live_owner {
                PENDING_CAPTURE_FAILURES.remove(&failure_key);
                debug!(
                    pod_uid,
                    owner_pod_uid,
                    cgroup_id,
                    operation,
                    "Cleared stale cgroup map removal because a tracked pod owns the key"
                );
                complete_removed_udp_close_handoff(pod_states, config, &state_key, &pod_uid);
                continue;
            }
            let result = if operation == CAPTURE_FAILURE_INCLUDE_PORTS_REMOVE {
                backend.remove_pod_include_ports(cgroup_id)
            } else {
                backend.remove_workload_identity(cgroup_id)
            };
            match result {
                Ok(()) => {
                    PENDING_CAPTURE_FAILURES.remove(&failure_key);
                    debug!(
                        pod_uid,
                        cgroup_id, operation, "Recovered pending cgroup map removal failure"
                    );
                    complete_removed_udp_close_handoff(pod_states, config, &state_key, &pod_uid);
                }
                Err(e) => {
                    warn!(
                        pod_uid,
                        cgroup_id,
                        operation,
                        error = %e,
                        "Retrying pending cgroup map removal failed; keeping capture state degraded"
                    );
                }
            }
        }
    }

    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

fn retry_pending_pod_ip_removals(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
) {
    let pending = pending_pod_ip_removal_failures(pod_states);
    if pending.is_empty() {
        return;
    }

    for (failure_key, state_key, pod_uid, ip) in pending {
        if let Some(owner_pod_uid) = pod_owning_ip_addr(pod_states, ip) {
            PENDING_CAPTURE_FAILURES.remove(&failure_key);
            debug!(
                owner_pod_uid,
                %ip,
                "Cleared pending pod IP removal failure because another tracked pod owns the IP"
            );
            complete_removed_udp_close_handoff(pod_states, config, &state_key, &pod_uid);
            continue;
        }

        let result = match ip {
            std::net::IpAddr::V4(ip) => backend.remove_pod_ip(ip),
            std::net::IpAddr::V6(ip) => backend.remove_pod_ip6(ip),
        };
        match result {
            Ok(()) => {
                PENDING_CAPTURE_FAILURES.remove(&failure_key);
                debug!(%ip, "Recovered pending pod IP map removal failure");
                complete_removed_udp_close_handoff(pod_states, config, &state_key, &pod_uid);
            }
            Err(e) => {
                warn!(
                    %ip,
                    error = %e,
                    "Retrying pending pod IP map removal failed; keeping capture state degraded"
                );
            }
        }
    }

    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

fn retry_pending_pod_detaches(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
) {
    let pending = pending_pod_detach_failures(pod_states);
    if pending.is_empty() {
        return;
    }

    for (failure_key, state_key, pod_uid) in pending {
        // A same-UID pod that is live again may own newly-attached links. Do not
        // let a stale removal retry detach the current enrollment.
        if pod_states.contains_key(&pod_uid) {
            continue;
        }
        match backend.detach_pod(&pod_uid) {
            Ok(()) => {
                PENDING_CAPTURE_FAILURES.remove(&failure_key);
                debug!(pod_uid, "Recovered pending pod BPF detach failure");
                complete_removed_udp_close_handoff(pod_states, config, &state_key, &pod_uid);
            }
            Err(e) => {
                warn!(
                    pod_uid,
                    error = %e,
                    "Retrying pending pod BPF detach failed; keeping capture state degraded"
                );
            }
        }
    }

    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

/// Reject a `pod_uid` that could escape the registry directory. A pod UID is a
/// Kubernetes-assigned value; treating it as a path component without checks
/// would let an empty, slash-, backslash-, or `..`-bearing value write or
/// delete files outside `dir`. Returns `true` when the UID is unsafe to use as
/// a leaf filename.
fn pod_registry_uid_is_unsafe(pod_uid: &str) -> bool {
    pod_uid.is_empty() || pod_uid.contains('/') || pod_uid.contains('\\') || pod_uid.contains("..")
}

/// Best-effort publish of a single pod's registry entry: ensure `dir` exists,
/// then write `dir/<pod_uid>` containing `cgroup_path` on one line. The mesh
/// proxy's in-netns capture listeners poll this directory. Never panics and
/// never propagates: any I/O error (or an unsafe `pod_uid`) is logged at
/// `warn!` and swallowed so pod enrollment is never aborted by registry I/O.
fn publish_pod_registry(
    dir: &std::path::Path,
    pod_uid: &str,
    cgroup_path: &str,
    pod_source_ips: PodSourceIps,
    source_identity: Option<&crate::identity::SpiffeId>,
) {
    if pod_registry_uid_is_unsafe(pod_uid) {
        warn!(
            pod_uid,
            "Refusing to publish node-waypoint pod registry entry: pod UID is empty or contains \
             path separators / '..'"
        );
        return;
    }
    if let Err(e) = std::fs::create_dir_all(dir) {
        warn!(
            pod_uid,
            dir = %dir.display(),
            error = %e,
            "Failed to create node-waypoint pod registry directory"
        );
        return;
    }
    let path = dir.join(pod_uid);
    // Line 1: pod cgroup path. Optional keyed lines: same-family source pod IPs
    // the mesh proxy uses to override the loopback peer of in-netns capture
    // connections so authz/logs/IP-keyed plugins see the real pod IP.
    let mut contents = format!("{cgroup_path}\n");
    if let Some(identity) = source_identity {
        contents.push_str(&format!("spiffe_id={identity}\n"));
    }
    if let Some(ip) = pod_source_ips.ipv4 {
        contents.push_str(&format!("ipv4={ip}\n"));
    }
    if let Some(ip) = pod_source_ips.ipv6 {
        contents.push_str(&format!("ipv6={ip}\n"));
    }
    if let Err(e) = std::fs::write(&path, contents) {
        warn!(
            pod_uid,
            path = %path.display(),
            error = %e,
            "Failed to write node-waypoint pod registry entry"
        );
    }
}

/// Best-effort removal of a single pod's registry entry (`dir/<pod_uid>`).
/// A missing file is treated as success (the entry was never published or was
/// already cleaned up); any other I/O error (or an unsafe `pod_uid`) is logged
/// at `warn!` and swallowed.
fn remove_pod_registry(dir: &std::path::Path, pod_uid: &str) {
    if pod_registry_uid_is_unsafe(pod_uid) {
        warn!(
            pod_uid,
            "Refusing to remove node-waypoint pod registry entry: pod UID is empty or contains \
             path separators / '..'"
        );
        return;
    }
    let path = dir.join(pod_uid);
    if let Err(e) = std::fs::remove_file(&path)
        && e.kind() != std::io::ErrorKind::NotFound
    {
        warn!(
            pod_uid,
            path = %path.display(),
            error = %e,
            "Failed to remove node-waypoint pod registry entry"
        );
    }
}

/// Remove the mesh proxy's readiness markers on pod teardown. The proxy also
/// removes them when its in-netns listeners close, but doing it here too closes
/// the window where a same-UID re-enroll could observe stale readiness for the
/// torn-down listeners. Returns whether every marker is absent so enrollment
/// can fail closed; teardown callers may deliberately use it best-effort.
fn remove_pod_ready_marker(dir: &std::path::Path, pod_uid: &str) -> bool {
    if pod_registry_uid_is_unsafe(pod_uid) {
        return false;
    }
    let mut removed = true;
    for marker_dir in [
        ".ready",
        ".ready4",
        ".ready6",
        ".udp-ready",
        ".udp-not-ready",
    ] {
        let path = dir.join(marker_dir).join(pod_uid);
        if let Err(e) = std::fs::remove_file(&path)
            && e.kind() != std::io::ErrorKind::NotFound
        {
            removed = false;
            warn!(
                pod_uid,
                path = %path.display(),
                error = %e,
                "Failed to remove node-waypoint readiness marker"
            );
        }
    }
    removed
}

fn write_udp_not_ready_ack(dir: &std::path::Path, pod_uid: &str) {
    if pod_registry_uid_is_unsafe(pod_uid) {
        return;
    }
    let ack_dir = dir.join(".udp-not-ready");
    if let Err(error) = std::fs::create_dir_all(&ack_dir) {
        warn!(pod_uid, %error, "Failed to create Ambient UDP not-ready acknowledgement dir");
        return;
    }
    if let Err(error) = std::fs::write(ack_dir.join(pod_uid), b"") {
        warn!(pod_uid, %error, "Failed to publish Ambient UDP not-ready acknowledgement");
    }
}

fn remove_udp_not_ready_ack(dir: &std::path::Path, pod_uid: &str) {
    if pod_registry_uid_is_unsafe(pod_uid) {
        return;
    }
    if let Err(error) = std::fs::remove_file(dir.join(".udp-not-ready").join(pod_uid))
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(pod_uid, %error, "Failed to remove Ambient UDP not-ready acknowledgement");
    }
}

/// Remove a live pod's `.udp-ack-required` marker only once it is old enough
/// to be restart residue. The producer's close handshake persists the request
/// BEFORE retracting `.udp-ready` (separate process), so a reconcile tick can
/// observe (ready, request present) mid-close; deleting that fresh request
/// would forfeit the durable restart-recovery insurance if the node-agent
/// crashed before acking and the pod was removed during the outage. Residue
/// left by a node-agent restart is by definition older than the orphan grace.
fn remove_udp_ack_requirement_older_than(
    dir: &std::path::Path,
    pod_uid: &str,
    min_age: std::time::Duration,
) {
    if pod_registry_uid_is_unsafe(pod_uid) {
        return;
    }
    let path = dir.join(".udp-ack-required").join(pod_uid);
    let old_enough = std::fs::metadata(&path)
        .and_then(|metadata| metadata.modified())
        .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
        .is_ok_and(|age| age >= min_age);
    if !old_enough {
        return;
    }
    if let Err(error) = std::fs::remove_file(&path)
        && error.kind() != std::io::ErrorKind::NotFound
    {
        warn!(pod_uid, %error, "Failed to remove stale Ambient UDP close request");
    }
}

fn udp_gate_cleaned_proof_path(dir: &std::path::Path, pod_uid: &str) -> Option<std::path::PathBuf> {
    (!pod_registry_uid_is_unsafe(pod_uid)).then(|| dir.join(".udp-gate-cleaned").join(pod_uid))
}

/// Persist node-agent-owned evidence that pod removal completed both classifier
/// detach and pod-IP map cleanup. The close-ack responder accepts an absent UID
/// only with this proof; `.udp-ack-required` alone is proxy-authored and is not
/// evidence that the host gate is closed.
fn write_udp_gate_cleaned_proof(dir: &std::path::Path, pod_uid: &str) -> bool {
    let Some(path) = udp_gate_cleaned_proof_path(dir, pod_uid) else {
        return false;
    };
    let Some(proof_dir) = path.parent() else {
        return false;
    };
    if let Err(error) = std::fs::create_dir_all(proof_dir) {
        warn!(pod_uid, %error, "Failed to create Ambient UDP cleaned-gate proof dir");
        return false;
    }
    if let Err(error) = std::fs::write(&path, b"") {
        warn!(pod_uid, path = %path.display(), %error, "Failed to persist Ambient UDP cleaned-gate proof");
        return false;
    }
    true
}

fn remove_udp_gate_cleaned_proof(dir: &std::path::Path, pod_uid: &str) -> bool {
    let Some(path) = udp_gate_cleaned_proof_path(dir, pod_uid) else {
        return false;
    };
    match std::fs::remove_file(&path) {
        Ok(()) => true,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => true,
        Err(error) => {
            warn!(pod_uid, path = %path.display(), %error, "Failed to remove Ambient UDP cleaned-gate proof");
            false
        }
    }
}

fn has_pending_removal_blocking_failure(state_key: &str) -> bool {
    PENDING_CAPTURE_FAILURES.iter().any(|entry| {
        parse_pending_capture_failure_key(entry.key()).is_some_and(|failure| {
            failure.state_key == state_key
                && (failure.operation == CAPTURE_FAILURE_POD_IP_REMOVE
                    || failure.operation == CAPTURE_FAILURE_POD_DETACH
                    || failure.operation == CAPTURE_FAILURE_NODE_PROBE_PORT_REMOVE
                    || failure.operation == CAPTURE_FAILURE_INCLUDE_PORTS_REMOVE
                    || failure.operation == CAPTURE_FAILURE_WORKLOAD_IDENTITY_REMOVE)
        })
    })
}

/// Complete a removed pod's durable UDP close handoff after all removal-blocking
/// cleanup retries succeed. Live-pod retries must never mint removal proof, and
/// detach plus every recorded partial map entry must all recover first.
fn complete_removed_udp_close_handoff(
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    state_key: &str,
    pod_uid: &str,
) {
    if !udp_readiness_reconcile_enabled(config)
        || pod_states.contains_key(pod_uid)
        || has_failed_pod_enrollment_attempt(state_key)
        || has_pending_removal_blocking_failure(state_key)
    {
        return;
    }
    let Some(dir) = &config.node_waypoint_pod_registry_dir else {
        return;
    };
    if write_udp_gate_cleaned_proof(dir, pod_uid) {
        write_udp_not_ready_ack(dir, pod_uid);
    } else {
        warn!(
            pod_uid,
            "Withholding Ambient UDP not-ready acknowledgement because durable cleaned-gate proof could not be persisted after removal cleanup retry"
        );
    }
}

/// Answer durable producer close requests for pods that have already left
/// `pod_states`. A node-agent restart loses the in-memory removal result, so the
/// node-agent-owned cleaned-gate proof is the authority. Initial pod sync must
/// complete first: until then an absent UID may simply not have been relisted.
fn reconcile_removed_udp_close_acknowledgements(
    dir: &std::path::Path,
    pod_states: &DashMap<String, PodAttachmentState>,
    initial_pod_sync_complete: bool,
) {
    if !initial_pod_sync_complete {
        return;
    }
    const MAX_ACKS_PER_PASS: usize = 256;
    let required_dir = dir.join(".udp-ack-required");
    let entries = match std::fs::read_dir(&required_dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return,
        Err(error) => {
            warn!(path = %required_dir.display(), %error, "Failed to scan Ambient UDP close requests");
            return;
        }
    };
    let mut answered = 0usize;
    for entry in entries.flatten() {
        if answered >= MAX_ACKS_PER_PASS {
            break;
        }
        let Ok(uid) = entry.file_name().into_string() else {
            continue;
        };
        if pod_registry_uid_is_unsafe(&uid) || pod_states.contains_key(&uid) {
            continue;
        }
        let state_key = pod_state_key(pod_states, &uid);
        // Failed enrollments are live pods even though they have no
        // `pod_states` entry. A stale proof surviving re-enrollment cleanup
        // must not authorize their producer to drop its fail-closed guard.
        // Genuine removal consumes that record before cleanup retries finish,
        // so pending removal failures must independently keep the responder
        // closed until a retry mints fresh proof and acknowledgement.
        if has_failed_pod_enrollment_attempt(&state_key)
            || has_pending_removal_blocking_failure(&state_key)
        {
            continue;
        }
        if dir.join(".udp-not-ready").join(&uid).is_file() {
            continue;
        }
        let gate_cleaned =
            udp_gate_cleaned_proof_path(dir, &uid).is_some_and(|path| path.is_file());
        if !gate_cleaned {
            debug!(
                pod_uid = uid.as_str(),
                "Withholding Ambient UDP close acknowledgement for unknown pod without verified cleaned-gate proof"
            );
            continue;
        }
        write_udp_not_ready_ack(dir, &uid);
        answered += 1;
    }
}

/// Reap orphaned UDP handshake markers whose pod is no longer tracked.
///
/// Kubernetes pod UIDs are unique per pod lifetime, so an enroll→remove cycle
/// writes `.udp-not-ready/<uid>`, while a producer whose stop acknowledgement
/// times out can leave `.udp-ack-required/<uid>` after the registry entry is
/// gone. Left unswept these files accumulate one inode per pod ever seen on the
/// node. The grace below gives the proxy time to consume a late acknowledgement;
/// after that, inactive marker sets are safe to remove. A verified handoff with
/// an outstanding ack requirement gets a wider, bounded restart/consumption
/// window before it is also considered orphaned.
/// The scan is bounded per directory per call so a large backlog drains over
/// several reconcile ticks.
fn reap_orphaned_udp_not_ready_acks(
    dir: &std::path::Path,
    pod_states: &DashMap<String, PodAttachmentState>,
    initial_pod_sync_complete: bool,
) {
    // The proxy polls the registry every ~2s. Keep a much wider grace so a
    // freshly-published pod-removal ack cannot be reaped before the producer
    // observes the registry removal and consumes it.
    let minimum_age = UDP_HANDSHAKE_ORPHAN_GRACE;
    // Drain verified handshakes proof+request first. The proof pass refreshes
    // an extant ack once at the TTL boundary, preserving the ordinary grace
    // for producer consumption without rewriting it on every reconcile tick.
    for marker_dir in [".udp-gate-cleaned", ".udp-ack-required", ".udp-not-ready"] {
        reap_orphaned_udp_handshake_markers_older_than(
            dir,
            marker_dir,
            pod_states,
            initial_pod_sync_complete,
            minimum_age,
        );
    }
}

fn reap_orphaned_udp_handshake_markers_older_than(
    dir: &std::path::Path,
    marker_dir: &str,
    pod_states: &DashMap<String, PodAttachmentState>,
    initial_pod_sync_complete: bool,
    minimum_age: std::time::Duration,
) {
    // Until the initial watcher relist completes, absence from `pod_states` is
    // unknown rather than orphaned. Preserve both sides of the durable handoff
    // so a restart cannot drop the producer guard before the node-agent has
    // re-established authoritative pod state and emitted a fresh close ack.
    if !initial_pod_sync_complete {
        return;
    }
    const MAX_REAP_PER_PASS: usize = 256;
    let ack_dir = dir.join(marker_dir);
    let entries = match std::fs::read_dir(&ack_dir) {
        Ok(entries) => entries,
        Err(error) => {
            if error.kind() != std::io::ErrorKind::NotFound {
                warn!(
                    path = %ack_dir.display(),
                    marker_dir,
                    %error,
                    "Failed to scan Ambient UDP handshake dir for orphan cleanup"
                );
            }
            return;
        }
    };
    let mut reaped = 0usize;
    for entry in entries.flatten() {
        if reaped >= MAX_REAP_PER_PASS {
            break;
        }
        let Ok(uid) = entry.file_name().into_string() else {
            continue;
        };
        if pod_registry_uid_is_unsafe(&uid) || pod_states.contains_key(&uid) {
            continue;
        }
        let ack_required = dir.join(".udp-ack-required").join(&uid).is_file();
        let gate_cleaned =
            udp_gate_cleaned_proof_path(dir, &uid).is_some_and(|path| path.is_file());
        // Only a VERIFIED durable handoff — a producer `.udp-ack-required`
        // request paired with the node-agent-owned `.udp-gate-cleaned` proof —
        // gets the wider retention window. That lets restart recovery publish
        // and preserve an ack long enough for a producer to consume it, while
        // eventually reaping all three records when the producer died after an
        // ack timeout. An `.udp-ack-required` request WITHOUT proof is
        // unverified: it is not evidence the host gate closed, so it must NOT
        // preserve its companion `.udp-not-ready` ack beyond the ordinary
        // orphan grace. Reaping remains fail-closed: a late producer must write
        // a fresh request and retain its guard if no cleanup proof remains.
        let verified_handshake = ack_required && gate_cleaned;
        let retention = if verified_handshake {
            minimum_age.saturating_mul(VERIFIED_UDP_HANDSHAKE_RETENTION_MULTIPLIER)
        } else {
            minimum_age
        };
        let old_enough = entry
            .metadata()
            .and_then(|metadata| metadata.modified())
            .and_then(|modified| modified.elapsed().map_err(std::io::Error::other))
            .is_ok_and(|age| age >= retention);
        if !old_enough {
            continue;
        }
        if verified_handshake && matches!(marker_dir, ".udp-gate-cleaned" | ".udp-ack-required") {
            let ack_path = dir.join(".udp-not-ready").join(&uid);
            if ack_path.is_file()
                && let Err(error) = std::fs::write(&ack_path, b"")
            {
                warn!(
                    pod_uid = uid.as_str(),
                    path = %ack_path.display(),
                    %error,
                    "Failed to refresh Ambient UDP acknowledgement for TTL drain"
                );
                continue;
            }
        }
        if let Err(error) = std::fs::remove_file(entry.path())
            && error.kind() != std::io::ErrorKind::NotFound
        {
            warn!(
                pod_uid = uid.as_str(),
                marker_dir,
                %error,
                "Failed to reap orphaned Ambient UDP handshake marker"
            );
            continue;
        }
        reaped += 1;
    }
}

fn udp_ready_marker_exists(config: &NodeAgentConfig, pod_uid: &str) -> bool {
    config
        .node_waypoint_pod_registry_dir
        .as_ref()
        .filter(|_| !pod_registry_uid_is_unsafe(pod_uid))
        .is_some_and(|dir| dir.join(".udp-ready").join(pod_uid).is_file())
}

fn pod_map_info(config: &NodeAgentConfig, udp_ready: bool) -> PodInfo {
    PodInfo::for_capture(
        config.capture_config.outbound_port,
        config.capture_config.udp_capture_enabled,
        udp_ready,
    )
}

fn udp_readiness_reconcile_enabled(config: &NodeAgentConfig) -> bool {
    config.capture_config.udp_capture_enabled
        || (config.node_waypoint_pod_registry_dir.is_some()
            && config.capture_contract.proxy_mode == NodeAgentProxyMode::LocalPod)
}

/// Open or close the host-veth enrollment guard from producer readiness
/// markers. New pod map entries are always installed with `udp_ready=false`;
/// only the producer's post-guard/post-bind marker can transition them open.
fn reconcile_udp_capture_readiness_with_sync_state(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    ready_uids: &mut HashSet<String>,
    initial_pod_sync_complete: bool,
) {
    if !config.capture_config.udp_capture_enabled {
        // Disabled is an intentional pass-through posture, but the stale-rule
        // cleanup manager still needs a freshly-derived acknowledgement before
        // it removes rules left by an enabled predecessor. For tracked pods,
        // re-apply the disabled pod-map flags once per live process generation;
        // for removed pods, `handle_pod_removed` persists equivalent evidence
        // only after detach and pod-IP cleanup succeed. Never treat a
        // proxy-authored request or a persisted ack alone as cleanup evidence.
        ready_uids.retain(|uid| pod_states.contains_key(uid));
        for state in pod_states.iter() {
            if !state.attached {
                continue;
            }
            let uid = state.key();
            let ack_exists = config
                .node_waypoint_pod_registry_dir
                .as_ref()
                .is_some_and(|dir| dir.join(".udp-not-ready").join(uid).is_file());
            if ready_uids.contains(uid) && ack_exists {
                continue;
            }
            let state_key = pod_state_key(pod_states, uid);
            if let Some(dir) = &config.node_waypoint_pod_registry_dir {
                remove_udp_not_ready_ack(dir, uid);
            }
            let info = pod_map_info(config, false);
            let v4_ok = state
                .pod_ip
                .is_none_or(|ip| backend.update_pod_ip(ip, &info).is_ok());
            let v6_ok = state
                .pod_ip6
                .is_none_or(|ip| backend.update_pod_ip6(ip, &info).is_ok());
            if v4_ok && v6_ok {
                forget_pending_capture_failure(
                    &state_key,
                    CAPTURE_FAILURE_UDP_READINESS,
                    CAPTURE_FAILURE_DETAIL_UDP_READINESS,
                );
                ready_uids.insert(uid.clone());
                if let Some(dir) = &config.node_waypoint_pod_registry_dir {
                    write_udp_not_ready_ack(dir, uid);
                }
            } else {
                metrics.record_attach_error();
                remember_pending_capture_failure(
                    &state_key,
                    CAPTURE_FAILURE_UDP_READINESS,
                    CAPTURE_FAILURE_DETAIL_UDP_READINESS,
                );
                warn!(
                    pod_uid = uid.as_str(),
                    "Failed to verify disabled Ambient UDP pod-map posture; withholding cleanup acknowledgement and retrying"
                );
            }
        }
        if let Some(dir) = &config.node_waypoint_pod_registry_dir {
            reconcile_removed_udp_close_acknowledgements(
                dir,
                pod_states,
                initial_pod_sync_complete,
            );
            reap_orphaned_udp_not_ready_acks(dir, pod_states, initial_pod_sync_complete);
        }
        clear_partial_capture_state_if_recovered(pod_states, metrics);
        return;
    }

    ready_uids.retain(|uid| pod_states.contains_key(uid));
    for state in pod_states.iter() {
        if !state.attached {
            continue;
        }
        let uid = state.key();
        // Pending-failure keys are namespaced by the `pod_states` map pointer
        // (see `pod_state_key`) so `has_pending_capture_failures` — which scans by
        // that prefix — and `handle_pod_removed`'s cleanup both find them. Using
        // the bare uid here would store an unmatched key that never gates
        // `clear_partial_capture_state_if_recovered`.
        let state_key = pod_state_key(pod_states, uid);
        let ready = udp_ready_marker_exists(config, uid);
        let not_ready_ack_exists = config
            .node_waypoint_pod_registry_dir
            .as_ref()
            .is_some_and(|dir| dir.join(".udp-not-ready").join(uid).is_file());
        // Stable ready state requires the mutually-exclusive marker posture:
        // ready => no close ack, not-ready => close ack present. If removal of a
        // stale ack failed transiently, keep reconciling until it is gone rather
        // than letting producer teardown trust it while the BPF gate is open.
        if ready_uids.contains(uid) == ready && not_ready_ack_exists != ready {
            if ready && let Some(dir) = &config.node_waypoint_pod_registry_dir {
                remove_udp_ack_requirement_older_than(dir, uid, UDP_HANDSHAKE_ORPHAN_GRACE);
            }
            continue;
        }
        if ready {
            // Invalidate the closed-state acknowledgement BEFORE either family
            // can be opened. A partial v4/v6 update must never leave a stale ack
            // that would authorize producer teardown while one family is ready.
            if let Some(dir) = &config.node_waypoint_pod_registry_dir {
                remove_udp_not_ready_ack(dir, uid);
            }
        }
        let info = pod_map_info(config, ready);
        let v4_ok = state
            .pod_ip
            .is_none_or(|ip| backend.update_pod_ip(ip, &info).is_ok());
        let v6_ok = state
            .pod_ip6
            .is_none_or(|ip| backend.update_pod_ip6(ip, &info).is_ok());
        if v4_ok && v6_ok {
            forget_pending_capture_failure(
                &state_key,
                CAPTURE_FAILURE_UDP_READINESS,
                CAPTURE_FAILURE_DETAIL_UDP_READINESS,
            );
            if ready {
                ready_uids.insert(uid.clone());
                if let Some(dir) = &config.node_waypoint_pod_registry_dir {
                    remove_udp_not_ready_ack(dir, uid);
                    remove_udp_ack_requirement_older_than(dir, uid, UDP_HANDSHAKE_ORPHAN_GRACE);
                }
            } else {
                ready_uids.remove(uid);
                if let Some(dir) = &config.node_waypoint_pod_registry_dir {
                    write_udp_not_ready_ack(dir, uid);
                }
            }
            debug!(
                pod_uid = uid.as_str(),
                udp_ready = ready,
                "Reconciled Ambient UDP producer readiness guard"
            );
        } else {
            metrics.record_attach_error();
            remember_pending_capture_failure(
                &state_key,
                CAPTURE_FAILURE_UDP_READINESS,
                CAPTURE_FAILURE_DETAIL_UDP_READINESS,
            );
            warn!(
                pod_uid = uid.as_str(),
                udp_ready = ready,
                "Failed to reconcile Ambient UDP producer readiness guard; will retry"
            );
        }
    }
    // Bounded sweep of not-ready acks for pods that have fully left the node so
    // the `.udp-not-ready/` dir does not grow one inode per pod ever enrolled.
    if let Some(dir) = &config.node_waypoint_pod_registry_dir {
        reconcile_removed_udp_close_acknowledgements(dir, pod_states, initial_pod_sync_complete);
        reap_orphaned_udp_not_ready_acks(dir, pod_states, initial_pod_sync_complete);
    }
    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

#[cfg(test)]
fn reconcile_udp_capture_readiness(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    ready_uids: &mut HashSet<String>,
) {
    reconcile_udp_capture_readiness_with_sync_state(
        backend, pod_states, config, metrics, ready_uids, true,
    );
}

fn handle_pod_added(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    event: &PodEvent<'_>,
) {
    handle_pod_added_inner(backend, pod_states, config, metrics, event, false);
}

fn handle_pod_added_after_backoff(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    event: &PodEvent<'_>,
) {
    handle_pod_added_inner(backend, pod_states, config, metrics, event, true);
}

fn handle_pod_added_inner(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    event: &PodEvent<'_>,
    bypass_retry_backoff: bool,
) {
    let (pod_uid, pod_name, namespace) = (event.pod_uid, event.pod_name, event.namespace);
    let state_key = pod_state_key(pod_states, pod_uid);
    // Capture cleanup evidence before any elapsed/forced backoff replay forgets
    // the old attempt. Every failure below must carry it forward: a pre-BPF
    // failure preserves it unchanged, while a later BPF failure unions the
    // exact cgroup keys from both attempts. Genuine removal is the only path
    // allowed to consume this evidence without a successful enrollment.
    let prior_cleanup_state = FAILED_POD_ENROLLMENT_ATTEMPTS
        .get(&state_key)
        .and_then(|attempt| attempt.cleanup_state.clone());
    let decision = pod_watcher::evaluate_enrollment(
        event.labels,
        event.annotations,
        namespace,
        &config.excluded_namespaces,
    );
    if decision != EnrollmentDecision::Enroll {
        // Leaving the mesh is a removal transition even while the pod/netns is
        // still live. Route tracked and failed-untracked enrollments through
        // the same evidence-based cleanup and durable close handoff.
        handle_pod_removed(backend, pod_states, config, metrics, pod_uid);
        debug!(
            pod_uid,
            pod_name, namespace, "Pod does not meet enrollment criteria"
        );
        return;
    }

    let pod_ip = event
        .pod_ip_str
        .and_then(pod_watcher::parse_pod_ip)
        .or(event.pod_source_ips.ipv4);
    let pod_ip6 = event.pod_source_ips.ipv6;
    let cgroup_path = cgroup::resolve_pod_cgroup_path(&config.cgroup_root, pod_uid)
        .map(|p| p.to_string_lossy().to_string());
    // Production: the kube-rs caller sets `veth_iface_override = None`; the
    // resolver first uses an explicit pod PID when available, then falls back
    // to the resolved pod cgroup to find a live process in that pod. Some
    // container runtimes expose neither pod sysfs nor setns from the node-agent
    // container, so use the host route table as a final pod-IP-scoped fallback.
    // Tests supply a synthetic name so the post-65606d87 inbound-tc invariant
    // is satisfied without a real pod PID / Linux kernel.
    let veth_iface = event
        .veth_iface_override
        .map(|s| s.to_string())
        .or_else(|| veth::discover_veth_for_pod(event.pod_pid, cgroup_path.as_deref()))
        .or_else(|| pod_ip.and_then(veth::discover_veth_for_pod_ip));

    if let Some(mut state) = pod_states.get_mut(pod_uid) {
        let attachment_target_changed = state.cgroup_path != cgroup_path
            || veth_iface
                .as_ref()
                .is_some_and(|iface| state.veth_iface.as_ref() != Some(iface));
        if attachment_target_changed {
            drop(state);
            handle_pod_removed(backend, pod_states, config, metrics, pod_uid);
        } else {
            let previous_node_probe_ports = state.node_probe_ports.clone();
            let pod_ip_reconcile = reconcile_existing_pod_ip(
                backend, config, metrics, &state_key, pod_uid, pod_ip, &mut state,
            );
            let pod_ip6_reconcile = reconcile_existing_pod_ip6(
                backend, config, metrics, &state_key, pod_uid, pod_ip6, &mut state,
            );
            reconcile_existing_pod_include_ports(
                backend,
                metrics,
                pod_uid,
                event.annotations,
                &mut state,
            );
            reconcile_existing_pod_workload_identity(
                backend,
                config,
                pod_uid,
                namespace,
                event.service_account,
                &mut state,
            );
            let node_probe_reconcile = reconcile_existing_node_probe_ports(
                backend,
                metrics,
                &state_key,
                pod_uid,
                &event.node_probe_ports,
                &mut state,
            );
            if !pod_ip_reconcile.pod_ip_update_failed
                && !pod_ip6_reconcile.pod_ip_update_failed
                && let (Some(dir), Some(cgroup)) = (
                    &config.node_waypoint_pod_registry_dir,
                    state.cgroup_path.as_deref(),
                )
            {
                let source_identity = build_workload_spiffe_id(
                    namespace,
                    event.service_account.unwrap_or("default"),
                    &config.trust_domain,
                );
                publish_pod_registry(
                    dir,
                    pod_uid,
                    cgroup,
                    event.pod_source_ips,
                    source_identity.as_ref(),
                );
            }
            let current_pod_ip = state.pod_ip;
            let current_pod_ip6 = state.pod_ip6;
            let stale_node_probe_ports = node_probe_reconcile.stale_probe_ports.clone();
            debug!(pod_uid, pod_name, "Pod already enrolled, reconciled state");
            drop(state);
            if pod_ip_reconcile.recovered_pending_failure
                || pod_ip6_reconcile.recovered_pending_failure
                || node_probe_reconcile.recovered_pending_failure
            {
                clear_partial_capture_state_if_recovered(pod_states, metrics);
            }
            if let Some(ip) = pod_ip_reconcile.stale_pod_ip {
                remove_node_probe_ports_for_ip(
                    backend,
                    pod_states,
                    metrics,
                    pod_uid,
                    std::net::IpAddr::V4(ip),
                    &previous_node_probe_ports,
                    "pod IP changed",
                );
                remove_pod_ip_if_unowned(
                    backend,
                    pod_states,
                    metrics,
                    pod_uid,
                    ip,
                    "pod IP changed",
                );
            }
            if let Some(ip) = pod_ip6_reconcile.stale_pod_ip {
                remove_node_probe_ports_for_ip(
                    backend,
                    pod_states,
                    metrics,
                    pod_uid,
                    std::net::IpAddr::V6(ip),
                    &previous_node_probe_ports,
                    "pod IPv6 changed",
                );
                remove_pod_ip6_if_unowned(
                    backend,
                    pod_states,
                    metrics,
                    pod_uid,
                    ip,
                    "pod IPv6 changed",
                );
            }
            if !stale_node_probe_ports.is_empty() {
                if let Some(ip) = current_pod_ip {
                    remove_node_probe_ports_for_ip(
                        backend,
                        pod_states,
                        metrics,
                        pod_uid,
                        std::net::IpAddr::V4(ip),
                        &stale_node_probe_ports,
                        "probe ports changed",
                    );
                }
                if let Some(ip) = current_pod_ip6 {
                    remove_node_probe_ports_for_ip(
                        backend,
                        pod_states,
                        metrics,
                        pod_uid,
                        std::net::IpAddr::V6(ip),
                        &stale_node_probe_ports,
                        "probe ports changed",
                    );
                }
            }
            return;
        }
    }

    let attempt_signature =
        pod_enrollment_attempt_signature(event, pod_ip, &cgroup_path, &veth_iface);
    if !bypass_retry_backoff && recently_failed_pod_enrollment(&state_key, &attempt_signature) {
        debug!(
            pod_uid,
            pod_name, namespace, "Skipping repeated pod enrollment attempt during retry backoff"
        );
        return;
    }
    if bypass_retry_backoff {
        forget_failed_pod_enrollment(&state_key);
    }

    // Owned event snapshot stored alongside the failed-enrollment record so the
    // periodic retry loop in `run_with_backend` can re-drive this enrollment
    // once the backoff window expires, even if no further pod/CNI event arrives
    // for this pod. Cheap to build but only needed on the cold failure paths
    // below, so each `remember_failed_pod_enrollment` call clones it.
    let enrollment_snapshot = RetryablePodEnrollment::from_event(event);

    if config.capture_config.udp_capture_enabled && pod_ip.is_none() && pod_ip6.is_none() {
        warn!(
            pod_uid,
            pod_name,
            namespace,
            "Ambient UDP enrollment has no pod source IP yet; deferring until the readiness guard can be keyed"
        );
        metrics.record_attach_error();
        remember_failed_pod_enrollment_preserving_cleanup(
            &state_key,
            attempt_signature,
            enrollment_snapshot,
            prior_cleanup_state.as_ref(),
        );
        return;
    }

    let mut state = PodAttachmentState {
        pod_uid: pod_uid.to_string(),
        pod_name: pod_name.to_string(),
        namespace: namespace.to_string(),
        pod_ip,
        pod_ip6,
        cgroup_path: cgroup_path.clone(),
        veth_iface: veth_iface.clone(),
        attached: false,
        include_ports_cgroup_ids: Vec::new(),
        include_ports_policy: None,
        workload_identity_cgroup_ids: Vec::new(),
        node_probe_ports: event.node_probe_ports.clone(),
    };

    // A same-UID sandbox replacement must never inherit the old producer's
    // readiness. Close the BPF UDP gate before publishing the new registry
    // entry; the producer will publish a fresh marker only after its guard and
    // TPROXY socket/rules are live.
    if udp_readiness_reconcile_enabled(config)
        && let Some(dir) = &config.node_waypoint_pod_registry_dir
    {
        if !remove_pod_ready_marker(dir, pod_uid) {
            metrics.record_attach_error();
            remember_failed_pod_enrollment_preserving_cleanup(
                &state_key,
                attempt_signature,
                enrollment_snapshot,
                prior_cleanup_state.as_ref(),
            );
            return;
        }
        // A live pod can leave and later re-enter mesh enrollment with the same
        // Kubernetes UID. It must not inherit the prior removal's durable proof,
        // which would let an old proxy request authorize teardown after this
        // enrollment opens the host gate again.
        if !remove_udp_gate_cleaned_proof(dir, pod_uid) {
            metrics.record_attach_error();
            remember_failed_pod_enrollment_preserving_cleanup(
                &state_key,
                attempt_signature,
                enrollment_snapshot,
                prior_cleanup_state.as_ref(),
            );
            return;
        }
    }

    if let Some(ref cgroup) = cgroup_path {
        // Seed per-cgroup policy maps before connect hooks can run. Otherwise
        // the first connection from an annotated pod can observe missing
        // `includeOutboundPorts` policy and fall back to the node-wide capture
        // shape before the enrollment path writes the pod-specific map entry.
        if let Some(applied) =
            apply_include_outbound_ports(backend, pod_uid, cgroup, event.annotations)
        {
            state.include_ports_cgroup_ids = applied.cgroup_ids;
            state.include_ports_policy = Some(applied.policy);
        }
        state.workload_identity_cgroup_ids = apply_workload_identity(
            backend,
            config,
            pod_uid,
            namespace,
            event.service_account,
            cgroup,
        );

        // Attach cgroup programs before marking the pod enrolled. When outbound
        // capture is disabled (FERRUM_MESH_OUTBOUND_LISTEN_ADDR port 0), the
        // connect hooks are intentionally omitted and egress flows normally.
        // Otherwise attach both connect hooks up front, including NodeWaypoint
        // in-netns mode: delaying them until the mesh proxy listener is ready
        // would leave a startup window where egress bypasses mesh_authz entirely.
        // Attaching immediately is fail-closed until the proxy opens the
        // pod-loopback listener (connects may be refused, but they cannot bypass
        // policy).
        let outbound_enabled = config.capture_config.outbound_capture_enabled;
        let programs: &[&str] = if !outbound_enabled {
            &["ferrum_getpeername4", "ferrum_getpeername6"]
        } else {
            &[
                "ferrum_connect4",
                "ferrum_connect6",
                "ferrum_getpeername4",
                "ferrum_getpeername6",
            ]
        };
        let mut attach_ok = true;
        for prog in programs {
            if let Err(e) = backend.attach_cgroup(pod_uid, cgroup, prog) {
                warn!(pod_uid, program = prog, error = %e, "Failed to attach cgroup program");
                metrics.record_attach_error();
                attach_ok = false;
                break;
            }
        }
        if attach_ok {
            // Seed the source-IP lifecycle flags BEFORE attaching tc. Once the
            // classifier is live its lookup therefore cannot miss and allow a
            // pre-producer UDP datagram through.
            if config.capture_config.udp_capture_enabled {
                let info = pod_map_info(config, false);
                if let Some(ip) = pod_ip
                    && let Err(e) = backend.update_pod_ip(ip, &info)
                {
                    warn!(pod_uid, %ip, error = %e, "Failed to arm UDP enrollment guard");
                    metrics.record_attach_error();
                    cleanup_partial_pod_enrollment(backend, pod_states, metrics, pod_uid, &state);
                    remember_failed_pod_enrollment_with_merged_cleanup_state(
                        &state_key,
                        attempt_signature,
                        enrollment_snapshot.clone(),
                        prior_cleanup_state.as_ref(),
                        &state,
                    );
                    return;
                }
                if let Some(ip) = pod_ip6
                    && let Err(e) = backend.update_pod_ip6(ip, &info)
                {
                    warn!(pod_uid, %ip, error = %e, "Failed to arm IPv6 UDP enrollment guard");
                    metrics.record_attach_error();
                    cleanup_partial_pod_enrollment(backend, pod_states, metrics, pod_uid, &state);
                    remember_failed_pod_enrollment_with_merged_cleanup_state(
                        &state_key,
                        attempt_signature,
                        enrollment_snapshot.clone(),
                        prior_cleanup_state.as_ref(),
                        &state,
                    );
                    return;
                }
            }
            let Some(ref iface) = veth_iface else {
                warn!(
                    pod_uid,
                    pod_name,
                    namespace,
                    "Could not resolve pod veth interface, skipping attachment"
                );
                metrics.record_attach_error();
                cleanup_partial_pod_enrollment(backend, pod_states, metrics, pod_uid, &state);
                remember_failed_pod_enrollment_with_merged_cleanup_state(
                    &state_key,
                    attempt_signature,
                    enrollment_snapshot.clone(),
                    prior_cleanup_state.as_ref(),
                    &state,
                );
                return;
            };

            for direction in [TcAttachDirection::Ingress, TcAttachDirection::Egress] {
                if let Err(e) = backend.attach_tc(pod_uid, iface, "ferrum_tc_inbound", direction) {
                    warn!(
                        pod_uid,
                        iface,
                        direction = direction.as_str(),
                        error = %e,
                        "Failed to attach tc program"
                    );
                    metrics.record_attach_error();
                    cleanup_partial_pod_enrollment(backend, pod_states, metrics, pod_uid, &state);
                    remember_failed_pod_enrollment_with_merged_cleanup_state(
                        &state_key,
                        attempt_signature,
                        enrollment_snapshot.clone(),
                        prior_cleanup_state.as_ref(),
                        &state,
                    );
                    return;
                }
            }
            // NodeWaypoint inbound relay dials this pod from a node-local source
            // address, so an enrolled pod whose address family has no trusted
            // node source IP would have its relay dial silently dropped by the
            // source-bound guard. Surface that per family so a dual-stack install
            // that configured only one family's source IP reports degraded rather
            // than black-holing the other family. (The all-empty case already
            // fails closed at startup in `initialize_backend`.)
            if config.capture_contract.proxy_mode == NodeAgentProxyMode::NodeWaypoint {
                if pod_ip.is_some() && !backend.has_node_source_ipv4() {
                    warn!(
                        pod_uid,
                        "NodeWaypoint enrolled an IPv4 pod but no trusted IPv4 node source IP is \
                         configured (FERRUM_NODE_AGENT_NODE_IP / FERRUM_NODE_AGENT_NODE_IPS); the \
                         inbound relay dial to this pod will be dropped until an IPv4 node source \
                         IP is added"
                    );
                    metrics.set_topology_degraded("node_waypoint_node_source_ipv4_missing");
                }
                if pod_ip6.is_some() && !backend.has_node_source_ipv6() {
                    warn!(
                        pod_uid,
                        "NodeWaypoint enrolled an IPv6 pod but no trusted IPv6 node source IP is \
                         configured (FERRUM_NODE_AGENT_NODE_IP / FERRUM_NODE_AGENT_NODE_IPS); the \
                         inbound relay dial to this pod will be dropped until an IPv6 node source \
                         IP is added"
                    );
                    metrics.set_topology_degraded("node_waypoint_node_source_ipv6_missing");
                }
            }
            if let Some(ip) = pod_ip {
                let info = pod_map_info(config, false);
                if let Err(e) = backend.update_pod_ip(ip, &info) {
                    warn!(pod_uid, %ip, error = %e, "Failed to update pod IP map");
                    metrics.record_attach_error();
                    cleanup_partial_pod_enrollment(backend, pod_states, metrics, pod_uid, &state);
                    remember_failed_pod_enrollment_with_merged_cleanup_state(
                        &state_key,
                        attempt_signature,
                        enrollment_snapshot.clone(),
                        prior_cleanup_state.as_ref(),
                        &state,
                    );
                    return;
                }
            }
            if let Some(ip) = pod_ip6 {
                let info = pod_map_info(config, false);
                if let Err(e) = backend.update_pod_ip6(ip, &info) {
                    warn!(pod_uid, %ip, error = %e, "Failed to update pod IPv6 map");
                    metrics.record_attach_error();
                    cleanup_partial_pod_enrollment(backend, pod_states, metrics, pod_uid, &state);
                    remember_failed_pod_enrollment_with_merged_cleanup_state(
                        &state_key,
                        attempt_signature,
                        enrollment_snapshot.clone(),
                        prior_cleanup_state.as_ref(),
                        &state,
                    );
                    return;
                }
            }
            if let Err(e) = apply_node_probe_ports(backend, pod_uid, &state) {
                warn!(pod_uid, error = %e, "Failed to update node probe-port maps");
                metrics.record_attach_error();
                cleanup_partial_pod_enrollment(backend, pod_states, metrics, pod_uid, &state);
                remember_failed_pod_enrollment_with_merged_cleanup_state(
                    &state_key,
                    attempt_signature,
                    enrollment_snapshot.clone(),
                    prior_cleanup_state.as_ref(),
                    &state,
                );
                return;
            }
            state.attached = true;
            metrics.pods_enrolled.fetch_add(1, Ordering::Relaxed);
            info!(
                pod_uid,
                pod_name,
                namespace,
                ?pod_ip,
                ?pod_ip6,
                include_ports_cgroups = state.include_ports_cgroup_ids.len(),
                workload_identity_cgroups = state.workload_identity_cgroup_ids.len(),
                "Pod enrolled for eBPF capture"
            );
        } else {
            cleanup_partial_pod_enrollment(backend, pod_states, metrics, pod_uid, &state);
            remember_failed_pod_enrollment_with_merged_cleanup_state(
                &state_key,
                attempt_signature,
                enrollment_snapshot,
                prior_cleanup_state.as_ref(),
                &state,
            );
        }
    } else {
        warn!(
            pod_uid,
            pod_name, "Could not resolve cgroup path, skipping attachment"
        );
        metrics.record_attach_error();
        remember_failed_pod_enrollment_preserving_cleanup(
            &state_key,
            attempt_signature,
            enrollment_snapshot,
            prior_cleanup_state.as_ref(),
        );
        return;
    }

    if state.attached {
        forget_failed_pod_enrollment(&state_key);
        if forget_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_DETACH,
            CAPTURE_FAILURE_DETAIL_POD_DETACH,
        ) {
            debug!(
                pod_uid,
                "Cleared superseded detach failure after same-UID pod re-enrollment"
            );
        }
        if let Some(ip) = pod_ip {
            forget_pending_pod_ip_remove_failures_for_ip(pod_states, ip);
        }
        if let Some(ip) = pod_ip6 {
            forget_pending_pod_ip_remove_failures_for_ip(pod_states, ip);
        }
        clear_partial_capture_state_if_recovered(pod_states, metrics);
        pod_states.insert(pod_uid.to_string(), state);
        // Publish to the in-netns capture registry only AFTER enrollment fully
        // succeeded (programs attached, pod-IP + identity written), so a failed
        // or partial enrollment never leaves a stale entry that would make the
        // mesh proxy open a listener for a pod that was never captured. Removal
        // is handled by `handle_pod_removed`. Gated on the registry being
        // configured (in-netns listeners + NodeWaypoint topology).
        if let (Some(dir), Some(cgroup_path_value)) = (
            &config.node_waypoint_pod_registry_dir,
            cgroup_path.as_deref(),
        ) {
            let source_identity = build_workload_spiffe_id(
                namespace,
                event.service_account.unwrap_or("default"),
                &config.trust_domain,
            );
            publish_pod_registry(
                dir,
                pod_uid,
                cgroup_path_value,
                event.pod_source_ips,
                source_identity.as_ref(),
            );
        }
    }
}

#[derive(Debug)]
struct PodIpReconcileResult<Ip> {
    stale_pod_ip: Option<Ip>,
    recovered_pending_failure: bool,
    pod_ip_update_failed: bool,
}

impl<Ip> Default for PodIpReconcileResult<Ip> {
    fn default() -> Self {
        Self {
            stale_pod_ip: None,
            recovered_pending_failure: false,
            pod_ip_update_failed: false,
        }
    }
}

#[derive(Debug, Default)]
struct NodeProbePortReconcileResult {
    recovered_pending_failure: bool,
    stale_probe_ports: Vec<u16>,
}

fn reconcile_existing_node_probe_ports(
    backend: &mut dyn EbpfBackend,
    metrics: &NodeAgentMetrics,
    state_key: &str,
    pod_uid: &str,
    desired_ports: &[u16],
    state: &mut PodAttachmentState,
) -> NodeProbePortReconcileResult {
    let stale_probe_ports: Vec<u16> = state
        .node_probe_ports
        .iter()
        .copied()
        .filter(|port| !desired_ports.contains(port))
        .collect();
    let mut desired_state = state.clone();
    desired_state.node_probe_ports = desired_ports.to_vec();
    if let Err(e) = apply_node_probe_ports_collecting(backend, pod_uid, &desired_state) {
        for port in e.applied_ports {
            remember_applied_node_probe_port(&mut state.node_probe_ports, port);
        }
        warn!(
            pod_uid,
            error = %e.message,
            "Failed to reconcile node probe-port maps for existing pod"
        );
        metrics.record_attach_error();
        forget_pending_node_probe_port_update_failures_for_state(state_key);
        remember_pending_capture_failure(
            state_key,
            CAPTURE_FAILURE_NODE_PROBE_PORT_UPDATE,
            &node_probe_port_update_failure_detail(desired_ports),
        );
        return NodeProbePortReconcileResult {
            recovered_pending_failure: false,
            stale_probe_ports: Vec::new(),
        };
    }

    let recovered_pending_failure =
        forget_pending_node_probe_port_update_failures_for_state(state_key) > 0;
    state.node_probe_ports = desired_ports.to_vec();
    NodeProbePortReconcileResult {
        recovered_pending_failure,
        stale_probe_ports,
    }
}

fn reconcile_existing_pod_ip(
    backend: &mut dyn EbpfBackend,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    state_key: &str,
    pod_uid: &str,
    pod_ip: Option<std::net::Ipv4Addr>,
    state: &mut PodAttachmentState,
) -> PodIpReconcileResult<std::net::Ipv4Addr> {
    let Some(new_ip) = pod_ip else {
        return PodIpReconcileResult::default();
    };
    if state.pod_ip == Some(new_ip) {
        return PodIpReconcileResult::default();
    }

    let info = pod_map_info(config, udp_ready_marker_exists(config, pod_uid));
    if let Err(e) = backend.update_pod_ip(new_ip, &info) {
        warn!(pod_uid, %new_ip, error = %e, "Failed to update pod IP map for existing pod");
        metrics.record_attach_error();
        remember_pending_capture_failure(
            state_key,
            CAPTURE_FAILURE_POD_IP_UPDATE,
            CAPTURE_FAILURE_DETAIL_POD_IP,
        );
        return PodIpReconcileResult {
            pod_ip_update_failed: true,
            ..PodIpReconcileResult::default()
        };
    }
    forget_pending_capture_failure(
        state_key,
        CAPTURE_FAILURE_POD_IP_UPDATE,
        CAPTURE_FAILURE_DETAIL_POD_IP,
    );
    let old_ip = state.pod_ip;
    state.pod_ip = Some(new_ip);
    PodIpReconcileResult {
        stale_pod_ip: old_ip,
        recovered_pending_failure: true,
        pod_ip_update_failed: false,
    }
}

fn reconcile_existing_pod_ip6(
    backend: &mut dyn EbpfBackend,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    state_key: &str,
    pod_uid: &str,
    pod_ip: Option<std::net::Ipv6Addr>,
    state: &mut PodAttachmentState,
) -> PodIpReconcileResult<std::net::Ipv6Addr> {
    let Some(new_ip) = pod_ip else {
        return PodIpReconcileResult::default();
    };
    if state.pod_ip6 == Some(new_ip) {
        return PodIpReconcileResult::default();
    }

    let info = pod_map_info(config, udp_ready_marker_exists(config, pod_uid));
    if let Err(e) = backend.update_pod_ip6(new_ip, &info) {
        warn!(pod_uid, %new_ip, error = %e, "Failed to update pod IPv6 map for existing pod");
        metrics.record_attach_error();
        remember_pending_capture_failure(
            state_key,
            CAPTURE_FAILURE_POD_IP_UPDATE,
            CAPTURE_FAILURE_DETAIL_POD_IP6,
        );
        return PodIpReconcileResult {
            pod_ip_update_failed: true,
            ..PodIpReconcileResult::default()
        };
    }
    forget_pending_capture_failure(
        state_key,
        CAPTURE_FAILURE_POD_IP_UPDATE,
        CAPTURE_FAILURE_DETAIL_POD_IP6,
    );
    let old_ip = state.pod_ip6;
    state.pod_ip6 = Some(new_ip);
    PodIpReconcileResult {
        stale_pod_ip: old_ip,
        recovered_pending_failure: true,
        pod_ip_update_failed: false,
    }
}

fn remove_pod_ip_if_unowned(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    ip: std::net::Ipv4Addr,
    removal_reason: &'static str,
) {
    if let Some(owner_pod_uid) = other_pod_owning_ip(pod_states, pod_uid, ip) {
        debug!(
            pod_uid,
            owner_pod_uid,
            %ip,
            removal_reason,
            "Skipping pod IP map removal; IP is owned by another tracked pod"
        );
        let state_key = pod_state_key(pod_states, pod_uid);
        forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
        forget_pending_pod_ip_remove_failures_for_ip(pod_states, ip);
        clear_partial_capture_state_if_recovered(pod_states, metrics);
        return;
    }
    let state_key = pod_state_key(pod_states, pod_uid);
    if let Err(e) = backend.remove_pod_ip(ip) {
        warn!(pod_uid, %ip, error = %e, removal_reason, "Failed to remove pod IP from map");
        metrics.record_attach_error();
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_IP_REMOVE,
            &ip.to_string(),
        );
        return;
    }
    forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

fn remove_pod_ip6_if_unowned(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    ip: std::net::Ipv6Addr,
    removal_reason: &'static str,
) {
    if let Some(owner_pod_uid) = other_pod_owning_ip6(pod_states, pod_uid, ip) {
        debug!(
            pod_uid,
            owner_pod_uid,
            %ip,
            removal_reason,
            "Skipping pod IPv6 map removal; IP is owned by another tracked pod"
        );
        let state_key = pod_state_key(pod_states, pod_uid);
        forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
        forget_pending_pod_ip_remove_failures_for_ip(pod_states, ip);
        clear_partial_capture_state_if_recovered(pod_states, metrics);
        return;
    }
    let state_key = pod_state_key(pod_states, pod_uid);
    if let Err(e) = backend.remove_pod_ip6(ip) {
        warn!(pod_uid, %ip, error = %e, removal_reason, "Failed to remove pod IPv6 from map");
        metrics.record_attach_error();
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_IP_REMOVE,
            &ip.to_string(),
        );
        return;
    }
    forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

fn other_pod_owning_ip(
    pod_states: &DashMap<String, PodAttachmentState>,
    pod_uid: &str,
    ip: std::net::Ipv4Addr,
) -> Option<String> {
    pod_states.iter().find_map(|entry| {
        (entry.key().as_str() != pod_uid && entry.value().pod_ip == Some(ip))
            .then(|| entry.key().clone())
    })
}

fn other_pod_owning_ip6(
    pod_states: &DashMap<String, PodAttachmentState>,
    pod_uid: &str,
    ip: std::net::Ipv6Addr,
) -> Option<String> {
    pod_states.iter().find_map(|entry| {
        (entry.key().as_str() != pod_uid && entry.value().pod_ip6 == Some(ip))
            .then(|| entry.key().clone())
    })
}

fn other_pod_owning_probe_port_addr(
    pod_states: &DashMap<String, PodAttachmentState>,
    pod_uid: &str,
    ip: std::net::IpAddr,
    port: u16,
) -> Option<String> {
    pod_states.iter().find_map(|entry| {
        (entry.key().as_str() != pod_uid
            && entry.value().node_probe_ports.contains(&port)
            && match ip {
                std::net::IpAddr::V4(ip) => entry.value().pod_ip == Some(ip),
                std::net::IpAddr::V6(ip) => entry.value().pod_ip6 == Some(ip),
            })
        .then(|| entry.key().clone())
    })
}

fn pod_owning_ip(
    pod_states: &DashMap<String, PodAttachmentState>,
    ip: std::net::Ipv4Addr,
) -> Option<String> {
    pod_states
        .iter()
        .find_map(|entry| (entry.value().pod_ip == Some(ip)).then(|| entry.key().clone()))
}

fn pod_owning_ip6(
    pod_states: &DashMap<String, PodAttachmentState>,
    ip: std::net::Ipv6Addr,
) -> Option<String> {
    pod_states
        .iter()
        .find_map(|entry| (entry.value().pod_ip6 == Some(ip)).then(|| entry.key().clone()))
}

fn pod_owning_ip_addr(
    pod_states: &DashMap<String, PodAttachmentState>,
    ip: std::net::IpAddr,
) -> Option<String> {
    match ip {
        std::net::IpAddr::V4(ip) => pod_owning_ip(pod_states, ip),
        std::net::IpAddr::V6(ip) => pod_owning_ip6(pod_states, ip),
    }
}

fn pod_owning_probe_port_addr(
    pod_states: &DashMap<String, PodAttachmentState>,
    ip: std::net::IpAddr,
    port: u16,
) -> Option<String> {
    pod_states.iter().find_map(|entry| {
        (entry.value().node_probe_ports.contains(&port)
            && match ip {
                std::net::IpAddr::V4(ip) => entry.value().pod_ip == Some(ip),
                std::net::IpAddr::V6(ip) => entry.value().pod_ip6 == Some(ip),
            })
        .then(|| entry.key().clone())
    })
}

fn remove_pre_enrollment_pod_ip_if_unowned(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    ip: std::net::Ipv4Addr,
    removal_reason: &'static str,
) {
    let state_key = pod_state_key(pod_states, pod_uid);
    if let Some(owner_pod_uid) = other_pod_owning_ip(pod_states, pod_uid, ip) {
        debug!(
            pod_uid,
            owner_pod_uid,
            %ip,
            removal_reason,
            "Skipping pre-enrollment pod IP map removal; IP is owned by another tracked pod"
        );
        forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
        forget_pending_pod_ip_remove_failures_for_ip(pod_states, ip);
        return;
    }
    if let Err(e) = backend.remove_pod_ip(ip) {
        warn!(
            pod_uid,
            %ip,
            error = %e,
            removal_reason,
            "Failed to remove pre-enrollment pod IP from map"
        );
        metrics.record_attach_error();
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_IP_REMOVE,
            &ip.to_string(),
        );
        return;
    }
    forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
}

fn remove_pre_enrollment_pod_ip6_if_unowned(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
    ip: std::net::Ipv6Addr,
    removal_reason: &'static str,
) {
    let state_key = pod_state_key(pod_states, pod_uid);
    if let Some(owner_pod_uid) = other_pod_owning_ip6(pod_states, pod_uid, ip) {
        debug!(
            pod_uid,
            owner_pod_uid,
            %ip,
            removal_reason,
            "Skipping pre-enrollment pod IPv6 map removal; IP is owned by another tracked pod"
        );
        forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
        forget_pending_pod_ip_remove_failures_for_ip(pod_states, ip);
        return;
    }
    if let Err(e) = backend.remove_pod_ip6(ip) {
        warn!(
            pod_uid,
            %ip,
            error = %e,
            removal_reason,
            "Failed to remove pre-enrollment pod IPv6 from map"
        );
        metrics.record_attach_error();
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_IP_REMOVE,
            &ip.to_string(),
        );
        return;
    }
    forget_pending_capture_failure(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
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

    // Cheap fast path for unannotated pods (the common case): no policy now and
    // none before → nothing to reconcile, and crucially no cgroup-tree walk.
    // Most Modified events (status updates, restart counts) hit this.
    if desired.is_none() && state.include_ports_policy.is_none() {
        return;
    }

    match desired {
        Some(new_policy) => {
            // Re-walk the whole pod cgroup subtree on every event (not just on a
            // policy change): the `connect4`/`connect6` gate keys
            // `FERRUM_INCLUDE_PORTS` by the container *leaf* cgroup, and
            // container leaves start (and restart under fresh inodes) after the
            // initial pod event — so a leaf that appears later must still pick up
            // the policy or narrowing silently never engages for it. (The
            // workload-identity reconcile re-walks for the same reason; here the
            // per-event read_dir is paid only for annotated pods.)
            let current = state
                .cgroup_path
                .as_deref()
                .map(|path| cgroup::collect_cgroup_tree_inodes(std::path::Path::new(path)))
                .unwrap_or_default();
            if current.is_empty() {
                // No readable cgroup inode yet (the Pod object reached the
                // watcher before kubelet created the cgroup). Skip and let a
                // future event retry; operationally normal, not a failure.
                debug!(
                    pod_uid,
                    "Mid-life includeOutboundPorts update deferred: no cgroup inode available"
                );
                return;
            }
            let current_set: HashSet<u64> = current.iter().copied().collect();
            let enrolled_set: HashSet<u64> =
                state.include_ports_cgroup_ids.iter().copied().collect();
            // Diff-skip: same policy AND same enrolled cgroup set → no map work.
            if state.include_ports_policy.as_ref() == Some(&new_policy)
                && current_set == enrolled_set
            {
                return;
            }
            // Drop entries for inodes that left the tree (a restarted
            // container's old leaf) so they don't linger in the fixed-size map.
            for cgroup_id in &state.include_ports_cgroup_ids {
                if !current_set.contains(cgroup_id)
                    && let Err(e) = backend.remove_pod_include_ports(*cgroup_id)
                {
                    warn!(
                        pod_uid,
                        cgroup_id = *cgroup_id,
                        error = %e,
                        "Failed to remove stale includeOutboundPorts entry for a departed cgroup inode"
                    );
                }
            }
            let mut written = Vec::with_capacity(current.len());
            for cgroup_id in current {
                match backend.update_pod_include_ports(cgroup_id, &new_policy) {
                    Ok(()) => written.push(cgroup_id),
                    Err(e) => warn!(
                        pod_uid,
                        cgroup_id,
                        error = %e,
                        "Failed to write mid-life includeOutboundPorts update for a cgroup inode"
                    ),
                }
            }
            if written.is_empty() {
                metrics
                    .pod_annotation_updates_failed
                    .fetch_add(1, Ordering::Relaxed);
                return;
            }
            let prev_summary = describe_policy(state.include_ports_policy.as_ref());
            let new_summary = describe_policy(Some(&new_policy));
            info!(
                pod_uid,
                cgroup_ids = written.len(),
                prev_policy = %prev_summary,
                new_policy = %new_summary,
                "Re-applied mid-life pod includeOutboundPorts annotation update across cgroup tree"
            );
            state.include_ports_cgroup_ids = written;
            state.include_ports_policy = Some(new_policy);
            metrics
                .pod_annotation_updates_applied
                .fetch_add(1, Ordering::Relaxed);
        }
        None => {
            // The pod removed its annotation entirely → drop every entry so the
            // gate fail-opens back to "capture everything" for this pod. Use the
            // stashed ids (the cgroup tree may already be gone); ENOENT-tolerant.
            if state.include_ports_cgroup_ids.is_empty() {
                // Nothing was written (e.g. enrolled before the cgroup existed)
                // but the baseline disagreed; just clear it for future diffs.
                state.include_ports_policy = None;
                return;
            }
            for cgroup_id in &state.include_ports_cgroup_ids {
                if let Err(e) = backend.remove_pod_include_ports(*cgroup_id) {
                    warn!(
                        pod_uid,
                        cgroup_id = *cgroup_id,
                        error = %e,
                        "Failed to drop mid-life pod includeOutboundPorts BPF entry"
                    );
                }
            }
            let prev_summary = describe_policy(state.include_ports_policy.as_ref());
            info!(
                pod_uid,
                cgroup_ids = state.include_ports_cgroup_ids.len(),
                prev_policy = %prev_summary,
                "Mid-life pod removed includeOutboundPorts annotation; dropped BPF map entries"
            );
            state.include_ports_cgroup_ids.clear();
            state.include_ports_policy = None;
            metrics
                .pod_annotation_updates_applied
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}

/// Re-walk an already-enrolled pod's cgroup tree on reconcile and reconcile the
/// `FERRUM_WORKLOAD_IDENTITY` entries against it: write the source workload
/// identity under newly-observed cgroup inodes and drop entries for inodes that
/// have left the tree.
///
/// Container cgroups appear *after* the pod cgroup (containers start once the
/// pod object exists) and rotate to fresh inodes on restart, so the leaf
/// cgroups the connect hook reads via `bpf_get_current_cgroup_id()` may not
/// have existed at initial enrollment. Kubernetes emits many Modified events
/// over a pod's lifecycle (readiness, container statuses, IP), so re-walking
/// here enrolls a newly-started container's cgroup within seconds.
///
/// A restarted container's old leaf `.scope` is deleted and recreated under a
/// fresh inode, so this also removes entries whose inode has left the tree —
/// otherwise every restart would leak one entry into the fixed-size (4096)
/// `FERRUM_WORKLOAD_IDENTITY` map until pod deletion, eventually exhausting it
/// and failing identity writes (hence node-waypoint resolution) for other pods.
/// An empty walk means the pod cgroup itself is gone (pod teardown); leave that
/// to `handle_pod_removed` rather than flushing live entries on a transient or
/// teardown read. Best-effort: failures log and continue.
fn reconcile_existing_pod_workload_identity(
    backend: &mut dyn EbpfBackend,
    config: &NodeAgentConfig,
    pod_uid: &str,
    namespace: &str,
    service_account: Option<&str>,
    state: &mut PodAttachmentState,
) {
    let Some(cgroup_path) = state.cgroup_path.clone() else {
        return;
    };
    let current = cgroup::collect_cgroup_tree_inodes(std::path::Path::new(&cgroup_path));
    if current.is_empty() {
        return;
    }
    let current_set: HashSet<u64> = current.iter().copied().collect();

    // Fast path: skip the SVID build + per-leaf map churn when the observed
    // cgroup tree exactly matches what we have already written. We compare the
    // full descendant inode set (the same depth-bounded BFS the writes use),
    // not a shallow direct-children fingerprint, so deeply-nested container
    // cgroup churn is still observed; and we compare against the *written* set
    // (`workload_identity_cgroup_ids`, which only holds ids the backend
    // accepted), not a separately-seeded baseline, so an earlier partial write
    // is retried instead of being permanently skipped. The tree walk above is
    // retained deliberately: a cheaper signal cannot detect either case
    // without failing closed for an un-enrolled container cgroup.
    if current_set.len() == state.workload_identity_cgroup_ids.len()
        && state
            .workload_identity_cgroup_ids
            .iter()
            .all(|cgroup_id| current_set.contains(cgroup_id))
    {
        return;
    }

    // Drop entries no longer present in the tree (e.g. a restarted container's
    // old leaf cgroup) from both the BPF map and our tracking set.
    state.workload_identity_cgroup_ids.retain(|cgroup_id| {
        if current_set.contains(cgroup_id) {
            return true;
        }
        match backend.remove_workload_identity(*cgroup_id) {
            Ok(()) => debug!(
                pod_uid,
                cgroup_id = *cgroup_id,
                "Removed stale (restarted-container) cgroup inode from FERRUM_WORKLOAD_IDENTITY"
            ),
            Err(e) => warn!(
                pod_uid,
                cgroup_id = *cgroup_id,
                error = %e,
                "Failed to remove stale pod cgroup inode from FERRUM_WORKLOAD_IDENTITY"
            ),
        }
        false
    });

    // Write the identity for newly-observed leaves.
    let Some(identity) = build_workload_identity(
        pod_uid,
        namespace,
        service_account.unwrap_or("default"),
        &config.trust_domain,
    ) else {
        return;
    };
    for cgroup_id in current {
        if state.workload_identity_cgroup_ids.contains(&cgroup_id) {
            continue;
        }
        match backend.update_workload_identity(cgroup_id, &identity) {
            Ok(()) => {
                debug!(
                    pod_uid,
                    cgroup_id,
                    "Enrolled newly-observed pod cgroup inode into FERRUM_WORKLOAD_IDENTITY"
                );
                state.workload_identity_cgroup_ids.push(cgroup_id);
            }
            Err(e) => {
                warn!(
                    pod_uid,
                    cgroup_id,
                    error = %e,
                    "Failed to write FERRUM_WORKLOAD_IDENTITY for a newly-observed pod cgroup inode"
                );
            }
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

fn record_removed_pod_detach_result(
    state_key: &str,
    pod_uid: &str,
    result: Result<(), String>,
    metrics: &NodeAgentMetrics,
) -> bool {
    match result {
        Ok(()) => {
            forget_pending_capture_failure(
                state_key,
                CAPTURE_FAILURE_POD_DETACH,
                CAPTURE_FAILURE_DETAIL_POD_DETACH,
            );
            true
        }
        Err(e) => {
            warn!(pod_uid, error = %e, "Failed to detach BPF programs");
            metrics.record_attach_error();
            remember_pending_capture_failure(
                state_key,
                CAPTURE_FAILURE_POD_DETACH,
                CAPTURE_FAILURE_DETAIL_POD_DETACH,
            );
            false
        }
    }
}

fn remove_pod_cgroup_maps_recording_failures(
    backend: &mut dyn EbpfBackend,
    metrics: &NodeAgentMetrics,
    state_key: &str,
    pod_uid: &str,
    state: &PodAttachmentState,
) {
    for cgroup_id in &state.include_ports_cgroup_ids {
        let detail = cgroup_id.to_string();
        match backend.remove_pod_include_ports(*cgroup_id) {
            Ok(()) => {
                forget_pending_capture_failure(
                    state_key,
                    CAPTURE_FAILURE_INCLUDE_PORTS_REMOVE,
                    &detail,
                );
            }
            Err(e) => {
                warn!(
                    pod_uid,
                    cgroup_id = *cgroup_id,
                    error = %e,
                    "Failed to remove pod includeOutboundPorts entry"
                );
                metrics.record_attach_error();
                remember_pending_capture_failure(
                    state_key,
                    CAPTURE_FAILURE_INCLUDE_PORTS_REMOVE,
                    &detail,
                );
            }
        }
    }
    for cgroup_id in &state.workload_identity_cgroup_ids {
        let detail = cgroup_id.to_string();
        match backend.remove_workload_identity(*cgroup_id) {
            Ok(()) => {
                forget_pending_capture_failure(
                    state_key,
                    CAPTURE_FAILURE_WORKLOAD_IDENTITY_REMOVE,
                    &detail,
                );
            }
            Err(e) => {
                warn!(
                    pod_uid,
                    cgroup_id = *cgroup_id,
                    error = %e,
                    "Failed to remove pod workload-identity entry"
                );
                metrics.record_attach_error();
                remember_pending_capture_failure(
                    state_key,
                    CAPTURE_FAILURE_WORKLOAD_IDENTITY_REMOVE,
                    &detail,
                );
            }
        }
    }
}

fn verify_failed_enrollment_cleanup_on_removal(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    metrics: &NodeAgentMetrics,
    state_key: &str,
    pod_uid: &str,
    state: &PodAttachmentState,
) -> bool {
    // The failed attempt reached the BPF mutation phase. Any subset of the
    // cgroup/tc attaches may have succeeded, so a successful detach is required
    // even though the pod never became tracked.
    let mut cleanup_succeeded =
        record_removed_pod_detach_result(state_key, pod_uid, backend.detach_pod(pod_uid), metrics);
    cleanup_node_probe_ports(backend, pod_states, metrics, pod_uid, state);
    if let Some(ip) = state.pod_ip {
        remove_pod_ip_if_unowned(
            backend,
            pod_states,
            metrics,
            pod_uid,
            ip,
            "failed enrollment pod removed",
        );
    }
    if let Some(ip) = state.pod_ip6 {
        remove_pod_ip6_if_unowned(
            backend,
            pod_states,
            metrics,
            pod_uid,
            ip,
            "failed enrollment pod removed",
        );
    }
    remove_pod_cgroup_maps_recording_failures(backend, metrics, state_key, pod_uid, state);
    cleanup_succeeded &= !has_pending_removal_blocking_failure(state_key);
    cleanup_succeeded
}

/// Remove a tracked pod and clean up its eBPF enrollment state.
///
/// When the registry-backed UDP handshake reconciler is active, successful BPF
/// detach plus removal of every recorded gate-related map entry is sufficient
/// node-agent-owned evidence to persist the cleaned-gate proof and close
/// acknowledgement. This includes
/// UDP-disabled Ambient cleanup after an enabled-to-disabled rollout: the
/// disabled reconciler independently verifies the same closed pod-map posture,
/// so removed pods must not lose their producer close handoff solely because
/// the current process is no longer arming UDP capture.
#[allow(dead_code)]
pub fn handle_pod_removed(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
    metrics: &NodeAgentMetrics,
    pod_uid: &str,
) {
    let state_key = pod_state_key(pod_states, pod_uid);
    // Snapshot before forgetting: a failed attempt may have written partial
    // BPF state without ever entering `pod_states`.
    let failed_attempt = FAILED_POD_ENROLLMENT_ATTEMPTS
        .get(&state_key)
        .map(|attempt| attempt.value().clone());
    forget_pending_capture_failure(
        &state_key,
        CAPTURE_FAILURE_POD_IP_UPDATE,
        CAPTURE_FAILURE_DETAIL_POD_IP,
    );
    forget_pending_capture_failure(
        &state_key,
        CAPTURE_FAILURE_POD_IP_UPDATE,
        CAPTURE_FAILURE_DETAIL_POD_IP6,
    );
    forget_pending_capture_failure(
        &state_key,
        CAPTURE_FAILURE_UDP_READINESS,
        CAPTURE_FAILURE_DETAIL_UDP_READINESS,
    );
    forget_pending_node_probe_port_update_failures_for_state(&state_key);
    // Drop this pod's per-pod registry entry (if publishing is enabled) so the
    // mesh proxy's in-netns capture listeners stop discovering a torn-down pod.
    // Best-effort and independent of whether the pod was actually attached: a
    // pod that failed to fully enroll may still have a stale registry file.
    if let Some(dir) = &config.node_waypoint_pod_registry_dir {
        remove_pod_registry(dir, pod_uid);
        // Also drop the proxy's readiness marker so a same-UID re-enroll within
        // the proxy's ~2s reconcile window cannot observe a stale `ready` for the
        // torn-down listener.
        remove_pod_ready_marker(dir, pod_uid);
    }

    let removed = pod_states.remove(pod_uid);
    let Some((_, state)) = removed else {
        if let Some(failed_attempt) = failed_attempt {
            // `None` proves the attempt failed before the BPF mutation phase;
            // `Some` retains every exact key that may have been applied. Use
            // that evidence before lifting failed-enrollment suppression,
            // regardless of whether this process currently publishes UDP
            // readiness handoffs.
            let cleanup_succeeded = failed_attempt.cleanup_state.as_ref().is_none_or(|state| {
                verify_failed_enrollment_cleanup_on_removal(
                    backend, pod_states, metrics, &state_key, pod_uid, state,
                )
            });
            forget_pod_enrollment_attempt(&state_key);
            // Pod events, retry ticks, and responder ticks share this select!
            // task, so the responder cannot observe suppression lifted between
            // the pending-failure writes above and this completion attempt.
            if cleanup_succeeded {
                complete_removed_udp_close_handoff(pod_states, config, &state_key, pod_uid);
            } else {
                warn!(
                    pod_uid,
                    "Withholding Ambient UDP not-ready acknowledgement because failed-enrollment BPF cleanup is incomplete"
                );
            }
        } else {
            forget_pod_enrollment_attempt(&state_key);
        }
        clear_partial_capture_state_if_recovered(pod_states, metrics);
        return;
    };

    forget_pod_enrollment_attempt(&state_key);

    let mut udp_gate_cleanup_succeeded = true;
    if state.attached {
        let detach_result = backend.detach_pod(pod_uid);
        udp_gate_cleanup_succeeded &=
            record_removed_pod_detach_result(&state_key, pod_uid, detach_result, metrics);
        cleanup_node_probe_ports(backend, pod_states, metrics, pod_uid, &state);
        if let Some(ip) = state.pod_ip {
            remove_pod_ip_if_unowned(backend, pod_states, metrics, pod_uid, ip, "pod removed");
        }
        if let Some(ip) = state.pod_ip6 {
            remove_pod_ip6_if_unowned(backend, pod_states, metrics, pod_uid, ip, "pod removed");
        }
        // Pair with the enrollment writes using the stashed pod + descendant
        // cgroup inode keys. Failures are removal blockers just like detach and
        // pod-IP failures: retries must clear them before proof/ack is minted.
        remove_pod_cgroup_maps_recording_failures(backend, metrics, &state_key, pod_uid, &state);
        metrics.pods_unenrolled.fetch_add(1, Ordering::Relaxed);
        info!(pod_uid, pod_name = %state.pod_name, "Pod unenrolled from eBPF capture");
        udp_gate_cleanup_succeeded &= !has_pending_removal_blocking_failure(&state_key);
    }
    if udp_readiness_reconcile_enabled(config) {
        if udp_gate_cleanup_succeeded {
            if let Some(dir) = &config.node_waypoint_pod_registry_dir {
                if write_udp_gate_cleaned_proof(dir, pod_uid) {
                    write_udp_not_ready_ack(dir, pod_uid);
                } else {
                    warn!(
                        pod_uid,
                        "Withholding Ambient UDP not-ready acknowledgement because durable cleaned-gate proof could not be persisted"
                    );
                }
            }
        } else {
            warn!(
                pod_uid,
                "Withholding Ambient UDP not-ready acknowledgement because BPF gate cleanup is incomplete"
            );
        }
    }
    clear_partial_capture_state_if_recovered(pod_states, metrics);
}

async fn handle_fallback(
    config: &NodeAgentConfig,
    probe: &KernelProbeResult,
    metrics: Arc<NodeAgentMetrics>,
    shutdown_tx: &tokio::sync::watch::Sender<bool>,
    startup_ready: Arc<AtomicBool>,
    cni_config: CniListenerConfig,
) -> Result<(), anyhow::Error> {
    let cni_handles =
        if cni_config.enabled && matches!(config.fallback_mode, FallbackMode::Iptables) {
            Some(spawn_cni_passthrough_listener(
                cni_config.socket_path.clone(),
                metrics.clone(),
                shutdown_tx.subscribe(),
            ))
        } else {
            None
        };

    let result = handle_fallback_with(
        config,
        probe,
        metrics.as_ref(),
        shutdown_tx,
        |cmds, phase| async move { execute_iptables_commands(&cmds, phase).await },
        startup_ready,
    )
    .await;

    if let Some((listener, worker)) = cni_handles {
        let _ = shutdown_tx.send(true);
        if let Err(err) = listener.await {
            warn!(error = %err, "Node agent CNI passthrough listener task panicked");
        }
        if let Err(err) = worker.await {
            warn!(error = %err, "Node agent CNI passthrough worker task panicked");
        }
    }

    result
}

fn spawn_cni_passthrough_listener(
    socket_path: String,
    metrics: Arc<NodeAgentMetrics>,
    shutdown: tokio::sync::watch::Receiver<bool>,
) -> (tokio::task::JoinHandle<()>, tokio::task::JoinHandle<()>) {
    let (cni_work_tx, mut cni_work_rx) = cni_work_channel();
    let listener = spawn_cni_listener(socket_path, cni_work_tx.clone(), metrics, shutdown);
    drop(cni_work_tx);
    let worker = tokio::spawn(async move {
        while let Some(work) = cni_work_rx.recv().await {
            let _ = work.respond.send(CniRpcResponse::Ok);
        }
    });
    (listener, worker)
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
    metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);

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
                 FERRUM_NODE_AGENT_FALLBACK_MODE=iptables is explicit opt-in and requires a runtime image \
                 with /bin/sh plus iptables/ip6tables. Per-pod ambient capture remains available via iptables \
                 injection — configure the injector NodeSelector so pods on this node receive an iptables init container."
            );

            let plan = IptablesPlan::for_config(&config.capture_config);
            // Always try IPv6 cleanup: an earlier process/config may have
            // created ip6tables chains even when the current plan has none.
            let include_v6_cleanup = true;
            let udp_capture_enabled = config.capture_config.udp_capture_enabled;

            // The node-agent runs in the HOST netns, where the UDP TPROXY
            // `addrtype --dst-type LOCAL` direction split is wrong (pod IPs are
            // FORWARDED, not LOCAL), so `udp_tproxy_commands_for_family` emits NO
            // UDP TPROXY rules for `host_netns`. Surface that explicitly so an
            // operator who set FERRUM_MESH_CAPTURE_UDP_ENABLED=true on the
            // node-agent is not silently left thinking UDP is captured: node-agent
            // host-netns UDP capture is unsupported in this stage and eBPF does NOT
            // cover UDP either (the connect()-cgroup hooks are TCP-only). UDP
            // capture lives in the injector's pod-netns path; node-agent /
            // node-waypoint UDP capture is a future stage.
            if udp_capture_enabled && config.capture_config.host_netns {
                warn!(
                    "FERRUM_MESH_CAPTURE_UDP_ENABLED=true but the node-agent iptables \
                     fallback runs in the host network namespace, where the UDP TPROXY \
                     direction split (addrtype --dst-type LOCAL) cannot distinguish \
                     inbound-to-pod from outbound traffic. No UDP TPROXY rules will be \
                     installed (TCP capture is unaffected). Node-agent host-netns UDP \
                     capture is NOT supported in this stage (the direction split is \
                     pod-netns-only); eBPF capture does NOT cover UDP either (the \
                     connect()-cgroup hooks are TCP-only). For UDP capture, use the \
                     injector's pod-netns path (an iptables init container that runs in \
                     the pod netns where the pod IP is LOCAL); node-agent / node-waypoint \
                     UDP capture is a future stage."
                );
            }

            // UNCONDITIONAL pre-setup teardown of the EXACT Ferrum-owned UDP TPROXY
            // state, regardless of the CURRENT `udp_capture_enabled` flag (codex
            // r4). A prior UDP-enabled run that crashed before its shutdown cleanup
            // leaves the UDP mangle chains/jumps + the fwmark `ip rule` + the local
            // route installed; restarting with `FERRUM_MESH_CAPTURE_UDP_ENABLED=false`
            // would otherwise NEVER remove them (both the shutdown cleanup and the
            // setup-failure cleanup gate the UDP teardown on the now-false flag, and
            // disabled setup emits no UDP rules to overwrite them), so captured UDP
            // stays diverted into table 33133 while disabled — and with no Stage 3
            // listener that is a black-hole. This teardown touches ONLY exact
            // Ferrum-owned UDP state (mangle chains by name + fwmark rule by stable
            // priority + route by exact table spec) — never the TCP nat chains,
            // which setup is about to rebuild — and every command is
            // idempotent/best-effort (`|| true`), so it is harmless when no stale
            // UDP state exists. Setup then (re)installs the UDP rules only when the
            // current flag is enabled. Failures only warn — a stale-state cleanup
            // must never block bringing the current capture posture up.
            let pre_setup_udp_teardown = udp_pre_setup_teardown_commands(include_v6_cleanup);
            if let Err(teardown_err) =
                execute(pre_setup_udp_teardown, "pre-setup UDP teardown").await
            {
                warn!(
                    error = %teardown_err,
                    "Failed to tear down stale Ferrum UDP capture state before setup; continuing"
                );
            }

            let setup = setup_commands_for_plan(&plan);
            if let Err(setup_err) = execute(setup, "setup").await {
                let cleanup = cleanup_commands_for_plan(include_v6_cleanup, udp_capture_enabled);
                if let Err(cleanup_err) = execute(cleanup, "cleanup").await {
                    warn!(
                        error = %cleanup_err,
                        "Failed to clean up iptables fallback rules after setup failure"
                    );
                }
                return Err(setup_err);
            }
            metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_NODE_GLOBAL_FALLBACK);
            startup_ready.store(true, Ordering::Release);

            info!("Iptables fallback rules applied, awaiting shutdown signal");

            wait_for_shutdown(shutdown_tx).await;

            info!("Shutdown signal received, cleaning up iptables rules");
            let cleanup = cleanup_commands_for_plan(include_v6_cleanup, udp_capture_enabled);
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
                 when the runtime image includes /bin/sh plus iptables/ip6tables.",
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

fn cleanup_commands_for_plan(include_v6: bool, udp_capture_enabled: bool) -> Vec<String> {
    // `udp_capture_enabled` gates the UDP TPROXY teardown (mangle chains + the
    // Ferrum-owned `ip rule`/`ip route`): when this node never installs UDP
    // capture, cleanup must not touch routing state it never created (codex r1).
    //
    // The cleanup is split into the iptables-TABLE teardown and the RAW `ip`
    // routing teardown. The IPv4 routing teardown is already emitted
    // unconditionally (raw `ip`, no iptables dependency).
    let v4 = IptablesPlan::cleanup_split(udp_capture_enabled);
    let mut commands = v4.iptables;
    commands.extend(v4.ip_routing);
    if include_v6 {
        let v6 = IptablesPlan::cleanup_v6_split(udp_capture_enabled);
        // Only the ip6tables-TABLE teardown is guarded behind an `ip6tables`
        // availability probe — stale v6 chains from an earlier config should not
        // make node-agent fallback cleanup fail when `ip6tables` is absent.
        commands.extend(
            v6.iptables
                .iter()
                .map(|cmd| ip6tables_best_effort_wrapped_command(cmd)),
        );
        // The RAW `ip -6` routing teardown (fwmark rule + local route) is emitted
        // UNCONDITIONALLY — `ip -6` does not depend on `ip6tables`, so gating it on
        // the probe would leak the rule/route and keep diverting marked UDP after
        // shutdown when `ip6tables` is missing (codex r3). It carries its own
        // best-effort `|| true`.
        commands.extend(v6.ip_routing);
    }
    commands
}

/// The UNCONDITIONAL pre-setup teardown of the EXACT Ferrum-owned UDP TPROXY
/// state, regardless of the current `udp_capture_enabled` (codex r4). Mirrors
/// [`cleanup_commands_for_plan`]'s ip6tables-guard discipline, but composes ONLY
/// the UDP teardown (mangle chains + fwmark rule by stable priority + local
/// route) — never the TCP nat chains, which setup is about to rebuild — so it can
/// run before setup to reap stale UDP state from a prior UDP-enabled-then-crashed
/// run without disturbing TCP capture. The IPv6 table half is guarded behind the
/// `ip6tables` probe, which checks the **mangle** table (where the UDP TPROXY
/// chains live — probing `nat` would wrongly skip the mangle teardown on a host
/// with mangle but no nat table, codex r10); the raw `ip`/`ip -6` routing halves
/// are emitted unconditionally (they do not depend on `ip6tables` and must not
/// leak the fwmark rule/route when it is absent). Every command is
/// idempotent/best-effort.
fn udp_pre_setup_teardown_commands(include_v6: bool) -> Vec<String> {
    let v4 = IptablesPlan::udp_teardown_split();
    let mut commands = v4.iptables;
    commands.extend(v4.ip_routing);
    if include_v6 {
        let v6 = IptablesPlan::udp_teardown_v6_split();
        commands.extend(
            v6.iptables
                .iter()
                .map(|cmd| ip6tables_best_effort_wrapped_udp_command(cmd)),
        );
        commands.extend(v6.ip_routing);
    }
    commands
}

fn ip6tables_best_effort_wrapped_command(cmd: &str) -> String {
    // TCP mesh capture lives in the `nat` table, so the availability probe checks
    // `nat` for the setup/cleanup paths that wrap nat (and mixed nat+mangle) rules.
    ip6tables_best_effort_wrapped_command_for_table(cmd, "nat")
}

/// The UDP TPROXY teardown operates on the `mangle` table, so it must probe
/// `mangle` — NOT `nat` — for ip6tables availability: a host with `mangle`
/// support but no `nat` table would otherwise wrongly skip the mangle UDP
/// teardown behind a `nat` probe (codex r10).
fn ip6tables_best_effort_wrapped_udp_command(cmd: &str) -> String {
    ip6tables_best_effort_wrapped_command_for_table(cmd, "mangle")
}

fn ip6tables_best_effort_wrapped_command_for_table(cmd: &str, table: &str) -> String {
    // Shared with the Ambient per-pod-netns UDP producer's teardown so the probe
    // shape can never drift between the node-agent fallback cleanup and the
    // producer (`IptablesPlan::udp_teardown_script`).
    crate::capture::ip6tables_probe_guard(cmd, table)
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
    metrics: &NodeAgentMetrics,
) -> Result<(), anyhow::Error> {
    if config.capture_config.mode != CaptureMode::Ebpf {
        metrics.set_topology_degraded("capture_mode_not_ebpf");
        metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
        anyhow::bail!(
            "node_agent mode requires FERRUM_MESH_CAPTURE_MODE=ebpf for the managed capture backend; \
             got {:?}. Use the explicit injector path or set FERRUM_NODE_AGENT_FALLBACK_MODE=iptables \
             only for explicit node-global fallback on unsupported kernels.",
            config.capture_config.mode
        );
    }

    if let Err(e) = backend.load_programs() {
        metrics.set_topology_degraded("capture_unavailable");
        metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
        return Err(anyhow::Error::msg(e));
    }
    let require_sock_ops = config.capture_contract.proxy_mode == NodeAgentProxyMode::NodeWaypoint;
    if let Err(e) = backend.update_capture_config(&config.capture_contract.bpf_capture_config()) {
        metrics.set_topology_degraded("capture_unavailable");
        metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
        return Err(anyhow::Error::msg(e));
    }

    if require_sock_ops {
        let node_source_ips = match node_agent_node_source_ips_from_env() {
            Ok(ips) => ips,
            Err(e) => {
                metrics.set_topology_degraded("capture_unavailable");
                metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
                return Err(anyhow::Error::msg(e));
            }
        };
        for ip in &node_source_ips.ipv4 {
            if let Err(e) = backend.update_node_ip(*ip) {
                metrics.set_topology_degraded("capture_unavailable");
                metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
                return Err(anyhow::Error::msg(e));
            }
        }
        for ip in &node_source_ips.ipv6 {
            if let Err(e) = backend.update_node_ip6(*ip) {
                metrics.set_topology_degraded("capture_unavailable");
                metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
                return Err(anyhow::Error::msg(e));
            }
        }
        if node_source_ips.is_empty() {
            // The NodeWaypoint inbound direct-pod guard now admits the relay's
            // marked SYN only when it ALSO comes from a trusted node source IP
            // (so a forgeable socket mark alone cannot bypass HBONE/mTLS). The
            // inbound HBONE relay dials backend pods from a node-local source
            // address, so with an empty node-source set the guard would drop the
            // relay's own traffic — and all direct inbound to enrolled pods —
            // silently. Fail closed instead of black-holing the data path: the
            // relay source IP is CNI-specific (e.g. the node's pod-CIDR gateway
            // or its kubelet probe source) and cannot be auto-detected, so the
            // operator must supply it explicitly.
            metrics.set_topology_degraded("capture_unavailable");
            metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
            return Err(anyhow::Error::msg(
                "NodeWaypoint inbound direct-pod guard requires at least one trusted node \
                 source IP, but neither FERRUM_NODE_AGENT_NODE_IP nor FERRUM_NODE_AGENT_NODE_IPS \
                 is set. The inbound HBONE relay dials backend pods from a node-local source \
                 address, so the source-bound guard would drop the relay's own SYNs (and all \
                 direct inbound to enrolled pods). Set the host source address(es) used to reach \
                 local pods — CNI-specific, e.g. the node's pod-CIDR gateway or kubelet probe \
                 source — via nodeAgent.trustedKubeletProbeSourceIps (FERRUM_NODE_AGENT_NODE_IP / \
                 FERRUM_NODE_AGENT_NODE_IPS).",
            ));
        }
    }

    if let Some(uid) = config.capture_config.proxy_uid
        && let Err(e) = backend.update_bypass_uid(uid)
    {
        metrics.set_topology_degraded("capture_unavailable");
        metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
        return Err(anyhow::Error::msg(e));
    }

    for cidr in &config.capture_config.include_cidrs {
        if let Err(e) = backend.update_cidr_include(cidr) {
            metrics.set_topology_degraded("capture_unavailable");
            metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
            return Err(anyhow::Error::msg(e));
        }
    }
    for cidr in &config.capture_config.exclude_cidrs {
        if let Err(e) = backend.update_cidr_exclude(cidr) {
            metrics.set_topology_degraded("capture_unavailable");
            metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
            return Err(anyhow::Error::msg(e));
        }
    }
    for port in &config.capture_config.exclude_ports {
        if let Err(e) = backend.update_port_exclude(*port) {
            metrics.set_topology_degraded("capture_unavailable");
            metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
            return Err(anyhow::Error::msg(e));
        }
    }
    // Per-pod `includeOutboundPorts` narrowing is applied later in
    // `handle_pod_added` via `apply_include_outbound_ports` because the
    // BPF map is keyed by per-pod cgroup id, not by the global
    // capture-config slot. `initialize_backend` only seeds the
    // node-global shape (CIDR includes/excludes, port excludes, proxy
    // UID bypass).

    if require_sock_ops {
        // SOCK_OPS at the cgroup root carries BOTH TCP-layer telemetry AND the
        // GAP-2M accept-side cookie bridge that node-waypoint per-pod identity
        // resolution depends on. A failure here is therefore not merely lost
        // counters: with no accept-side cookie stamping, every node-waypoint
        // connection resolves `UnknownCookie` and scoped authz fails closed.
        // Surface it as topology degradation (gauge + error) — not a quiet
        // telemetry warning — and refuse readiness so operators see identity
        // resolution is down before traffic is admitted.
        if let Err(e) = backend.attach_sock_ops(&config.cgroup_root) {
            metrics.set_topology_degraded("node_waypoint_sock_ops_unavailable");
            metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_IDENTITY_BRIDGE_UNAVAILABLE);
            error!(
                cgroup_root = %config.cgroup_root,
                error = %e,
                "Failed to attach SOCK_OPS in node-waypoint mode: the GAP-2M accept-side \
                 cookie bridge is not running, so per-pod source-identity resolution would \
                 be disabled and scoped node-waypoint authz would fail closed (TCP-layer \
                 telemetry is also lost). Refusing startup so /health cannot report Ready \
                 for a partially attached node-waypoint topology. Set \
                 ferrum_mesh_node_topology_degraded{{reason=\"node_waypoint_sock_ops_unavailable\"}}=1."
            );
            anyhow::bail!(
                "node-waypoint eBPF capture requires the SOCK_OPS identity bridge to attach; \
                 source workload identity resolution would be unavailable: {e}"
            );
        }
    }

    if let Err(e) = backend.validate_startup_ready(require_sock_ops) {
        if require_sock_ops && e.contains("SOCK_OPS") {
            metrics.set_topology_degraded("node_waypoint_sock_ops_unavailable");
            metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_IDENTITY_BRIDGE_UNAVAILABLE);
        } else {
            metrics.set_topology_degraded("capture_unavailable");
            metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_UNAVAILABLE);
        }
        anyhow::bail!("node-agent eBPF startup validation failed: {e}");
    }

    metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_READY);
    info!("BPF programs loaded and maps initialized");
    Ok(())
}

fn cleanup_all_pods(
    backend: &mut dyn EbpfBackend,
    pod_states: &DashMap<String, PodAttachmentState>,
    config: &NodeAgentConfig,
) {
    for entry in pod_states.iter() {
        let state = entry.value();
        // Drop the in-netns registry entry + readiness marker so a mesh proxy
        // that keeps running after this node-agent stops/restarts does not keep a
        // dead in-netns listener open for a pod that is no longer enrolled.
        if let Some(dir) = &config.node_waypoint_pod_registry_dir {
            remove_pod_registry(dir, &state.pod_uid);
            remove_pod_ready_marker(dir, &state.pod_uid);
        }
        if state.attached
            && let Err(e) = backend.detach_pod(&state.pod_uid)
        {
            warn!(pod_uid = %state.pod_uid, error = %e, "Failed to detach BPF programs during shutdown");
        }
    }
    if let Err(e) = backend.cleanup_all() {
        warn!(error = %e, "Failed to cleanup BPF state during shutdown");
    }
    // Deliberately do NOT write the `.udp-not-ready` ack here. By this point
    // `cleanup_all()` has detached the tc classifier and torn down the pod-IP
    // registry, so the host-veth gate that normally drops pod-originated UDP is
    // *gone*, not closed. If a mesh proxy keeps running across a node-agent
    // DaemonSet restart, publishing the ack would tell its still-live per-netns
    // producer that the host gate is closed (`retain_guard = false`) and let it
    // tear its in-netns DROP guard down into plaintext — enrolled pods would
    // then egress UDP uncaptured/unauthorized until the new node-agent
    // re-enrolls and reopens the producer. Fail closed instead: withholding the
    // ack makes `await_udp_not_ready_ack` time out on the producer side, so it
    // retains the in-netns guard (self-healing — reaped on the producer's next
    // open). A fresh ack is only ever published by `reconcile_udp_capture_readiness`
    // once the BPF gate is verifiably re-closed, which a restarted node-agent
    // re-derives from live state rather than trusting a persisted marker.
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

    fn test_failed_enrollment_signature(
        pod_ip: std::net::Ipv4Addr,
        cgroup_path: Option<&str>,
    ) -> PodEnrollmentAttemptSignature {
        PodEnrollmentAttemptSignature {
            namespace: "default".to_string(),
            service_account: None,
            pod_ip: Some(pod_ip),
            pod_source_ips: PodSourceIps::default(),
            node_probe_ports: Vec::new(),
            cgroup_path: cgroup_path.map(ToOwned::to_owned),
            veth_iface: Some("veth-test".to_string()),
            labels_fingerprint: 0,
            annotations_fingerprint: 0,
        }
    }

    fn test_retryable_enrollment(
        pod_uid: &str,
        pod_ip: std::net::Ipv4Addr,
    ) -> RetryablePodEnrollment {
        RetryablePodEnrollment {
            pod_uid: pod_uid.to_string(),
            pod_name: pod_uid.to_string(),
            namespace: "default".to_string(),
            service_account: None,
            labels: HashMap::new(),
            annotations: HashMap::new(),
            pod_ip: Some(pod_ip.to_string()),
            pod_source_ips: PodSourceIps::default(),
            node_probe_ports: Vec::new(),
            pod_pid: None,
        }
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
    fn from_env_config_captures_ipv6_only_in_node_waypoint_mode() {
        // NodeWaypoint in-netns capture binds both pod-loopback families, so the
        // node-agent must include IPv6 destinations but must not set the old
        // global deny flag. Other proxy modes leave the normal IPv4-only default
        // include shape alone.
        let waypoint = EnvConfig {
            node_agent_proxy_mode: NodeAgentProxyMode::NodeWaypoint,
            ..EnvConfig::default()
        };
        with_env_vars(&[("FERRUM_NODE_AGENT_NODE_NAME", "node-a")], || {
            let config = NodeAgentConfig::from_env_config(&waypoint)
                .expect("node-agent config should parse");
            assert!(
                !config.capture_contract.ipv6_outbound_deny,
                "NodeWaypoint in-netns mode must redirect captured IPv6 egress to the IPv6 pod-loopback listener"
            );
            assert_eq!(
                config
                    .capture_contract
                    .bpf_capture_config()
                    .ipv6_outbound_deny,
                0,
                "the old deny flag must remain clear so connect6 redirects to [::1]"
            );
            assert!(
                config
                    .capture_config
                    .include_cidrs
                    .iter()
                    .any(|cidr| cidr == "::/0"),
                "NodeWaypoint must include IPv6 destinations so connect6 captures them instead of bypassing"
            );
            assert!(
                config.node_waypoint_pod_registry_dir.is_some(),
                "in-netns registry is published in NodeWaypoint mode"
            );
        });

        let local_pod = EnvConfig {
            node_agent_proxy_mode: NodeAgentProxyMode::LocalPod,
            ..EnvConfig::default()
        };
        with_env_vars(&[("FERRUM_NODE_AGENT_NODE_NAME", "node-b")], || {
            let config = NodeAgentConfig::from_env_config(&local_pod)
                .expect("node-agent config should parse");
            assert!(
                !config.capture_contract.ipv6_outbound_deny,
                "non-NodeWaypoint modes do not fail-close IPv6 egress"
            );
            assert!(
                !config
                    .capture_config
                    .include_cidrs
                    .iter()
                    .any(|cidr| cidr == "::/0"),
                "non-NodeWaypoint modes preserve the normal IPv4-only default include"
            );
        });
    }

    #[test]
    fn from_env_config_publishes_registry_for_ambient_udp_capture() {
        // #2013: a plain Ambient (LocalPod) node-agent with UDP capture enabled
        // must publish the per-pod registry so the mesh proxy's per-pod-netns UDP
        // producer can discover enrolled pods — WITHOUT taking on the NodeWaypoint
        // ipv6-deny / connect4-deferral posture (which stays gated on
        // `node_waypoint_in_netns`).
        let local_pod = EnvConfig {
            node_agent_proxy_mode: NodeAgentProxyMode::LocalPod,
            ..EnvConfig::default()
        };
        with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_NAME", "node-udp"),
                ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true"),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
            ],
            || {
                let config = NodeAgentConfig::from_env_config(&local_pod)
                    .expect("node-agent config should parse");
                assert!(
                    config.node_waypoint_pod_registry_dir.is_some(),
                    "Ambient/LocalPod + UDP capture must publish the per-pod registry (#2013)"
                );
                assert!(
                    !config.capture_contract.ipv6_outbound_deny,
                    "the UDP producer must not flip the NodeWaypoint ipv6-deny posture"
                );
                assert!(
                    !config
                        .capture_config
                        .include_cidrs
                        .iter()
                        .any(|cidr| cidr == "::/0"),
                    "the UDP producer must not force the NodeWaypoint ::/0 include"
                );
            },
        );
    }

    #[test]
    fn from_env_config_keeps_ambient_registry_for_disabled_udp_cleanup() {
        let local_pod = EnvConfig {
            node_agent_proxy_mode: NodeAgentProxyMode::LocalPod,
            ..EnvConfig::default()
        };
        with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_NAME", "node-udp-cleanup"),
                ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "false"),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
            ],
            || {
                let config = NodeAgentConfig::from_env_config(&local_pod)
                    .expect("node-agent config should parse");
                assert!(
                    !config.capture_config.udp_capture_enabled,
                    "disabled cleanup must not arm the UDP readiness guard"
                );
                assert!(
                    config.node_waypoint_pod_registry_dir.is_some(),
                    "Ambient must keep publishing pod netns for disabled stale-rule cleanup"
                );
                assert!(
                    udp_readiness_reconcile_enabled(&config),
                    "disabled Ambient cleanup must keep live ack reconciliation scheduled"
                );
            },
        );
    }

    #[test]
    fn from_env_config_publishes_udp_registry_when_tcp_outbound_disabled() {
        // #2013 (codex): a port-0 FERRUM_MESH_OUTBOUND_LISTEN_ADDR clears
        // `outbound_capture_enabled` for the TCP connect4/connect6 redirect path,
        // but the Ambient UDP producer binds its OWN FERRUM_MESH_CAPTURE_UDP_PORT
        // inside each pod netns and does not use the TCP outbound listener at all.
        // The registry MUST still be published so the producer can discover pods —
        // otherwise it polls an empty directory while pod UDP egress bypasses
        // capture/authz (fail-open). This pins the gate to `udp_capture_enabled`
        // ALONE, not anded with `outbound_capture_enabled`.
        let local_pod = EnvConfig {
            node_agent_proxy_mode: NodeAgentProxyMode::LocalPod,
            ..EnvConfig::default()
        };
        with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_NAME", "node-udp-no-tcp"),
                ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true"),
                ("FERRUM_MESH_TOPOLOGY", "ambient"),
                ("FERRUM_MESH_OUTBOUND_LISTEN_ADDR", "127.0.0.1:0"),
            ],
            || {
                let config = NodeAgentConfig::from_env_config(&local_pod)
                    .expect("node-agent config should parse");
                assert!(
                    !config.capture_config.outbound_capture_enabled,
                    "port-0 outbound listener must clear the TCP outbound-capture flag"
                );
                assert!(
                    config.node_waypoint_pod_registry_dir.is_some(),
                    "UDP capture must publish the registry even when TCP outbound is \
                     disabled (port 0) — the producer is independent of the TCP \
                     listener (#2013)"
                );
            },
        );
    }

    #[test]
    fn from_env_config_does_not_arm_udp_guard_without_ambient_producer() {
        let local_pod = EnvConfig {
            node_agent_proxy_mode: NodeAgentProxyMode::LocalPod,
            ..EnvConfig::default()
        };
        with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_NAME", "node-sidecar-udp"),
                ("FERRUM_MESH_CAPTURE_UDP_ENABLED", "true"),
                ("FERRUM_MESH_TOPOLOGY", "sidecar"),
            ],
            || {
                let config = NodeAgentConfig::from_env_config(&local_pod)
                    .expect("node-agent config should parse");
                assert!(!config.capture_config.udp_capture_enabled);
                assert!(config.node_waypoint_pod_registry_dir.is_none());
                assert!(!udp_readiness_reconcile_enabled(&config));
            },
        );
    }

    #[test]
    fn from_env_config_no_registry_for_local_pod_without_udp() {
        // A plain LocalPod with no UDP capture stays registry-free (no consumer).
        let local_pod = EnvConfig {
            node_agent_proxy_mode: NodeAgentProxyMode::LocalPod,
            ..EnvConfig::default()
        };
        with_env_vars(&[("FERRUM_NODE_AGENT_NODE_NAME", "node-x")], || {
            let config = NodeAgentConfig::from_env_config(&local_pod)
                .expect("node-agent config should parse");
            assert!(
                config.node_waypoint_pod_registry_dir.is_none(),
                "LocalPod without UDP capture must not publish a registry"
            );
        });
    }

    #[test]
    fn ambient_udp_registry_requires_ebpf_fails_closed_on_iptables_fallback() {
        // Ambient UDP lifecycle + a configured registry + a node that
        // cannot run eBPF (would take the iptables `handle_fallback()` path) must
        // refuse startup: `handle_fallback()` never runs the pod watcher that
        // populates the registry, so producer startup or disabled stale-rule
        // cleanup would poll an empty directory (#2013).
        assert!(
            ambient_udp_registry_requires_ebpf(false, true, true),
            "no eBPF + configured Ambient lifecycle registry must fail closed"
        );

        // eBPF-capable nodes run `run_with_backend`, which publishes the
        // registry via the pod watcher — no need to refuse.
        assert!(
            !ambient_udp_registry_requires_ebpf(true, true, true),
            "eBPF-capable node publishes the registry; must not refuse"
        );

        // Disabled capture still runs the registry-dependent stale-rule cleanup,
        // so fallback must refuse rather than strand retained guards forever.
        assert!(ambient_udp_registry_requires_ebpf(false, true, true));

        // NodeWaypoint also has a registry-backed in-netns path, but its
        // established iptables fallback remains valid when Ambient lifecycle
        // cleanup is not selected.
        assert!(!ambient_udp_registry_requires_ebpf(false, false, true));

        // Without a configured registry directory there is nothing for the
        // producer or cleanup manager to poll, so there is no lifecycle to guard.
        assert!(
            !ambient_udp_registry_requires_ebpf(false, true, false),
            "no registry configured means no registry-dependent producer to protect"
        );
    }

    #[test]
    fn from_env_config_preserves_explicit_ipv6_include_for_node_waypoint() {
        let waypoint = EnvConfig {
            node_agent_proxy_mode: NodeAgentProxyMode::NodeWaypoint,
            ..EnvConfig::default()
        };
        with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_NAME", "node-a"),
                ("FERRUM_MESH_CAPTURE_INCLUDE_CIDRS", "10.0.0.0/8,fd00::/8"),
            ],
            || {
                let config = NodeAgentConfig::from_env_config(&waypoint)
                    .expect("node-agent config should parse");
                assert_eq!(
                    config.capture_config.include_cidrs,
                    vec!["10.0.0.0/8".to_string(), "fd00::/8".to_string()]
                );
            },
        );
    }

    #[test]
    fn node_agent_node_source_ips_parse_from_env() {
        with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_IP", "192.0.2.10"),
                (
                    "FERRUM_NODE_AGENT_NODE_IPS",
                    "192.0.2.11,fd00::10,fd00::11,192.0.2.10",
                ),
            ],
            || {
                let ips =
                    node_agent_node_source_ips_from_env().expect("node source IPs should parse");
                assert_eq!(
                    ips.ipv4,
                    vec![
                        std::net::Ipv4Addr::new(192, 0, 2, 10),
                        std::net::Ipv4Addr::new(192, 0, 2, 11)
                    ]
                );
                assert_eq!(
                    ips.ipv6,
                    vec![
                        "fd00::10".parse::<std::net::Ipv6Addr>().unwrap(),
                        "fd00::11".parse::<std::net::Ipv6Addr>().unwrap()
                    ]
                );
            },
        );
    }

    #[test]
    fn node_source_ips_extend_preserves_all_unique_addresses() {
        let mut ips = NodeSourceIps::default();
        ips.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)));
        ips.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::new(192, 0, 2, 10)));

        let mut discovered = NodeSourceIps::default();
        discovered.insert(std::net::IpAddr::V4(std::net::Ipv4Addr::new(10, 244, 1, 1)));
        discovered.insert(std::net::IpAddr::V6(
            "fd00::1".parse::<std::net::Ipv6Addr>().unwrap(),
        ));
        ips.extend(discovered);

        assert_eq!(
            ips.ipv4,
            vec![
                std::net::Ipv4Addr::new(192, 0, 2, 10),
                std::net::Ipv4Addr::new(10, 244, 1, 1),
            ]
        );
        assert_eq!(
            ips.ipv6,
            vec!["fd00::1".parse::<std::net::Ipv6Addr>().unwrap()]
        );
    }

    #[test]
    fn pod_probe_ports_from_spec_resolves_named_and_numeric_ports() {
        use k8s_openapi::api::core::v1::{
            ContainerPort, GRPCAction, HTTPGetAction, TCPSocketAction,
        };

        let spec = PodSpec {
            containers: vec![Container {
                name: "app".to_string(),
                ports: Some(vec![
                    ContainerPort {
                        name: Some("http".to_string()),
                        container_port: 8080,
                        protocol: Some("TCP".to_string()),
                        ..ContainerPort::default()
                    },
                    ContainerPort {
                        name: Some("metrics-udp".to_string()),
                        container_port: 9091,
                        protocol: Some("UDP".to_string()),
                        ..ContainerPort::default()
                    },
                ]),
                readiness_probe: Some(Probe {
                    http_get: Some(HTTPGetAction {
                        port: IntOrString::String("http".to_string()),
                        ..HTTPGetAction::default()
                    }),
                    ..Probe::default()
                }),
                liveness_probe: Some(Probe {
                    tcp_socket: Some(TCPSocketAction {
                        port: IntOrString::Int(9090),
                        ..TCPSocketAction::default()
                    }),
                    ..Probe::default()
                }),
                startup_probe: Some(Probe {
                    grpc: Some(GRPCAction {
                        port: 7070,
                        ..GRPCAction::default()
                    }),
                    ..Probe::default()
                }),
                ..Container::default()
            }],
            ..PodSpec::default()
        };

        assert_eq!(
            pod_probe_ports_from_spec(Some(&spec)),
            vec![7070, 8080, 9090]
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
                outbound_capture_enabled: true,
                include_cidrs: vec!["10.0.0.0/8".to_string()],
                include_cidrs_explicit: true,
                include_all_outbound_ports: false,
                include_outbound_ports: Vec::new(),
                exclude_cidrs: vec!["10.0.0.1/32".to_string()],
                exclude_ports: vec![15020],
                exclude_ports_explicit: true,
                exclude_inbound_ports: Vec::new(),
                ip6tables_mode: Ip6TablesMode::Auto,
                udp_capture_enabled: false,
                udp_outbound_port: crate::capture::DEFAULT_UDP_OUTBOUND_PORT,
                tproxy_mark: crate::capture::DEFAULT_TPROXY_MARK,
                host_netns: true,
            },
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };

        let mut backend = MockEbpfBackend::default();
        let metrics = NodeAgentMetrics::default();
        initialize_backend(&mut backend, &config, &metrics).unwrap();

        assert!(backend.programs_loaded);
        assert_eq!(backend.bypass_uids, vec![1337]);
        assert_eq!(backend.cidr_includes, vec!["10.0.0.0/8"]);
        assert_eq!(backend.cidr_excludes, vec!["10.0.0.1/32"]);
        assert_eq!(backend.port_excludes, vec![15020]);
        assert_eq!(
            backend.capture_config,
            Some(config.capture_contract.bpf_capture_config())
        );
        assert!(backend.sock_ops_attached_cgroup_root.is_none());
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[test]
    fn initialize_backend_attaches_sock_ops_for_node_waypoint() {
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.mode = CaptureMode::Ebpf;
        let mut config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        config.capture_contract.proxy_mode = NodeAgentProxyMode::NodeWaypoint;

        let mut backend = MockEbpfBackend::default();
        let metrics = NodeAgentMetrics::default();
        with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_IP", "192.0.2.10"),
                ("FERRUM_NODE_AGENT_NODE_IPS", "192.0.2.11,fd00::10"),
            ],
            || initialize_backend(&mut backend, &config, &metrics).unwrap(),
        );

        assert_eq!(
            backend.sock_ops_attached_cgroup_root.as_deref(),
            Some("/sys/fs/cgroup")
        );
        assert!(
            backend
                .node_ips
                .contains(&std::net::Ipv4Addr::new(192, 0, 2, 10))
        );
        assert!(
            backend
                .node_ips
                .contains(&std::net::Ipv4Addr::new(192, 0, 2, 11))
        );
        assert!(backend.node_ips6.contains(&"fd00::10".parse().unwrap()));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[test]
    fn initialize_backend_node_waypoint_sock_ops_failure_marks_degraded() {
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.mode = CaptureMode::Ebpf;
        let mut config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        config.capture_contract.proxy_mode = NodeAgentProxyMode::NodeWaypoint;
        let mut backend = MockEbpfBackend {
            fail_attach_sock_ops: true,
            ..MockEbpfBackend::default()
        };
        let metrics = NodeAgentMetrics::default();

        // Seed node source IPs so initialization reaches the sock-ops attach
        // branch under test rather than failing closed on the (separately
        // tested) empty trusted-node-source guard.
        let err = with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_IP", "192.0.2.10"),
                ("FERRUM_NODE_AGENT_NODE_IPS", "192.0.2.11,fd00::10"),
            ],
            || {
                initialize_backend(&mut backend, &config, &metrics)
                    .expect_err("missing identity bridge must fail startup")
            },
        );

        assert!(backend.sock_ops_attached_cgroup_root.is_none());
        assert!(err.to_string().contains("SOCK_OPS identity bridge"));
        assert_eq!(
            metrics.snapshot().topology_degraded_reason,
            Some("node_waypoint_sock_ops_unavailable")
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_IDENTITY_BRIDGE_UNAVAILABLE
        );
    }

    #[test]
    fn initialize_backend_node_waypoint_without_node_source_ip_fails_closed() {
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.mode = CaptureMode::Ebpf;
        let mut config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        config.capture_contract.proxy_mode = NodeAgentProxyMode::NodeWaypoint;

        let mut backend = MockEbpfBackend::default();
        let metrics = NodeAgentMetrics::default();

        // No trusted node source IP configured: NodeWaypoint must fail closed
        // (the source-bound guard would otherwise drop the relay's own dial and
        // all inbound to enrolled pods) instead of warning and continuing.
        let err = with_env_vars(
            &[
                ("FERRUM_NODE_AGENT_NODE_IP", ""),
                ("FERRUM_NODE_AGENT_NODE_IPS", ""),
            ],
            || {
                initialize_backend(&mut backend, &config, &metrics)
                    .expect_err("empty trusted node source must fail closed")
            },
        );

        assert!(err.to_string().contains("trusted node"));
        assert!(backend.node_ips.is_empty());
        assert!(backend.node_ips6.is_empty());
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_UNAVAILABLE
        );
    }

    #[test]
    fn initialize_backend_capture_config_failure_is_fatal() {
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.mode = CaptureMode::Ebpf;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let mut backend = MockEbpfBackend {
            fail_update_capture_config: true,
            ..MockEbpfBackend::default()
        };

        let metrics = NodeAgentMetrics::default();
        let err = initialize_backend(&mut backend, &config, &metrics)
            .expect_err("capture-config failure should abort initialization");

        assert!(err.to_string().contains("capture config update failed"));
        assert!(backend.programs_loaded);
        assert!(backend.capture_config.is_none());
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_UNAVAILABLE
        );
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
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080],
            },
        );
        pod_states.insert(
            "pod-2".to_string(),
            PodAttachmentState {
                pod_uid: "pod-2".to_string(),
                pod_name: "skipped-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: None,
                attached: false,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080],
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        cleanup_all_pods(&mut backend, &pod_states, &config);

        assert_eq!(backend.detached_pods.len(), 1);
        assert_eq!(backend.detached_pods[0], "pod-1");
        assert!(backend.cleaned_up);
    }

    #[test]
    fn cleanup_all_pods_removes_registry_and_ready_files() {
        // Shutdown must drop each enrolled pod's registry entry + readiness
        // markers so a mesh proxy that keeps running doesn't leak dead
        // in-netns listeners.
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let registry = tempfile::tempdir().unwrap();
        let ready_dir = registry.path().join(".ready");
        let ready4_dir = registry.path().join(".ready4");
        let ready6_dir = registry.path().join(".ready6");
        std::fs::create_dir_all(&ready_dir).unwrap();
        std::fs::create_dir_all(&ready4_dir).unwrap();
        std::fs::create_dir_all(&ready6_dir).unwrap();
        std::fs::write(registry.path().join("pod-x"), "/cg/x\n").unwrap();
        std::fs::write(ready_dir.join("pod-x"), b"").unwrap();
        std::fs::write(ready4_dir.join("pod-x"), b"").unwrap();
        std::fs::write(ready6_dir.join("pod-x"), b"").unwrap();
        pod_states.insert(
            "pod-x".to_string(),
            PodAttachmentState {
                pod_uid: "pod-x".to_string(),
                pod_name: "p".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: Some("/cg/x".to_string()),
                veth_iface: None,
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080],
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };

        cleanup_all_pods(&mut backend, &pod_states, &config);

        assert!(
            !registry.path().join("pod-x").exists(),
            "registry entry removed on shutdown"
        );
        assert!(
            !ready_dir.join("pod-x").exists(),
            "legacy ready marker removed on shutdown"
        );
        assert!(
            !ready4_dir.join("pod-x").exists(),
            "IPv4 ready marker removed on shutdown"
        );
        assert!(
            !ready6_dir.join("pod-x").exists(),
            "IPv6 ready marker removed on shutdown"
        );
        // Fail-closed on node-agent restart: `cleanup_all()` has already detached
        // the tc gate, so the not-ready ack must NOT be published here. Publishing
        // it would let a still-running mesh proxy tear its in-netns DROP guard down
        // into plaintext for pods that egress uncaptured until re-enrollment.
        assert!(
            !registry
                .path()
                .join(".udp-not-ready")
                .join("pod-x")
                .exists(),
            "shutdown must not ack UDP closure once the tc gate is already detached"
        );
    }

    #[test]
    fn cleanup_all_pods_withholds_udp_not_ready_ack_for_fail_closed_restart() {
        // Regression for the node-agent DaemonSet restart path: even with a stale
        // `.udp-ready` marker present (producer still live), shutdown teardown must
        // never write the `.udp-not-ready` ack, so the surviving producer times out
        // its ack wait and RETAINS its fail-closed in-netns guard rather than
        // reopening plaintext.
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let registry = tempfile::tempdir().unwrap();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 9);
        backend
            .update_pod_ip(ip, &PodInfo::for_capture(15001, true, true))
            .unwrap();
        let udp_ready_dir = registry.path().join(".udp-ready");
        std::fs::create_dir_all(&udp_ready_dir).unwrap();
        std::fs::write(udp_ready_dir.join("pod-udp"), b"").unwrap();
        pod_states.insert(
            "pod-udp".to_string(),
            PodAttachmentState {
                pod_uid: "pod-udp".to_string(),
                pod_name: "p".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: Some("/cg/u".to_string()),
                veth_iface: Some("veth-u".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };

        cleanup_all_pods(&mut backend, &pod_states, &config);

        assert!(
            !registry
                .path()
                .join(".udp-not-ready")
                .join("pod-udp")
                .exists(),
            "restart teardown must withhold the UDP not-ready ack (fail closed)"
        );
    }

    #[test]
    fn pod_ip_removal_retry_completes_udp_close_handoff() {
        for udp_capture_enabled in [true, false] {
            let registry = tempfile::tempdir().unwrap();
            let mut capture_config = CaptureConfig::explicit(15006, 15001);
            capture_config.udp_capture_enabled = udp_capture_enabled;
            let config = NodeAgentConfig {
                node_name: "test-node".to_string(),
                capture_config,
                cgroup_root: "/nonexistent".to_string(),
                bpf_fs_path: "/nonexistent".to_string(),
                fallback_mode: FallbackMode::Fail,
                excluded_namespaces: HashSet::new(),
                capture_contract: CaptureContract::local_pod_defaults(),
                trust_domain: "cluster.local".to_string(),
                node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
            };
            let ip = std::net::Ipv4Addr::new(10, 0, 0, 11);
            let pod_states = DashMap::new();
            pod_states.insert(
                "pod-udp".to_string(),
                PodAttachmentState {
                    pod_uid: "pod-udp".to_string(),
                    pod_name: "pod-udp".to_string(),
                    namespace: "default".to_string(),
                    pod_ip: Some(ip),
                    pod_ip6: None,
                    cgroup_path: Some("/cg/udp".to_string()),
                    veth_iface: Some("veth-udp".to_string()),
                    attached: true,
                    include_ports_cgroup_ids: Vec::new(),
                    include_ports_policy: None,
                    workload_identity_cgroup_ids: Vec::new(),
                    node_probe_ports: Vec::new(),
                },
            );
            let state_key = pod_state_key(&pod_states, "pod-udp");
            let mut backend = MockEbpfBackend {
                fail_remove_pod_ip: true,
                ..MockEbpfBackend::default()
            };
            backend
                .update_pod_ip(ip, &PodInfo::for_capture(15001, true, true))
                .unwrap();
            let metrics = NodeAgentMetrics::default();

            handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-udp");

            let required_dir = registry.path().join(".udp-ack-required");
            std::fs::create_dir_all(&required_dir).unwrap();
            std::fs::write(required_dir.join("pod-udp"), b"").unwrap();
            reconcile_removed_udp_close_acknowledgements(registry.path(), &pod_states, true);

            assert!(
                !registry
                    .path()
                    .join(".udp-not-ready")
                    .join("pod-udp")
                    .exists(),
                "failed BPF gate cleanup must not authorize producer teardown (udp_capture_enabled={udp_capture_enabled})"
            );
            assert!(
                !registry
                    .path()
                    .join(".udp-gate-cleaned")
                    .join("pod-udp")
                    .exists(),
                "failed cleanup must not leave durable proof that could authorize a later ack (udp_capture_enabled={udp_capture_enabled})"
            );
            assert_eq!(
                metrics.snapshot().capture_state,
                NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
            );

            backend.fail_remove_pod_ip = false;
            retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);

            let ack = registry.path().join(".udp-not-ready").join("pod-udp");
            let proof = registry.path().join(".udp-gate-cleaned").join("pod-udp");
            assert!(
                proof.is_file(),
                "recovered cleanup must persist proof (udp_capture_enabled={udp_capture_enabled})"
            );
            assert!(
                ack.is_file(),
                "recovered cleanup must publish an ack (udp_capture_enabled={udp_capture_enabled})"
            );
            assert!(!has_pending_removal_blocking_failure(&state_key));
            assert_eq!(
                metrics.snapshot().capture_state,
                NODE_AGENT_CAPTURE_STATE_READY
            );

            std::fs::remove_file(&ack).unwrap();
            reconcile_removed_udp_close_acknowledgements(registry.path(), &pod_states, true);
            assert!(
                ack.is_file(),
                "durable request must receive a replacement ack after retry recovery (udp_capture_enabled={udp_capture_enabled})"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn backed_off_enrollment_replay_preserves_and_merges_prior_cleanup_state() {
        let pod_states = DashMap::new();
        // Workload-identity enrollment validates Kubernetes pod UIDs as UUIDs.
        // Keep this replay fixture valid so the later attempt writes both
        // cgroup-backed maps before the injected tc attach failure.
        let pod_uid = "123e4567-e89b-12d3-a456-426614174000";
        let state_key = pod_state_key(&pod_states, pod_uid);
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 21);
        let cgroup_root = tempfile::tempdir().unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let cleanup_state = PodAttachmentState {
            pod_uid: pod_uid.to_string(),
            pod_name: pod_uid.to_string(),
            namespace: "default".to_string(),
            pod_ip: Some(ip),
            pod_ip6: None,
            cgroup_path: Some("/cg/first-attempt".to_string()),
            veth_iface: Some("veth-test".to_string()),
            attached: false,
            include_ports_cgroup_ids: vec![41],
            include_ports_policy: None,
            workload_identity_cgroup_ids: vec![42],
            node_probe_ports: vec![15021],
        };
        let mut retryable = test_retryable_enrollment(pod_uid, ip);
        retryable.labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        retryable.annotations = HashMap::from([(
            "ferrum.io/includeOutboundPorts".to_string(),
            "8080".to_string(),
        )]);
        remember_failed_pod_enrollment_with_cleanup_state(
            &state_key,
            test_failed_enrollment_signature(ip, Some("/cg/first-attempt")),
            retryable,
            &cleanup_state,
        );

        let metrics = NodeAgentMetrics::default();
        let mut backend = MockEbpfBackend::default();
        retry_backed_off_pod_enrollments(&mut backend, &pod_states, &config, &metrics, true);

        {
            let remembered = FAILED_POD_ENROLLMENT_ATTEMPTS.get(&state_key).unwrap();
            let remembered_cleanup = remembered.cleanup_state.as_ref().unwrap();
            assert_eq!(remembered_cleanup.include_ports_cgroup_ids, vec![41]);
            assert_eq!(remembered_cleanup.workload_identity_cgroup_ids, vec![42]);
            assert_eq!(remembered_cleanup.node_probe_ports, vec![15021]);
        }

        // A later replay reaches a different cgroup's BPF maps before failing.
        // Both attempts' exact cgroup keys must remain cleanup evidence.
        std::fs::create_dir_all(
            cgroup_root
                .path()
                .join("kubepods")
                .join(format!("pod{pod_uid}")),
        )
        .unwrap();
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth-test");
        backend.fail_attach_tc = true;
        retry_backed_off_pod_enrollments(&mut backend, &pod_states, &config, &metrics, true);

        let remembered = FAILED_POD_ENROLLMENT_ATTEMPTS.get(&state_key).unwrap();
        let remembered_cleanup = remembered.cleanup_state.as_ref().unwrap();
        assert!(remembered_cleanup.include_ports_cgroup_ids.contains(&41));
        assert!(remembered_cleanup.include_ports_cgroup_ids.len() > 1);
        assert!(
            remembered_cleanup
                .workload_identity_cgroup_ids
                .contains(&42)
        );
        assert!(remembered_cleanup.workload_identity_cgroup_ids.len() > 1);
        assert!(remembered_cleanup.node_probe_ports.contains(&15021));
        drop(remembered);
        forget_failed_pod_enrollment(&state_key);
    }

    #[test]
    fn pod_ip_removal_retry_withholds_udp_close_handoff_for_failed_live_enrollment() {
        let registry = tempfile::tempdir().unwrap();
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let pod_states = DashMap::new();
        let pod_uid = "pod-live-failed";
        let state_key = pod_state_key(&pod_states, pod_uid);
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 12);
        let mut backend = MockEbpfBackend::default();
        backend
            .update_pod_ip(ip, &PodInfo::for_capture(15001, true, true))
            .unwrap();
        let metrics = NodeAgentMetrics::default();

        let failed_cleanup_state = PodAttachmentState {
            pod_uid: pod_uid.to_string(),
            pod_name: pod_uid.to_string(),
            namespace: "default".to_string(),
            pod_ip: Some(ip),
            pod_ip6: None,
            cgroup_path: Some("/cg/live-failed".to_string()),
            veth_iface: Some("veth-live-failed".to_string()),
            attached: false,
            include_ports_cgroup_ids: Vec::new(),
            include_ports_policy: None,
            workload_identity_cgroup_ids: Vec::new(),
            node_probe_ports: Vec::new(),
        };
        remember_failed_pod_enrollment_with_cleanup_state(
            &state_key,
            PodEnrollmentAttemptSignature {
                namespace: "default".to_string(),
                service_account: None,
                pod_ip: Some(ip),
                pod_source_ips: PodSourceIps::default(),
                node_probe_ports: Vec::new(),
                cgroup_path: Some("/cg/live-failed".to_string()),
                veth_iface: Some("veth-live-failed".to_string()),
                labels_fingerprint: 0,
                annotations_fingerprint: 0,
            },
            RetryablePodEnrollment {
                pod_uid: pod_uid.to_string(),
                pod_name: pod_uid.to_string(),
                namespace: "default".to_string(),
                service_account: None,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                pod_ip: Some(ip.to_string()),
                pod_source_ips: PodSourceIps::default(),
                node_probe_ports: Vec::new(),
                pod_pid: None,
            },
            &failed_cleanup_state,
        );
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_IP_REMOVE,
            &ip.to_string(),
        );
        retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(
            has_failed_pod_enrollment_attempt(&state_key),
            "the live pod's failed enrollment retry record must still gate UDP close handoff"
        );
        assert!(
            !has_pending_removal_blocking_failure(&state_key),
            "the pre-enrollment pod-IP cleanup retry should still be cleared after recovery"
        );
        assert!(
            !registry
                .path()
                .join(".udp-gate-cleaned")
                .join(pod_uid)
                .exists(),
            "pre-enrollment cleanup retry must not mint removed-pod cleanup proof"
        );
        assert!(
            !registry
                .path()
                .join(".udp-not-ready")
                .join(pod_uid)
                .exists(),
            "pre-enrollment cleanup retry must not acknowledge UDP closure for a live failed pod"
        );

        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, pod_uid);

        assert!(!has_failed_pod_enrollment_attempt(&state_key));
        assert!(
            registry
                .path()
                .join(".udp-gate-cleaned")
                .join(pod_uid)
                .is_file(),
            "genuine removal must persist proof after re-verifying failed-enrollment cleanup"
        );
        assert!(
            registry
                .path()
                .join(".udp-not-ready")
                .join(pod_uid)
                .is_file(),
            "genuine removal must complete the suppressed close handoff"
        );
    }

    #[test]
    fn failed_enrollment_removal_retries_cleanup_before_udp_close_handoff() {
        let registry = tempfile::tempdir().unwrap();
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let pod_states = DashMap::new();
        let pod_uid = "pod-live-failed-remove-retry";
        let state_key = pod_state_key(&pod_states, pod_uid);
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 14);
        let metrics = NodeAgentMetrics::default();
        let mut backend = MockEbpfBackend::default();
        backend
            .update_pod_ip(ip, &PodInfo::for_capture(15001, true, true))
            .unwrap();
        let failed_cleanup_state = PodAttachmentState {
            pod_uid: pod_uid.to_string(),
            pod_name: pod_uid.to_string(),
            namespace: "default".to_string(),
            pod_ip: Some(ip),
            pod_ip6: None,
            cgroup_path: Some("/cg/live-failed-remove-retry".to_string()),
            veth_iface: Some("veth-live-failed-remove-retry".to_string()),
            attached: false,
            include_ports_cgroup_ids: Vec::new(),
            include_ports_policy: None,
            workload_identity_cgroup_ids: Vec::new(),
            node_probe_ports: Vec::new(),
        };
        remember_failed_pod_enrollment_with_cleanup_state(
            &state_key,
            PodEnrollmentAttemptSignature {
                namespace: "default".to_string(),
                service_account: None,
                pod_ip: Some(ip),
                pod_source_ips: PodSourceIps::default(),
                node_probe_ports: Vec::new(),
                cgroup_path: failed_cleanup_state.cgroup_path.clone(),
                veth_iface: failed_cleanup_state.veth_iface.clone(),
                labels_fingerprint: 0,
                annotations_fingerprint: 0,
            },
            RetryablePodEnrollment {
                pod_uid: pod_uid.to_string(),
                pod_name: pod_uid.to_string(),
                namespace: "default".to_string(),
                service_account: None,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                pod_ip: Some(ip.to_string()),
                pod_source_ips: PodSourceIps::default(),
                node_probe_ports: Vec::new(),
                pod_pid: None,
            },
            &failed_cleanup_state,
        );
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_IP_REMOVE,
            &ip.to_string(),
        );
        retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);
        assert!(!has_pending_removal_blocking_failure(&state_key));
        assert!(
            !registry
                .path()
                .join(".udp-gate-cleaned")
                .join(pod_uid)
                .exists()
        );

        backend.fail_remove_pod_ip = true;
        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, pod_uid);

        assert!(!has_failed_pod_enrollment_attempt(&state_key));
        assert!(has_pending_removal_blocking_failure(&state_key));
        assert!(
            !registry
                .path()
                .join(".udp-gate-cleaned")
                .join(pod_uid)
                .exists()
        );
        assert!(
            !registry
                .path()
                .join(".udp-not-ready")
                .join(pod_uid)
                .exists()
        );

        backend.fail_remove_pod_ip = false;
        retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(!has_pending_removal_blocking_failure(&state_key));
        assert!(
            registry
                .path()
                .join(".udp-gate-cleaned")
                .join(pod_uid)
                .is_file()
        );
        assert!(
            registry
                .path()
                .join(".udp-not-ready")
                .join(pod_uid)
                .is_file()
        );
    }

    #[test]
    fn failed_enrollment_cgroup_map_removal_retries_before_udp_close_handoff() {
        let registry = tempfile::tempdir().unwrap();
        let required_dir = registry.path().join(".udp-ack-required");
        std::fs::create_dir_all(&required_dir).unwrap();
        let pod_uid = "pod-cgroup-map-remove-retry";
        std::fs::write(required_dir.join(pod_uid), b"").unwrap();
        assert!(write_udp_gate_cleaned_proof(registry.path(), pod_uid));

        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let pod_states = DashMap::new();
        let state_key = pod_state_key(&pod_states, pod_uid);
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 22);
        let cleanup_state = PodAttachmentState {
            pod_uid: pod_uid.to_string(),
            pod_name: pod_uid.to_string(),
            namespace: "default".to_string(),
            pod_ip: None,
            pod_ip6: None,
            cgroup_path: Some("/cg/cgroup-map-remove-retry".to_string()),
            veth_iface: Some("veth-test".to_string()),
            attached: false,
            include_ports_cgroup_ids: vec![51],
            include_ports_policy: None,
            workload_identity_cgroup_ids: vec![52],
            node_probe_ports: Vec::new(),
        };
        remember_failed_pod_enrollment_with_cleanup_state(
            &state_key,
            test_failed_enrollment_signature(ip, Some("/cg/cgroup-map-remove-retry")),
            test_retryable_enrollment(pod_uid, ip),
            &cleanup_state,
        );
        let metrics = NodeAgentMetrics::default();
        let mut backend = MockEbpfBackend {
            fail_remove_pod_include_ports: true,
            fail_remove_workload_identity: true,
            ..MockEbpfBackend::default()
        };

        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, pod_uid);

        assert!(!has_failed_pod_enrollment_attempt(&state_key));
        assert!(has_pending_removal_blocking_failure(&state_key));
        let ack = registry.path().join(".udp-not-ready").join(pod_uid);
        assert!(
            !ack.exists(),
            "failed cgroup-map cleanup must withhold handoff"
        );

        // The failed-attempt record has been consumed, but the durable
        // responder must still reject the stale proof while either removal
        // failure remains pending.
        reconcile_removed_udp_close_acknowledgements(registry.path(), &pod_states, true);
        assert!(
            !ack.exists(),
            "pending cgroup-map cleanup must block stale-proof responder answers"
        );

        backend.fail_remove_pod_include_ports = false;
        backend.fail_remove_workload_identity = false;
        retry_pending_cgroup_map_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(!has_pending_removal_blocking_failure(&state_key));
        assert!(
            registry
                .path()
                .join(".udp-gate-cleaned")
                .join(pod_uid)
                .is_file(),
            "the final retry must persist fresh cleanup proof"
        );
        assert!(
            ack.is_file(),
            "the final retry must complete the close handoff"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[cfg(unix)]
    #[test]
    fn stale_cgroup_map_removal_retries_preserve_same_uid_reenrollment() {
        let pod_uid = "123e4567-e89b-12d3-a456-426614174000";
        let cgroup_root = tempfile::tempdir().unwrap();
        let cgroup_path = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        std::fs::create_dir_all(&cgroup_path).unwrap();
        let cgroup_ids = cgroup::collect_cgroup_tree_inodes(&cgroup_path);
        assert!(!cgroup_ids.is_empty());

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let pod_states = DashMap::new();
        let state_key = pod_state_key(&pod_states, pod_uid);
        let cleanup_state = PodAttachmentState {
            pod_uid: pod_uid.to_string(),
            pod_name: pod_uid.to_string(),
            namespace: "default".to_string(),
            pod_ip: None,
            pod_ip6: None,
            cgroup_path: Some(cgroup_path.to_string_lossy().to_string()),
            veth_iface: Some("veth-test".to_string()),
            attached: false,
            include_ports_cgroup_ids: cgroup_ids.clone(),
            include_ports_policy: Some(IncludePortsPolicy::all()),
            workload_identity_cgroup_ids: cgroup_ids.clone(),
            node_probe_ports: Vec::new(),
        };
        remember_failed_pod_enrollment_with_cleanup_state(
            &state_key,
            test_failed_enrollment_signature(
                std::net::Ipv4Addr::new(10, 0, 0, 31),
                cleanup_state.cgroup_path.as_deref(),
            ),
            test_retryable_enrollment(pod_uid, std::net::Ipv4Addr::new(10, 0, 0, 31)),
            &cleanup_state,
        );
        let mut backend = MockEbpfBackend {
            fail_remove_pod_include_ports: true,
            fail_remove_workload_identity: true,
            ..MockEbpfBackend::default()
        };
        for cgroup_id in &cgroup_ids {
            backend
                .update_pod_include_ports(*cgroup_id, &IncludePortsPolicy::all())
                .unwrap();
            backend
                .update_workload_identity(*cgroup_id, &crate::ebpf::WorkloadIdentity::unknown())
                .unwrap();
        }
        let metrics = NodeAgentMetrics::default();
        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, pod_uid);
        assert!(has_pending_removal_blocking_failure(&state_key));

        backend.fail_remove_pod_include_ports = false;
        backend.fail_remove_workload_identity = false;
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations = HashMap::from([(
            "ferrum.io/includeOutboundPorts".to_string(),
            "8080".to_string(),
        )]);
        let event = PodEvent {
            pod_uid,
            pod_name: "reenrolled-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.31"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.31")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-test"),
        };
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        assert!(pod_states.contains_key(pod_uid));

        retry_pending_cgroup_map_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(!has_pending_removal_blocking_failure(&state_key));
        for cgroup_id in &cgroup_ids {
            assert!(backend.include_ports.contains_key(cgroup_id));
            assert!(backend.workload_identities.contains_key(cgroup_id));
        }
        forget_pending_capture_failures_for_pod(&state_key);
    }

    #[test]
    fn tracked_cgroup_map_removal_failures_block_udp_handoff_until_retry() {
        let registry = tempfile::tempdir().unwrap();
        let pod_uid = "tracked-cgroup-map-remove-retry";
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let pod_states = DashMap::new();
        pod_states.insert(
            pod_uid.to_string(),
            PodAttachmentState {
                pod_uid: pod_uid.to_string(),
                pod_name: pod_uid.to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: Some("/cg/tracked-remove-retry".to_string()),
                veth_iface: Some("veth-test".to_string()),
                attached: true,
                include_ports_cgroup_ids: vec![71],
                include_ports_policy: Some(IncludePortsPolicy::all()),
                workload_identity_cgroup_ids: vec![72],
                node_probe_ports: Vec::new(),
            },
        );
        let state_key = pod_state_key(&pod_states, pod_uid);
        let mut backend = MockEbpfBackend {
            fail_remove_pod_include_ports: true,
            fail_remove_workload_identity: true,
            ..MockEbpfBackend::default()
        };
        backend
            .update_pod_include_ports(71, &IncludePortsPolicy::all())
            .unwrap();
        backend
            .update_workload_identity(72, &crate::ebpf::WorkloadIdentity::unknown())
            .unwrap();
        let metrics = NodeAgentMetrics::default();

        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, pod_uid);

        assert!(has_pending_removal_blocking_failure(&state_key));
        assert!(
            !registry
                .path()
                .join(".udp-gate-cleaned")
                .join(pod_uid)
                .exists()
        );
        assert!(
            !registry
                .path()
                .join(".udp-not-ready")
                .join(pod_uid)
                .exists()
        );

        backend.fail_remove_pod_include_ports = false;
        backend.fail_remove_workload_identity = false;
        retry_pending_cgroup_map_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(!has_pending_removal_blocking_failure(&state_key));
        assert!(!backend.include_ports.contains_key(&71));
        assert!(!backend.workload_identities.contains_key(&72));
        assert!(
            registry
                .path()
                .join(".udp-gate-cleaned")
                .join(pod_uid)
                .is_file()
        );
        assert!(
            registry
                .path()
                .join(".udp-not-ready")
                .join(pod_uid)
                .is_file()
        );
    }

    #[test]
    fn removed_udp_ack_responder_withholds_stale_proof_for_failed_live_enrollment() {
        let registry = tempfile::tempdir().unwrap();
        let required_dir = registry.path().join(".udp-ack-required");
        std::fs::create_dir_all(&required_dir).unwrap();
        let pod_uid = "pod-live-failed";
        std::fs::write(required_dir.join(pod_uid), b"").unwrap();
        assert!(write_udp_gate_cleaned_proof(registry.path(), pod_uid));

        let pod_states = DashMap::new();
        let state_key = pod_state_key(&pod_states, pod_uid);
        remember_failed_pod_enrollment(
            &state_key,
            PodEnrollmentAttemptSignature {
                namespace: "default".to_string(),
                service_account: None,
                pod_ip: Some(std::net::Ipv4Addr::new(10, 0, 0, 13)),
                pod_source_ips: PodSourceIps::default(),
                node_probe_ports: Vec::new(),
                cgroup_path: Some("/cg/live-failed".to_string()),
                veth_iface: Some("veth-live-failed".to_string()),
                labels_fingerprint: 0,
                annotations_fingerprint: 0,
            },
            RetryablePodEnrollment {
                pod_uid: pod_uid.to_string(),
                pod_name: pod_uid.to_string(),
                namespace: "default".to_string(),
                service_account: None,
                labels: HashMap::new(),
                annotations: HashMap::new(),
                pod_ip: Some("10.0.0.13".to_string()),
                pod_source_ips: PodSourceIps::default(),
                node_probe_ports: Vec::new(),
                pod_pid: None,
            },
        );

        reconcile_removed_udp_close_acknowledgements(registry.path(), &pod_states, true);

        let ack = registry.path().join(".udp-not-ready").join(pod_uid);
        assert!(
            !ack.exists(),
            "stale cleanup proof must not authorize an ack for a live pod with failed enrollment"
        );

        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        handle_pod_removed(
            &mut MockEbpfBackend::default(),
            &pod_states,
            &config,
            &NodeAgentMetrics::default(),
            pod_uid,
        );
        assert!(
            !has_failed_pod_enrollment_attempt(&state_key),
            "pod removal must forget the failed enrollment attempt"
        );

        reconcile_removed_udp_close_acknowledgements(registry.path(), &pod_states, true);
        assert!(
            ack.is_file(),
            "the responder must acknowledge the durable request once the pod is genuinely removed"
        );
    }

    #[test]
    fn pod_ip_retry_waits_for_pending_detach_before_udp_handoff() {
        let registry = tempfile::tempdir().unwrap();
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let pod_states = DashMap::new();
        let state_key = pod_state_key(&pod_states, "pod-udp");
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 13);
        let metrics = NodeAgentMetrics::default();
        let mut backend = MockEbpfBackend::default();
        backend
            .update_pod_ip(ip, &PodInfo::for_capture(15001, true, true))
            .unwrap();
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_IP_REMOVE,
            &ip.to_string(),
        );
        assert!(!record_removed_pod_detach_result(
            &state_key,
            "pod-udp",
            Err("injected detach failure".to_string()),
            &metrics,
        ));

        retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(has_pending_removal_blocking_failure(&state_key));
        assert!(
            !registry
                .path()
                .join(".udp-gate-cleaned")
                .join("pod-udp")
                .exists(),
            "pod-IP recovery must not mint proof while detach remains pending"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED,
            "a pending detach must keep the node honestly degraded"
        );

        retry_pending_pod_detaches(&mut backend, &pod_states, &config, &metrics);

        assert!(!has_pending_removal_blocking_failure(&state_key));
        assert_eq!(backend.detached_pods, vec!["pod-udp"]);
        assert!(
            registry
                .path()
                .join(".udp-gate-cleaned")
                .join("pod-udp")
                .is_file()
        );
        assert!(
            registry
                .path()
                .join(".udp-not-ready")
                .join("pod-udp")
                .is_file()
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[test]
    fn removed_pod_close_request_republishes_ack_after_verified_cleanup() {
        for udp_capture_enabled in [true, false] {
            let registry = tempfile::tempdir().unwrap();
            let mut capture_config = CaptureConfig::explicit(15006, 15001);
            capture_config.udp_capture_enabled = udp_capture_enabled;
            let config = NodeAgentConfig {
                node_name: "test-node".to_string(),
                capture_config,
                cgroup_root: "/nonexistent".to_string(),
                bpf_fs_path: "/nonexistent".to_string(),
                fallback_mode: FallbackMode::Fail,
                excluded_namespaces: HashSet::new(),
                capture_contract: CaptureContract::local_pod_defaults(),
                trust_domain: "cluster.local".to_string(),
                node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
            };
            let ip = std::net::Ipv4Addr::new(10, 0, 0, 12);
            let pod_states = DashMap::new();
            pod_states.insert(
                "pod-udp".to_string(),
                PodAttachmentState {
                    pod_uid: "pod-udp".to_string(),
                    pod_name: "pod-udp".to_string(),
                    namespace: "default".to_string(),
                    pod_ip: Some(ip),
                    pod_ip6: None,
                    cgroup_path: Some("/cg/udp".to_string()),
                    veth_iface: Some("veth-udp".to_string()),
                    attached: true,
                    include_ports_cgroup_ids: Vec::new(),
                    include_ports_policy: None,
                    workload_identity_cgroup_ids: Vec::new(),
                    node_probe_ports: Vec::new(),
                },
            );
            let mut backend = MockEbpfBackend::default();
            backend
                .update_pod_ip(ip, &PodInfo::for_capture(15001, true, true))
                .unwrap();
            let metrics = NodeAgentMetrics::default();

            handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-udp");

            let ack = registry.path().join(".udp-not-ready").join("pod-udp");
            assert!(
                ack.is_file(),
                "verified removal must publish an ack (udp_capture_enabled={udp_capture_enabled})"
            );
            assert!(
                registry
                    .path()
                    .join(".udp-gate-cleaned")
                    .join("pod-udp")
                    .is_file(),
                "verified removal must persist proof (udp_capture_enabled={udp_capture_enabled})"
            );
            std::fs::remove_file(&ack).unwrap();
            let required_dir = registry.path().join(".udp-ack-required");
            std::fs::create_dir_all(&required_dir).unwrap();
            std::fs::write(required_dir.join("pod-udp"), b"").unwrap();

            reconcile_udp_capture_readiness(
                &mut backend,
                &pod_states,
                &config,
                &metrics,
                &mut HashSet::new(),
            );

            assert!(
                ack.is_file(),
                "the producer's fresh request must receive a replacement ack after verified removal (udp_capture_enabled={udp_capture_enabled})"
            );
        }
    }

    #[test]
    fn restart_recovers_removed_pod_ack_from_durable_cleaned_gate_proof() {
        let registry = tempfile::tempdir().unwrap();
        let required_dir = registry.path().join(".udp-ack-required");
        std::fs::create_dir_all(&required_dir).unwrap();
        std::fs::write(required_dir.join("pod-gone"), b"").unwrap();
        assert!(write_udp_gate_cleaned_proof(registry.path(), "pod-gone"));
        let pod_states = DashMap::new();

        reconcile_removed_udp_close_acknowledgements(registry.path(), &pod_states, true);
        for marker_dir in [".udp-gate-cleaned", ".udp-ack-required", ".udp-not-ready"] {
            reap_orphaned_udp_handshake_markers_older_than(
                registry.path(),
                marker_dir,
                &pod_states,
                true,
                UDP_HANDSHAKE_ORPHAN_GRACE,
            );
        }

        assert!(
            registry
                .path()
                .join(".udp-not-ready")
                .join("pod-gone")
                .is_file(),
            "a restarted node-agent must answer the durable request from its verified cleanup proof"
        );
        assert!(
            required_dir.join("pod-gone").is_file()
                && registry
                    .path()
                    .join(".udp-gate-cleaned")
                    .join("pod-gone")
                    .is_file(),
            "the verified handoff must survive reaping below its restart-recovery retention"
        );

        // A zero base age injects an already-expired verified retention without
        // sleeping or mutating filesystem timestamps.
        for marker_dir in [".udp-gate-cleaned", ".udp-ack-required", ".udp-not-ready"] {
            reap_orphaned_udp_handshake_markers_older_than(
                registry.path(),
                marker_dir,
                &pod_states,
                true,
                std::time::Duration::ZERO,
            );
        }
        assert!(
            !registry
                .path()
                .join(".udp-not-ready")
                .join("pod-gone")
                .exists()
                && !required_dir.join("pod-gone").exists()
                && !registry
                    .path()
                    .join(".udp-gate-cleaned")
                    .join("pod-gone")
                    .exists(),
            "the verified handoff must be reaped after its bounded retention expires"
        );
    }

    #[test]
    fn existing_removed_pod_ack_is_not_rewritten() {
        let registry = tempfile::tempdir().unwrap();
        let required_dir = registry.path().join(".udp-ack-required");
        let ack_dir = registry.path().join(".udp-not-ready");
        std::fs::create_dir_all(&required_dir).unwrap();
        std::fs::create_dir_all(&ack_dir).unwrap();
        std::fs::write(required_dir.join("pod-gone"), b"").unwrap();
        assert!(write_udp_gate_cleaned_proof(registry.path(), "pod-gone"));
        let ack = ack_dir.join("pod-gone");
        std::fs::write(&ack, b"").unwrap();
        let modified_before = std::fs::metadata(&ack).unwrap().modified().unwrap();
        std::thread::sleep(std::time::Duration::from_millis(20));

        reconcile_removed_udp_close_acknowledgements(registry.path(), &DashMap::new(), true);

        assert_eq!(
            std::fs::metadata(&ack).unwrap().modified().unwrap(),
            modified_before,
            "an existing ack must not consume responder budget or churn its mtime"
        );
    }

    #[test]
    fn verified_udp_handoff_drains_request_and_proof_before_ack_grace() {
        let registry = tempfile::tempdir().unwrap();
        let required = registry.path().join(".udp-ack-required").join("pod-gone");
        let ack = registry.path().join(".udp-not-ready").join("pod-gone");
        std::fs::create_dir_all(required.parent().unwrap()).unwrap();
        std::fs::create_dir_all(ack.parent().unwrap()).unwrap();
        std::fs::write(&required, b"").unwrap();
        std::fs::write(&ack, b"").unwrap();
        assert!(write_udp_gate_cleaned_proof(registry.path(), "pod-gone"));
        let pod_states = DashMap::new();

        for marker_dir in [".udp-gate-cleaned", ".udp-ack-required"] {
            reap_orphaned_udp_handshake_markers_older_than(
                registry.path(),
                marker_dir,
                &pod_states,
                true,
                std::time::Duration::ZERO,
            );
        }

        assert!(!required.exists());
        assert!(
            !registry
                .path()
                .join(".udp-gate-cleaned")
                .join("pod-gone")
                .exists()
        );
        reap_orphaned_udp_handshake_markers_older_than(
            registry.path(),
            ".udp-not-ready",
            &pod_states,
            true,
            UDP_HANDSHAKE_ORPHAN_GRACE,
        );
        assert!(
            ack.exists(),
            "the TTL transition must refresh the ack for one final unverified grace"
        );

        reap_orphaned_udp_handshake_markers_older_than(
            registry.path(),
            ".udp-not-ready",
            &pod_states,
            true,
            std::time::Duration::ZERO,
        );
        assert!(!ack.exists(), "the final ack grace must still converge");
    }

    #[test]
    fn unsynced_pod_preserves_udp_ack_requirement() {
        let registry = tempfile::tempdir().unwrap();
        let required_dir = registry.path().join(".udp-ack-required");
        std::fs::create_dir_all(&required_dir).unwrap();
        std::fs::write(required_dir.join("pod-unknown"), b"").unwrap();
        let pod_states = DashMap::new();

        reap_orphaned_udp_handshake_markers_older_than(
            registry.path(),
            ".udp-ack-required",
            &pod_states,
            false,
            std::time::Duration::ZERO,
        );

        assert!(
            required_dir.join("pod-unknown").exists(),
            "an un-synced pod is uncertain, so its durable ack requirement must survive"
        );
    }

    #[test]
    fn reconcile_reaps_orphaned_udp_not_ready_acks() {
        // A pod that enrolled and then left the node leaves a `.udp-not-ready/<uid>`
        // ack that no reconcile revisits; without reaping these accumulate one inode
        // per pod ever seen. A fresh ack must survive the normal reconcile grace so
        // the proxy's slower registry poll can consume it; the age-qualified sweep
        // then drops departed UIDs while preserving still-present pods.
        let registry = tempfile::tempdir().unwrap();
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let ack_dir = registry.path().join(".udp-not-ready");
        std::fs::create_dir_all(&ack_dir).unwrap();
        // Ack for a live, still-tracked pod (must survive) and for two departed pods.
        std::fs::write(ack_dir.join("pod-live"), b"").unwrap();
        std::fs::write(ack_dir.join("pod-gone-1"), b"").unwrap();
        std::fs::write(ack_dir.join("pod-gone-2"), b"").unwrap();
        let required_dir = registry.path().join(".udp-ack-required");
        std::fs::create_dir_all(&required_dir).unwrap();
        std::fs::write(required_dir.join("pod-gone-1"), b"").unwrap();

        let ip = std::net::Ipv4Addr::new(10, 0, 0, 7);
        let pod_states = DashMap::new();
        pod_states.insert(
            "pod-live".to_string(),
            PodAttachmentState {
                pod_uid: "pod-live".to_string(),
                pod_name: "pod-live".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: Some("/cg/live".to_string()),
                veth_iface: Some("veth-live".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        let mut backend = MockEbpfBackend::default();
        backend
            .update_pod_ip(ip, &pod_map_info(&config, false))
            .unwrap();
        let mut ready_uids = HashSet::new();
        let metrics = NodeAgentMetrics::default();

        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );

        assert!(
            ack_dir.join("pod-live").exists(),
            "ack for a still-tracked pod must be preserved"
        );
        assert!(
            ack_dir.join("pod-gone-1").exists() && ack_dir.join("pod-gone-2").exists(),
            "fresh pod-removal acks must survive long enough for the proxy poll"
        );

        reap_orphaned_udp_handshake_markers_older_than(
            registry.path(),
            ".udp-not-ready",
            &pod_states,
            true,
            std::time::Duration::ZERO,
        );
        assert!(
            !ack_dir.join("pod-gone-1").exists(),
            "orphaned ack for a departed pod must be reaped"
        );
        assert!(
            !ack_dir.join("pod-gone-2").exists(),
            "orphaned ack for a departed pod must be reaped"
        );
        reap_orphaned_udp_handshake_markers_older_than(
            registry.path(),
            ".udp-ack-required",
            &pod_states,
            true,
            std::time::Duration::ZERO,
        );
        assert!(
            !required_dir.join("pod-gone-1").exists(),
            "orphaned durable ack requirement must be reaped"
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_waypoint_disabled_outbound_skips_connect_redirect() {
        // FERRUM_MESH_OUTBOUND_LISTEN_ADDR port 0 disables outbound capture: the
        // node-agent must NOT attach connect4/connect6 (egress would otherwise be
        // rewritten to a dead loopback port), but inbound getpeername still attaches.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "pod-uid-noout";
        std::fs::create_dir_all(cgroup_root.path().join(format!("kubepods/pod{pod_uid}"))).unwrap();
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.outbound_capture_enabled = false;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let attached: Vec<&str> = backend
            .cgroup_attachments
            .iter()
            .map(|(_, p)| p.as_str())
            .collect();
        assert!(
            !attached.contains(&"ferrum_connect4") && !attached.contains(&"ferrum_connect6"),
            "outbound redirect must not attach when outbound capture is disabled, got {attached:?}"
        );
        assert!(
            attached.contains(&"ferrum_getpeername4"),
            "inbound capture still attaches when outbound is disabled, got {attached:?}"
        );
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
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
            // The unconditional pre-setup UDP teardown (codex r4) always runs
            // first to reap stale UDP state from a prior UDP-enabled run, before
            // the current capture posture is (re)installed.
            vec!["pre-setup UDP teardown", "setup", "cleanup"]
        );
        // The degraded gauge must reflect the first-failing kernel
        // prerequisite even when iptables setup succeeded — operators rely
        // on it to filter dashboards by remediation type.
        assert_eq!(
            metrics.snapshot().topology_degraded_reason,
            Some("kernel_too_old"),
            "kernel-version failure should set the degraded gauge"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_NODE_GLOBAL_FALLBACK,
            "explicit iptables fallback should be observable as node-global fallback"
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
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
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_UNAVAILABLE
        );
        assert_eq!(
            *phases.lock().expect("phases mutex"),
            // The unconditional pre-setup UDP teardown (codex r4) always runs
            // first to reap stale UDP state from a prior UDP-enabled run, before
            // the current capture posture is (re)installed.
            vec!["pre-setup UDP teardown", "setup", "cleanup"]
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
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_UNAVAILABLE,
        );
    }

    #[test]
    fn cleanup_commands_try_ipv6_teardown_when_ip6tables_disabled() {
        let commands = cleanup_commands_for_plan(true, false);

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
        let commands = cleanup_commands_for_plan(true, false);

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
    fn cleanup_emits_v6_ip_routing_unconditionally_not_ip6tables_gated() {
        // codex r3: the raw `ip -6 rule/route del` UDP routing teardown must be
        // emitted UNCONDITIONALLY (NOT wrapped in the `ip6tables` availability
        // probe) — `ip -6` can remove the fwmark rule + local route even when
        // `ip6tables` is missing, so gating it would leak routing state and keep
        // marked UDP diverting after shutdown.
        let commands = cleanup_commands_for_plan(true, true);

        // The v6 `ip -6 rule del`/`ip -6 route del` must appear as standalone
        // commands, NOT embedded inside an `if command -v ip6tables` wrapper.
        let v6_rule_del = commands
            .iter()
            .find(|cmd| cmd.contains("ip -6 rule del") && cmd.contains("lookup 33133"))
            .expect("v6 ip rule del must be present");
        assert!(
            !v6_rule_del.contains("ip6tables"),
            "v6 `ip -6 rule del` must not be wrapped in the ip6tables probe: {v6_rule_del}"
        );
        let v6_route_del = commands
            .iter()
            .find(|cmd| cmd.contains("ip -6 route del local ::/0 dev lo"))
            .expect("v6 ip route del must be present");
        assert!(
            !v6_route_del.contains("ip6tables"),
            "v6 `ip -6 route del` must not be wrapped in the ip6tables probe: {v6_route_del}"
        );
        // The IPv6 mangle-CHAIN teardown stays ip6tables-guarded (table ops).
        assert!(
            commands.iter().any(|cmd| cmd.contains("ip6tables")
                && cmd.contains("FERRUM_MESH_UDP")
                && cmd.contains("command -v ip6tables")),
            "v6 mangle-chain teardown should remain behind the ip6tables probe: {commands:?}"
        );
        // The IPv4 routing teardown is also emitted unconditionally (raw `ip`).
        assert!(
            commands.iter().any(|cmd| cmd.contains("ip rule del")
                && cmd.contains("lookup 33133")
                && !cmd.contains("ip6tables")),
            "v4 `ip rule del` routing teardown must be unconditional: {commands:?}"
        );
    }

    #[test]
    fn udp_pre_setup_teardown_is_unconditional_udp_only_and_v6_safe() {
        // codex r4 (finding #3): the node-agent runs a pre-setup UDP teardown
        // UNCONDITIONALLY (no `udp_capture_enabled` flag) so a prior
        // UDP-enabled-then-crashed run is cleaned even when the current config sets
        // `FERRUM_MESH_CAPTURE_UDP_ENABLED=false`. It must tear down ONLY the exact
        // Ferrum-owned UDP state (never the TCP nat chains) and keep the codex-r3
        // v6 discipline (raw `ip -6` routing unconditional; ip6tables-table guarded).
        let commands = udp_pre_setup_teardown_commands(true);

        // UDP mangle chains are torn down.
        assert!(
            commands
                .iter()
                .any(|c| c.contains("-t mangle") && c.contains("-X FERRUM_MESH_UDP_OUTBOUND")),
            "pre-setup teardown must delete the UDP mangle chains: {commands:?}"
        );
        // The fwmark rule is deleted by stable priority (mark-independent).
        assert!(
            commands.iter().any(|c| c.contains("ip rule del")
                && c.contains("priority 100")
                && c.contains("lookup 33133")
                && !c.contains("fwmark")
                && !c.contains("ip -6")),
            "pre-setup teardown must delete the v4 fwmark rule by priority: {commands:?}"
        );
        // It must NOT touch the TCP nat chains (those are rebuilt by setup).
        assert!(
            !commands
                .iter()
                .any(|c| c.contains("FERRUM_MESH_INBOUND") || c.contains("FERRUM_MESH_OUTBOUND")),
            "pre-setup UDP teardown must not touch the TCP nat chains: {commands:?}"
        );
        // The raw `ip -6` routing teardown is emitted unconditionally (codex r3).
        assert!(
            commands.iter().any(|c| c.contains("ip -6 rule del")
                && c.contains("lookup 33133")
                && !c.contains("ip6tables")),
            "pre-setup teardown must emit unconditional v6 `ip -6 rule del`: {commands:?}"
        );
        // The v6 mangle-chain teardown stays behind the ip6tables probe.
        assert!(
            commands.iter().any(|c| c.contains("ip6tables")
                && c.contains("FERRUM_MESH_UDP")
                && c.contains("command -v ip6tables")),
            "v6 mangle-chain teardown must stay ip6tables-guarded: {commands:?}"
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
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
            // The unconditional pre-setup UDP teardown (codex r4) always runs
            // first to reap stale UDP state from a prior UDP-enabled run, before
            // the current capture posture is (re)installed.
            vec!["pre-setup UDP teardown", "setup", "cleanup"]
        );
    }

    #[test]
    fn handle_pod_added_enrolls_matching_pod() {
        // PR #934 (commit 65606d87) requires the inbound tc attach to
        // succeed before enrollment is accepted; that means
        // `discover_veth_for_pod` must return `Some(_)`. Tests don't have
        // a real pod network namespace, so we use the test-only veth
        // override seam (`crate::ebpf::veth::tests::TestOverrideGuard`)
        // to feed the production path a stable interface name. The guard
        // is RAII-scoped — it restores the previous override on drop so
        // sibling tests stay isolated.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let state_key = pod_state_key(&pod_states, "pod-uid-1");
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_DETACH,
            CAPTURE_FAILURE_DETAIL_POD_DETACH,
        );
        metrics.set_capture_state(NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED);
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "8080")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
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
        assert!(!has_pending_removal_blocking_failure(&state_key));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY,
            "successful same-UID re-enrollment must supersede a stale detach blocker"
        );
    }

    #[test]
    fn handle_pod_added_closes_udp_guard_before_registry_publication() {
        for udp_capture_enabled in [true, false] {
            let mut backend = MockEbpfBackend::default();
            backend.load_programs().unwrap();
            let pod_states = DashMap::new();
            let metrics = NodeAgentMetrics::default();
            let cgroup_root = tempfile::tempdir().unwrap();
            std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-udp")).unwrap();
            let registry = tempfile::tempdir().unwrap();
            let ready_dir = registry.path().join(".udp-ready");
            let proof_dir = registry.path().join(".udp-gate-cleaned");
            std::fs::create_dir_all(&ready_dir).unwrap();
            std::fs::create_dir_all(&proof_dir).unwrap();
            std::fs::write(ready_dir.join("pod-udp"), b"stale").unwrap();
            std::fs::write(proof_dir.join("pod-udp"), b"stale").unwrap();
            let mut capture_config = CaptureConfig::explicit(15006, 15001);
            capture_config.udp_capture_enabled = udp_capture_enabled;
            let config = NodeAgentConfig {
                node_name: "test-node".to_string(),
                capture_config,
                cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
                bpf_fs_path: "/nonexistent".to_string(),
                fallback_mode: FallbackMode::Fail,
                excluded_namespaces: HashSet::new(),
                capture_contract: CaptureContract::local_pod_defaults(),
                trust_domain: "cluster.local".to_string(),
                node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
            };
            let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
            let annotations = HashMap::new();
            let event = PodEvent {
                pod_uid: "pod-udp",
                pod_name: "pod-udp",
                namespace: "default",
                service_account: None,
                labels: &labels,
                annotations: &annotations,
                pod_ip_str: Some("10.0.0.9"),
                pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.9")),
                node_probe_ports: Vec::new(),
                pod_pid: None,
                veth_iface_override: Some("veth-udp"),
            };

            handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

            assert!(registry.path().join("pod-udp").is_file());
            assert!(
                !ready_dir.join("pod-udp").exists(),
                "stale readiness must be cleared before re-enrollment (udp_capture_enabled={udp_capture_enabled})"
            );
            assert!(
                !proof_dir.join("pod-udp").exists(),
                "stale cleanup proof must be cleared before re-enrollment (udp_capture_enabled={udp_capture_enabled})"
            );
            let info = &backend.pod_ips[&"10.0.0.9".parse().unwrap()];
            assert_eq!(
                info.capture_flags & ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_ENABLED != 0,
                udp_capture_enabled
            );
            assert!(info.capture_flags & ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_READY == 0);
        }
    }

    #[test]
    fn handle_pod_added_retries_when_stale_udp_ready_marker_cannot_be_removed() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-udp-delete-fail"))
            .unwrap();
        let registry = tempfile::tempdir().unwrap();
        let marker = registry
            .path()
            .join(".udp-ready")
            .join("pod-udp-delete-fail");
        std::fs::create_dir_all(&marker).unwrap();
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations = HashMap::new();
        let event = PodEvent {
            pod_uid: "pod-udp-delete-fail",
            pod_name: "pod-udp-delete-fail",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.10"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.10")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-udp"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state_key = pod_state_key(&pod_states, event.pod_uid);
        assert!(FAILED_POD_ENROLLMENT_ATTEMPTS.contains_key(&state_key));
        assert!(!pod_states.contains_key(event.pod_uid));
        assert!(!registry.path().join(event.pod_uid).exists());
        forget_failed_pod_enrollment(&state_key);
    }

    #[test]
    fn handle_pod_added_uses_status_pod_ips_ipv4_when_primary_is_ipv6() {
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-v6-primary")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations = HashMap::new();
        let event = PodEvent {
            pod_uid: "pod-uid-v6-primary",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("fd00::5"),
            pod_source_ips: PodSourceIps {
                ipv4: Some("10.0.0.5".parse().unwrap()),
                ipv6: Some("fd00::5".parse().unwrap()),
            },
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let ipv4 = std::net::Ipv4Addr::new(10, 0, 0, 5);
        let ipv6 = "fd00::5".parse().unwrap();
        assert_eq!(
            pod_states.get("pod-uid-v6-primary").unwrap().pod_ip,
            Some(ipv4)
        );
        assert_eq!(
            pod_states.get("pod-uid-v6-primary").unwrap().pod_ip6,
            Some(ipv6)
        );
        assert!(
            backend.pod_ips.contains_key(&ipv4),
            "IPv4 FERRUM_POD_IPS map entry should use status.podIPs when status.podIP is IPv6"
        );
        assert!(
            backend.pod_ips6.contains_key(&ipv6),
            "IPv6 FERRUM_POD_IPS6 map entry should be enrolled for dual-stack pods"
        );
    }

    #[cfg(unix)]
    #[test]
    fn handle_pod_added_node_waypoint_missing_family_source_reports_degraded() {
        // Dual-stack regression: with only an IPv4 node source IP configured,
        // enrolling a pod that also has an IPv6 address must surface the missing
        // IPv6 node source (whose inbound relay dial the source-bound guard would
        // drop) as degraded instead of reporting healthy.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        // Trust an IPv4 node source IP only; leave IPv6 unconfigured.
        backend
            .update_node_ip("192.0.2.10".parse().unwrap())
            .unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "pod-uid-dualstack";
        std::fs::create_dir_all(cgroup_root.path().join(format!("kubepods/pod{pod_uid}"))).unwrap();
        let registry = tempfile::tempdir().unwrap();
        let mut config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        config.capture_contract.proxy_mode = NodeAgentProxyMode::NodeWaypoint;
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "8080")]);
        let pod_source_ips = PodSourceIps {
            ipv4: Some("10.0.0.5".parse().unwrap()),
            ipv6: Some("fd00::5".parse().unwrap()),
        };
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips,
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        // The pod still enrolls (the guard stays active for the configured
        // family), but the missing IPv6 source is surfaced as degraded.
        assert!(pod_states.contains_key(pod_uid), "pod still enrolls");
        assert_eq!(
            metrics.snapshot().topology_degraded_reason,
            Some("node_waypoint_node_source_ipv6_missing"),
            "a dual-stack pod with no IPv6 node source must report the IPv6 gap as degraded"
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_waypoint_attaches_redirects_at_enrollment() {
        // In-netns NodeWaypoint mode still publishes the pod registry for the
        // proxy listener, but cgroup enforcement must be active before enrollment
        // returns. Delaying connect4 creates a startup egress bypass; attaching
        // it immediately is fail-closed until the pod-loopback listener is ready.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "pod-uid-enforce";
        std::fs::create_dir_all(cgroup_root.path().join(format!("kubepods/pod{pod_uid}"))).unwrap();
        let registry = tempfile::tempdir().unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "8080")]);
        let pod_source_ips = PodSourceIps {
            ipv4: Some("10.0.0.5".parse().unwrap()),
            ipv6: Some("fd00::5".parse().unwrap()),
        };
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips,
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(pod_states.contains_key(pod_uid), "pod is enrolled");
        let attached: Vec<&str> = backend
            .cgroup_attachments
            .iter()
            .map(|(_, prog)| prog.as_str())
            .collect();
        assert!(
            attached.contains(&"ferrum_connect4"),
            "connect4 must attach during enrollment so IPv4 egress cannot bypass mesh_authz, got {attached:?}"
        );
        let include_write = backend
            .operations
            .iter()
            .position(|op| op.starts_with("update_pod_include_ports:"))
            .expect("includeOutboundPorts map must be written");
        let connect4_attach = backend
            .operations
            .iter()
            .position(|op| op == "attach_cgroup:ferrum_connect4")
            .expect("connect4 must attach");
        assert!(
            include_write < connect4_attach,
            "includeOutboundPorts policy must be seeded before connect4 is active, got {:?}",
            backend.operations
        );
        assert!(
            attached.contains(&"ferrum_connect6"),
            "connect6 attaches immediately so IPv6 egress cannot bypass mesh_authz, got {attached:?}"
        );
        assert!(
            attached.contains(&"ferrum_getpeername4") && attached.contains(&"ferrum_getpeername6"),
            "inbound getpeername programs attach immediately, got {attached:?}"
        );
        assert_eq!(
            std::fs::read_to_string(registry.path().join(pod_uid)).unwrap(),
            format!(
                "{}\nspiffe_id=spiffe://cluster.local/ns/default/sa/default\nipv4=10.0.0.5\nipv6=fd00::5\n",
                cgroup_root
                    .path()
                    .join(format!("kubepods/pod{pod_uid}"))
                    .display()
            ),
            "capture registry must publish workload identity and family-specific pod source IPs"
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_waypoint_republishes_registry_when_source_ips_change() {
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "pod-uid-source-ips";
        let cgroup_path = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        std::fs::create_dir_all(&cgroup_path).unwrap();
        let registry = tempfile::tempdir().unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations = HashMap::new();
        let make_event = |source_ips: PodSourceIps| PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: source_ips,
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &make_event(PodSourceIps::from_primary_str(Some("10.0.0.5"))),
        );
        assert_eq!(
            std::fs::read_to_string(registry.path().join(pod_uid)).unwrap(),
            format!(
                "{}\nspiffe_id=spiffe://cluster.local/ns/default/sa/default\nipv4=10.0.0.5\n",
                cgroup_path.display()
            )
        );

        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &make_event(PodSourceIps {
                ipv4: Some("10.0.0.5".parse().unwrap()),
                ipv6: Some("fd00::5".parse().unwrap()),
            }),
        );

        assert_eq!(
            std::fs::read_to_string(registry.path().join(pod_uid)).unwrap(),
            format!(
                "{}\nspiffe_id=spiffe://cluster.local/ns/default/sa/default\nipv4=10.0.0.5\nipv6=fd00::5\n",
                cgroup_path.display()
            ),
            "same-UID status.podIPs updates must refresh IPv6 source overrides"
        );
    }

    #[cfg(unix)]
    #[test]
    fn node_waypoint_reenrollment_attaches_redirect_immediately() {
        // A same-UID re-enroll (sandbox/veth change) detaches and then reattaches
        // the redirect as part of the new enrollment; no asynchronous promotion
        // ledger is needed to restore enforcement.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "pod-uid-reenroll";
        std::fs::create_dir_all(cgroup_root.path().join(format!("kubepods/pod{pod_uid}"))).unwrap();
        let registry = tempfile::tempdir().unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations = HashMap::new();
        let make_event = |veth: &'static str| PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some(veth),
        };
        let connect4_count = |b: &MockEbpfBackend| {
            b.cgroup_attachments
                .iter()
                .filter(|(_, p)| p == "ferrum_connect4")
                .count()
        };

        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &make_event("veth-A"),
        );
        assert_eq!(
            connect4_count(&backend),
            1,
            "connect4 attached during first enrollment"
        );

        handle_pod_added(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &make_event("veth-B"),
        );
        assert_eq!(
            connect4_count(&backend),
            2,
            "connect4 reattaches immediately during same-UID re-enrollment"
        );
    }

    #[test]
    fn handle_pod_removed_clears_readiness_marker() {
        // Pod teardown must drop the proxy's readiness markers too, so a
        // same-UID re-enroll can't see stale readiness for torn-down listeners.
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let registry = tempfile::tempdir().unwrap();
        let ready_dir = registry.path().join(".ready");
        let ready4_dir = registry.path().join(".ready4");
        let ready6_dir = registry.path().join(".ready6");
        std::fs::create_dir_all(&ready_dir).unwrap();
        std::fs::create_dir_all(&ready4_dir).unwrap();
        std::fs::create_dir_all(&ready6_dir).unwrap();
        let marker = ready_dir.join("pod-x");
        let marker4 = ready4_dir.join("pod-x");
        let marker6 = ready6_dir.join("pod-x");
        std::fs::write(&marker, b"").unwrap();
        std::fs::write(&marker4, b"").unwrap();
        std::fs::write(&marker6, b"").unwrap();
        std::fs::write(registry.path().join("pod-x"), "/cg/x\n").unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };

        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-x");

        assert!(
            !registry.path().join("pod-x").exists(),
            "registry entry removed on teardown"
        );
        assert!(
            !marker.exists(),
            "legacy readiness marker removed on pod teardown"
        );
        assert!(
            !marker4.exists(),
            "IPv4 readiness marker removed on pod teardown"
        );
        assert!(
            !marker6.exists(),
            "IPv6 readiness marker removed on pod teardown"
        );
    }

    #[cfg(unix)]
    #[test]
    fn handle_pod_added_enrolls_identity_under_container_cgroup_leaves() {
        use std::os::unix::fs::MetadataExt;

        // Regression for the leaf-vs-pod cgroup bug (P1): the connect hook reads
        // `bpf_get_current_cgroup_id()`, which is the *container* leaf cgroup —
        // a child of the pod cgroup — so the node-agent must write
        // FERRUM_WORKLOAD_IDENTITY under the container cgroup inodes, not only
        // the pod cgroup inode, or the hook's lookup misses and node-waypoint
        // resolution fails closed in real pods.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        let cgroup_root = tempfile::tempdir().unwrap();
        // A valid UUID so the SPIFFE identity builds; cgroupfs driver layout.
        let pod_uid = "11111111-1111-1111-1111-111111111111";
        let pod_cgroup = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        let container_cgroup = pod_cgroup.join("crio-abc123.scope");
        std::fs::create_dir_all(&container_cgroup).unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: Some("api"),
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let pod_ino = std::fs::metadata(&pod_cgroup).unwrap().ino();
        let container_ino = std::fs::metadata(&container_cgroup).unwrap().ino();

        // The container leaf inode — the id the connect hook actually looks up —
        // must carry the identity, alongside the pod inode.
        assert!(
            backend.workload_identities.contains_key(&container_ino),
            "identity must be enrolled under the container (leaf) cgroup inode"
        );
        assert!(
            backend.workload_identities.contains_key(&pod_ino),
            "identity must also be enrolled under the pod cgroup inode"
        );
        // It is a real derived identity, not the all-zero fail-closed sentinel.
        let identity = backend.workload_identities.get(&container_ino).unwrap();
        assert_ne!(identity.pod_uid, [0u8; 16]);
        assert_ne!(identity.workload_spiffe_hash, 0);

        let state = pod_states.get(pod_uid).unwrap();
        assert!(state.workload_identity_cgroup_ids.contains(&container_ino));
        assert!(state.workload_identity_cgroup_ids.contains(&pod_ino));
    }

    #[cfg(unix)]
    #[test]
    fn reconcile_removes_stale_container_cgroup_identity_on_restart() {
        use std::os::unix::fs::MetadataExt;

        // Regression: a container restart replaces its leaf cgroup with a fresh
        // inode. Reconcile must drop the old leaf's FERRUM_WORKLOAD_IDENTITY
        // entry (from both the BPF map and state) and not just append the new
        // one, or stale entries accumulate in the fixed-size map across restarts
        // and eventually fail other pods' enrollments.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "11111111-1111-1111-1111-111111111111";
        let pod_cgroup = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        let container1 = pod_cgroup.join("crio-aaaa.scope");
        std::fs::create_dir_all(&container1).unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: Some("api"),
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        // Initial enrollment writes the pod inode + container1's leaf inode.
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        let container1_ino = std::fs::metadata(&container1).unwrap().ino();
        let pod_ino = std::fs::metadata(&pod_cgroup).unwrap().ino();
        assert!(backend.workload_identities.contains_key(&container1_ino));

        // Container restarts: a new leaf cgroup appears. Create it *before*
        // removing the old one so the two inodes are guaranteed distinct (a
        // freed inode can be reused immediately by the next mkdir).
        let container2 = pod_cgroup.join("crio-bbbb.scope");
        std::fs::create_dir_all(&container2).unwrap();
        let container2_ino = std::fs::metadata(&container2).unwrap().ino();
        assert_ne!(container1_ino, container2_ino);
        std::fs::remove_dir(&container1).unwrap();

        // Same pod cgroup path → the reconcile branch runs.
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        // The new leaf is enrolled and the pod inode kept; the stale leaf is gone
        // from both the BPF map and the tracked id set.
        assert!(
            backend.workload_identities.contains_key(&container2_ino),
            "the restarted container's new leaf cgroup must be enrolled"
        );
        assert!(backend.workload_identities.contains_key(&pod_ino));
        assert!(
            !backend.workload_identities.contains_key(&container1_ino),
            "the restarted container's stale leaf cgroup entry must be removed"
        );
        let state = pod_states.get(pod_uid).unwrap();
        assert!(state.workload_identity_cgroup_ids.contains(&container2_ino));
        assert!(!state.workload_identity_cgroup_ids.contains(&container1_ino));
    }

    #[cfg(unix)]
    #[test]
    fn reconcile_skips_workload_identity_writes_when_cgroup_set_unchanged() {
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "22222222-2222-2222-2222-222222222222";
        let pod_cgroup = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        let container1 = pod_cgroup.join("crio-aaaa.scope");
        std::fs::create_dir_all(&container1).unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: Some("api"),
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        let identity_ops_after_enroll = backend
            .operations
            .iter()
            .filter(|op| op.starts_with("update_workload_identity:"))
            .count();
        assert!(identity_ops_after_enroll >= 2);

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        let identity_ops_after_unchanged_apply = backend
            .operations
            .iter()
            .filter(|op| op.starts_with("update_workload_identity:"))
            .count();
        assert_eq!(
            identity_ops_after_unchanged_apply, identity_ops_after_enroll,
            "unchanged Apply must skip the workload identity writes"
        );

        let container2 = pod_cgroup.join("crio-bbbb.scope");
        std::fs::create_dir_all(&container2).unwrap();
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let identity_ops_after_changed_apply = backend
            .operations
            .iter()
            .filter(|op| op.starts_with("update_workload_identity:"))
            .count();
        assert!(
            identity_ops_after_changed_apply > identity_ops_after_unchanged_apply,
            "new container cgroup must still trigger workload identity reconciliation"
        );
    }

    /// Regression: a container cgroup created *below an intermediate child*
    /// (a grandchild of the pod cgroup) must still trigger reconciliation even
    /// though the pod cgroup's direct children are unchanged. A shallow
    /// direct-children fingerprint would miss this and leave the new container
    /// without a `FERRUM_WORKLOAD_IDENTITY` entry (fail-closed).
    #[cfg(unix)]
    #[test]
    fn reconcile_workload_identity_detects_nested_grandchild_cgroup() {
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "33333333-3333-3333-3333-333333333333";
        let pod_cgroup = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        // Container lives under an intermediate `burstable` QoS child, so the
        // pod cgroup's only direct child stays `burstable` across both Applies.
        let intermediate = pod_cgroup.join("burstable");
        std::fs::create_dir_all(intermediate.join("crio-aaaa.scope")).unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: Some("api"),
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.6"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.6")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        let ops_after_enroll = backend
            .operations
            .iter()
            .filter(|op| op.starts_with("update_workload_identity:"))
            .count();

        // Add a second container as another grandchild. Pod's direct children
        // ({burstable}) are unchanged, but the full descendant set grew.
        std::fs::create_dir_all(intermediate.join("crio-bbbb.scope")).unwrap();
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        let ops_after_grandchild = backend
            .operations
            .iter()
            .filter(|op| op.starts_with("update_workload_identity:"))
            .count();
        assert!(
            ops_after_grandchild > ops_after_enroll,
            "a deeply-nested (grandchild) container cgroup must trigger reconciliation"
        );
    }

    /// Regression: when enrollment writes some cgroups but the backend rejects
    /// one (e.g. a transient BPF map error), the missing entry must be retried
    /// on the next Apply with an unchanged tree, instead of being permanently
    /// skipped by a baseline that was seeded from the partial write.
    #[cfg(unix)]
    #[test]
    fn reconcile_workload_identity_retries_partial_write() {
        use std::os::unix::fs::MetadataExt;

        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend {
            // Fail exactly the first identity write (the pod cgroup root); the
            // container leaf write that follows succeeds.
            fail_workload_identity_writes: 1,
            ..MockEbpfBackend::default()
        };
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "44444444-4444-4444-4444-444444444444";
        let pod_cgroup = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        let container = pod_cgroup.join("crio-aaaa.scope");
        std::fs::create_dir_all(&container).unwrap();
        let pod_ino = std::fs::metadata(&pod_cgroup).unwrap().ino();
        let container_ino = std::fs::metadata(&container).unwrap().ino();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: Some("api"),
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.7"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.7")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        // Enrollment: the pod-root write fails, the container write succeeds.
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        assert!(
            backend.workload_identities.contains_key(&container_ino),
            "container cgroup should enroll despite the pod-root write failing"
        );
        assert!(
            !backend.workload_identities.contains_key(&pod_ino),
            "pod-root cgroup write was injected to fail on first enrollment"
        );

        // Next Apply over the same (unchanged) tree must retry the missing
        // pod-root write rather than treating the tree as fully enrolled.
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        assert!(
            backend.workload_identities.contains_key(&pod_ino),
            "partial workload-identity write must be retried on the next Apply"
        );
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-1"));
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_added_repeated_missing_cgroup_is_backed_off_but_late_cgroup_retries() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        assert_eq!(
            metrics.attach_errors.load(Ordering::Relaxed),
            1,
            "unchanged failed Apply should not inflate attach_errors during backoff"
        );

        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(pod_states.contains_key("pod-uid-1"));
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn retryable_pod_enrollment_reconstructs_equivalent_event() {
        // The owned snapshot stored for a failed enrollment must rebuild a
        // PodEvent that matches the original (minus the test-only veth override,
        // which production never sets and the retry path always re-resolves).
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations = HashMap::from([(
            "ferrum.io/include-outbound-ports".to_string(),
            "8080".to_string(),
        )]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "ns-a",
            service_account: Some("sa-a"),
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: vec![8080],
            pod_pid: Some(4242),
            veth_iface_override: Some("veth-mock"),
        };

        let snapshot = RetryablePodEnrollment::from_event(&event);
        let rebuilt = snapshot.as_event();

        assert_eq!(rebuilt.pod_uid, "pod-uid-1");
        assert_eq!(rebuilt.pod_name, "test-pod");
        assert_eq!(rebuilt.namespace, "ns-a");
        assert_eq!(rebuilt.service_account, Some("sa-a"));
        assert_eq!(rebuilt.labels, &labels);
        assert_eq!(rebuilt.annotations, &annotations);
        assert_eq!(rebuilt.pod_ip_str, Some("10.0.0.5"));
        assert_eq!(rebuilt.node_probe_ports, vec![8080]);
        assert_eq!(rebuilt.pod_pid, Some(4242));
        // Production re-resolves the veth on every retry, so the snapshot never
        // carries the override.
        assert_eq!(rebuilt.veth_iface_override, None);
    }

    #[test]
    fn backed_off_pod_enrollment_is_retried_after_backoff_window() {
        // A transient inbound-tc attach failure lands AFTER the pod's cgroup and
        // veth have resolved. The pod is therefore never inserted into
        // `pod_states`, so nothing reconciles it from `pod_states`; only the
        // stored failed-enrollment snapshot + the periodic retry loop can
        // recover it. Drive that failure, confirm the gap, clear the transient
        // condition, then re-drive via the retry helper (force-bypassing the
        // 30s window so the test stays deterministic with no real sleeps).
        //
        // We use the production veth resolver (via the test override guard)
        // rather than `PodEvent::veth_iface_override`, because the stored retry
        // snapshot always carries `veth_iface_override: None` (matching
        // production, which re-resolves the veth on each retry). With the guard,
        // both the initial attempt and the re-drive resolve the same synthetic
        // interface, so the only failure is the injected attach_tc error.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        backend.fail_attach_tc = true;
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        // cgroup present => cgroup_path resolves; guard => veth resolves; so the
        // only failure is the injected attach_tc error (strictly post-resolve).
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-1")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            // None mirrors production and the retry snapshot; veth resolves via
            // the override guard above.
            veth_iface_override: None,
        };

        // First enrollment fails transiently at attach_tc.
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        assert!(
            !pod_states.contains_key("pod-uid-1"),
            "transiently-failed pod must not be inserted into pod_states"
        );
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );
        let state_key = pod_state_key(&pod_states, "pod-uid-1");
        assert!(
            FAILED_POD_ENROLLMENT_ATTEMPTS
                .get(&state_key)
                .map(|r| r.snapshot.is_some())
                .unwrap_or(false),
            "a failed record carrying an owned snapshot must exist for the retry loop"
        );

        // The transient condition clears (e.g., the kernel/map is now writable).
        backend.fail_attach_tc = false;

        // The retry loop re-drives the stored snapshot. `force = true` bypasses
        // the 30s elapsed gate that is otherwise unreachable without wall time.
        retry_backed_off_pod_enrollments(&mut backend, &pod_states, &config, &metrics, true);

        assert!(
            pod_states.contains_key("pod-uid-1"),
            "pod must enroll once the transient failure clears and the retry runs"
        );
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 1);
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY,
            "successful retry should clear a recovered partial-attach state"
        );
        assert!(
            !FAILED_POD_ENROLLMENT_ATTEMPTS.contains_key(&state_key),
            "successful re-drive must clear the failed-enrollment record"
        );

        // Clean up the global between tests sharing this static. Keying is by
        // pod_states pointer, but be explicit so a reused address can't leak.
        forget_failed_pod_enrollment(&state_key);
    }

    #[test]
    fn retry_backed_off_pod_enrollments_is_noop_when_none_pending() {
        // With no pending failures the retry pass must do nothing (no enroll, no
        // error churn) — the empty-map fast path.
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };

        retry_backed_off_pod_enrollments(&mut backend, &pod_states, &config, &metrics, true);

        assert!(pod_states.is_empty());
        assert_eq!(metrics.pods_enrolled.load(Ordering::Relaxed), 0);
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn failed_enrollment_cleanup_keeps_ip_owned_by_tracked_pod() {
        let mut backend = MockEbpfBackend {
            fail_attach_tc: true,
            ..MockEbpfBackend::default()
        };
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podpod-uid-new")).unwrap();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 5);

        pod_states.insert(
            "pod-uid-old".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-old".to_string(),
                pod_name: "old-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: Some("/sys/fs/cgroup/kubepods/pod-old".to_string()),
                veth_iface: Some("veth-old".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        backend
            .update_pod_ip(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-new",
            pod_name: "new-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-new"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-new"));
        assert!(
            backend.pod_ips.contains_key(&ip),
            "rollback for failed new enrollment must not remove the old pod's IP map entry"
        );
        forget_failed_pod_enrollment(&pod_state_key(&pod_states, "pod-uid-new"));
    }

    #[test]
    fn existing_pod_ip_reconcile_writes_probe_ports_when_ip_appears() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080],
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.8")),
            node_probe_ports: vec![8080],
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(backend.pod_ips.contains_key(&ip));
        assert!(
            backend.node_probe_ports.contains(&(ip, 8080)),
            "late pod-IP reconcile must write the matching probe-port exemption"
        );
    }

    #[test]
    fn existing_pod_probe_port_reconcile_removes_stale_current_ip_port() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080, 9090],
            },
        );
        backend.update_node_probe_port(ip, 8080).unwrap();
        backend.update_node_probe_port(ip, 9090).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.8")),
            node_probe_ports: vec![9090],
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(
            !backend.node_probe_ports.contains(&(ip, 8080)),
            "probe ports removed from the pod spec must lose their exemption"
        );
        assert!(
            backend.node_probe_ports.contains(&(ip, 9090)),
            "probe ports still owned by the pod must remain exempt"
        );
        assert_eq!(
            pod_states
                .get("pod-uid-1")
                .expect("pod state present")
                .node_probe_ports
                .as_slice(),
            &[9090]
        );
    }

    #[test]
    fn existing_pod_ip_and_probe_port_reconcile_removes_old_ip_old_port() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let old_ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        let new_ip = std::net::Ipv4Addr::new(10, 0, 0, 9);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(old_ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080],
            },
        );
        backend.update_node_probe_port(old_ip, 8080).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.9"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.9")),
            node_probe_ports: vec![9090],
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(
            !backend.node_probe_ports.contains(&(old_ip, 8080)),
            "old pod-IP probe-port exemption must be removed using the previous port list"
        );
        assert!(
            backend.node_probe_ports.contains(&(new_ip, 9090)),
            "new pod-IP probe-port exemption must be written from the current pod spec"
        );
    }

    #[test]
    fn partial_probe_port_reconcile_tracks_written_port_for_cleanup() {
        let mut backend = MockEbpfBackend {
            fail_update_node_probe_port6: true,
            ..MockEbpfBackend::default()
        };
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        let ip6 = std::net::Ipv6Addr::LOCALHOST;
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: Some(ip6),
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_source_ips: PodSourceIps {
                ipv4: Some(ip),
                ipv6: Some(ip6),
            },
            node_probe_ports: vec![8080],
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(
            backend.node_probe_ports.contains(&(ip, 8080)),
            "IPv4 probe-port write should have happened before the IPv6 failure"
        );
        assert_eq!(
            pod_states
                .get("pod-uid-1")
                .expect("pod state present")
                .node_probe_ports
                .as_slice(),
            &[8080],
            "partially written probe port must stay tracked for later cleanup"
        );

        backend.fail_update_node_probe_port6 = false;
        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-uid-1");

        assert!(
            !backend.node_probe_ports.contains(&(ip, 8080)),
            "tracked partial write must be removed when the pod is deleted"
        );
    }

    #[test]
    fn pending_node_probe_port_update_retry_writes_missing_exemption() {
        let mut backend = MockEbpfBackend {
            fail_update_node_probe_port: true,
            ..MockEbpfBackend::default()
        };
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.8")),
            node_probe_ports: vec![8080],
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state_key = pod_state_key(&pod_states, "pod-uid-1");
        let failure_key = pending_capture_failure_key(
            &state_key,
            CAPTURE_FAILURE_NODE_PROBE_PORT_UPDATE,
            &node_probe_port_update_failure_detail(&[8080]),
        );
        assert!(PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert!(
            !backend.node_probe_ports.contains(&(ip, 8080)),
            "failed update must leave the probe-port exemption absent until retry"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );

        backend.fail_update_node_probe_port = false;
        retry_pending_node_probe_port_updates(&mut backend, &pod_states, &metrics);

        assert!(!PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert!(
            backend.node_probe_ports.contains(&(ip, 8080)),
            "retry must write the missing probe-port exemption without another pod event"
        );
        assert_eq!(
            pod_states
                .get("pod-uid-1")
                .expect("pod state present")
                .node_probe_ports
                .as_slice(),
            &[8080]
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[test]
    fn probe_port_cleanup_removes_only_ports_not_owned_by_replacement() {
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        pod_states.insert(
            "old-pod".to_string(),
            PodAttachmentState {
                pod_uid: "old-pod".to_string(),
                pod_name: "old".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-old".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080, 9090],
            },
        );
        pod_states.insert(
            "replacement-pod".to_string(),
            PodAttachmentState {
                pod_uid: "replacement-pod".to_string(),
                pod_name: "replacement".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-new".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![9090],
            },
        );
        backend.update_node_probe_port(ip, 8080).unwrap();
        backend.update_node_probe_port(ip, 9090).unwrap();

        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "old-pod");

        assert!(
            !backend.node_probe_ports.contains(&(ip, 8080)),
            "old-only probe port must not survive IP reuse"
        );
        assert!(
            backend.node_probe_ports.contains(&(ip, 9090)),
            "probe port owned by replacement pod must remain"
        );
    }

    #[test]
    fn pre_enrollment_pod_ip_remove_failure_retries_stale_map_entry() {
        let mut backend = MockEbpfBackend {
            fail_remove_pod_ip: true,
            ..MockEbpfBackend::default()
        };
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        let state = PodAttachmentState {
            pod_uid: "pod-uid-1".to_string(),
            pod_name: "partial".to_string(),
            namespace: "default".to_string(),
            pod_ip: Some(ip),
            pod_ip6: None,
            cgroup_path: None,
            veth_iface: Some("veth-mock".to_string()),
            attached: false,
            include_ports_cgroup_ids: Vec::new(),
            include_ports_policy: None,
            workload_identity_cgroup_ids: Vec::new(),
            node_probe_ports: Vec::new(),
        };
        backend
            .update_pod_ip(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();

        cleanup_partial_pod_enrollment(&mut backend, &pod_states, &metrics, "pod-uid-1", &state);

        let state_key = pod_state_key(&pod_states, "pod-uid-1");
        let failure_key =
            pending_capture_failure_key(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
        assert!(PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );

        backend.fail_remove_pod_ip = false;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(!PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert!(
            !backend.pod_ips.contains_key(&ip),
            "retry must remove stale pod IP left by partial enrollment cleanup"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[test]
    fn pre_enrollment_probe_port_cleanup_does_not_clear_partial_state() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        let state = PodAttachmentState {
            pod_uid: "pod-uid-1".to_string(),
            pod_name: "partial".to_string(),
            namespace: "default".to_string(),
            pod_ip: Some(ip),
            pod_ip6: None,
            cgroup_path: None,
            veth_iface: Some("veth-mock".to_string()),
            attached: false,
            include_ports_cgroup_ids: Vec::new(),
            include_ports_policy: None,
            workload_identity_cgroup_ids: Vec::new(),
            node_probe_ports: vec![8080],
        };
        backend.update_node_probe_port(ip, 8080).unwrap();
        metrics.record_attach_error();

        cleanup_partial_pod_enrollment(&mut backend, &pod_states, &metrics, "pod-uid-1", &state);

        assert!(
            !backend.node_probe_ports.contains(&(ip, 8080)),
            "pre-enrollment cleanup should still remove any partially written probe-port entry"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED,
            "rollback must not report ready before the failed-enrollment retry record is inserted"
        );
    }

    #[test]
    fn relist_prunes_failed_enrollment_for_vanished_pod_but_keeps_present_one() {
        // Codex finding: a pod that fails enrollment before it is inserted into
        // `pod_states` keeps an owned snapshot in FAILED_POD_ENROLLMENT_ATTEMPTS.
        // The InitDone sweep only reconciles `pod_states`, so if that pod
        // disappears across a watcher relist nothing clears the record and the
        // retry loop replays it forever (warn + attach_errors every ~30s for a
        // UID the API no longer reports). Pruning against the relist `seen` set
        // must drop the vanished pod's record — but never one still in `seen`.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        backend.fail_attach_tc = true; // transient failure lands post-resolve.
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        // Both pods resolve a cgroup so the only failure is the injected attach.
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podgone-uid")).unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podstays-uid")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let mut failed_event = |uid: &'static str, ip: &'static str| {
            let event = PodEvent {
                pod_uid: uid,
                pod_name: "p",
                namespace: "default",
                service_account: None,
                labels: &labels,
                annotations: &HashMap::new(),
                pod_ip_str: Some(ip),
                pod_source_ips: PodSourceIps::from_primary_str(Some(ip)),
                node_probe_ports: Vec::new(),
                pod_pid: None,
                veth_iface_override: None,
            };
            handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        };
        failed_event("gone-uid", "10.0.0.1");
        failed_event("stays-uid", "10.0.0.2");

        let gone_key = pod_state_key(&pod_states, "gone-uid");
        let stays_key = pod_state_key(&pod_states, "stays-uid");
        assert!(FAILED_POD_ENROLLMENT_ATTEMPTS.contains_key(&gone_key));
        assert!(FAILED_POD_ENROLLMENT_ATTEMPTS.contains_key(&stays_key));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );

        // Relist saw `stays-uid` but not `gone-uid`.
        let mut seen = HashSet::new();
        seen.insert("stays-uid".to_string());
        prune_failed_enrollments_from_relist(&mut backend, &pod_states, &config, &metrics, &seen);

        assert!(
            !FAILED_POD_ENROLLMENT_ATTEMPTS.contains_key(&gone_key),
            "failed record for a pod absent from the relist must be pruned"
        );
        assert!(
            FAILED_POD_ENROLLMENT_ATTEMPTS.contains_key(&stays_key),
            "failed record for a pod still present in the relist must be retained for retry"
        );
        assert_eq!(
            backend
                .detached_pods
                .iter()
                .filter(|uid| uid.as_str() == "gone-uid")
                .count(),
            2,
            "relist removal must re-verify cleanup from the failed-attempt snapshot"
        );
        assert_eq!(
            backend
                .detached_pods
                .iter()
                .filter(|uid| uid.as_str() == "stays-uid")
                .count(),
            1,
            "a failed pod still present in the relist must not be removed"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED,
            "remaining failed enrollment should keep the node marked partially attached"
        );

        seen.clear();
        prune_failed_enrollments_from_relist(&mut backend, &pod_states, &config, &metrics, &seen);
        assert!(
            !FAILED_POD_ENROLLMENT_ATTEMPTS.contains_key(&stays_key),
            "second relist with no failed pods seen should prune the last failed record"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY,
            "pruning the last failed enrollment should clear the recovered partial state"
        );
        assert_eq!(
            backend
                .detached_pods
                .iter()
                .filter(|uid| uid.as_str() == "stays-uid")
                .count(),
            2,
            "a later missed delete must also consume cleanup evidence through removal"
        );

        // Clean up the global between tests sharing this static.
        forget_failed_pod_enrollment(&gone_key);
        forget_failed_pod_enrollment(&stays_key);
    }

    #[test]
    fn handle_pod_added_repeated_missing_veth_skips_bpf_attach_retry() {
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: None,
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        let cgroup_attachments_after_first = backend.cgroup_attachments.len();
        assert!(cgroup_attachments_after_first > 0);
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 1);

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert_eq!(
            backend.cgroup_attachments.len(),
            cgroup_attachments_after_first,
            "unchanged failed Apply should not retry cgroup attaches during backoff"
        );
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let event = PodEvent {
            pod_uid: "pod-uid-2",
            pod_name: "no-mesh-pod",
            namespace: "default",
            service_account: None,
            labels: &HashMap::new(),
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_source_ips: PodSourceIps::default(),
            node_probe_ports: Vec::new(),
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
                pod_ip6: None,
                cgroup_path: Some("/sys/fs/cgroup/kubepods/poduid2".to_string()),
                veth_iface: None,
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let event = PodEvent {
            pod_uid: "pod-uid-2",
            pod_name: "mesh-pod",
            namespace: "default",
            service_account: None,
            labels: &HashMap::new(),
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_source_ips: PodSourceIps::default(),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!pod_states.contains_key("pod-uid-2"));
        assert_eq!(backend.detached_pods, vec!["pod-uid-2"]);
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_added_unenrolls_failed_untracked_pod_with_cleanup_evidence() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let pod_uid = "pod-failed-opt-out";
        let state_key = pod_state_key(&pod_states, pod_uid);
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 23);
        let cleanup_state = PodAttachmentState {
            pod_uid: pod_uid.to_string(),
            pod_name: pod_uid.to_string(),
            namespace: "default".to_string(),
            pod_ip: None,
            pod_ip6: None,
            cgroup_path: Some("/cg/failed-opt-out".to_string()),
            veth_iface: Some("veth-test".to_string()),
            attached: false,
            include_ports_cgroup_ids: Vec::new(),
            include_ports_policy: None,
            workload_identity_cgroup_ids: Vec::new(),
            node_probe_ports: Vec::new(),
        };
        remember_failed_pod_enrollment_with_cleanup_state(
            &state_key,
            test_failed_enrollment_signature(ip, Some("/cg/failed-opt-out")),
            test_retryable_enrollment(pod_uid, ip),
            &cleanup_state,
        );
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let event = PodEvent {
            pod_uid,
            pod_name: pod_uid,
            namespace: "default",
            service_account: None,
            labels: &HashMap::new(),
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.23"),
            pod_source_ips: PodSourceIps::default(),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-test"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert!(!has_failed_pod_enrollment_attempt(&state_key));
        assert_eq!(backend.detached_pods, vec![pod_uid]);
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-3",
            pod_name: "system-pod",
            namespace: "kube-system",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_source_ips: PodSourceIps::default(),
            node_probe_ports: Vec::new(),
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
        let ip6 = "fd00::5".parse().unwrap();

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "test-pod".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: Some(ip6),
                cgroup_path: Some("/sys/fs/cgroup/kubepods/poduid1".to_string()),
                veth_iface: Some("veth123".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080],
            },
        );
        backend
            .update_pod_ip(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();
        backend
            .update_pod_ip6(
                ip6,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();
        backend.update_node_probe_port(ip, 8080).unwrap();
        backend.update_node_probe_port6(ip6, 8080).unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-uid-1");

        assert!(!pod_states.contains_key("pod-uid-1"));
        assert_eq!(backend.detached_pods, vec!["pod-uid-1"]);
        assert!(!backend.pod_ips.contains_key(&ip));
        assert!(!backend.pod_ips6.contains_key(&ip6));
        assert!(!backend.node_probe_ports.contains(&(ip, 8080)));
        assert!(!backend.node_probe_ports6.contains(&(ip6, 8080)));
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 1);
    }

    #[test]
    fn handle_pod_removed_keeps_ip_owned_by_another_pod() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 5);

        for pod_uid in ["pod-uid-old", "pod-uid-new"] {
            pod_states.insert(
                pod_uid.to_string(),
                PodAttachmentState {
                    pod_uid: pod_uid.to_string(),
                    pod_name: pod_uid.to_string(),
                    namespace: "default".to_string(),
                    pod_ip: Some(ip),
                    pod_ip6: None,
                    cgroup_path: Some(format!("/sys/fs/cgroup/kubepods/{pod_uid}")),
                    veth_iface: Some(format!("veth-{pod_uid}")),
                    attached: true,
                    include_ports_cgroup_ids: Vec::new(),
                    include_ports_policy: None,
                    workload_identity_cgroup_ids: Vec::new(),
                    node_probe_ports: Vec::new(),
                },
            );
        }
        backend
            .update_pod_ip(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-uid-old");

        assert!(!pod_states.contains_key("pod-uid-old"));
        assert!(pod_states.contains_key("pod-uid-new"));
        assert!(
            backend.pod_ips.contains_key(&ip),
            "delayed delete for old pod must not clobber recycled IP owned by new pod"
        );
    }

    #[test]
    fn handle_pod_removed_noop_for_unknown() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };

        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "nonexistent");

        assert!(backend.detached_pods.is_empty());
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn publish_pod_registry_writes_file_with_cgroup_path() {
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("node-waypoint-pods");
        // Directory does not exist yet — publish must create it.
        assert!(!registry.exists());
        let source_identity =
            crate::identity::SpiffeId::new("spiffe://cluster.local/ns/default/sa/api").unwrap();

        publish_pod_registry(
            &registry,
            "pod-uid-1",
            "/sys/fs/cgroup/kubepods/poduid1",
            PodSourceIps {
                ipv4: Some(std::net::Ipv4Addr::new(10, 1, 2, 3)),
                ipv6: Some("fd00::123".parse().unwrap()),
            },
            Some(&source_identity),
        );

        let path = registry.join("pod-uid-1");
        assert!(path.exists(), "registry entry must be written");
        let contents = std::fs::read_to_string(&path).unwrap();
        assert_eq!(
            contents,
            "/sys/fs/cgroup/kubepods/poduid1\nspiffe_id=spiffe://cluster.local/ns/default/sa/api\nipv4=10.1.2.3\nipv6=fd00::123\n",
            "registry entry carries the workload identity and family-specific source pod IPs"
        );
    }

    #[test]
    fn udp_enrollment_guard_opens_only_after_producer_ready_marker() {
        let registry = tempfile::tempdir().unwrap();
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.udp_capture_enabled = true;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 5);
        let pod_states = DashMap::new();
        pod_states.insert(
            "pod-a".to_string(),
            PodAttachmentState {
                pod_uid: "pod-a".to_string(),
                pod_name: "pod-a".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: Some("/cg/a".to_string()),
                veth_iface: Some("veth-a".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        let mut backend = MockEbpfBackend::default();
        backend
            .update_pod_ip(ip, &pod_map_info(&config, false))
            .unwrap();
        let mut ready_uids = HashSet::new();
        let metrics = NodeAgentMetrics::default();

        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );
        assert!(
            backend.pod_ips[&ip].capture_flags & ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_READY
                == 0,
            "registry publication alone must leave UDP fail-closed"
        );

        let ready_dir = registry.path().join(".udp-ready");
        std::fs::create_dir_all(&ready_dir).unwrap();
        std::fs::write(ready_dir.join("pod-a"), b"").unwrap();
        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );
        assert!(
            backend.pod_ips[&ip].capture_flags & ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_READY
                != 0,
            "only producer readiness may open the enrollment guard"
        );

        let stable = backend.pod_ips[&ip].clone();
        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );
        assert_eq!(
            backend.pod_ips[&ip], stable,
            "ready reconcile is idempotent"
        );

        let required_dir = registry.path().join(".udp-ack-required");
        std::fs::create_dir_all(&required_dir).unwrap();
        std::fs::write(required_dir.join("pod-a"), b"stale-after-restart").unwrap();
        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );
        assert!(
            required_dir.join("pod-a").exists(),
            "a fresh close request may be a producer mid-close (request persists before \
             the ready marker retracts), so the residue sweep must not delete it"
        );
        remove_udp_ack_requirement_older_than(registry.path(), "pod-a", Duration::ZERO);
        assert!(
            !required_dir.join("pod-a").exists(),
            "aged restart residue for a ready live pod is swept once past the orphan grace"
        );

        let ack_dir = registry.path().join(".udp-not-ready");
        std::fs::create_dir_all(&ack_dir).unwrap();
        std::fs::write(ack_dir.join("pod-a"), b"stale").unwrap();
        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );
        assert!(
            !ack_dir.join("pod-a").exists(),
            "ready reconcile must retry removal of a stale close acknowledgement"
        );

        std::fs::remove_file(ready_dir.join("pod-a")).unwrap();
        backend.fail_update_pod_ip = true;
        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );
        assert!(
            !registry
                .path()
                .join(".udp-not-ready")
                .join("pod-a")
                .exists(),
            "failed BPF closure must not acknowledge producer teardown"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );

        backend.fail_update_pod_ip = false;
        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );
        assert!(
            backend.pod_ips[&ip].capture_flags & ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_READY
                == 0,
            "marker removal must close the BPF gate again"
        );
        assert!(
            registry
                .path()
                .join(".udp-not-ready")
                .join("pod-a")
                .is_file()
        );
        std::fs::write(required_dir.join("pod-a"), b"close-in-progress").unwrap();
        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut ready_uids,
        );
        assert!(
            required_dir.join("pod-a").is_file(),
            "a live pod without producer readiness may be mid-close, so its request must remain"
        );
    }

    #[test]
    fn disabled_udp_rederives_cleanup_ack_from_live_pod_map_state() {
        let registry = tempfile::tempdir().unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: Some(registry.path().to_path_buf()),
        };
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 6);
        let pod_states = DashMap::new();
        pod_states.insert(
            "pod-a".to_string(),
            PodAttachmentState {
                pod_uid: "pod-a".to_string(),
                pod_name: "pod-a".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: Some("/cg/a".to_string()),
                veth_iface: Some("veth-a".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        let mut backend = MockEbpfBackend::default();
        backend
            .update_pod_ip(ip, &PodInfo::for_capture(15001, true, true))
            .unwrap();
        let ack_dir = registry.path().join(".udp-not-ready");
        std::fs::create_dir_all(&ack_dir).unwrap();
        std::fs::write(ack_dir.join("pod-a"), b"stale").unwrap();
        let mut verified_uids = HashSet::new();
        let metrics = NodeAgentMetrics::default();

        reconcile_udp_capture_readiness(
            &mut backend,
            &pod_states,
            &config,
            &metrics,
            &mut verified_uids,
        );

        let info = &backend.pod_ips[&ip];
        assert_eq!(
            info.capture_flags
                & (ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_ENABLED
                    | ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_READY),
            0,
            "disabled posture must be applied to the live pod map before cleanup"
        );
        assert_eq!(std::fs::read(ack_dir.join("pod-a")).unwrap(), b"");
        assert!(verified_uids.contains("pod-a"));
    }

    #[test]
    fn pod_source_ips_from_status_uses_dual_stack_pod_ips() {
        let status = PodStatus {
            pod_ip: Some("fd00::5".to_string()),
            pod_ips: Some(vec![
                k8s_openapi::api::core::v1::PodIP {
                    ip: "fd00::5".to_string(),
                },
                k8s_openapi::api::core::v1::PodIP {
                    ip: "10.0.0.5".to_string(),
                },
            ]),
            ..Default::default()
        };

        let ips = PodSourceIps::from_status(Some(&status));

        assert_eq!(ips.ipv4, Some(std::net::Ipv4Addr::new(10, 0, 0, 5)));
        assert_eq!(ips.ipv6, Some("fd00::5".parse().unwrap()));
    }

    #[test]
    fn remove_pod_registry_removes_entry_and_tolerates_absent() {
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("node-waypoint-pods");
        publish_pod_registry(
            &registry,
            "pod-uid-1",
            "/cg/path",
            PodSourceIps::default(),
            None,
        );
        let path = registry.join("pod-uid-1");
        assert!(path.exists());

        remove_pod_registry(&registry, "pod-uid-1");
        assert!(!path.exists(), "registry entry must be removed");

        // A second removal (file already gone) must be a no-op, not a panic.
        remove_pod_registry(&registry, "pod-uid-1");
        // Removing from a directory that never existed must also be tolerated.
        remove_pod_registry(&dir.path().join("missing-dir"), "pod-uid-1");
    }

    #[test]
    fn publish_pod_registry_rejects_path_traversal_uids() {
        let dir = tempfile::tempdir().unwrap();
        let registry = dir.path().join("node-waypoint-pods");

        // None of these may write anything; an escaping UID must be refused
        // before any directory is created or file written.
        for unsafe_uid in ["", "../escape", "a/b", "a\\b", "..", "foo/../bar"] {
            publish_pod_registry(
                &registry,
                unsafe_uid,
                "/cg/path",
                PodSourceIps::default(),
                None,
            );
        }

        // The guard fires before `create_dir_all`, so nothing was created and
        // no traversal target was written.
        assert!(
            !registry.exists(),
            "unsafe pod UID must not create the registry directory"
        );
        assert!(
            !dir.path().join("escape").exists(),
            "'..' in pod UID must not write outside the registry directory"
        );

        // remove_pod_registry shares the guard: an unsafe UID is a no-op even
        // when the directory exists with a sibling file.
        std::fs::create_dir_all(&registry).unwrap();
        let keep = registry.join("real-pod");
        std::fs::write(&keep, "x").unwrap();
        remove_pod_registry(&registry, "../real-pod");
        remove_pod_registry(&registry, "..");
        assert!(keep.exists(), "unsafe UID must not delete a sibling entry");
    }

    /// `apply_cni_request` ADD without Kubernetes metadata is a no-op and
    /// returns `Ok`. The kube-rs watcher (or the metadata-enriched ADD path)
    /// performs the real enrollment once labels/annotations are available.
    #[test]
    fn apply_cni_request_add_with_empty_labels_returns_ok_and_skips_enrollment() {
        use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            pod_namespace: "default".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: Some("pod-uid-1".to_string()),
            container_id: "ctr-1".to_string(),
            netns_path: Some("/var/run/netns/cni-1".to_string()),
            args: HashMap::new(),
        };
        let resp = apply_cni_request(&mut backend, &pod_states, &config, &metrics, &req);
        assert_eq!(resp, CniRpcResponse::Ok);
        assert!(
            !pod_states.contains_key("pod-uid-1"),
            "empty labels intentionally short-circuit enrollment; the watcher reconciles later"
        );
        assert_eq!(
            metrics.pods_enrolled.load(Ordering::Relaxed),
            0,
            "no BPF attach should fire on the metadata-free fallback path"
        );
    }

    #[test]
    fn apply_cni_request_add_with_empty_labels_does_not_unenroll_existing_pod() {
        use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 9);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "alpha".to_string(),
                namespace: "default".to_string(),
                attached: true,
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: None,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            pod_namespace: "default".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: Some("pod-uid-1".to_string()),
            container_id: "ctr-1".to_string(),
            netns_path: Some("/var/run/netns/cni-1".to_string()),
            args: HashMap::new(),
        };

        let resp = apply_cni_request(&mut backend, &pod_states, &config, &metrics, &req);
        assert_eq!(resp, CniRpcResponse::Ok);
        assert!(pod_states.contains_key("pod-uid-1"));
        assert!(backend.detached_pods.is_empty());
        assert_eq!(metrics.pods_unenrolled.load(Ordering::Relaxed), 0);
    }

    fn enrolled_pod_state(uid: &str) -> PodAttachmentState {
        PodAttachmentState {
            pod_uid: uid.to_string(),
            pod_name: "alpha".to_string(),
            namespace: "default".to_string(),
            pod_ip: None,
            pod_ip6: None,
            cgroup_path: Some("/sys/fs/cgroup/kubepods/poduid1".to_string()),
            veth_iface: Some("veth123".to_string()),
            attached: true,
            include_ports_cgroup_ids: Vec::new(),
            include_ports_policy: None,
            workload_identity_cgroup_ids: Vec::new(),
            node_probe_ports: Vec::new(),
        }
    }

    #[test]
    fn cni_add_during_relist_marks_tracked_pod_seen() {
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        pod_states.insert("pod-uid-1".to_string(), enrolled_pod_state("pod-uid-1"));
        let mut init_seen = Some(HashSet::new());

        // The CNI apply path reports the UID it actually enrolled.
        mark_relist_seen_from_cni_add(&mut init_seen, Some("pod-uid-1"));

        let seen = init_seen.take().expect("relist in progress");
        assert!(
            watcher_init_stale_uids(&pod_states, &seen).is_empty(),
            "CNI-enrolled pod should survive the current watcher InitDone sweep"
        );
    }

    #[test]
    fn unrelated_cni_add_during_relist_does_not_mask_stale_pod() {
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        pod_states.insert("pod-uid-1".to_string(), enrolled_pod_state("pod-uid-1"));
        let mut init_seen = Some(HashSet::new());

        // A CNI ADD that enrolled a *different* pod marks only that UID.
        mark_relist_seen_from_cni_add(&mut init_seen, Some("pod-uid-2"));

        let seen = init_seen.take().expect("relist in progress");
        assert_eq!(
            watcher_init_stale_uids(&pod_states, &seen),
            vec!["pod-uid-1".to_string()],
            "unrelated CNI ADD must not protect a stale watcher entry"
        );
    }

    #[test]
    fn cni_add_with_metadata_free_request_marks_enrolled_api_uid_seen() {
        // Codex finding: when the CRI omits K8S_POD_UID, the pod still enrolls
        // under the Kubernetes API metadata.uid. The relist-preservation must
        // mark *that* UID so InitDone does not tear the CNI fast-path enrollment
        // back down. `apply_cni_add_from_pod` surfaces the enrolled UID even
        // though `request.pod_uid` is None.
        use crate::cni::rpc::{CniRpcRequest, RpcVerb};
        use k8s_openapi::api::core::v1::{Pod, PodSpec, PodStatus};
        use k8s_openapi::apimachinery::pkg::apis::meta::v1::ObjectMeta;

        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let cgroup_root = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(cgroup_root.path().join("kubepods/podapi-uid-x")).unwrap();
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let pod = Pod {
            metadata: ObjectMeta {
                name: Some("alpha".to_string()),
                namespace: Some("default".to_string()),
                uid: Some("api-uid-x".to_string()),
                labels: Some(
                    [("ferrum.io/mesh".to_string(), "enabled".to_string())]
                        .into_iter()
                        .collect(),
                ),
                ..Default::default()
            },
            spec: Some(PodSpec::default()),
            status: Some(PodStatus {
                pod_ip: Some("10.0.0.9".to_string()),
                ..Default::default()
            }),
        };
        // CRI omitted the pod UID.
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            pod_namespace: "default".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "ctr-1".to_string(),
            netns_path: Some("/var/run/netns/cni-1".to_string()),
            args: HashMap::new(),
        };

        let (response, enrolled_uid) =
            apply_cni_add_from_pod(&mut backend, &pod_states, &config, &metrics, &req, &pod);
        assert!(matches!(response, CniRpcResponse::Ok));
        assert_eq!(enrolled_uid.as_deref(), Some("api-uid-x"));
        assert!(pod_states.contains_key("api-uid-x"));

        // And it survives the InitDone sweep once marked.
        let mut init_seen = Some(HashSet::new());
        mark_relist_seen_from_cni_add(&mut init_seen, enrolled_uid.as_deref());
        let seen = init_seen.take().expect("relist in progress");
        assert!(watcher_init_stale_uids(&pod_states, &seen).is_empty());
    }

    /// `apply_cni_request` ADD without a pod_uid maps to `Rejected` (we
    /// cannot key BPF state without a UID) — the watcher fallback handles
    /// the reconcile by selector instead. Kubelet treats `Rejected` as a
    /// soft signal but the CNI binary still emits a success result so
    /// pod networking isn't broken.
    #[test]
    fn apply_cni_request_add_without_pod_uid_returns_rejected() {
        use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let req = CniRpcRequest {
            verb: RpcVerb::Add,
            pod_namespace: "default".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: None,
            container_id: "ctr-1".to_string(),
            netns_path: None,
            args: HashMap::new(),
        };
        let resp = apply_cni_request(&mut backend, &pod_states, &config, &metrics, &req);
        match resp {
            CniRpcResponse::Rejected { reason } => {
                assert!(
                    reason.contains("K8S_POD_UID"),
                    "rejection message should explain why; got: {reason}"
                );
            }
            other => panic!("expected Rejected, got {other:?}"),
        }
    }

    /// `apply_cni_request` DEL tears down BPF state for a pod the watcher
    /// previously enrolled. Idempotent: a second DEL is a no-op (still
    /// returns Ok) so kubelet retries are safe.
    #[test]
    fn apply_cni_request_del_unenrolls_and_is_idempotent() {
        use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        // Pre-populate as if the watcher had already enrolled the pod.
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "alpha".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: Some("/sys/fs/cgroup/kubepods/poduid1".to_string()),
                veth_iface: Some("veth123".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        let req = CniRpcRequest {
            verb: RpcVerb::Del,
            pod_namespace: "default".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: Some("pod-uid-1".to_string()),
            container_id: "ctr-1".to_string(),
            netns_path: None,
            args: HashMap::new(),
        };
        let resp = apply_cni_request(&mut backend, &pod_states, &config, &metrics, &req);
        assert_eq!(resp, CniRpcResponse::Ok);
        assert!(
            !pod_states.contains_key("pod-uid-1"),
            "DEL should remove the pod-state entry"
        );
        assert_eq!(backend.detached_pods, vec!["pod-uid-1".to_string()]);

        // Idempotency: a second DEL is a no-op.
        let resp2 = apply_cni_request(&mut backend, &pod_states, &config, &metrics, &req);
        assert_eq!(
            resp2,
            CniRpcResponse::Ok,
            "second DEL still returns Ok so kubelet retries are safe"
        );
        // Backend should not detach again — `handle_pod_removed` short-
        // circuits on the empty state map.
        assert_eq!(
            backend.detached_pods,
            vec!["pod-uid-1".to_string()],
            "second DEL must not double-detach"
        );
    }

    /// `apply_cni_request` CHECK on a tracked pod returns Ok; CHECK on an
    /// untracked pod returns Rejected. Kubelet uses Rejected as a hint to
    /// replay ADD.
    #[test]
    fn apply_cni_request_check_distinguishes_tracked_and_untracked() {
        use crate::cni::rpc::{CniRpcRequest, CniRpcResponse, RpcVerb};
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };

        // Untracked pod: CHECK is Rejected.
        let req = CniRpcRequest {
            verb: RpcVerb::Check,
            pod_namespace: "default".to_string(),
            pod_name: "alpha".to_string(),
            pod_uid: Some("pod-uid-1".to_string()),
            container_id: "ctr-1".to_string(),
            netns_path: None,
            args: HashMap::new(),
        };
        match apply_cni_request(&mut backend, &pod_states, &config, &metrics, &req) {
            CniRpcResponse::Rejected { reason } => {
                assert!(
                    reason.contains("not currently enrolled"),
                    "expected enrollment-miss reason, got: {reason}"
                );
            }
            other => panic!("expected Rejected for untracked pod, got {other:?}"),
        }

        // Tracked pod: CHECK is Ok.
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "alpha".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: None,
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        let resp = apply_cni_request(&mut backend, &pod_states, &config, &metrics, &req);
        assert_eq!(resp, CniRpcResponse::Ok);
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );

        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "duplicate",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: None,
            pod_source_ips: PodSourceIps::default(),
            node_probe_ports: Vec::new(),
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: Some(cgroup_path.to_string_lossy().to_string()),
                veth_iface: Some("veth-old".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );

        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "sandbox-recreated",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.9"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.9")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-new"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert_eq!(backend.detached_pods, vec!["pod-uid-1".to_string()]);
        for direction in [TcAttachDirection::Ingress, TcAttachDirection::Egress] {
            assert!(
                backend
                    .tc_attachments
                    .iter()
                    .any(|(iface, program, actual_direction)| {
                        iface == "veth-new"
                            && program == "ferrum_tc_inbound"
                            && *actual_direction == direction
                    }),
                "expected {direction:?} tc attach on recreated veth"
            );
        }
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);

        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );

        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.8")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        assert_eq!(pod_states.get("pod-uid-1").unwrap().pod_ip, Some(ip));
        assert!(backend.pod_ips.contains_key(&ip));
        assert_eq!(metrics.attach_errors.load(Ordering::Relaxed), 0);
    }

    #[test]
    fn existing_pod_ip_update_failure_keeps_partial_state_until_recovered() {
        let mut backend = MockEbpfBackend {
            fail_update_pod_ip: true,
            ..MockEbpfBackend::default()
        };
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: None,
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.8")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state_key = pod_state_key(&pod_states, "pod-uid-1");
        let failure_key = pending_capture_failure_key(
            &state_key,
            CAPTURE_FAILURE_POD_IP_UPDATE,
            CAPTURE_FAILURE_DETAIL_POD_IP,
        );
        assert!(PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );
        clear_partial_capture_state_if_recovered(&pod_states, &metrics);
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED,
            "untracked pod-IP update failures must not be cleared by enrollment recovery checks"
        );

        backend.fail_update_pod_ip = false;
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert_eq!(
            pod_states.get("pod-uid-1").unwrap().pod_ip,
            Some(std::net::Ipv4Addr::new(10, 0, 0, 8))
        );
        assert!(!PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
        forget_pending_capture_failures_for_pod(&state_key);
    }

    #[test]
    fn pod_ip_remove_failure_keeps_partial_state_pending() {
        let mut backend = MockEbpfBackend {
            fail_remove_pod_ip: true,
            ..MockEbpfBackend::default()
        };
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        backend
            .update_pod_ip(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();

        let state_key = pod_state_key(&pod_states, "pod-uid-1");
        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-uid-1");

        let failure_key =
            pending_capture_failure_key(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, "10.0.0.8");
        assert!(PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );
        clear_partial_capture_state_if_recovered(&pod_states, &metrics);
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED,
            "pod-IP removal failures can leave stale map entries and must keep degraded readiness"
        );

        backend.fail_remove_pod_ip = false;
        retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(!PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert!(
            !backend.pod_ips.contains_key(&ip),
            "retry must remove the stale pod-IP map entry"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[test]
    fn node_probe_port_remove_failure_retries_stale_map_entry() {
        let mut backend = MockEbpfBackend {
            fail_remove_node_probe_port: true,
            ..MockEbpfBackend::default()
        };
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "existing".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: vec![8080],
            },
        );
        backend.update_node_probe_port(ip, 8080).unwrap();

        let state_key = pod_state_key(&pod_states, "pod-uid-1");
        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-uid-1");

        let detail = node_probe_port_failure_detail(std::net::IpAddr::V4(ip), 8080);
        let failure_key = pending_capture_failure_key(
            &state_key,
            CAPTURE_FAILURE_NODE_PROBE_PORT_REMOVE,
            &detail,
        );
        assert!(PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );

        backend.fail_remove_node_probe_port = false;
        retry_pending_node_probe_port_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(!PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert!(
            !backend.node_probe_ports.contains(&(ip, 8080)),
            "retry must remove stale probe-port map entry"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[test]
    fn pending_ipv6_pod_ip_remove_retry_removes_stale_map_entry() {
        let mut backend = MockEbpfBackend::default();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();
        let ip: std::net::Ipv6Addr = "fd00::8".parse().unwrap();
        backend
            .update_pod_ip6(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();

        let state_key = pod_state_key(&pod_states, "pod-uid-1");
        remember_pending_capture_failure(
            &state_key,
            CAPTURE_FAILURE_POD_IP_REMOVE,
            &ip.to_string(),
        );
        let failure_key =
            pending_capture_failure_key(&state_key, CAPTURE_FAILURE_POD_IP_REMOVE, &ip.to_string());
        assert!(PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert_eq!(
            parse_pending_capture_failure_key(&failure_key)
                .unwrap()
                .detail,
            ip.to_string()
        );

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: "/nonexistent".to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(!PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert!(
            !backend.pod_ips6.contains_key(&ip),
            "retry must remove stale IPv6 pod map entries"
        );
    }

    #[test]
    fn pod_ip_remove_failure_clears_when_ip_is_reowned() {
        let mut backend = MockEbpfBackend {
            fail_remove_pod_ip: true,
            ..MockEbpfBackend::default()
        };
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let ip = std::net::Ipv4Addr::new(10, 0, 0, 8);
        pod_states.insert(
            "pod-uid-1".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-1".to_string(),
                pod_name: "old".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );
        backend
            .update_pod_ip(
                ip,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();

        let old_state_key = pod_state_key(&pod_states, "pod-uid-1");
        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-uid-1");

        let failure_key =
            pending_capture_failure_key(&old_state_key, CAPTURE_FAILURE_POD_IP_REMOVE, "10.0.0.8");
        assert!(PENDING_CAPTURE_FAILURES.contains_key(&failure_key));
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED
        );

        pod_states.insert(
            "pod-uid-2".to_string(),
            PodAttachmentState {
                pod_uid: "pod-uid-2".to_string(),
                pod_name: "new".to_string(),
                namespace: "default".to_string(),
                pod_ip: Some(ip),
                pod_ip6: None,
                cgroup_path: None,
                veth_iface: Some("veth-mock".to_string()),
                attached: true,
                include_ports_cgroup_ids: Vec::new(),
                include_ports_policy: None,
                workload_identity_cgroup_ids: Vec::new(),
                node_probe_ports: Vec::new(),
            },
        );

        retry_pending_pod_ip_removals(&mut backend, &pod_states, &config, &metrics);

        assert!(
            !PENDING_CAPTURE_FAILURES.contains_key(&failure_key),
            "re-owned pod IP should clear stale removal failure instead of keeping readiness degraded"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_READY
        );
    }

    #[test]
    fn handle_pod_added_keeps_old_ip_when_another_pod_owns_it() {
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let old_ip = std::net::Ipv4Addr::new(10, 0, 0, 5);
        let new_ip = std::net::Ipv4Addr::new(10, 0, 0, 8);

        for (pod_uid, veth) in [("pod-uid-1", "veth-a"), ("pod-uid-2", "veth-b")] {
            pod_states.insert(
                pod_uid.to_string(),
                PodAttachmentState {
                    pod_uid: pod_uid.to_string(),
                    pod_name: pod_uid.to_string(),
                    namespace: "default".to_string(),
                    pod_ip: Some(old_ip),
                    pod_ip6: None,
                    cgroup_path: None,
                    veth_iface: Some(veth.to_string()),
                    attached: true,
                    include_ports_cgroup_ids: Vec::new(),
                    include_ports_policy: None,
                    workload_identity_cgroup_ids: Vec::new(),
                    node_probe_ports: Vec::new(),
                },
            );
        }
        backend
            .update_pod_ip(
                old_ip,
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 0,
                },
            )
            .unwrap();

        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "existing",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.8"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.8")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-a"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        assert_eq!(pod_states.get("pod-uid-1").unwrap().pod_ip, Some(new_ip));
        assert_eq!(pod_states.get("pod-uid-2").unwrap().pod_ip, Some(old_ip));
        assert!(
            backend.pod_ips.contains_key(&old_ip),
            "old IP should stay mapped because pod-uid-2 still owns it"
        );
        assert!(backend.pod_ips.contains_key(&new_ip));
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let probe = kernel_probe::KernelProbeResult {
            kernel_release: "4.19.0".to_string(),
            meets_version_requirement: false,
            cgroup_v2_available: false,
            bpf_fs_available: false,
        };
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let startup_ready = Arc::new(AtomicBool::new(false));
        let metrics = Arc::new(NodeAgentMetrics::default());

        assert!(
            handle_fallback(
                &config,
                &probe,
                metrics.clone(),
                &shutdown_tx,
                startup_ready.clone(),
                CniListenerConfig {
                    enabled: false,
                    socket_path: "/tmp/ferrum-test.sock".to_string(),
                }
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
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
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_NODE_GLOBAL_FALLBACK,
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

    #[tokio::test]
    async fn admin_listener_bind_failure_aborts_startup() {
        let blocker = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("reserve node-agent admin port");
        let blocked_port = blocker.local_addr().expect("reserved address").port();
        let env_config = EnvConfig {
            node_agent_admin_enabled: true,
            admin_http_port: blocked_port,
            ..EnvConfig::default()
        };
        let (shutdown_tx, _) = tokio::sync::watch::channel(false);
        let startup_ready = Arc::new(AtomicBool::new(false));

        let err =
            start_node_agent_admin_listeners(&env_config, &shutdown_tx, startup_ready.clone())
                .await
                .expect_err("occupied admin port must abort node-agent startup");

        assert!(
            err.to_string()
                .contains("Node agent admin HTTP listener exited before completing startup"),
            "unexpected startup error: {err}"
        );
        assert!(
            !startup_ready.load(Ordering::Acquire),
            "a failed admin bind must not report node-agent ready"
        );
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
    fn decide_admin_bind_allowlist_only_binds_unspecified_over_loopback_default() {
        // Codex finding: with the admin bind defaulting to loopback, an
        // allowlist-only opt-in (no explicit FERRUM_ADMIN_BIND_ADDRESS) must
        // still expose /metrics by binding 0.0.0.0 (restricted by the allowlist),
        // not stay on the loopback default.
        let addr = decide_admin_bind_address("127.0.0.1", 9000, &signals(false, true))
            .expect("loopback default + allowlist should be valid");
        assert_eq!(
            addr,
            std::net::SocketAddr::new(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED), 9000),
            "allowlist opt-in must bind 0.0.0.0 even when the configured bind is the loopback default"
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

    #[test]
    fn handle_pod_added_writes_include_ports_for_annotated_pod() {
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "5432,8080")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state = pod_states.get("pod-uid-1").expect("pod enrolled");
        let cgroup_id = state
            .include_ports_cgroup_ids
            .first()
            .copied()
            .expect("cgroup id stashed for annotated pod");
        let policy = backend
            .include_ports
            .get(&cgroup_id)
            .expect("BPF map populated for annotated pod");
        assert!(!policy.is_all_ports());
        assert_eq!(policy.port_count, 2);
        assert_eq!(&policy.ports[..2], &[5432, 8080]);
    }

    #[cfg(unix)]
    #[test]
    fn handle_pod_added_writes_include_ports_under_container_cgroup_leaves() {
        use std::os::unix::fs::MetadataExt;

        // Finding-1 regression: the connect4/connect6 gate looks up
        // FERRUM_INCLUDE_PORTS by `bpf_get_current_cgroup_id()` (the container
        // leaf cgroup), so the policy must be written under the container
        // cgroup inodes, not only the pod inode, or per-pod port narrowing
        // silently never engages on real pods.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "pod-uid-1";
        let pod_cgroup = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        let container_cgroup = pod_cgroup.join("crio-abc123.scope");
        std::fs::create_dir_all(&container_cgroup).unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "5432,8080")]);
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let pod_ino = std::fs::metadata(&pod_cgroup).unwrap().ino();
        let container_ino = std::fs::metadata(&container_cgroup).unwrap().ino();

        // The container leaf inode — the id the gate actually looks up — must
        // carry the narrowing policy, alongside the pod inode.
        let leaf_policy = backend
            .include_ports
            .get(&container_ino)
            .expect("includeOutboundPorts must be written under the container leaf inode");
        assert_eq!(leaf_policy.port_count, 2);
        assert!(backend.include_ports.contains_key(&pod_ino));

        let state = pod_states.get(pod_uid).unwrap();
        assert!(state.include_ports_cgroup_ids.contains(&container_ino));
        assert!(state.include_ports_cgroup_ids.contains(&pod_ino));
    }

    #[cfg(unix)]
    #[test]
    fn reconcile_enrolls_late_container_include_ports_under_unchanged_policy() {
        use std::os::unix::fs::MetadataExt;

        // Finding regression: a container leaf cgroup that appears AFTER the
        // initial pod event (the common case — containers start once the pod
        // cgroup exists) must pick up the includeOutboundPorts policy even
        // though the annotation is unchanged. The reconcile re-walks the tree on
        // every event, so a later Modified event enrolls the new leaf.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        let pod_states: DashMap<String, PodAttachmentState> = DashMap::new();
        let metrics = NodeAgentMetrics::default();

        let cgroup_root = tempfile::tempdir().unwrap();
        let pod_uid = "pod-uid-1";
        let pod_cgroup = cgroup_root.path().join(format!("kubepods/pod{pod_uid}"));
        // Only the pod cgroup exists at the initial event — no container yet.
        std::fs::create_dir_all(&pod_cgroup).unwrap();

        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config: CaptureConfig::explicit(15006, 15001),
            cgroup_root: cgroup_root.path().to_string_lossy().to_string(),
            bpf_fs_path: "/nonexistent".to_string(),
            fallback_mode: FallbackMode::Iptables,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "5432,8080")]);
        let event = PodEvent {
            pod_uid,
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        // Initial enrollment: only the pod inode is present.
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        let pod_ino = std::fs::metadata(&pod_cgroup).unwrap().ino();
        assert!(backend.include_ports.contains_key(&pod_ino));

        // A container starts AFTER enrollment, creating its leaf cgroup.
        let container_cgroup = pod_cgroup.join("crio-late.scope");
        std::fs::create_dir_all(&container_cgroup).unwrap();
        let container_ino = std::fs::metadata(&container_cgroup).unwrap().ino();
        assert!(
            !backend.include_ports.contains_key(&container_ino),
            "the late container leaf is not enrolled until the next reconcile"
        );

        // A subsequent Modified event with the SAME annotation must still enroll
        // the new leaf (the reconcile re-walks despite the unchanged policy).
        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let leaf_policy = backend
            .include_ports
            .get(&container_ino)
            .expect("late container leaf must be enrolled on reconcile under unchanged policy");
        assert_eq!(leaf_policy.port_count, 2);
        let state = pod_states.get(pod_uid).unwrap();
        assert!(state.include_ports_cgroup_ids.contains(&container_ino));
        assert!(state.include_ports_cgroup_ids.contains(&pod_ino));
    }

    #[test]
    fn handle_pod_added_wildcard_annotation_writes_all_ports() {
        // See note on `handle_pod_added_enrolls_matching_pod` for why
        // this guard is required.
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "*")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state = pod_states.get("pod-uid-1").expect("pod enrolled");
        let cgroup_id = state
            .include_ports_cgroup_ids
            .first()
            .copied()
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
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &HashMap::new(),
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state = pod_states.get("pod-uid-1").expect("pod enrolled");
        assert!(
            state.include_ports_cgroup_ids.is_empty(),
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
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "bogus")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);

        let state = pod_states.get("pod-uid-1").expect("pod still enrolls");
        assert!(state.attached);
        assert!(
            state.include_ports_cgroup_ids.is_empty(),
            "malformed annotation must not write a BPF entry"
        );
        assert!(backend.include_ports.is_empty());
    }

    #[test]
    fn handle_pod_removed_removes_include_ports_entry() {
        let _veth_guard = crate::ebpf::veth::tests::TestOverrideGuard::new("veth_test");
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let labels = HashMap::from([("ferrum.io/mesh".to_string(), "enabled".to_string())]);
        let annotations =
            annotations_with(&[("traffic.sidecar.istio.io/includeOutboundPorts", "5432")]);
        let event = PodEvent {
            pod_uid: "pod-uid-1",
            pod_name: "test-pod",
            namespace: "default",
            service_account: None,
            labels: &labels,
            annotations: &annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
            pod_pid: None,
            veth_iface_override: Some("veth-mock"),
        };

        handle_pod_added(&mut backend, &pod_states, &config, &metrics, &event);
        assert_eq!(backend.include_ports.len(), 1, "entry must be written");

        handle_pod_removed(&mut backend, &pod_states, &config, &metrics, "pod-uid-1");
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
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
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
            service_account: None,
            labels,
            annotations,
            pod_ip_str: Some("10.0.0.5"),
            pod_source_ips: PodSourceIps::from_primary_str(Some("10.0.0.5")),
            node_probe_ports: Vec::new(),
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
            .include_ports_cgroup_ids
            .first()
            .copied()
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
            .include_ports_cgroup_ids
            .first()
            .copied()
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
            .include_ports_cgroup_ids
            .first()
            .copied()
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
            state.include_ports_cgroup_ids.is_empty(),
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
            .include_ports_cgroup_ids
            .first()
            .copied()
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
            .include_ports_cgroup_ids
            .first()
            .copied()
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
        assert!(
            state.include_ports_cgroup_ids.contains(&cgroup_id),
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

    /// GAP-1b: on a build without `--features ebpf`, `create_backend` must set
    /// the degraded gauge to `ebpf_feature_disabled` so the "no capture
    /// occurs" condition is observable instead of a silent mock no-op. On
    /// eBPF builds the kernel-probe path owns degradation, so this assertion
    /// only applies to the non-eBPF fallback.
    #[cfg(not(all(feature = "ebpf", target_os = "linux")))]
    #[test]
    fn create_backend_sets_degraded_gauge_without_ebpf_feature() {
        let mut capture_config = CaptureConfig::explicit(15006, 15001);
        capture_config.mode = CaptureMode::Ebpf;
        let config = NodeAgentConfig {
            node_name: "test-node".to_string(),
            capture_config,
            cgroup_root: "/sys/fs/cgroup".to_string(),
            bpf_fs_path: "/sys/fs/bpf".to_string(),
            fallback_mode: FallbackMode::Fail,
            excluded_namespaces: HashSet::new(),
            capture_contract: CaptureContract::local_pod_defaults(),
            trust_domain: "cluster.local".to_string(),
            node_waypoint_pod_registry_dir: None,
        };
        let metrics = Arc::new(NodeAgentMetrics::default());
        assert_eq!(metrics.snapshot().topology_degraded_reason, None);

        let err = match create_backend(&config, &metrics) {
            Ok(_) => panic!("mock backend must not start for enabled eBPF capture"),
            Err(err) => err,
        };

        assert_eq!(
            metrics.snapshot().topology_degraded_reason,
            Some("ebpf_feature_disabled"),
            "mock-backend fallback must mark the node topology degraded"
        );
        assert_eq!(
            metrics.snapshot().capture_state,
            NODE_AGENT_CAPTURE_STATE_UNAVAILABLE
        );
        assert!(err.to_string().contains("--features ebpf"));
    }

    /// GAP-1b: the workload identity the node-agent writes to
    /// `FERRUM_WORKLOAD_IDENTITY` must hash to the SAME value the
    /// node-waypoint resolver computes for the corresponding SPIFFE ID,
    /// otherwise the connect-stamped record never matches the enrolled
    /// identity and resolution always fails closed. This pins the
    /// producer/consumer agreement without needing a kernel.
    #[test]
    fn build_workload_identity_hash_matches_resolver() {
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::node_waypoint::workload_spiffe_hash;

        let pod_uid = "11111111-2222-3333-4444-555555555555";
        let identity = build_workload_identity(pod_uid, "prod", "api", "cluster.local")
            .expect("identity should build for valid inputs");

        // Independently derive the expected hash exactly as the CP/resolver do.
        let td = TrustDomain::new("cluster.local").expect("trust domain");
        let spiffe = SpiffeId::from_parts(&td, "ns/prod/sa/api").expect("spiffe id");
        assert_eq!(identity.workload_spiffe_hash, workload_spiffe_hash(&spiffe));
        assert_ne!(identity.workload_spiffe_hash, 0);

        // Pod UID bytes match the parsed UUID.
        let expected_uid =
            crate::modes::mesh::node_waypoint::parse_pod_uid(pod_uid).expect("parse uid");
        assert_eq!(identity.pod_uid, expected_uid);
    }

    #[test]
    fn build_workload_identity_rejects_bad_pod_uid() {
        assert!(build_workload_identity("not-a-uuid", "prod", "api", "cluster.local").is_none());
    }

    /// A missing `serviceAccountName` defaults to the `default` SA, matching
    /// Kubernetes semantics, so resolution still works for pods that don't set
    /// one explicitly.
    #[test]
    fn build_workload_identity_defaults_service_account_via_caller() {
        use crate::identity::spiffe::{SpiffeId, TrustDomain};
        use crate::modes::mesh::node_waypoint::workload_spiffe_hash;

        // `apply_workload_identity` passes `service_account.unwrap_or("default")`,
        // so build_workload_identity is called with "default" here.
        let identity = build_workload_identity(
            "11111111-2222-3333-4444-555555555555",
            "prod",
            "default",
            "cluster.local",
        )
        .expect("identity builds");
        let td = TrustDomain::new("cluster.local").expect("trust domain");
        let spiffe = SpiffeId::from_parts(&td, "ns/prod/sa/default").expect("spiffe id");
        assert_eq!(identity.workload_spiffe_hash, workload_spiffe_hash(&spiffe));
    }
}
