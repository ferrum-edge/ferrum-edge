#![allow(dead_code)]
//! Userspace eBPF manager for the node-agent capture mode.
//!
//! This module owns the trait surface, shared types, and mock backend for
//! managing BPF program attachment to pod cgroups and veth interfaces.
//! The real aya-based loader lives behind
//! `#[cfg(all(feature = "ebpf", target_os = "linux"))]`; default and non-Linux
//! builds use `MockEbpfBackend` for lifecycle tests without kernel interaction.

pub mod bpf_metrics;
pub mod cgroup;
pub mod event_consumer;
pub mod kernel_probe;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub mod loader;
pub mod maps;
pub mod orig_dst_bridge;
pub mod pod_watcher;
pub mod veth;

#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub use loader::AyaEbpfBackend;

use std::collections::{HashMap, HashSet};
use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use ferrum_ebpf_common::{BpfCaptureConfig, INBOUND_HBONE_PORT, OUTBOUND_CAPTURE_PORT};
pub use ferrum_ebpf_common::{
    INCLUDE_PORTS_MAX, IncludePortsPolicy, NODE_WAYPOINT_INBOUND_AUTH_MARK,
    NODE_WAYPOINT_INGRESS_REDIRECT_MARK, NODE_WAYPOINT_INGRESS_REDIRECT_RULE_PRIORITY,
    NODE_WAYPOINT_INGRESS_REDIRECT_TABLE, POD_CAPTURE_FLAG_INBOUND_REDIRECT, WorkloadIdentity,
};

pub const NODE_AGENT_CAPTURE_STATE_STARTING: &str = "starting";
pub const NODE_AGENT_CAPTURE_STATE_READY: &str = "ready";
pub const NODE_AGENT_CAPTURE_STATE_UNAVAILABLE: &str = "unavailable";
pub const NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED: &str = "partially_attached";
pub const NODE_AGENT_CAPTURE_STATE_IDENTITY_BRIDGE_UNAVAILABLE: &str =
    "identity_bridge_unavailable";
pub const NODE_AGENT_CAPTURE_STATE_NODE_GLOBAL_FALLBACK: &str = "node_global_fallback";
pub const NODE_AGENT_CAPTURE_STATES: &[&str] = &[
    NODE_AGENT_CAPTURE_STATE_STARTING,
    NODE_AGENT_CAPTURE_STATE_READY,
    NODE_AGENT_CAPTURE_STATE_UNAVAILABLE,
    NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED,
    NODE_AGENT_CAPTURE_STATE_IDENTITY_BRIDGE_UNAVAILABLE,
    NODE_AGENT_CAPTURE_STATE_NODE_GLOBAL_FALLBACK,
];

pub const DEFAULT_NODE_AGENT_SOCKET_PATH: &str = "/run/ferrum/node-agent.sock";
pub const BPF_MAP_ORIG_DST4: &str = "FERRUM_ORIG_DST4";
pub const BPF_MAP_ORIG_DST6: &str = "FERRUM_ORIG_DST6";
pub const BPF_MAP_POD_IPS: &str = "FERRUM_POD_IPS";
pub const BPF_MAP_POD_IPS6: &str = "FERRUM_POD_IPS6";
pub const BPF_MAP_NODE_IPS: &str = "FERRUM_NODE_IPS";
pub const BPF_MAP_NODE_IPS6: &str = "FERRUM_NODE_IPS6";
pub const BPF_MAP_NODE_PROBE_PORTS: &str = "FERRUM_NODE_PROBE_PORTS";
pub const BPF_MAP_NODE_PROBE_PORTS6: &str = "FERRUM_NODE_PROBE_PORTS6";
/// Declared inbound application ports of enrolled pods. Scopes the tc ingress
/// redirect to `(pod address, port)` pairs the workload actually serves.
pub const BPF_MAP_POD_INBOUND_PORTS: &str = "FERRUM_POD_INBOUND_PORTS";
pub const BPF_MAP_POD_INBOUND_PORTS6: &str = "FERRUM_POD_INBOUND_PORTS6";
pub const BPF_MAP_BYPASS_UIDS: &str = "FERRUM_BYPASS_UIDS";
pub const BPF_MAP_CIDR_EXCLUDE4: &str = "FERRUM_CIDR_EXCLUDE4";
pub const BPF_MAP_CIDR_EXCLUDE6: &str = "FERRUM_CIDR_EXCLUDE6";
pub const BPF_MAP_CIDR_INCLUDE4: &str = "FERRUM_CIDR_INCLUDE4";
pub const BPF_MAP_CIDR_INCLUDE6: &str = "FERRUM_CIDR_INCLUDE6";
pub const BPF_MAP_PORT_EXCLUDE: &str = "FERRUM_PORT_EXCLUDE";
pub const BPF_MAP_INCLUDE_PORTS: &str = "FERRUM_INCLUDE_PORTS";
pub const BPF_MAP_CAPTURE_CONFIG: &str = "FERRUM_CAPTURE_CONFIG";
/// Per-cgroup source workload identity map. Written by the node-agent on pod
/// enrollment; read by the connect hooks to stamp orig-dst records.
pub const BPF_MAP_WORKLOAD_IDENTITY: &str = "FERRUM_WORKLOAD_IDENTITY";

/// Name of the BPF ringbuf map that ferries SOCK_OPS event records from the
/// kernel to the userspace consumer.
pub const BPF_MAP_SOCK_OPS_EVENTS: &str = "FERRUM_SOCK_OPS_EVENTS";

/// Name of the per-CPU stats array that tracks events dropped because the
/// ringbuf could not be reserved.
pub const BPF_MAP_SOCK_OPS_STATS: &str = "FERRUM_SOCK_OPS_STATS";

/// Pinned path for the SOCK_OPS event ringbuf. Node-agent loads + pins;
/// mesh-proxy opens by path. Both sides agree on the constant so no IPC is
/// required.
pub const BPF_SOCK_OPS_EVENTS_PIN_PATH: &str = "/sys/fs/bpf/ferrum/sock_ops_events";

/// Pinned path for the SOCK_OPS dropped-events counter array.
pub const BPF_SOCK_OPS_STATS_PIN_PATH: &str = "/sys/fs/bpf/ferrum/sock_ops_stats";

/// Pinned path for the IPv4 original-destination map. Node-agent loads + pins;
/// the node-waypoint mesh-proxy opens by path through the orig-dst bridge
/// (GAP-1b) to recover per-socket source identity. Both sides agree on the
/// constant so no IPC is required — mirroring the SOCK_OPS pin contract.
pub const BPF_ORIG_DST4_PIN_PATH: &str = "/sys/fs/bpf/ferrum/orig_dst4";

/// Pinned path for the IPv6 original-destination map.
pub const BPF_ORIG_DST6_PIN_PATH: &str = "/sys/fs/bpf/ferrum/orig_dst6";

/// Program name of the SOCK_OPS kernel program in the ELF.
pub const BPF_PROGRAM_SOCK_OPS: &str = "ferrum_sock_ops";

/// Program name of the per-pod-veth direct-inbound guard classifier.
pub const BPF_PROGRAM_TC_INBOUND: &str = "ferrum_tc_inbound";

/// Program name of the node-level tc **ingress** redirect classifier. Attached
/// once per configured node capture interface (never per pod), it steers
/// inbound TCP for enrolled workloads into the local NodeWaypoint relay with
/// `bpf_sk_assign` instead of relying on a node-global iptables REDIRECT.
pub const BPF_PROGRAM_TC_INGRESS_REDIRECT: &str = "ferrum_tc_ingress_redirect";

/// Node-agent proxy topology for the capture contract.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeAgentProxyMode {
    LocalPod,
    NodeWaypoint,
}

impl NodeAgentProxyMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "local_pod" => Ok(Self::LocalPod),
            "node_waypoint" => Ok(Self::NodeWaypoint),
            other => Err(format!(
                "Invalid FERRUM_NODE_AGENT_PROXY_MODE {}. Expected: local_pod or node_waypoint",
                crate::secrets::quoted_env_value("FERRUM_NODE_AGENT_PROXY_MODE", other)
            )),
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalPod => "local_pod",
            Self::NodeWaypoint => "node_waypoint",
        }
    }
}

impl std::fmt::Display for NodeAgentProxyMode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// BPF map names that form the node-agent/proxy capture ABI.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CaptureBpfMaps {
    pub orig_dst4: &'static str,
    pub orig_dst6: &'static str,
    pub pod_ips: &'static str,
    pub pod_ips6: &'static str,
    pub node_ips: &'static str,
    pub node_ips6: &'static str,
    pub node_probe_ports: &'static str,
    pub node_probe_ports6: &'static str,
    pub pod_inbound_ports: &'static str,
    pub pod_inbound_ports6: &'static str,
    pub bypass_uids: &'static str,
    pub cidr_exclude4: &'static str,
    pub cidr_exclude6: &'static str,
    pub cidr_include4: &'static str,
    pub cidr_include6: &'static str,
    pub port_exclude: &'static str,
    pub include_ports: &'static str,
    pub capture_config: &'static str,
}

impl Default for CaptureBpfMaps {
    fn default() -> Self {
        Self {
            orig_dst4: BPF_MAP_ORIG_DST4,
            orig_dst6: BPF_MAP_ORIG_DST6,
            pod_ips: BPF_MAP_POD_IPS,
            pod_ips6: BPF_MAP_POD_IPS6,
            node_ips: BPF_MAP_NODE_IPS,
            node_ips6: BPF_MAP_NODE_IPS6,
            node_probe_ports: BPF_MAP_NODE_PROBE_PORTS,
            node_probe_ports6: BPF_MAP_NODE_PROBE_PORTS6,
            pod_inbound_ports: BPF_MAP_POD_INBOUND_PORTS,
            pod_inbound_ports6: BPF_MAP_POD_INBOUND_PORTS6,
            bypass_uids: BPF_MAP_BYPASS_UIDS,
            cidr_exclude4: BPF_MAP_CIDR_EXCLUDE4,
            cidr_exclude6: BPF_MAP_CIDR_EXCLUDE6,
            cidr_include4: BPF_MAP_CIDR_INCLUDE4,
            cidr_include6: BPF_MAP_CIDR_INCLUDE6,
            port_exclude: BPF_MAP_PORT_EXCLUDE,
            include_ports: BPF_MAP_INCLUDE_PORTS,
            capture_config: BPF_MAP_CAPTURE_CONFIG,
        }
    }
}

/// Formal node-agent/proxy capture surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CaptureContract {
    pub proxy_mode: NodeAgentProxyMode,
    pub outbound_capture_port: u16,
    pub hbone_redirect_port: u16,
    pub unix_socket_path: String,
    pub bpf_maps: CaptureBpfMaps,
    /// Fail closed on captured IPv6 outbound (the `connect6` hook returns
    /// `EPERM`) instead of redirecting it. This remains available as a safety
    /// valve, but NodeWaypoint now keeps it disabled because the in-netns capture
    /// manager opens an IPv6 pod-loopback listener and missing listeners fail
    /// closed by connection refusal.
    pub ipv6_outbound_deny: bool,
    pub node_waypoint_inbound_auth_mark: u32,
    /// Node capture interfaces that carry the tc **ingress** redirect
    /// classifier. Empty (the default) means the redirect is not installed and
    /// the datapath keeps its previous inbound behavior.
    ///
    /// These are node uplink interfaces, not pod veths: off-node traffic to an
    /// enrolled pod is only visible on a tc ingress hook before routing decides
    /// to forward it, and `bpf_sk_assign` is ingress-only. The program is still
    /// scoped per packet by the enrolled-pod maps, so attaching here does not
    /// capture unenrolled traffic.
    pub ingress_redirect_ifaces: Vec<String>,
    /// `skb->mark` used for local delivery of redirected inbound packets. Zero
    /// (the default) disarms the kernel-side redirect entirely.
    pub node_waypoint_ingress_redirect_mark: u32,
    /// TCP port of the proxy's transparent inbound **capture** listener — the
    /// redirect's steer target, read from the same
    /// `FERRUM_MESH_INBOUND_LISTEN_ADDR` the proxy binds so the two processes
    /// cannot drift. Zero disarms the redirect.
    ///
    /// Never [`Self::hbone_redirect_port`]: HBONE terminates authenticated H2
    /// CONNECT over mesh mTLS, while captured traffic is raw application bytes.
    /// [`Self::validate_ingress_redirect`] rejects a configuration that
    /// collapses the two.
    pub ingress_capture_port: u16,
    /// Whether the capture listener's bind address can accept IPv6.
    ///
    /// `bpf_sk_assign` resolves the listener with a wildcard socket lookup in
    /// the packet's own address family, and the kernel never returns an
    /// `AF_INET` socket for an IPv6 lookup. So a listener bound `0.0.0.0` (the
    /// default) is invisible to the classifier's IPv6 path, and an in-scope
    /// IPv6 packet would be **dropped** fail-closed rather than delivered. A
    /// `[::]` bind is dual-stack (`bindv6only=0`) and covers both families.
    ///
    /// The node-agent therefore publishes IPv6 redirect scope only when this is
    /// set; otherwise enrolled pods' IPv6 traffic stays out of scope entirely
    /// and falls through to the pre-existing direct-pod guard, exactly as it
    /// did before the redirect existed.
    pub ingress_capture_supports_ipv6: bool,
}

impl CaptureContract {
    /// `true` when the inbound tc ingress redirect should be installed: it is
    /// NodeWaypoint-only (local-pod mode has no capture listener to steer
    /// into), needs at least one capture interface, a non-zero delivery mark,
    /// and a non-zero capture listener port.
    pub fn ingress_redirect_enabled(&self) -> bool {
        self.proxy_mode == NodeAgentProxyMode::NodeWaypoint
            && self.node_waypoint_ingress_redirect_mark != 0
            && self.ingress_capture_port != 0
            && !self.ingress_redirect_ifaces.is_empty()
    }

    /// Fail-closed validation of the ingress-redirect port contract, run at
    /// node-agent startup before anything is attached.
    ///
    /// The node-agent and the mesh proxy are separate processes in the same
    /// DaemonSet; they agree on the capture port only because both read
    /// `FERRUM_MESH_INBOUND_LISTEN_ADDR`. This check makes a disagreement (or a
    /// port collision that would make the datapath ambiguous) a startup error
    /// rather than a silent black hole.
    pub fn validate_ingress_redirect(&self) -> Result<(), String> {
        if self.ingress_redirect_ifaces.is_empty() {
            return Ok(());
        }
        if self.proxy_mode != NodeAgentProxyMode::NodeWaypoint {
            return Err(format!(
                "FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES requires \
                 FERRUM_NODE_AGENT_PROXY_MODE=node_waypoint (got {}); only NodeWaypoint runs the \
                 transparent inbound capture listener the redirect steers into",
                self.proxy_mode
            ));
        }
        if self.ingress_capture_port == 0 {
            return Err(
                "FERRUM_NODE_AGENT_INGRESS_REDIRECT_IFACES requires a non-zero port in \
                 FERRUM_MESH_INBOUND_LISTEN_ADDR: that is the transparent inbound capture \
                 listener the redirect steers captured traffic into"
                    .to_string(),
            );
        }
        if self.ingress_capture_port == self.hbone_redirect_port {
            return Err(format!(
                "the NodeWaypoint inbound capture port ({}) must differ from the HBONE port \
                 (FERRUM_NODE_AGENT_HBONE_REDIRECT_PORT={}). HBONE terminates authenticated \
                 HTTP/2 CONNECT over mesh mTLS; captured traffic is raw application bytes, so \
                 steering it at the HBONE listener would fail the mesh TLS handshake",
                self.ingress_capture_port, self.hbone_redirect_port
            ));
        }
        if self.ingress_capture_port == self.outbound_capture_port {
            return Err(format!(
                "the NodeWaypoint inbound capture port ({}) must differ from the outbound \
                 capture port ({})",
                self.ingress_capture_port, self.outbound_capture_port
            ));
        }
        Ok(())
    }

    pub fn new(
        proxy_mode: NodeAgentProxyMode,
        outbound_capture_port: u16,
        hbone_redirect_port: u16,
        unix_socket_path: impl Into<String>,
    ) -> Result<Self, String> {
        if outbound_capture_port == 0 {
            return Err("CaptureContract outbound_capture_port must be non-zero".to_string());
        }
        if hbone_redirect_port == 0 {
            return Err("CaptureContract hbone_redirect_port must be non-zero".to_string());
        }
        if outbound_capture_port == hbone_redirect_port {
            return Err(
                "CaptureContract outbound_capture_port and hbone_redirect_port must differ"
                    .to_string(),
            );
        }
        let unix_socket_path = unix_socket_path.into();
        if unix_socket_path.trim().is_empty() {
            return Err("CaptureContract unix_socket_path must not be empty".to_string());
        }

        Ok(Self {
            proxy_mode,
            outbound_capture_port,
            hbone_redirect_port,
            unix_socket_path,
            bpf_maps: CaptureBpfMaps::default(),
            ipv6_outbound_deny: false,
            node_waypoint_inbound_auth_mark: NODE_WAYPOINT_INBOUND_AUTH_MARK,
            ingress_redirect_ifaces: Vec::new(),
            node_waypoint_ingress_redirect_mark: 0,
            ingress_capture_port: 0,
            ingress_capture_supports_ipv6: false,
        })
    }

    pub fn local_pod_defaults() -> Self {
        Self {
            proxy_mode: NodeAgentProxyMode::LocalPod,
            outbound_capture_port: OUTBOUND_CAPTURE_PORT,
            hbone_redirect_port: INBOUND_HBONE_PORT,
            unix_socket_path: DEFAULT_NODE_AGENT_SOCKET_PATH.to_string(),
            bpf_maps: CaptureBpfMaps::default(),
            ipv6_outbound_deny: false,
            node_waypoint_inbound_auth_mark: NODE_WAYPOINT_INBOUND_AUTH_MARK,
            ingress_redirect_ifaces: Vec::new(),
            node_waypoint_ingress_redirect_mark: 0,
            ingress_capture_port: 0,
            ingress_capture_supports_ipv6: false,
        }
    }

    pub fn bpf_capture_config(&self) -> BpfCaptureConfig {
        let inbound_auth_mark = match self.proxy_mode {
            NodeAgentProxyMode::LocalPod => 0,
            NodeAgentProxyMode::NodeWaypoint => self.node_waypoint_inbound_auth_mark,
        };
        // The kernel-side redirect mark is published only when every
        // precondition holds (NodeWaypoint, a capture interface to attach to,
        // and a configured mark). Publishing it otherwise would arm a kernel
        // datapath whose local-delivery routing was never installed.
        //
        // The capture PORT is published on the same all-or-nothing condition:
        // a port without a mark (or vice versa) would leave the classifier
        // half-configured, and `ingress_redirect_armed()` requires both.
        let (ingress_redirect_mark, ingress_capture_port) = if self.ingress_redirect_enabled() {
            (
                self.node_waypoint_ingress_redirect_mark,
                self.ingress_capture_port,
            )
        } else {
            (0, 0)
        };
        BpfCaptureConfig::new(self.outbound_capture_port, self.hbone_redirect_port)
            .with_ipv6_outbound_deny(self.ipv6_outbound_deny)
            .with_node_waypoint_inbound_auth_mark(inbound_auth_mark)
            .with_node_waypoint_ingress_redirect_mark(ingress_redirect_mark)
            .with_node_waypoint_ingress_capture_port(ingress_capture_port)
    }
}

/// Metrics tracked by the node agent.
pub struct NodeAgentMetrics {
    pub pods_enrolled: AtomicU64,
    pub pods_unenrolled: AtomicU64,
    pub attach_errors: AtomicU64,
    /// Successful re-applications of an `includeOutboundPorts` annotation
    /// change on a live pod (Kubernetes Modified event whose parsed policy
    /// differed from the stashed baseline and was written into the BPF
    /// map). Excludes the initial enrollment write and excludes Modified
    /// events whose parsed policy was unchanged (diff-skip). Operators
    /// can graph this alongside `pods_enrolled_total` to confirm a kubectl
    /// annotate took effect without a pod restart.
    pub pod_annotation_updates_applied: AtomicU64,
    /// Failed attempts to re-apply an `includeOutboundPorts` annotation
    /// change on a live pod (annotation parse error or BPF map write
    /// error). The pod stays enrolled with its previous policy so
    /// capture does not silently widen on failure. Cgroup-id-unavailable
    /// retries (Pod object reached the watcher before kubelet finished
    /// creating the cgroup) are intentionally not counted here — they
    /// are routinely observed during early pod startup and are retried
    /// on the next Apply event without ever needing operator attention.
    pub pod_annotation_updates_failed: AtomicU64,
    /// Reason this node detected missing eBPF prerequisites, or `None` when
    /// running the nominal eBPF capture path. Stored via `ArcSwap` so
    /// the Prometheus render path is lock-free. The value is set exactly
    /// once at startup (after the kernel probe runs) — operators must
    /// restart the node agent after a kernel/cgroup/bpffs change, which
    /// matches the rest of the node-agent contract.
    pub topology_degraded_reason: ArcSwap<Option<&'static str>>,
    /// Bounded operational state for the capture backend. This is separate from
    /// `topology_degraded_reason`: the reason explains the first fault, while
    /// this state is an alerting-friendly condition that distinguishes startup,
    /// ready, unavailable, partially attached, identity-bridge unavailable, and
    /// explicit node-global fallback.
    pub capture_state: ArcSwap<&'static str>,
    /// CNI plugin RPC counts split by `(verb, outcome)` where verb is one
    /// of `add`/`del`/`check` and outcome is `success`/`rejected`/`error`.
    /// Bounded cardinality (3 × 3 = 9 series at most). Lets operators see
    /// whether the CNI plugin is the primary enrollment path or the
    /// kube-rs watcher fallback is doing all the work. Read by the
    /// Prometheus render path and reset only on process restart.
    pub cni_calls: [[AtomicU64; 3]; 3],
    /// CNI socket lifecycle failures split by a closed reason set. These
    /// process-lifetime counters distinguish a refused live-owner overlap from
    /// stale cleanup, publication/identity, and shutdown cleanup failures.
    pub cni_socket_lifecycle: [AtomicU64; 6],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct NodeAgentMetricsSnapshot {
    pub pods_enrolled: u64,
    pub pods_unenrolled: u64,
    pub attach_errors: u64,
    pub pod_annotation_updates_applied: u64,
    pub pod_annotation_updates_failed: u64,
    pub topology_degraded_reason: Option<&'static str>,
    pub capture_state: &'static str,
    /// Snapshot of [`NodeAgentMetrics::cni_calls`]. Same `[verb][outcome]`
    /// layout as the source atomics. The outer axis is verb
    /// (`add`/`del`/`check`); the inner axis is outcome
    /// (`success`/`rejected`/`error`).
    pub cni_calls: [[u64; 3]; 3],
    /// Snapshot of [`NodeAgentMetrics::cni_socket_lifecycle`], indexed by
    /// [`CniSocketLifecycleReason`].
    pub cni_socket_lifecycle: [u64; 6],
}

/// Closed set of verbs tracked by [`NodeAgentMetrics::cni_calls`].
/// The discriminant is the row index into the atomic / snapshot matrices.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum CniCallVerb {
    Add = 0,
    Del = 1,
    Check = 2,
}

impl CniCallVerb {
    pub fn label(self) -> &'static str {
        match self {
            Self::Add => "add",
            Self::Del => "del",
            Self::Check => "check",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Add, Self::Del, Self::Check]
    }
}

/// Closed set of CNI RPC outcomes. The discriminant is the column index.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum CniCallOutcome {
    Success = 0,
    Rejected = 1,
    Error = 2,
}

impl CniCallOutcome {
    pub fn label(self) -> &'static str {
        match self {
            Self::Success => "success",
            Self::Rejected => "rejected",
            Self::Error => "error",
        }
    }

    pub fn all() -> [Self; 3] {
        [Self::Success, Self::Rejected, Self::Error]
    }
}

/// Closed reasons for node-agent CNI socket lifecycle failures.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(usize)]
pub enum CniSocketLifecycleReason {
    OwnershipConflict = 0,
    OwnershipIoError = 1,
    StaleSocketCleanupError = 2,
    HandoffIdentityError = 3,
    HandoffPublicationError = 4,
    ShutdownCleanupError = 5,
}

impl CniSocketLifecycleReason {
    pub fn label(self) -> &'static str {
        match self {
            Self::OwnershipConflict => "ownership_conflict",
            Self::OwnershipIoError => "ownership_io_error",
            Self::StaleSocketCleanupError => "stale_socket_cleanup_error",
            Self::HandoffIdentityError => "handoff_identity_error",
            Self::HandoffPublicationError => "handoff_publication_error",
            Self::ShutdownCleanupError => "shutdown_cleanup_error",
        }
    }

    pub fn all() -> [Self; 6] {
        [
            Self::OwnershipConflict,
            Self::OwnershipIoError,
            Self::StaleSocketCleanupError,
            Self::HandoffIdentityError,
            Self::HandoffPublicationError,
            Self::ShutdownCleanupError,
        ]
    }
}

impl NodeAgentMetrics {
    pub fn snapshot(&self) -> NodeAgentMetricsSnapshot {
        let mut cni_calls = [[0u64; 3]; 3];
        for verb in CniCallVerb::all() {
            for outcome in CniCallOutcome::all() {
                cni_calls[verb as usize][outcome as usize] =
                    self.cni_calls[verb as usize][outcome as usize].load(Ordering::Relaxed);
            }
        }
        let mut cni_socket_lifecycle = [0u64; 6];
        for reason in CniSocketLifecycleReason::all() {
            cni_socket_lifecycle[reason as usize] =
                self.cni_socket_lifecycle[reason as usize].load(Ordering::Relaxed);
        }
        NodeAgentMetricsSnapshot {
            pods_enrolled: self.pods_enrolled.load(Ordering::Relaxed),
            pods_unenrolled: self.pods_unenrolled.load(Ordering::Relaxed),
            attach_errors: self.attach_errors.load(Ordering::Relaxed),
            pod_annotation_updates_applied: self
                .pod_annotation_updates_applied
                .load(Ordering::Relaxed),
            pod_annotation_updates_failed: self
                .pod_annotation_updates_failed
                .load(Ordering::Relaxed),
            topology_degraded_reason: *self.topology_degraded_reason.load_full().as_ref(),
            capture_state: self.capture_state.load_full().as_ref(),
            cni_calls,
            cni_socket_lifecycle,
        }
    }

    /// Record that this node agent detected missing eBPF prerequisites.
    /// `reason` is a
    /// closed-set snake_case label from
    /// [`crate::ebpf::kernel_probe::KernelProbeResult::degradation_reason`].
    /// Idempotent — repeat calls with the same reason are no-ops.
    pub fn set_topology_degraded(&self, reason: &'static str) {
        self.topology_degraded_reason.store(Arc::new(Some(reason)));
    }

    /// Clear any prior degraded state. Intended for tests; the production
    /// path sets the reason once at startup and never clears it.
    pub fn clear_topology_degraded(&self) {
        self.topology_degraded_reason.store(Arc::new(None));
    }

    /// Update the operator-visible capture state. Labels must come from
    /// [`NODE_AGENT_CAPTURE_STATES`] to keep Prometheus cardinality bounded.
    pub fn set_capture_state(&self, state: &'static str) {
        self.capture_state.store(Arc::new(state));
    }

    pub fn record_attach_error(&self) {
        self.attach_errors.fetch_add(1, Ordering::Relaxed);
        self.set_capture_state(NODE_AGENT_CAPTURE_STATE_PARTIALLY_ATTACHED);
    }

    /// Increment the CNI call counter for one `(verb, outcome)` cell. The
    /// node-agent CNI server calls this exactly once per RPC.
    pub fn record_cni_call(&self, verb: CniCallVerb, outcome: CniCallOutcome) {
        self.cni_calls[verb as usize][outcome as usize].fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_cni_socket_lifecycle(&self, reason: CniSocketLifecycleReason) {
        self.cni_socket_lifecycle[reason as usize].fetch_add(1, Ordering::Relaxed);
    }
}

impl Default for NodeAgentMetrics {
    fn default() -> Self {
        Self {
            pods_enrolled: AtomicU64::new(0),
            pods_unenrolled: AtomicU64::new(0),
            attach_errors: AtomicU64::new(0),
            pod_annotation_updates_applied: AtomicU64::new(0),
            pod_annotation_updates_failed: AtomicU64::new(0),
            topology_degraded_reason: ArcSwap::from_pointee(None),
            capture_state: ArcSwap::from_pointee(NODE_AGENT_CAPTURE_STATE_STARTING),
            cni_calls: [
                [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
                [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
                [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)],
            ],
            cni_socket_lifecycle: [
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
                AtomicU64::new(0),
            ],
        }
    }
}

/// Metadata tracked per enrolled pod IP in the BPF `FERRUM_POD_IPS` map.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PodInfo {
    pub proxy_port: u16,
    /// Lifecycle flags encoded for the BPF pod-IP map. The low bits mirror
    /// `ferrum_ebpf_common::POD_CAPTURE_FLAG_*`.
    pub capture_flags: u32,
}

impl PodInfo {
    pub fn for_capture(proxy_port: u16, udp_enabled: bool, udp_ready: bool) -> Self {
        let mut capture_flags = 0_u32;
        if udp_enabled {
            capture_flags |= ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_ENABLED;
        }
        if udp_enabled && udp_ready {
            capture_flags |= ferrum_ebpf_common::POD_CAPTURE_FLAG_UDP_READY;
        }
        Self {
            proxy_port,
            capture_flags,
        }
    }

    /// Opt this pod into the NodeWaypoint inbound tc ingress redirect.
    ///
    /// Deliberately a separate, explicit step rather than a `for_capture`
    /// parameter: the flag must be set only after the pod's declared inbound
    /// ports have been written to the redirect scope maps, so an enrolled pod
    /// is never advertised as redirect-eligible before it is reachable.
    pub fn with_inbound_redirect(mut self, enabled: bool) -> Self {
        if enabled {
            self.capture_flags |= POD_CAPTURE_FLAG_INBOUND_REDIRECT;
        } else {
            self.capture_flags &= !POD_CAPTURE_FLAG_INBOUND_REDIRECT;
        }
        self
    }

    pub fn inbound_redirect_enabled(&self) -> bool {
        self.capture_flags & POD_CAPTURE_FLAG_INBOUND_REDIRECT != 0
    }
}

/// State tracked per attached pod for graceful cleanup on removal.
#[derive(Debug, Clone)]
pub struct PodAttachmentState {
    pub pod_uid: String,
    pub pod_name: String,
    pub namespace: String,
    pub pod_ip: Option<Ipv4Addr>,
    pub pod_ip6: Option<Ipv6Addr>,
    pub cgroup_path: Option<String>,
    pub veth_iface: Option<String>,
    pub attached: bool,
    /// Cgroup ids carrying this pod's `includeOutboundPorts` entries in
    /// `FERRUM_INCLUDE_PORTS`: the pod cgroup inode plus every descendant
    /// container-cgroup inode (`cgroup::collect_cgroup_tree_inodes`). The
    /// `connect4`/`connect6` gate keys this map by `bpf_get_current_cgroup_id()`
    /// — the container leaf cgroup, a child of the pod cgroup — so the policy
    /// must live under the leaf inodes, not just the pod inode, or narrowing
    /// never engages. Captured at enrollment as the removal keys so
    /// un-enrollment drops every entry without re-statting a possibly-gone
    /// cgroup tree. Empty when the pod is unannotated or no cgroup inode could
    /// be read.
    pub include_ports_cgroup_ids: Vec<u64>,
    /// Last `IncludePortsPolicy` applied to the BPF map for this pod, or
    /// `None` when the pod has no `includeOutboundPorts` annotation in
    /// effect. Used as the diff baseline on Kubernetes `Apply` (modify)
    /// events so the watcher can re-evaluate a live pod's annotations
    /// and only re-program the BPF map when the parsed policy actually
    /// changed. Without this baseline the node-agent would either churn
    /// the map on every Modified event (pod status updates fire many)
    /// or, worse, ignore live edits to `traffic.sidecar.istio.io/includeOutboundPorts`
    /// (the GAP-2K mid-life update gap this field closes).
    pub include_ports_policy: Option<IncludePortsPolicy>,
    /// Cgroup ids carrying this pod's `FERRUM_WORKLOAD_IDENTITY` entries
    /// (GAP-1b): the pod cgroup inode plus every descendant container-cgroup
    /// inode (see `cgroup::collect_cgroup_tree_inodes`). The connect hooks read
    /// `bpf_get_current_cgroup_id()`, which is the *container* leaf cgroup —
    /// a child of the pod cgroup on every Kubernetes cgroup driver — so the
    /// identity must be written under those leaf inodes, not just the pod inode,
    /// or the hook's lookup misses and resolution fails closed. Captured at
    /// enrollment as the removal keys so un-enrollment drops every entry without
    /// re-statting a possibly-gone cgroup path. Empty when the identity could
    /// not be derived or no cgroup inode could be read.
    pub workload_identity_cgroup_ids: Vec<u64>,
    /// Kubernetes liveness/readiness/startup probe TCP destination ports that
    /// were written to `FERRUM_NODE_PROBE_PORTS*` for this pod. Used as the
    /// removal baseline because Kubernetes delete events do not carry a stable
    /// spec snapshot.
    pub node_probe_ports: Vec<u16>,
    /// Declared inbound TCP application ports written to
    /// `FERRUM_POD_INBOUND_PORTS*` for this pod, scoping the tc ingress
    /// redirect. Like `node_probe_ports` this is the removal baseline: a
    /// Kubernetes delete event carries no spec, so the ports the redirect was
    /// scoped to must be remembered or teardown would leave the pod's addresses
    /// permanently redirect-eligible.
    ///
    /// Empty means the redirect is not scoped for this pod, which — combined
    /// with the per-pod [`POD_CAPTURE_FLAG_INBOUND_REDIRECT`] flag — is the
    /// "never capture this pod" posture.
    pub inbound_redirect_ports: Vec<u16>,
}

/// Fallback behavior when the kernel does not support eBPF capture.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FallbackMode {
    Iptables,
    Fail,
}

impl FallbackMode {
    pub fn parse(raw: &str) -> Result<Self, String> {
        match raw.to_ascii_lowercase().as_str() {
            "iptables" => Ok(Self::Iptables),
            "fail" => Ok(Self::Fail),
            other => Err(format!(
                "Invalid FERRUM_NODE_AGENT_FALLBACK_MODE {}. Expected: iptables, fail",
                crate::secrets::quoted_env_value("FERRUM_NODE_AGENT_FALLBACK_MODE", other)
            )),
        }
    }
}

/// Direction for attaching the tc classifier to a pod veth.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TcAttachDirection {
    Ingress,
    Egress,
}

impl TcAttachDirection {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Ingress => "ingress",
            Self::Egress => "egress",
        }
    }
}

/// Abstraction over BPF program management for testability.
///
/// `AyaEbpfBackend` uses `aya` to load and attach programs on Linux when the
/// `ebpf` feature is enabled; `MockEbpfBackend` is the in-memory test
/// substitute.
pub trait EbpfBackend: Send + Sync {
    fn load_programs(&mut self) -> Result<(), String>;
    fn update_capture_config(&mut self, config: &BpfCaptureConfig) -> Result<(), String>;
    fn attach_cgroup(
        &mut self,
        pod_uid: &str,
        cgroup_path: &str,
        program: &str,
    ) -> Result<(), String>;
    fn attach_tc(
        &mut self,
        pod_uid: &str,
        iface: &str,
        program: &str,
        direction: TcAttachDirection,
    ) -> Result<(), String>;
    fn detach_pod(&mut self, pod_uid: &str) -> Result<(), String>;
    fn update_pod_ip(&mut self, ip: Ipv4Addr, info: &PodInfo) -> Result<(), String>;
    /// Remove an enrolled pod IPv4 entry. Real BPF maps tolerate ENOENT because
    /// rollback paths may run before the corresponding update was applied.
    fn remove_pod_ip(&mut self, ip: Ipv4Addr) -> Result<(), String>;
    fn update_pod_ip6(&mut self, ip: Ipv6Addr, info: &PodInfo) -> Result<(), String>;
    /// Remove an enrolled pod IPv6 entry. Real BPF maps tolerate ENOENT because
    /// rollback paths may run before the corresponding update was applied.
    fn remove_pod_ip6(&mut self, ip: Ipv6Addr) -> Result<(), String>;
    fn update_node_ip(&mut self, ip: Ipv4Addr) -> Result<(), String>;
    fn update_node_ip6(&mut self, ip: Ipv6Addr) -> Result<(), String>;
    /// Whether the NodeWaypoint inbound direct-pod guard has at least one
    /// trusted node source IP for the given address family. Enrollment consults
    /// this so a dual-stack deployment that configured only one family's source
    /// IP surfaces the gap (the relay dial to the unconfigured family's pods is
    /// dropped by the source-bound guard) instead of silently black-holing it.
    fn has_node_source_ipv4(&self) -> bool;
    fn has_node_source_ipv6(&self) -> bool;
    /// Attach the node-level tc **ingress** redirect classifier to one node
    /// capture interface. Called once per configured interface at startup (not
    /// per pod); the program is scoped per packet by the enrolled-pod maps.
    ///
    /// Attaching twice to the same interface is the caller's responsibility to
    /// avoid — the node-agent attaches from a deduplicated interface list.
    fn attach_ingress_redirect(&mut self, iface: &str) -> Result<(), String>;

    /// Detach every node-level ingress redirect classifier this backend
    /// attached. Used when the redirect is turned off on reload and by
    /// shutdown cleanup, so a disabled redirect never leaves a live classifier
    /// steering traffic at a listener that is going away.
    ///
    /// **Retry contract:** an attachment that did not provably come down must
    /// stay recorded, so a later call (notably from `cleanup_all`) really is a
    /// second attempt and [`Self::ingress_redirect_attached`] keeps reporting
    /// it. Dropping a failed attachment would report success while the
    /// classifier is still assigning sockets.
    fn detach_ingress_redirect(&mut self) -> Result<(), String>;

    /// Whether any node-level ingress redirect classifier is still recorded as
    /// attached — i.e. a detach was never attempted, or was attempted and did
    /// not succeed.
    ///
    /// The node-agent gates the local-delivery **routing** teardown on this.
    /// A live classifier without its routing is the harmful half-state: the
    /// classifier keeps assigning packets to the capture socket while the
    /// `main` table forwards them to the pod, so they reach neither endpoint.
    /// Inert leftover routing is the safe one, so routing is removed only once
    /// this reports `false`.
    fn ingress_redirect_attached(&self) -> bool;

    /// Replace the declared inbound TCP application ports of an enrolled IPv4
    /// pod. Without a matching `(address, port)` entry the tc ingress redirect
    /// leaves the packet alone, so this is the per-port scope gate.
    ///
    /// Set-valued rather than per-port on purpose: the removal baseline is the
    /// **pod address**, not a list the caller has to carry. A Kubernetes delete
    /// event does not include a spec snapshot, so an enumerated removal list
    /// would go stale exactly when it matters. Replacing wholesale also makes
    /// a spec change (`containerPorts` edited on a live pod) converge without
    /// leaving a widened stale port behind.
    fn update_pod_inbound_ports(&mut self, ip: Ipv4Addr, ports: &[u16]) -> Result<(), String>;

    /// Remove **every** inbound-redirect scope entry for a pod address.
    /// Idempotent, and safe to call for a pod that was never scoped.
    fn clear_pod_inbound_ports(&mut self, ip: Ipv4Addr) -> Result<(), String>;

    fn update_pod_inbound_ports6(&mut self, ip: Ipv6Addr, ports: &[u16]) -> Result<(), String>;

    fn clear_pod_inbound_ports6(&mut self, ip: Ipv6Addr) -> Result<(), String>;

    fn update_node_probe_port(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), String>;
    fn remove_node_probe_port(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), String>;
    fn update_node_probe_port6(&mut self, ip: Ipv6Addr, port: u16) -> Result<(), String>;
    fn remove_node_probe_port6(&mut self, ip: Ipv6Addr, port: u16) -> Result<(), String>;
    fn update_bypass_uid(&mut self, uid: u32) -> Result<(), String>;
    fn update_cidr_exclude(&mut self, cidr: &str) -> Result<(), String>;
    fn update_cidr_include(&mut self, cidr: &str) -> Result<(), String>;
    fn update_port_exclude(&mut self, port: u16) -> Result<(), String>;
    /// Insert a per-cgroup `includeOutboundPorts` narrowing policy. The
    /// node-agent calls this when an annotated pod enrolls so the BPF
    /// `connect4` / `connect6` programs skip rewriting traffic to ports
    /// outside the pod's `traffic.sidecar.istio.io/includeOutboundPorts`
    /// list. Pods with no annotation never get an entry — the BPF gate
    /// fail-opens on missing lookups so unannotated traffic stays
    /// captured exactly like before this gate existed.
    fn update_pod_include_ports(
        &mut self,
        cgroup_id: u64,
        policy: &IncludePortsPolicy,
    ) -> Result<(), String>;
    /// Counterpart to `update_pod_include_ports`. Called on pod
    /// un-enrollment / removal. Tolerates ENOENT (pod was never
    /// annotated) by returning `Ok(())`.
    fn remove_pod_include_ports(&mut self, cgroup_id: u64) -> Result<(), String>;

    /// Write the source workload identity for a pod cgroup (GAP-1b). The
    /// node-agent calls this when a pod enrolls so the BPF connect hooks can
    /// stamp `FERRUM_ORIG_DST4/6` records with the source pod's UID and
    /// SPIFFE hash. Without it, the connect hooks emit the all-zero sentinel
    /// and the node-waypoint resolver can never recover a real identity from a
    /// socket cookie.
    fn update_workload_identity(
        &mut self,
        cgroup_id: u64,
        identity: &WorkloadIdentity,
    ) -> Result<(), String>;

    /// Counterpart to `update_workload_identity`. Called on pod
    /// un-enrollment / removal. Tolerates ENOENT by returning `Ok(())`.
    fn remove_workload_identity(&mut self, cgroup_id: u64) -> Result<(), String>;

    fn cleanup_all(&mut self) -> Result<(), String>;

    /// Attach the SOCK_OPS program to the cgroup root and pin the event
    /// ringbuf + stats map at the well-known paths
    /// (`BPF_SOCK_OPS_EVENTS_PIN_PATH`, `BPF_SOCK_OPS_STATS_PIN_PATH`) so
    /// the mesh-proxy can open them by path.
    ///
    /// The caller decides whether failure is fatal. In NodeWaypoint mode this
    /// link is part of source-identity recovery, so startup refuses readiness
    /// when it cannot be attached.
    fn attach_sock_ops(&mut self, cgroup_root: &str) -> Result<(), String>;

    /// Validate startup-level capture prerequisites after loading maps and
    /// attaching any global links. Per-pod cgroup/tc attachments are validated
    /// during pod enrollment and surface through `record_attach_error`; this
    /// hook covers the backend-wide state required before readiness can report
    /// healthy.
    fn validate_startup_ready(&self, require_sock_ops: bool) -> Result<(), String>;
}

/// Shared counters so tests can observe `cleanup_all` after a mock backend is
/// moved into `Box<dyn EbpfBackend>` (post-init cleanup-owner coverage).
#[derive(Debug, Default)]
pub struct MockCleanupWatch {
    pub calls: std::sync::atomic::AtomicUsize,
    pub cleaned_up: std::sync::atomic::AtomicBool,
}

/// Snapshot of the observable mock state taken at the **first** `cleanup_all`,
/// i.e. immediately before cleanup wipes it.
///
/// Startup rollback deliberately tears the maps down on a failed
/// `initialize_backend`, which means assertions like "the failed
/// capture-config write left no live config" or "SOCK_OPS never attached"
/// would pass vacuously if read off the post-cleanup backend — `cleanup_all`
/// clears those very fields. Tests assert against this snapshot instead so
/// they still fail if the step under test actually succeeded.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct MockPreCleanupState {
    pub capture_config_set: bool,
    pub sock_ops_attached_cgroup_root: Option<String>,
    pub node_ip_count: usize,
    pub node_ip6_count: usize,
    pub cgroup_attachment_count: usize,
    pub tc_attachment_count: usize,
    pub pod_ip_count: usize,
}

/// In-memory mock backend for Phase 1 and integration tests.
#[derive(Debug, Default)]
pub struct MockEbpfBackend {
    pub programs_loaded: bool,
    pub cgroup_attachments: Vec<(String, String)>,
    pub tc_attachments: Vec<(String, String, TcAttachDirection)>,
    pub pod_ips: HashMap<Ipv4Addr, PodInfo>,
    pub pod_ips6: HashMap<Ipv6Addr, PodInfo>,
    pub node_ips: HashSet<Ipv4Addr>,
    pub node_ips6: HashSet<Ipv6Addr>,
    pub node_probe_ports: HashSet<(Ipv4Addr, u16)>,
    pub node_probe_ports6: HashSet<(Ipv6Addr, u16)>,
    /// Declared inbound application ports written to the redirect scope maps.
    pub pod_inbound_ports: HashSet<(Ipv4Addr, u16)>,
    pub pod_inbound_ports6: HashSet<(Ipv6Addr, u16)>,
    /// Node capture interfaces the ingress redirect classifier is attached to.
    pub ingress_redirect_attachments: Vec<String>,
    /// Number of times `detach_ingress_redirect` ran, so lifecycle tests can
    /// prove a disable/teardown really removed the classifier.
    pub ingress_redirect_detach_calls: usize,
    pub bypass_uids: Vec<u32>,
    pub cidr_excludes: Vec<String>,
    pub cidr_includes: Vec<String>,
    pub port_excludes: Vec<u16>,
    pub capture_config: Option<BpfCaptureConfig>,
    /// Per-cgroup `includeOutboundPorts` writes ordered by the order the
    /// node-agent issued them. Insert overwrites the previous entry for
    /// the same `cgroup_id`. Tests assert on this map to verify a pod's
    /// annotation parsed correctly all the way down to the BPF surface.
    pub include_ports: HashMap<u64, IncludePortsPolicy>,
    /// Per-cgroup source workload identity writes (GAP-1b). Insert overwrites
    /// the previous entry for the same `cgroup_id`. Tests assert on this map to
    /// verify a pod's identity reached the BPF surface.
    pub workload_identities: HashMap<u64, WorkloadIdentity>,
    /// Ordered mock operation log for tests that need to assert side-effect
    /// ordering across different BPF surfaces.
    pub operations: Vec<String>,
    pub detached_pods: Vec<String>,
    pub cleaned_up: bool,
    /// Number of times `cleanup_all` was invoked. Tests for startup rollback
    /// and shutdown assert exactly-once ownership via this counter (idempotent
    /// repeats still increment so double-cleanup paths are detectable).
    pub cleanup_all_calls: usize,
    /// Optional shared view of cleanup counters for tests that move this mock
    /// into a `Box<dyn EbpfBackend>` (see `InitializedBackendOwner`).
    pub cleanup_watch: Option<std::sync::Arc<MockCleanupWatch>>,
    /// Observable state captured at the first `cleanup_all`, before cleanup
    /// wiped it. `None` until cleanup runs. See [`MockPreCleanupState`].
    pub pre_cleanup_state: Option<MockPreCleanupState>,
    /// When `true`, `load_programs` fails without marking programs loaded, so
    /// tests can prove the rollback guard is armed only *after* a successful
    /// load (a pre-load failure created nothing and must not clean up).
    pub fail_load_programs: bool,
    /// When `true`, `cleanup_all` records the call then returns an error so
    /// callers can prove original startup/runtime errors stay visible.
    pub fail_cleanup_all: bool,
    pub fail_update_capture_config: bool,
    pub fail_update_pod_ip: bool,
    pub fail_update_node_probe_port: bool,
    pub fail_update_node_probe_port6: bool,
    pub fail_remove_pod_ip: bool,
    pub fail_remove_node_probe_port: bool,
    pub fail_remove_pod_include_ports: bool,
    pub fail_remove_workload_identity: bool,
    pub fail_attach_sock_ops: bool,
    pub sock_ops_attached_cgroup_root: Option<String>,
    /// When non-zero, the next N `update_workload_identity` calls return an
    /// error (decrementing the counter), letting tests exercise partial-write
    /// retry behaviour where some pod cgroups enroll and others fail.
    pub fail_workload_identity_writes: usize,
    /// When `true`, every `attach_tc` call returns an error, letting tests
    /// simulate a transient inbound-tc attach failure that strikes *after* a
    /// pod's cgroup and veth have already resolved — the exact scenario the
    /// post-enrollment retry loop (see `node_agent::retry_backed_off_pod_enrollments`)
    /// exists to recover from. Flip it back to `false` to model the transient
    /// condition clearing so a re-driven enrollment can succeed.
    pub fail_attach_tc: bool,
    /// When `true`, `attach_ingress_redirect` fails, letting tests prove the
    /// node-agent fails closed (capture unavailable) rather than reporting a
    /// redirect that is not installed.
    pub fail_attach_ingress_redirect: bool,
    /// Number of upcoming `detach_ingress_redirect` calls that fail (each call
    /// decrements). A failed detach RETAINS `ingress_redirect_attachments`,
    /// mirroring the real backend's retry contract, so tests can prove that
    /// (a) the routing teardown is withheld while a classifier may be live and
    /// (b) `cleanup_all`'s retry is a real second attempt that releases the
    /// routing once it succeeds.
    pub fail_detach_ingress_redirect_times: usize,
    /// When `true`, `update_pod_inbound_port` (and the v6 variant) fail, so
    /// tests can prove a pod whose redirect scope could not be written is not
    /// left flagged for redirect.
    pub fail_update_pod_inbound_port: bool,
    /// When `true`, `clear_pod_inbound_ports` / `clear_pod_inbound_ports6` fail
    /// so removal tests can prove a successful pod-IP map delete that cannot
    /// clear the bounded scope map stays pending and retryable.
    pub fail_clear_pod_inbound_ports: bool,
    /// When `true`, `validate_startup_ready` fails even though every earlier
    /// step succeeded, so tests can drive the post-attach startup-validation
    /// unwind (classifier detached, then Ferrum-owned routing removed).
    pub fail_validate_startup_ready: bool,
    /// Optional log shared with a test's own recorder, so ordering between mock
    /// operations and side effects the mock does not own — notably the
    /// node-agent's `ip rule`/`ip route` teardown — can be asserted from one
    /// interleaved sequence. Mirrors [`Self::operations`] for the ingress
    /// redirect attach/detach entries.
    pub op_log: Option<std::sync::Arc<std::sync::Mutex<Vec<String>>>>,
}

impl MockEbpfBackend {
    /// Record an operation on both the local log and the shared one (if any).
    fn record_operation(&mut self, op: String) {
        if let Some(log) = self.op_log.clone()
            && let Ok(mut entries) = log.lock()
        {
            entries.push(op.clone());
        }
        self.operations.push(op);
    }
}

impl EbpfBackend for MockEbpfBackend {
    fn load_programs(&mut self) -> Result<(), String> {
        if self.fail_load_programs {
            return Err("injected load_programs failure".to_string());
        }
        self.programs_loaded = true;
        Ok(())
    }

    fn update_capture_config(&mut self, config: &BpfCaptureConfig) -> Result<(), String> {
        if self.fail_update_capture_config {
            return Err("capture config update failed".to_string());
        }
        self.capture_config = Some(*config);
        Ok(())
    }

    fn attach_cgroup(
        &mut self,
        _pod_uid: &str,
        cgroup_path: &str,
        program: &str,
    ) -> Result<(), String> {
        self.operations.push(format!("attach_cgroup:{program}"));
        self.cgroup_attachments
            .push((cgroup_path.to_string(), program.to_string()));
        Ok(())
    }

    fn attach_tc(
        &mut self,
        _pod_uid: &str,
        iface: &str,
        program: &str,
        direction: TcAttachDirection,
    ) -> Result<(), String> {
        if self.fail_attach_tc {
            return Err(format!(
                "injected tc attach failure for {iface}/{program}/{}",
                direction.as_str()
            ));
        }
        self.tc_attachments
            .push((iface.to_string(), program.to_string(), direction));
        Ok(())
    }

    fn detach_pod(&mut self, pod_uid: &str) -> Result<(), String> {
        self.detached_pods.push(pod_uid.to_string());
        Ok(())
    }

    fn update_pod_ip(&mut self, ip: Ipv4Addr, info: &PodInfo) -> Result<(), String> {
        if self.fail_update_pod_ip {
            return Err(format!("injected pod IP update failure for {ip}"));
        }
        self.pod_ips.insert(ip, info.clone());
        Ok(())
    }

    fn remove_pod_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        if self.fail_remove_pod_ip {
            return Err(format!("injected pod IP remove failure for {ip}"));
        }
        self.pod_ips.remove(&ip);
        Ok(())
    }

    fn update_pod_ip6(&mut self, ip: Ipv6Addr, info: &PodInfo) -> Result<(), String> {
        if self.fail_update_pod_ip {
            return Err(format!("injected pod IPv6 update failure for {ip}"));
        }
        self.pod_ips6.insert(ip, info.clone());
        Ok(())
    }

    fn remove_pod_ip6(&mut self, ip: Ipv6Addr) -> Result<(), String> {
        if self.fail_remove_pod_ip {
            return Err(format!("injected pod IPv6 remove failure for {ip}"));
        }
        self.pod_ips6.remove(&ip);
        Ok(())
    }

    fn update_node_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        self.node_ips.insert(ip);
        Ok(())
    }

    fn update_node_ip6(&mut self, ip: Ipv6Addr) -> Result<(), String> {
        self.node_ips6.insert(ip);
        Ok(())
    }

    fn has_node_source_ipv4(&self) -> bool {
        !self.node_ips.is_empty()
    }

    fn has_node_source_ipv6(&self) -> bool {
        !self.node_ips6.is_empty()
    }

    fn attach_ingress_redirect(&mut self, iface: &str) -> Result<(), String> {
        if self.fail_attach_ingress_redirect {
            return Err(format!(
                "injected ingress redirect attach failure for {iface}"
            ));
        }
        self.record_operation(format!("attach_ingress_redirect:{iface}"));
        self.ingress_redirect_attachments.push(iface.to_string());
        Ok(())
    }

    fn detach_ingress_redirect(&mut self) -> Result<(), String> {
        self.ingress_redirect_detach_calls += 1;
        self.record_operation("detach_ingress_redirect".to_string());
        if self.fail_detach_ingress_redirect_times > 0 {
            // Model the real backend's retry contract: a failed detach RETAINS
            // its attachments, so the next call is a genuine second attempt and
            // `ingress_redirect_attached()` keeps reporting them.
            self.fail_detach_ingress_redirect_times -= 1;
            return Err(format!(
                "injected ingress redirect detach failure for {:?}",
                self.ingress_redirect_attachments
            ));
        }
        self.ingress_redirect_attachments.clear();
        Ok(())
    }

    fn ingress_redirect_attached(&self) -> bool {
        !self.ingress_redirect_attachments.is_empty()
    }

    fn update_pod_inbound_ports(&mut self, ip: Ipv4Addr, ports: &[u16]) -> Result<(), String> {
        if self.fail_update_pod_inbound_port {
            return Err(format!(
                "injected pod inbound redirect scope update failure for {ip} ({} ports)",
                ports.len()
            ));
        }
        // Replace, matching the real backend: a removed port must not survive.
        self.pod_inbound_ports
            .retain(|(entry_ip, _)| *entry_ip != ip);
        for port in ports {
            self.pod_inbound_ports.insert((ip, *port));
        }
        Ok(())
    }

    fn clear_pod_inbound_ports(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        if self.fail_clear_pod_inbound_ports {
            return Err(format!(
                "injected pod inbound redirect scope clear failure for {ip}"
            ));
        }
        self.pod_inbound_ports
            .retain(|(entry_ip, _)| *entry_ip != ip);
        Ok(())
    }

    fn update_pod_inbound_ports6(&mut self, ip: Ipv6Addr, ports: &[u16]) -> Result<(), String> {
        if self.fail_update_pod_inbound_port {
            return Err(format!(
                "injected pod IPv6 inbound redirect scope update failure for {ip} ({} ports)",
                ports.len()
            ));
        }
        self.pod_inbound_ports6
            .retain(|(entry_ip, _)| *entry_ip != ip);
        for port in ports {
            self.pod_inbound_ports6.insert((ip, *port));
        }
        Ok(())
    }

    fn clear_pod_inbound_ports6(&mut self, ip: Ipv6Addr) -> Result<(), String> {
        if self.fail_clear_pod_inbound_ports {
            return Err(format!(
                "injected pod IPv6 inbound redirect scope clear failure for {ip}"
            ));
        }
        self.pod_inbound_ports6
            .retain(|(entry_ip, _)| *entry_ip != ip);
        Ok(())
    }

    fn update_node_probe_port(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), String> {
        if self.fail_update_node_probe_port {
            return Err(format!(
                "injected node probe port update failure for {ip}:{port}"
            ));
        }
        self.node_probe_ports.insert((ip, port));
        Ok(())
    }

    fn remove_node_probe_port(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), String> {
        if self.fail_remove_node_probe_port {
            return Err(format!(
                "injected node probe port remove failure for {ip}:{port}"
            ));
        }
        self.node_probe_ports.remove(&(ip, port));
        Ok(())
    }

    fn update_node_probe_port6(&mut self, ip: Ipv6Addr, port: u16) -> Result<(), String> {
        if self.fail_update_node_probe_port6 {
            return Err(format!(
                "injected node IPv6 probe port update failure for {ip}:{port}"
            ));
        }
        self.node_probe_ports6.insert((ip, port));
        Ok(())
    }

    fn remove_node_probe_port6(&mut self, ip: Ipv6Addr, port: u16) -> Result<(), String> {
        if self.fail_remove_node_probe_port {
            return Err(format!(
                "injected node IPv6 probe port remove failure for {ip}:{port}"
            ));
        }
        self.node_probe_ports6.remove(&(ip, port));
        Ok(())
    }

    fn update_bypass_uid(&mut self, uid: u32) -> Result<(), String> {
        self.bypass_uids.push(uid);
        Ok(())
    }

    fn update_cidr_exclude(&mut self, cidr: &str) -> Result<(), String> {
        self.cidr_excludes.push(cidr.to_string());
        Ok(())
    }

    fn update_cidr_include(&mut self, cidr: &str) -> Result<(), String> {
        self.cidr_includes.push(cidr.to_string());
        Ok(())
    }

    fn update_port_exclude(&mut self, port: u16) -> Result<(), String> {
        self.port_excludes.push(port);
        Ok(())
    }

    fn update_pod_include_ports(
        &mut self,
        cgroup_id: u64,
        policy: &IncludePortsPolicy,
    ) -> Result<(), String> {
        self.operations
            .push(format!("update_pod_include_ports:{cgroup_id}"));
        self.include_ports.insert(cgroup_id, *policy);
        Ok(())
    }

    fn remove_pod_include_ports(&mut self, cgroup_id: u64) -> Result<(), String> {
        if self.fail_remove_pod_include_ports {
            return Err(format!(
                "injected pod include ports remove failure for cgroup {cgroup_id}"
            ));
        }
        self.include_ports.remove(&cgroup_id);
        Ok(())
    }

    fn update_workload_identity(
        &mut self,
        cgroup_id: u64,
        identity: &WorkloadIdentity,
    ) -> Result<(), String> {
        if self.fail_workload_identity_writes > 0 {
            self.fail_workload_identity_writes -= 1;
            return Err(format!(
                "injected workload identity write failure for cgroup {cgroup_id}"
            ));
        }
        self.operations
            .push(format!("update_workload_identity:{cgroup_id}"));
        self.workload_identities.insert(cgroup_id, *identity);
        Ok(())
    }

    fn remove_workload_identity(&mut self, cgroup_id: u64) -> Result<(), String> {
        if self.fail_remove_workload_identity {
            return Err(format!(
                "injected workload identity remove failure for cgroup {cgroup_id}"
            ));
        }
        self.workload_identities.remove(&cgroup_id);
        Ok(())
    }

    fn cleanup_all(&mut self) -> Result<(), String> {
        self.cleanup_all_calls = self.cleanup_all_calls.saturating_add(1);
        // Mirror the real backend: cleanup RETRIES the ingress-redirect detach
        // before wiping anything, and a still-failing detach leaves the
        // attachment recorded. This is what makes the node-agent's
        // "routing teardown only once no classifier may be live" ordering
        // testable against the mock.
        if !self.ingress_redirect_attachments.is_empty()
            && let Err(e) = self.detach_ingress_redirect()
        {
            self.operations.push(format!("cleanup_detach_failed:{e}"));
        }
        // Snapshot before the wipe so post-cleanup assertions stay meaningful.
        // Only the FIRST cleanup records: a second call would overwrite the
        // pre-rollback view with an already-empty one.
        if self.pre_cleanup_state.is_none() {
            self.pre_cleanup_state = Some(MockPreCleanupState {
                capture_config_set: self.capture_config.is_some(),
                sock_ops_attached_cgroup_root: self.sock_ops_attached_cgroup_root.clone(),
                node_ip_count: self.node_ips.len(),
                node_ip6_count: self.node_ips6.len(),
                cgroup_attachment_count: self.cgroup_attachments.len(),
                tc_attachment_count: self.tc_attachments.len(),
                pod_ip_count: self.pod_ips.len(),
            });
        }
        if let Some(watch) = &self.cleanup_watch {
            watch
                .calls
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);
            watch
                .cleaned_up
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        self.cgroup_attachments.clear();
        self.tc_attachments.clear();
        self.pod_ips.clear();
        self.pod_ips6.clear();
        self.node_ips.clear();
        self.node_ips6.clear();
        self.node_probe_ports.clear();
        self.node_probe_ports6.clear();
        self.include_ports.clear();
        self.workload_identities.clear();
        self.sock_ops_attached_cgroup_root = None;
        self.bypass_uids.clear();
        self.cidr_excludes.clear();
        self.cidr_includes.clear();
        self.port_excludes.clear();
        self.capture_config = None;
        self.cleaned_up = true;
        if self.fail_cleanup_all {
            return Err("injected cleanup_all failure".to_string());
        }
        Ok(())
    }

    fn attach_sock_ops(&mut self, cgroup_root: &str) -> Result<(), String> {
        if self.fail_attach_sock_ops {
            return Err("sock_ops attach failed".to_string());
        }
        self.sock_ops_attached_cgroup_root = Some(cgroup_root.to_string());
        Ok(())
    }

    fn validate_startup_ready(&self, require_sock_ops: bool) -> Result<(), String> {
        if self.fail_validate_startup_ready {
            return Err("injected startup validation failure".to_string());
        }
        if !self.programs_loaded {
            return Err("BPF programs not loaded".to_string());
        }
        if self.capture_config.is_none() {
            return Err("BPF capture config map not initialized".to_string());
        }
        if require_sock_ops && self.sock_ops_attached_cgroup_root.is_none() {
            return Err("SOCK_OPS identity bridge is not attached".to_string());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ferrum_ebpf_common::NODE_WAYPOINT_INGRESS_CAPTURE_PORT;

    #[test]
    fn fallback_mode_parse_valid() {
        assert_eq!(
            FallbackMode::parse("iptables").unwrap(),
            FallbackMode::Iptables
        );
        assert_eq!(FallbackMode::parse("fail").unwrap(), FallbackMode::Fail);
        assert_eq!(
            FallbackMode::parse("IPTABLES").unwrap(),
            FallbackMode::Iptables
        );
    }

    #[test]
    fn fallback_mode_parse_invalid() {
        assert!(FallbackMode::parse("other").is_err());
    }

    #[test]
    fn node_agent_proxy_mode_parse_valid() {
        assert_eq!(
            NodeAgentProxyMode::parse("local_pod").unwrap(),
            NodeAgentProxyMode::LocalPod
        );
        assert_eq!(
            NodeAgentProxyMode::parse("node_waypoint").unwrap(),
            NodeAgentProxyMode::NodeWaypoint
        );
        assert_eq!(
            NodeAgentProxyMode::parse("LOCAL_POD").unwrap(),
            NodeAgentProxyMode::LocalPod
        );
    }

    #[test]
    fn capture_contract_projects_bpf_config() {
        let contract = CaptureContract::new(
            NodeAgentProxyMode::NodeWaypoint,
            16001,
            16008,
            "/tmp/ferrum.sock",
        )
        .unwrap();

        assert_eq!(contract.proxy_mode, NodeAgentProxyMode::NodeWaypoint);
        assert_eq!(contract.bpf_maps.capture_config, BPF_MAP_CAPTURE_CONFIG);
        assert_eq!(contract.bpf_maps.node_ips, BPF_MAP_NODE_IPS);
        assert_eq!(contract.bpf_maps.node_ips6, BPF_MAP_NODE_IPS6);
        assert_eq!(contract.bpf_maps.node_probe_ports, BPF_MAP_NODE_PROBE_PORTS);
        assert_eq!(
            contract.bpf_maps.node_probe_ports6,
            BPF_MAP_NODE_PROBE_PORTS6
        );
        assert_eq!(
            contract.bpf_capture_config(),
            BpfCaptureConfig::new(16001, 16008)
                .with_node_waypoint_inbound_auth_mark(NODE_WAYPOINT_INBOUND_AUTH_MARK)
        );
    }

    #[test]
    fn ingress_redirect_port_contract_fails_closed() {
        let mut contract = CaptureContract::new(
            NodeAgentProxyMode::NodeWaypoint,
            OUTBOUND_CAPTURE_PORT,
            INBOUND_HBONE_PORT,
            "/tmp/ferrum.sock",
        )
        .unwrap();

        // Redirect not requested: nothing to validate, and nothing published.
        assert!(contract.validate_ingress_redirect().is_ok());
        assert!(!contract.ingress_redirect_enabled());

        contract.ingress_redirect_ifaces = vec!["eth0".to_string()];
        contract.node_waypoint_ingress_redirect_mark = NODE_WAYPOINT_INGRESS_REDIRECT_MARK;

        // Requested but with no capture listener port: the proxy would never
        // bind a socket for the classifier to assign, so in-scope traffic would
        // be dropped. Startup must refuse.
        contract.ingress_capture_port = 0;
        let error = contract.validate_ingress_redirect().unwrap_err();
        assert!(
            error.contains("FERRUM_MESH_INBOUND_LISTEN_ADDR"),
            "the error must name the variable both processes read: {error}"
        );
        assert!(
            !contract.ingress_redirect_enabled(),
            "a missing capture port must leave the redirect disarmed"
        );
        assert_eq!(
            contract
                .bpf_capture_config()
                .node_waypoint_ingress_redirect_mark,
            0,
            "a disarmed redirect must publish no mark to the kernel"
        );

        // The HBONE port is NOT a legal capture port — that collapse is the
        // protocol-boundary bug this contract exists to prevent.
        contract.ingress_capture_port = INBOUND_HBONE_PORT;
        let error = contract.validate_ingress_redirect().unwrap_err();
        assert!(error.contains("HBONE"), "{error}");

        // Nor is the outbound capture port.
        contract.ingress_capture_port = OUTBOUND_CAPTURE_PORT;
        assert!(contract.validate_ingress_redirect().is_err());

        // A distinct capture port is the supported configuration.
        contract.ingress_capture_port = NODE_WAYPOINT_INGRESS_CAPTURE_PORT;
        assert!(contract.validate_ingress_redirect().is_ok());
        assert!(contract.ingress_redirect_enabled());
        let published = contract.bpf_capture_config();
        assert_eq!(
            published.node_waypoint_ingress_capture_port,
            NODE_WAYPOINT_INGRESS_CAPTURE_PORT as u32
        );
        assert_ne!(
            published.node_waypoint_ingress_capture_port, published.hbone_redirect_port,
            "the kernel must steer at the capture listener, never at HBONE"
        );
        assert!(published.ingress_redirect_armed());

        // Local-pod mode has no capture listener at all.
        contract.proxy_mode = NodeAgentProxyMode::LocalPod;
        assert!(contract.validate_ingress_redirect().is_err());
        assert!(!contract.ingress_redirect_enabled());
    }

    #[test]
    fn capture_contract_disables_inbound_mark_for_local_pod() {
        let contract = CaptureContract::new(
            NodeAgentProxyMode::LocalPod,
            16001,
            16008,
            "/tmp/ferrum.sock",
        )
        .unwrap();

        assert_eq!(
            contract
                .bpf_capture_config()
                .node_waypoint_inbound_auth_mark,
            0
        );
    }

    #[test]
    fn capture_contract_rejects_invalid_surface() {
        assert!(
            CaptureContract::new(NodeAgentProxyMode::LocalPod, 0, 15008, "/tmp/ferrum.sock")
                .is_err()
        );
        assert!(
            CaptureContract::new(NodeAgentProxyMode::LocalPod, 15001, 0, "/tmp/ferrum.sock")
                .is_err()
        );
        assert!(
            CaptureContract::new(
                NodeAgentProxyMode::LocalPod,
                15001,
                15001,
                "/tmp/ferrum.sock"
            )
            .is_err()
        );
        assert!(CaptureContract::new(NodeAgentProxyMode::LocalPod, 15001, 15008, "").is_err());
    }

    #[test]
    fn mock_backend_load_and_attach() {
        let mut backend = MockEbpfBackend::default();
        backend.load_programs().unwrap();
        assert!(backend.programs_loaded);

        backend
            .update_capture_config(&BpfCaptureConfig::new(16001, 16008))
            .unwrap();
        assert_eq!(
            backend.capture_config,
            Some(BpfCaptureConfig::new(16001, 16008))
        );

        backend
            .attach_cgroup(
                "pod-abc",
                "/sys/fs/cgroup/kubepods/pod-abc",
                "ferrum_connect4",
            )
            .unwrap();
        backend
            .attach_tc(
                "pod-abc",
                "eth0",
                "ferrum_tc_inbound",
                TcAttachDirection::Ingress,
            )
            .unwrap();

        assert_eq!(backend.cgroup_attachments.len(), 1);
        assert_eq!(backend.tc_attachments.len(), 1);
    }

    #[test]
    fn mock_backend_pod_ip_lifecycle() {
        let mut backend = MockEbpfBackend::default();
        let ip = Ipv4Addr::new(10, 0, 0, 1);
        let ip6 = Ipv6Addr::LOCALHOST;
        let info = PodInfo {
            proxy_port: 15001,
            capture_flags: 42,
        };

        backend.update_pod_ip(ip, &info).unwrap();
        assert_eq!(backend.pod_ips.get(&ip), Some(&info));
        backend.update_pod_ip6(ip6, &info).unwrap();
        assert_eq!(backend.pod_ips6.get(&ip6), Some(&info));
        backend.update_node_ip(ip).unwrap();
        assert!(backend.node_ips.contains(&ip));
        backend.update_node_ip6(ip6).unwrap();
        assert!(backend.node_ips6.contains(&ip6));
        backend.update_node_probe_port(ip, 8080).unwrap();
        assert!(backend.node_probe_ports.contains(&(ip, 8080)));
        backend.update_node_probe_port6(ip6, 9090).unwrap();
        assert!(backend.node_probe_ports6.contains(&(ip6, 9090)));

        backend.remove_pod_ip(ip).unwrap();
        assert!(!backend.pod_ips.contains_key(&ip));
        backend.remove_pod_ip6(ip6).unwrap();
        assert!(!backend.pod_ips6.contains_key(&ip6));
        backend.remove_node_probe_port(ip, 8080).unwrap();
        assert!(!backend.node_probe_ports.contains(&(ip, 8080)));
        backend.remove_node_probe_port6(ip6, 9090).unwrap();
        assert!(!backend.node_probe_ports6.contains(&(ip6, 9090)));
    }

    #[test]
    fn mock_backend_cleanup() {
        let mut backend = MockEbpfBackend::default();
        backend
            .attach_cgroup(
                "pod-abc",
                "/sys/fs/cgroup/kubepods/pod-abc",
                "ferrum_connect4",
            )
            .unwrap();
        backend
            .update_pod_ip(
                Ipv4Addr::new(10, 0, 0, 1),
                &PodInfo {
                    proxy_port: 15001,
                    capture_flags: 1,
                },
            )
            .unwrap();

        backend.cleanup_all().unwrap();
        assert!(backend.cleaned_up);
        assert!(backend.cgroup_attachments.is_empty());
        assert!(backend.pod_ips.is_empty());
        assert!(backend.pod_ips6.is_empty());
        assert!(backend.node_ips.is_empty());
        assert!(backend.node_ips6.is_empty());
    }

    #[test]
    fn node_agent_metrics_default_topology_is_nominal() {
        let metrics = NodeAgentMetrics::default();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.topology_degraded_reason, None);
    }

    #[test]
    fn node_agent_metrics_records_degraded_reason() {
        let metrics = NodeAgentMetrics::default();
        metrics.set_topology_degraded("kernel_too_old");
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.topology_degraded_reason, Some("kernel_too_old"));
    }

    #[test]
    fn node_agent_metrics_clear_topology_degraded() {
        let metrics = NodeAgentMetrics::default();
        metrics.set_topology_degraded("bpffs_missing");
        metrics.clear_topology_degraded();
        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.topology_degraded_reason, None);
    }

    #[test]
    fn mock_backend_records_sock_ops_attachment() {
        let mut backend = MockEbpfBackend::default();
        assert!(backend.sock_ops_attached_cgroup_root.is_none());
        backend.attach_sock_ops("/sys/fs/cgroup").unwrap();
        assert_eq!(
            backend.sock_ops_attached_cgroup_root.as_deref(),
            Some("/sys/fs/cgroup")
        );
        backend.cleanup_all().unwrap();
        assert!(backend.sock_ops_attached_cgroup_root.is_none());
    }

    #[test]
    fn mock_backend_workload_identity_lifecycle() {
        let mut backend = MockEbpfBackend::default();
        let identity = WorkloadIdentity::new([7u8; 16], 0xdead_beef);

        backend.update_workload_identity(4242, &identity).unwrap();
        assert_eq!(backend.workload_identities.get(&4242), Some(&identity));

        // Re-write overwrites the same cgroup entry.
        let updated = WorkloadIdentity::new([8u8; 16], 0xfeed_face);
        backend.update_workload_identity(4242, &updated).unwrap();
        assert_eq!(backend.workload_identities.get(&4242), Some(&updated));

        backend.remove_workload_identity(4242).unwrap();
        assert!(backend.workload_identities.is_empty());
        // Removing a missing cgroup is tolerated.
        backend.remove_workload_identity(4242).unwrap();

        // cleanup_all clears the identity map too.
        backend.update_workload_identity(1, &identity).unwrap();
        backend.cleanup_all().unwrap();
        assert!(backend.workload_identities.is_empty());
    }
}
