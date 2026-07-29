//! Typed BPF map operations wrapping aya's map API.
//!
//! `BpfMaps` provides insert/remove helpers for each BPF map, converting
//! between Rust types and the `#[repr(C)]` shared types from
//! `ferrum-ebpf-common`. Only available on Linux with `--features ebpf`.

#![allow(dead_code)]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::Ebpf;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::maps::lpm_trie::Key as LpmKey;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::maps::{HashMap as BpfHashMap, LpmTrie, MapData};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use ferrum_ebpf_common::{
    BpfCaptureConfig, FERRUM_CAPTURE_CONFIG_KEY, InboundRedirectKey4, InboundRedirectKey6,
    IncludePortsPolicy, NodeProbePortKey4, NodeProbePortKey6, PodInfo as BpfPodInfo,
    WorkloadIdentity,
};
use ferrum_ebpf_common::{CidrKey4, CidrKey6};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use super::{
    BPF_MAP_CAPTURE_CONFIG, BPF_MAP_NODE_IPS, BPF_MAP_NODE_IPS6, BPF_MAP_NODE_PROBE_PORTS,
    BPF_MAP_NODE_PROBE_PORTS6, BPF_MAP_POD_INBOUND_PORTS, BPF_MAP_POD_INBOUND_PORTS6,
    BPF_MAP_POD_IPS6, BPF_MAP_WORKLOAD_IDENTITY, PodInfo,
};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub struct BpfMaps {
    pod_ips: BpfHashMap<MapData, u32, BpfPodInfo>,
    pod_ips6: BpfHashMap<MapData, CidrKey6, BpfPodInfo>,
    node_ips: Option<BpfHashMap<MapData, u32, u8>>,
    node_ips6: Option<BpfHashMap<MapData, CidrKey6, u8>>,
    node_probe_ports: Option<BpfHashMap<MapData, NodeProbePortKey4, u8>>,
    node_probe_ports6: Option<BpfHashMap<MapData, NodeProbePortKey6, u8>>,
    pod_inbound_ports: Option<BpfHashMap<MapData, InboundRedirectKey4, u8>>,
    pod_inbound_ports6: Option<BpfHashMap<MapData, InboundRedirectKey6, u8>>,
    bypass_uids: BpfHashMap<MapData, u32, u8>,
    cidr_exclude4: LpmTrie<MapData, CidrKey4, u8>,
    cidr_exclude6: LpmTrie<MapData, CidrKey6, u8>,
    cidr_include4: LpmTrie<MapData, CidrKey4, u8>,
    cidr_include6: LpmTrie<MapData, CidrKey6, u8>,
    port_exclude: BpfHashMap<MapData, u16, u8>,
    capture_config: Option<BpfHashMap<MapData, u32, BpfCaptureConfig>>,
    include_ports: Option<BpfHashMap<MapData, u64, IncludePortsPolicy>>,
    workload_identity: Option<BpfHashMap<MapData, u64, WorkloadIdentity>>,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
impl BpfMaps {
    pub fn from_ebpf(bpf: &mut Ebpf) -> Result<Self, String> {
        let pod_ips = BpfHashMap::try_from(
            bpf.take_map("FERRUM_POD_IPS")
                .ok_or("FERRUM_POD_IPS map not found")?,
        )
        .map_err(|e| format!("FERRUM_POD_IPS type mismatch: {e}"))?;

        let pod_ips6 = BpfHashMap::try_from(
            bpf.take_map(BPF_MAP_POD_IPS6)
                .ok_or("FERRUM_POD_IPS6 map not found")?,
        )
        .map_err(|e| format!("FERRUM_POD_IPS6 type mismatch: {e}"))?;

        let node_ips = match bpf.take_map(BPF_MAP_NODE_IPS) {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_NODE_IPS type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_NODE_IPS map not found; startup readiness will reject node-waypoint eBPF capture before reporting ready"
                );
                None
            }
        };

        let node_ips6 = match bpf.take_map(BPF_MAP_NODE_IPS6) {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_NODE_IPS6 type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_NODE_IPS6 map not found; startup readiness will reject node-waypoint eBPF capture before reporting ready"
                );
                None
            }
        };

        let node_probe_ports = match bpf.take_map(BPF_MAP_NODE_PROBE_PORTS) {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_NODE_PROBE_PORTS type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_NODE_PROBE_PORTS map not found; startup readiness will reject node-waypoint eBPF capture before reporting ready"
                );
                None
            }
        };

        let node_probe_ports6 = match bpf.take_map(BPF_MAP_NODE_PROBE_PORTS6) {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_NODE_PROBE_PORTS6 type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_NODE_PROBE_PORTS6 map not found; startup readiness will reject node-waypoint eBPF capture before reporting ready"
                );
                None
            }
        };

        // Redirect scope maps. A stale ELF without them is tolerated here and
        // rejected by `validate_required` when the redirect is actually
        // enabled, so a node-agent that cannot scope the redirect never arms
        // it rather than redirecting on pod-IP alone.
        let pod_inbound_ports = match bpf.take_map(BPF_MAP_POD_INBOUND_PORTS) {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_POD_INBOUND_PORTS type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_POD_INBOUND_PORTS map not found; the NodeWaypoint inbound tc redirect cannot be scoped and will not be enabled"
                );
                None
            }
        };

        let pod_inbound_ports6 = match bpf.take_map(BPF_MAP_POD_INBOUND_PORTS6) {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_POD_INBOUND_PORTS6 type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_POD_INBOUND_PORTS6 map not found; the NodeWaypoint inbound tc redirect cannot be scoped and will not be enabled"
                );
                None
            }
        };

        let bypass_uids = BpfHashMap::try_from(
            bpf.take_map("FERRUM_BYPASS_UIDS")
                .ok_or("FERRUM_BYPASS_UIDS map not found")?,
        )
        .map_err(|e| format!("FERRUM_BYPASS_UIDS type mismatch: {e}"))?;

        let cidr_exclude4 = LpmTrie::try_from(
            bpf.take_map("FERRUM_CIDR_EXCLUDE4")
                .ok_or("FERRUM_CIDR_EXCLUDE4 map not found")?,
        )
        .map_err(|e| format!("FERRUM_CIDR_EXCLUDE4 type mismatch: {e}"))?;

        let cidr_exclude6 = LpmTrie::try_from(
            bpf.take_map("FERRUM_CIDR_EXCLUDE6")
                .ok_or("FERRUM_CIDR_EXCLUDE6 map not found")?,
        )
        .map_err(|e| format!("FERRUM_CIDR_EXCLUDE6 type mismatch: {e}"))?;

        let cidr_include4 = LpmTrie::try_from(
            bpf.take_map("FERRUM_CIDR_INCLUDE4")
                .ok_or("FERRUM_CIDR_INCLUDE4 map not found")?,
        )
        .map_err(|e| format!("FERRUM_CIDR_INCLUDE4 type mismatch: {e}"))?;

        let cidr_include6 = LpmTrie::try_from(
            bpf.take_map("FERRUM_CIDR_INCLUDE6")
                .ok_or("FERRUM_CIDR_INCLUDE6 map not found")?,
        )
        .map_err(|e| format!("FERRUM_CIDR_INCLUDE6 type mismatch: {e}"))?;

        let port_exclude = BpfHashMap::try_from(
            bpf.take_map("FERRUM_PORT_EXCLUDE")
                .ok_or("FERRUM_PORT_EXCLUDE map not found")?,
        )
        .map_err(|e| format!("FERRUM_PORT_EXCLUDE type mismatch: {e}"))?;

        let capture_config = match bpf.take_map("FERRUM_CAPTURE_CONFIG") {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_CAPTURE_CONFIG type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_CAPTURE_CONFIG map not found; startup readiness will reject enabled eBPF capture before reporting ready"
                );
                None
            }
        };

        // Older BPF ELFs may predate the include-ports gate. Tolerate the
        // missing map so the node-agent still boots with a stale program;
        // the BPF `include_port_allowed` helper fail-opens on missing
        // lookups, so capture stays correct for unannotated pods. Pods
        // that DO carry `includeOutboundPorts` will be over-captured (no
        // narrowing), which is the prior GAP-2K behavior.
        let include_ports = match bpf.take_map("FERRUM_INCLUDE_PORTS") {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_INCLUDE_PORTS type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_INCLUDE_PORTS map not found; per-pod includeOutboundPorts narrowing disabled (eBPF ELF predates GAP-2K)"
                );
                None
            }
        };

        // Older BPF ELFs predate the GAP-1b per-cgroup identity map. Tolerate
        // the missing map so the node-agent still boots; the connect hooks
        // fall back to the all-zero sentinel, which node-waypoint resolution
        // treats as fail-closed (the prior behavior).
        let workload_identity = match bpf.take_map(super::BPF_MAP_WORKLOAD_IDENTITY) {
            Some(map) => Some(
                BpfHashMap::try_from(map)
                    .map_err(|e| format!("FERRUM_WORKLOAD_IDENTITY type mismatch: {e}"))?,
            ),
            None => {
                tracing::warn!(
                    "FERRUM_WORKLOAD_IDENTITY map not found; startup readiness will reject node-waypoint eBPF capture before reporting ready"
                );
                None
            }
        };

        Ok(Self {
            pod_ips,
            pod_ips6,
            node_ips,
            node_ips6,
            node_probe_ports,
            node_probe_ports6,
            pod_inbound_ports,
            pod_inbound_ports6,
            bypass_uids,
            cidr_exclude4,
            cidr_exclude6,
            cidr_include4,
            cidr_include6,
            port_exclude,
            capture_config,
            include_ports,
            workload_identity,
        })
    }

    /// `true` when both redirect scope maps are present. The node-agent
    /// consults this before arming the inbound tc redirect: without the scope
    /// maps the kernel could only match on pod IP, which would capture every
    /// port of an enrolled pod rather than its declared inbound ports.
    pub fn supports_inbound_redirect_scope(&self) -> bool {
        self.pod_inbound_ports.is_some() && self.pod_inbound_ports6.is_some()
    }

    pub fn validate_required(&self, require_workload_identity: bool) -> Result<(), String> {
        let mut missing = Vec::new();
        if self.capture_config.is_none() {
            missing.push(BPF_MAP_CAPTURE_CONFIG);
        }
        if require_workload_identity && self.workload_identity.is_none() {
            missing.push(BPF_MAP_WORKLOAD_IDENTITY);
        }
        if require_workload_identity && self.node_ips.is_none() {
            missing.push(BPF_MAP_NODE_IPS);
        }
        if require_workload_identity && self.node_ips6.is_none() {
            missing.push(BPF_MAP_NODE_IPS6);
        }
        if require_workload_identity && self.node_probe_ports.is_none() {
            missing.push(BPF_MAP_NODE_PROBE_PORTS);
        }
        if require_workload_identity && self.node_probe_ports6.is_none() {
            missing.push(BPF_MAP_NODE_PROBE_PORTS6);
        }
        if missing.is_empty() {
            return Ok(());
        }
        Err(format!(
            "BPF ELF is missing required map(s) for the selected capture topology: {}",
            missing.join(", ")
        ))
    }

    pub fn insert_pod_ip(&mut self, ip: Ipv4Addr, info: &PodInfo) -> Result<(), String> {
        let key = ipv4_to_nbo_key(ip);
        let value = BpfPodInfo {
            proxy_port: info.proxy_port as u32,
            capture_flags: info.capture_flags,
        };
        let map = &mut self.pod_ips;
        map.insert(key, value, 0)
            .map_err(|e| format!("Failed to insert pod IP {ip}: {e}"))
    }

    pub fn remove_pod_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        let key = ipv4_to_nbo_key(ip);
        let map = &mut self.pod_ips;
        tolerate_missing_map_remove(map.remove(&key), || format!("pod IP {ip}"))
    }

    pub fn insert_pod_ip6(&mut self, ip: Ipv6Addr, info: &PodInfo) -> Result<(), String> {
        let key = CidrKey6::host(ipv6_to_nbo_words(ip));
        let value = BpfPodInfo {
            proxy_port: info.proxy_port as u32,
            capture_flags: info.capture_flags,
        };
        let map = &mut self.pod_ips6;
        map.insert(key, value, 0)
            .map_err(|e| format!("Failed to insert pod IPv6 {ip}: {e}"))
    }

    pub fn remove_pod_ip6(&mut self, ip: Ipv6Addr) -> Result<(), String> {
        let key = CidrKey6::host(ipv6_to_nbo_words(ip));
        let map = &mut self.pod_ips6;
        tolerate_missing_map_remove(map.remove(&key), || format!("pod IPv6 {ip}"))
    }

    pub fn insert_node_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        let Some(node_ips) = self.node_ips.as_mut() else {
            return Ok(());
        };
        let key = ipv4_to_nbo_key(ip);
        node_ips
            .insert(key, 1u8, 0)
            .map_err(|e| format!("Failed to insert node IP {ip}: {e}"))
    }

    pub fn insert_node_ip6(&mut self, ip: Ipv6Addr) -> Result<(), String> {
        let Some(node_ips6) = self.node_ips6.as_mut() else {
            return Ok(());
        };
        let key = CidrKey6::host(ipv6_to_nbo_words(ip));
        node_ips6
            .insert(key, 1u8, 0)
            .map_err(|e| format!("Failed to insert node IPv6 {ip}: {e}"))
    }

    pub fn insert_node_probe_port(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), String> {
        let Some(node_probe_ports) = self.node_probe_ports.as_mut() else {
            return Ok(());
        };
        let key = NodeProbePortKey4::new(ipv4_to_nbo_key(ip), port);
        node_probe_ports
            .insert(key, 1u8, 0)
            .map_err(|e| format!("Failed to insert node probe port {ip}:{port}: {e}"))
    }

    pub fn remove_node_probe_port(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), String> {
        let Some(node_probe_ports) = self.node_probe_ports.as_mut() else {
            return Ok(());
        };
        let key = NodeProbePortKey4::new(ipv4_to_nbo_key(ip), port);
        tolerate_missing_map_remove(node_probe_ports.remove(&key), || {
            format!("node probe port {ip}:{port}")
        })
    }

    pub fn insert_node_probe_port6(&mut self, ip: Ipv6Addr, port: u16) -> Result<(), String> {
        let Some(node_probe_ports6) = self.node_probe_ports6.as_mut() else {
            return Ok(());
        };
        let key = NodeProbePortKey6::new(ipv6_to_nbo_words(ip), port);
        node_probe_ports6
            .insert(key, 1u8, 0)
            .map_err(|e| format!("Failed to insert node IPv6 probe port {ip}:{port}: {e}"))
    }

    pub fn remove_node_probe_port6(&mut self, ip: Ipv6Addr, port: u16) -> Result<(), String> {
        let Some(node_probe_ports6) = self.node_probe_ports6.as_mut() else {
            return Ok(());
        };
        let key = NodeProbePortKey6::new(ipv6_to_nbo_words(ip), port);
        tolerate_missing_map_remove(node_probe_ports6.remove(&key), || {
            format!("node IPv6 probe port {ip}:{port}")
        })
    }

    /// Replace the inbound-redirect scope of one enrolled IPv4 pod address with
    /// exactly `ports`. An empty slice clears the pod's scope.
    ///
    /// **Stale entries are removed before new ones are added**, so a
    /// `containerPorts` edit that *narrows* a pod's exposure converges instead
    /// of leaving the removed port redirectable. Removal is keyed by scanning
    /// the map for this address, which is what lets pod teardown work from a
    /// Kubernetes delete event that carries no spec snapshot.
    ///
    /// An absent map is a **hard error** when there is anything to write: the
    /// caller only reaches here after deciding to arm the redirect, and
    /// silently succeeding would flag a pod as redirect-eligible with no
    /// reachable port (a black hole, since in-scope traffic fails closed).
    /// Clearing an absent map is a no-op so teardown still succeeds against an
    /// older ELF.
    ///
    /// A key-iteration error is likewise a **hard error**, never skipped: the
    /// scan is what finds the stale keys, so swallowing an error would return
    /// success from a narrowing update that never removed the withdrawn
    /// `(pod, port)` — leaving a port the operator just took out of
    /// `containerPorts` still redirectable, with the caller's retry ledger
    /// cleared because the write "succeeded".
    pub fn replace_pod_inbound_ports(&mut self, ip: Ipv4Addr, ports: &[u16]) -> Result<(), String> {
        let addr = ipv4_to_nbo_key(ip);
        let Some(pod_inbound_ports) = self.pod_inbound_ports.as_mut() else {
            if ports.is_empty() {
                return Ok(());
            }
            return Err(format!(
                "FERRUM_POD_INBOUND_PORTS map is absent; cannot scope the inbound redirect for {ip}"
            ));
        };

        let mut stale: Vec<InboundRedirectKey4> = Vec::new();
        for key in pod_inbound_ports.keys() {
            let key = key.map_err(|e| {
                format!(
                    "Failed to scan FERRUM_POD_INBOUND_PORTS for stale inbound redirect ports of \
                     {ip}: {e}. Refusing to report the scope replaced: a withdrawn port may still \
                     be redirectable."
                )
            })?;
            if key.addr == addr && !ports.contains(&key.port) {
                stale.push(key);
            }
        }
        for key in stale {
            tolerate_missing_map_remove(pod_inbound_ports.remove(&key), || {
                format!("inbound redirect port {ip}:{}", key.port)
            })?;
        }

        for port in ports {
            pod_inbound_ports
                .insert(InboundRedirectKey4::new(addr, *port), 1u8, 0)
                .map_err(|e| format!("Failed to insert inbound redirect port {ip}:{port}: {e}"))?;
        }
        Ok(())
    }

    /// IPv6 counterpart to [`Self::replace_pod_inbound_ports`].
    pub fn replace_pod_inbound_ports6(
        &mut self,
        ip: Ipv6Addr,
        ports: &[u16],
    ) -> Result<(), String> {
        let addr = ipv6_to_nbo_words(ip);
        let Some(pod_inbound_ports6) = self.pod_inbound_ports6.as_mut() else {
            if ports.is_empty() {
                return Ok(());
            }
            return Err(format!(
                "FERRUM_POD_INBOUND_PORTS6 map is absent; cannot scope the inbound redirect for {ip}"
            ));
        };

        let mut stale: Vec<InboundRedirectKey6> = Vec::new();
        for key in pod_inbound_ports6.keys() {
            let key = key.map_err(|e| {
                format!(
                    "Failed to scan FERRUM_POD_INBOUND_PORTS6 for stale inbound redirect ports of \
                     {ip}: {e}. Refusing to report the scope replaced: a withdrawn port may still \
                     be redirectable."
                )
            })?;
            if key.addr == addr && !ports.contains(&key.port) {
                stale.push(key);
            }
        }
        for key in stale {
            tolerate_missing_map_remove(pod_inbound_ports6.remove(&key), || {
                format!("IPv6 inbound redirect port {ip}:{}", key.port)
            })?;
        }

        for port in ports {
            pod_inbound_ports6
                .insert(InboundRedirectKey6::new(addr, *port), 1u8, 0)
                .map_err(|e| {
                    format!("Failed to insert IPv6 inbound redirect port {ip}:{port}: {e}")
                })?;
        }
        Ok(())
    }

    pub fn insert_bypass_uid(&mut self, uid: u32) -> Result<(), String> {
        let map = &mut self.bypass_uids;
        map.insert(uid, 1u8, 0)
            .map_err(|e| format!("Failed to insert bypass UID {uid}: {e}"))
    }

    pub fn insert_cidr_exclude(&mut self, cidr: &str) -> Result<(), String> {
        match parse_cidr_to_lpm_key(cidr)? {
            ParsedLpmKey::V4(key) => {
                let map = &mut self.cidr_exclude4;
                map.insert(&key, 1u8, 0)
                    .map_err(|e| format!("Failed to insert exclude CIDR '{cidr}': {e}"))
            }
            ParsedLpmKey::V6(key) => {
                let map = &mut self.cidr_exclude6;
                map.insert(&key, 1u8, 0)
                    .map_err(|e| format!("Failed to insert exclude CIDR '{cidr}': {e}"))
            }
        }
    }

    pub fn insert_cidr_include(&mut self, cidr: &str) -> Result<(), String> {
        match parse_cidr_to_lpm_key(cidr)? {
            ParsedLpmKey::V4(key) => {
                let map = &mut self.cidr_include4;
                map.insert(&key, 1u8, 0)
                    .map_err(|e| format!("Failed to insert include CIDR '{cidr}': {e}"))
            }
            ParsedLpmKey::V6(key) => {
                let map = &mut self.cidr_include6;
                map.insert(&key, 1u8, 0)
                    .map_err(|e| format!("Failed to insert include CIDR '{cidr}': {e}"))
            }
        }
    }

    pub fn insert_port_exclude(&mut self, port: u16) -> Result<(), String> {
        let map = &mut self.port_exclude;
        map.insert(port, 1u8, 0)
            .map_err(|e| format!("Failed to insert exclude port {port}: {e}"))
    }

    pub fn update_capture_config(&mut self, config: &BpfCaptureConfig) -> Result<(), String> {
        let Some(capture_config) = self.capture_config.as_mut() else {
            tracing::warn!(
                "Skipping capture config update because FERRUM_CAPTURE_CONFIG map is absent"
            );
            return Ok(());
        };
        capture_config
            .insert(FERRUM_CAPTURE_CONFIG_KEY, *config, 0)
            .map_err(|e| format!("Failed to update capture config: {e}"))
    }

    /// Insert (or replace) a per-cgroup `includeOutboundPorts` narrowing
    /// policy. Absent map (older ELF) is a no-op so the node agent boots
    /// even when the new gate is unavailable.
    pub fn insert_include_ports(
        &mut self,
        cgroup_id: u64,
        policy: &IncludePortsPolicy,
    ) -> Result<(), String> {
        let Some(include_ports) = self.include_ports.as_mut() else {
            return Ok(());
        };
        include_ports
            .insert(cgroup_id, *policy, 0)
            .map_err(|e| format!("Failed to insert include-ports for cgroup {cgroup_id}: {e}"))
    }

    /// Remove a per-cgroup `includeOutboundPorts` entry, e.g. on pod
    /// un-enrollment. Absent map (older ELF) is a no-op; absent key is
    /// silently tolerated because the BPF gate fail-opens on missing
    /// lookups.
    pub fn remove_include_ports(&mut self, cgroup_id: u64) -> Result<(), String> {
        let Some(include_ports) = self.include_ports.as_mut() else {
            return Ok(());
        };
        if let Err(e) = include_ports.remove(&cgroup_id) {
            // `aya::maps::HashMap::remove` returns Err on ENOENT; demote
            // that to a debug log because pods that were never annotated
            // legitimately have no entry.
            tracing::debug!(cgroup_id, error = %e, "remove_include_ports: entry missing");
        }
        Ok(())
    }

    /// Insert (or replace) a per-cgroup source workload identity (GAP-1b).
    /// Absent map (older ELF) is a no-op so the node agent boots even when
    /// the new map is unavailable.
    pub fn insert_workload_identity(
        &mut self,
        cgroup_id: u64,
        identity: &WorkloadIdentity,
    ) -> Result<(), String> {
        let Some(workload_identity) = self.workload_identity.as_mut() else {
            return Ok(());
        };
        workload_identity
            .insert(cgroup_id, *identity, 0)
            .map_err(|e| format!("Failed to insert workload identity for cgroup {cgroup_id}: {e}"))
    }

    /// Remove a per-cgroup workload identity entry, e.g. on pod
    /// un-enrollment. Absent map (older ELF) is a no-op; absent key is
    /// tolerated because the connect hooks fail-open to the unknown sentinel.
    pub fn remove_workload_identity(&mut self, cgroup_id: u64) -> Result<(), String> {
        let Some(workload_identity) = self.workload_identity.as_mut() else {
            return Ok(());
        };
        match workload_identity.remove(&cgroup_id) {
            Ok(()) => Ok(()),
            // An absent key is benign (already removed / never written): the
            // connect hooks fail-open to the unknown sentinel, so tolerate it.
            Err(aya::maps::MapError::SyscallError(err))
                if err.io_error.raw_os_error() == Some(libc::ENOENT) =>
            {
                tracing::debug!(cgroup_id, "remove_workload_identity: entry already absent");
                Ok(())
            }
            // Any other failure leaves a stale identity in the map that could
            // misattribute a reused cgroup inode — surface it rather than
            // silently dropping the cgroup from the caller's tracking state.
            Err(e) => Err(format!(
                "Failed to remove workload identity for cgroup {cgroup_id}: {e}"
            )),
        }
    }
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn tolerate_missing_map_remove<F>(
    result: Result<(), aya::maps::MapError>,
    label: F,
) -> Result<(), String>
where
    F: FnOnce() -> String,
{
    match result {
        Ok(()) => Ok(()),
        Err(aya::maps::MapError::SyscallError(err))
            if err.io_error.raw_os_error() == Some(libc::ENOENT) =>
        {
            tracing::debug!(entry = %label(), "BPF map remove: entry already absent");
            Ok(())
        }
        Err(e) => Err(format!("Failed to remove {} from BPF map: {e}", label())),
    }
}

/// Parse a CIDR string (e.g. "10.0.0.0/8") into an LPM trie key.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
enum ParsedLpmKey {
    V4(LpmKey<CidrKey4>),
    V6(LpmKey<CidrKey6>),
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn parse_cidr_to_lpm_key(cidr: &str) -> Result<ParsedLpmKey, String> {
    match parse_cidr_to_lpm_key_data(cidr)? {
        ParsedCidrKey::V4 { prefix_len, data } => {
            Ok(ParsedLpmKey::V4(LpmKey::new(prefix_len, data)))
        }
        ParsedCidrKey::V6 { prefix_len, data } => {
            Ok(ParsedLpmKey::V6(LpmKey::new(prefix_len, data)))
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParsedCidrKey {
    V4 { prefix_len: u32, data: CidrKey4 },
    V6 { prefix_len: u32, data: CidrKey6 },
}

pub fn parse_cidr_to_lpm_key_data(cidr: &str) -> Result<ParsedCidrKey, String> {
    let (addr_str, prefix_str) = cidr
        .split_once('/')
        .ok_or_else(|| format!("CIDR '{cidr}' missing prefix length"))?;
    let addr: IpAddr = addr_str
        .parse()
        .map_err(|e| format!("CIDR '{cidr}' invalid address: {e}"))?;
    let prefix_len: u32 = prefix_str
        .parse()
        .map_err(|e| format!("CIDR '{cidr}' invalid prefix length: {e}"))?;

    match addr {
        IpAddr::V4(addr) => {
            if prefix_len > 32 {
                return Err(format!(
                    "CIDR '{cidr}' prefix length {prefix_len} exceeds max 32"
                ));
            }
            Ok(ParsedCidrKey::V4 {
                prefix_len,
                data: CidrKey4::new(u32::from(addr).to_be()),
            })
        }
        IpAddr::V6(addr) => {
            if prefix_len > 128 {
                return Err(format!(
                    "CIDR '{cidr}' prefix length {prefix_len} exceeds max 128"
                ));
            }
            Ok(ParsedCidrKey::V6 {
                prefix_len,
                data: CidrKey6::new(ipv6_to_nbo_words(addr)),
            })
        }
    }
}

fn ipv4_to_nbo_key(addr: Ipv4Addr) -> u32 {
    u32::from(addr).to_be()
}

fn ipv6_to_nbo_words(addr: Ipv6Addr) -> [u32; 4] {
    let octets = addr.octets();
    [
        u32::from_ne_bytes([octets[0], octets[1], octets[2], octets[3]]),
        u32::from_ne_bytes([octets[4], octets[5], octets[6], octets[7]]),
        u32::from_ne_bytes([octets[8], octets[9], octets[10], octets[11]]),
        u32::from_ne_bytes([octets[12], octets[13], octets[14], octets[15]]),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn parse_cidr_to_lpm_key_valid_ipv4() {
        let key = parse_cidr_to_lpm_key_data("10.0.0.0/8").unwrap();
        assert_eq!(
            key,
            ParsedCidrKey::V4 {
                prefix_len: 8,
                data: CidrKey4::new(u32::from(Ipv4Addr::new(10, 0, 0, 0)).to_be()),
            }
        );
    }

    #[test]
    fn parse_cidr_to_lpm_key_host_ipv4() {
        let key = parse_cidr_to_lpm_key_data("192.168.1.1/32").unwrap();
        assert_eq!(
            key,
            ParsedCidrKey::V4 {
                prefix_len: 32,
                data: CidrKey4::new(u32::from(Ipv4Addr::new(192, 168, 1, 1)).to_be()),
            }
        );
    }

    #[test]
    fn ipv4_pod_ip_key_uses_packet_byte_order() {
        let key = ipv4_to_nbo_key(Ipv4Addr::new(10, 0, 0, 5));
        assert_eq!(key.to_ne_bytes(), [10, 0, 0, 5]);
    }

    #[test]
    fn parse_cidr_to_lpm_key_valid_ipv6() {
        let key = parse_cidr_to_lpm_key_data("2001:db8::/32").unwrap();
        assert_eq!(
            key,
            ParsedCidrKey::V6 {
                prefix_len: 32,
                data: CidrKey6::new([u32::from_ne_bytes([0x20, 0x01, 0x0d, 0xb8]), 0, 0, 0,]),
            }
        );
    }

    #[test]
    fn parse_cidr_missing_prefix() {
        assert!(parse_cidr_to_lpm_key_data("10.0.0.0").is_err());
    }

    #[test]
    fn parse_cidr_invalid_addr() {
        assert!(parse_cidr_to_lpm_key_data("not.an.ip/8").is_err());
    }

    #[test]
    fn parse_cidr_invalid_prefix() {
        assert!(parse_cidr_to_lpm_key_data("10.0.0.0/abc").is_err());
    }

    #[test]
    fn parse_cidr_rejects_prefix_above_address_width() {
        assert!(parse_cidr_to_lpm_key_data("10.0.0.0/33").is_err());
        assert!(parse_cidr_to_lpm_key_data("2001:db8::/129").is_err());
    }
}
