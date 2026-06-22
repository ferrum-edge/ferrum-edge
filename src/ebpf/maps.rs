//! Typed BPF map operations wrapping aya's map API.
//!
//! `BpfMaps` provides insert/remove helpers for each BPF map, converting
//! between Rust types and the `#[repr(C)]` shared types from
//! `ferrum-ebpf-common`. Only available on Linux with `--features ebpf`.

#![allow(dead_code)]

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::net::Ipv4Addr;
use std::net::{IpAddr, Ipv6Addr};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::Ebpf;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::maps::lpm_trie::Key as LpmKey;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::maps::{HashMap as BpfHashMap, LpmTrie, MapData};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use ferrum_ebpf_common::{
    BpfCaptureConfig, FERRUM_CAPTURE_CONFIG_KEY, IncludePortsPolicy, PodInfo as BpfPodInfo,
    WorkloadIdentity,
};
use ferrum_ebpf_common::{CidrKey4, CidrKey6};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use super::{BPF_MAP_CAPTURE_CONFIG, BPF_MAP_WORKLOAD_IDENTITY, PodInfo};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub struct BpfMaps {
    pod_ips: BpfHashMap<MapData, u32, BpfPodInfo>,
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

    pub fn validate_required(&self, require_workload_identity: bool) -> Result<(), String> {
        let mut missing = Vec::new();
        if self.capture_config.is_none() {
            missing.push(BPF_MAP_CAPTURE_CONFIG);
        }
        if require_workload_identity && self.workload_identity.is_none() {
            missing.push(BPF_MAP_WORKLOAD_IDENTITY);
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
        let key = u32::from(ip);
        let value = BpfPodInfo {
            proxy_port: info.proxy_port as u32,
            _pad: 0,
        };
        let map = &mut self.pod_ips;
        map.insert(key, value, 0)
            .map_err(|e| format!("Failed to insert pod IP {ip}: {e}"))
    }

    pub fn remove_pod_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        let key = u32::from(ip);
        let map = &mut self.pod_ips;
        map.remove(&key)
            .map_err(|e| format!("Failed to remove pod IP {ip}: {e}"))
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
