//! aya-based eBPF program loader and attachment manager.
//!
//! `AyaEbpfBackend` implements `EbpfBackend` using the `aya` crate to load
//! BPF ELF bytes, attach programs to pod cgroups and veth interfaces, and
//! manage BPF map contents. Available only on Linux with `--features ebpf`.

#![allow(dead_code)]

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::collections::HashMap;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::fs::{self, File};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use std::os::fd::AsFd;

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::programs::cgroup_sock_addr::CgroupSockAddrLinkId;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::programs::sock_ops::SockOpsLinkId;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::programs::tc::SchedClassifierLinkId;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::programs::{CgroupAttachMode, CgroupSockAddr, SchedClassifier, SockOps, TcAttachType};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use aya::{Ebpf, EbpfLoader};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use tracing::{debug, info, warn};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
use super::maps::BpfMaps;
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use super::{
    BPF_MAP_ORIG_DST4, BPF_MAP_ORIG_DST6, BPF_MAP_SOCK_OPS_EVENTS, BPF_MAP_SOCK_OPS_STATS,
    BPF_ORIG_DST4_PIN_PATH, BPF_ORIG_DST6_PIN_PATH, BPF_PROGRAM_SOCK_OPS,
    BPF_SOCK_OPS_EVENTS_PIN_PATH, BPF_SOCK_OPS_STATS_PIN_PATH, EbpfBackend, IncludePortsPolicy,
    PodInfo, TcAttachDirection,
};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
use ferrum_ebpf_common::{BpfCaptureConfig, SOCK_OPS_RINGBUF_DEFAULT_BYTES};

#[cfg(all(feature = "ebpf", target_os = "linux"))]
const DEFAULT_BPF_ELF_PATH: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/ebpf/target/bpfel-unknown-none/release/ferrum-ebpf"
);

#[cfg(all(feature = "ebpf", target_os = "linux"))]
const CGROUP_PROGRAMS: &[&str] = &[
    "ferrum_connect4",
    "ferrum_connect6",
    "ferrum_getpeername4",
    "ferrum_getpeername6",
];

#[cfg(all(feature = "ebpf", target_os = "linux"))]
const TC_PROGRAM: &str = "ferrum_tc_inbound";

/// Tracks per-pod attachment state for cleanup.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
struct PodLinks {
    cgroup_link_ids: Vec<CgroupSockAddrLinkId>,
    tc_link_ids: Vec<SchedClassifierLinkId>,
}

/// Real aya-backed eBPF loader. Only available on Linux with `--features ebpf`.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
pub struct AyaEbpfBackend {
    bpf: Option<Ebpf>,
    maps: Option<BpfMaps>,
    pod_links: HashMap<String, PodLinks>,
    /// Link id for the global SOCK_OPS attach. Set on first successful
    /// `attach_sock_ops`; cleared by `cleanup_all` (the link is detached
    /// implicitly when `Ebpf` is dropped, but holding the id lets future
    /// callers detach explicitly if needed).
    sock_ops_link_id: Option<SockOpsLinkId>,
    orig_dst_maps_pinned: bool,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
impl AyaEbpfBackend {
    pub fn new() -> Self {
        Self {
            bpf: None,
            maps: None,
            pod_links: HashMap::new(),
            sock_ops_link_id: None,
            orig_dst_maps_pinned: false,
        }
    }

    fn bpf(&self) -> Result<&Ebpf, String> {
        self.bpf
            .as_ref()
            .ok_or_else(|| "BPF programs not loaded".to_string())
    }

    fn bpf_mut(&mut self) -> Result<&mut Ebpf, String> {
        self.bpf
            .as_mut()
            .ok_or_else(|| "BPF programs not loaded".to_string())
    }
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
impl EbpfBackend for AyaEbpfBackend {
    fn load_programs(&mut self) -> Result<(), String> {
        let bpf_elf_path =
            crate::config::conf_file::resolve_ferrum_var("FERRUM_NODE_AGENT_BPF_ELF_PATH")
                .unwrap_or_else(|| DEFAULT_BPF_ELF_PATH.to_string());
        let bpf_elf = fs::read(&bpf_elf_path)
            .map_err(|e| format!("Failed to read BPF ELF '{bpf_elf_path}': {e}"))?;

        // Size the SOCK_OPS event ringbuf from operator config. The kernel
        // baked a 4 MiB default into the ELF; `set_max_entries` rewrites
        // the descriptor at load time so the actual kernel object honors
        // FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES without rebuilding the ELF.
        let ringbuf_bytes = resolve_sock_ops_ringbuf_bytes();
        let mut bpf = EbpfLoader::new()
            .set_max_entries(BPF_MAP_SOCK_OPS_EVENTS, ringbuf_bytes)
            .load(&bpf_elf)
            .map_err(|e| format!("Failed to load BPF ELF: {e}"))?;

        if let Err(e) = aya_log::EbpfLogger::init(&mut bpf) {
            warn!("Failed to initialize eBPF logger (non-fatal): {e}");
        }

        for name in CGROUP_PROGRAMS {
            let prog: &mut CgroupSockAddr = bpf
                .program_mut(name)
                .ok_or_else(|| format!("BPF program '{name}' not found in ELF"))?
                .try_into()
                .map_err(|e| format!("'{name}' is not a CgroupSockAddr program: {e}"))?;
            prog.load()
                .map_err(|e| format!("Failed to load BPF program '{name}': {e}"))?;
            debug!(program = name, "BPF cgroup program loaded");
        }

        let tc: &mut SchedClassifier = bpf
            .program_mut(TC_PROGRAM)
            .ok_or_else(|| format!("BPF program '{TC_PROGRAM}' not found in ELF"))?
            .try_into()
            .map_err(|e| format!("'{TC_PROGRAM}' is not a SchedClassifier: {e}"))?;
        tc.load()
            .map_err(|e| format!("Failed to load BPF program '{TC_PROGRAM}': {e}"))?;
        debug!(program = TC_PROGRAM, "BPF tc program loaded");

        // Load the SOCK_OPS observability program. Best-effort: failing
        // to load this program does NOT break capture — it only loses
        // TCP-layer telemetry. The attach + pin happens in
        // `attach_sock_ops`, which the node-agent calls once at startup.
        if let Some(prog_ref) = bpf.program_mut(BPF_PROGRAM_SOCK_OPS) {
            match TryInto::<&mut SockOps>::try_into(prog_ref) {
                Ok(prog) => {
                    if let Err(e) = prog.load() {
                        warn!(
                            program = BPF_PROGRAM_SOCK_OPS,
                            error = %e,
                            "Failed to load SOCK_OPS program (TCP-layer observability disabled)"
                        );
                    } else {
                        debug!(
                            program = BPF_PROGRAM_SOCK_OPS,
                            ringbuf_bytes, "BPF sock_ops program loaded"
                        );
                    }
                }
                Err(e) => warn!(
                    program = BPF_PROGRAM_SOCK_OPS,
                    error = %e,
                    "SOCK_OPS program type mismatch (TCP-layer observability disabled)"
                ),
            }
        } else {
            warn!(
                program = BPF_PROGRAM_SOCK_OPS,
                "SOCK_OPS program not present in ELF (TCP-layer observability disabled)"
            );
        }

        self.maps = Some(BpfMaps::from_ebpf(&mut bpf)?);

        // GAP-1b: pin the original-destination maps so the node-waypoint
        // mesh-proxy can open them by path through the orig-dst bridge.
        // A pin failure is captured here and rejected by startup readiness in
        // NodeWaypoint mode, where source identity is required for policy scope.
        self.orig_dst_maps_pinned = match pin_orig_dst_maps(&mut bpf) {
            Ok(()) => true,
            Err(e) => {
                warn!(
                    error = %e,
                    "Failed to pin original-destination maps; node-waypoint source-identity \
                     resolution will be unavailable until startup readiness rejects this topology"
                );
                false
            }
        };

        self.bpf = Some(bpf);

        info!("All BPF programs loaded successfully");
        Ok(())
    }

    fn update_capture_config(&mut self, config: &BpfCaptureConfig) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.update_capture_config(config)
    }

    fn attach_cgroup(
        &mut self,
        pod_uid: &str,
        cgroup_path: &str,
        program: &str,
    ) -> Result<(), String> {
        let cgroup_fd = File::open(cgroup_path)
            .map_err(|e| format!("Failed to open cgroup '{cgroup_path}': {e}"))?;

        let bpf = self.bpf_mut()?;
        let prog: &mut CgroupSockAddr = bpf
            .program_mut(program)
            .ok_or_else(|| format!("BPF program '{program}' not found"))?
            .try_into()
            .map_err(|e| format!("'{program}' type mismatch: {e}"))?;

        let link_id = prog
            .attach(cgroup_fd.as_fd(), CgroupAttachMode::Single)
            .map_err(|e| format!("Failed to attach '{program}' to '{cgroup_path}': {e}"))?;

        let links = self
            .pod_links
            .entry(pod_uid.to_string())
            .or_insert_with(|| PodLinks {
                cgroup_link_ids: Vec::new(),
                tc_link_ids: Vec::new(),
            });
        links.cgroup_link_ids.push(link_id);

        debug!(program, cgroup_path, "BPF cgroup program attached");
        Ok(())
    }

    fn attach_tc(
        &mut self,
        pod_uid: &str,
        iface: &str,
        program: &str,
        direction: TcAttachDirection,
    ) -> Result<(), String> {
        let bpf = self.bpf_mut()?;
        let prog: &mut SchedClassifier = bpf
            .program_mut(program)
            .ok_or_else(|| format!("BPF program '{program}' not found"))?
            .try_into()
            .map_err(|e| format!("'{program}' type mismatch: {e}"))?;
        let attach_type = match direction {
            TcAttachDirection::Ingress => TcAttachType::Ingress,
            TcAttachDirection::Egress => TcAttachType::Egress,
        };

        let link_id = prog.attach(iface, attach_type).map_err(|e| {
            format!(
                "Failed to attach '{program}' to '{iface}' {}: {e}",
                direction.as_str()
            )
        })?;

        let links = self
            .pod_links
            .entry(pod_uid.to_string())
            .or_insert_with(|| PodLinks {
                cgroup_link_ids: Vec::new(),
                tc_link_ids: Vec::new(),
            });
        links.tc_link_ids.push(link_id);

        debug!(
            program,
            iface,
            direction = direction.as_str(),
            "BPF tc program attached"
        );
        Ok(())
    }

    fn detach_pod(&mut self, pod_uid: &str) -> Result<(), String> {
        self.pod_links.remove(pod_uid);
        debug!(pod_uid, "BPF programs detached for pod");
        Ok(())
    }

    fn update_pod_ip(&mut self, ip: Ipv4Addr, info: &PodInfo) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_pod_ip(ip, info)
    }

    fn remove_pod_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.remove_pod_ip(ip)
    }

    fn update_pod_ip6(&mut self, ip: Ipv6Addr, info: &PodInfo) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_pod_ip6(ip, info)
    }

    fn remove_pod_ip6(&mut self, ip: Ipv6Addr) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.remove_pod_ip6(ip)
    }

    fn update_bypass_uid(&mut self, uid: u32) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_bypass_uid(uid)
    }

    fn update_cidr_exclude(&mut self, cidr: &str) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_cidr_exclude(cidr)
    }

    fn update_cidr_include(&mut self, cidr: &str) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_cidr_include(cidr)
    }

    fn update_port_exclude(&mut self, port: u16) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_port_exclude(port)
    }

    fn update_pod_include_ports(
        &mut self,
        cgroup_id: u64,
        policy: &IncludePortsPolicy,
    ) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_include_ports(cgroup_id, policy)
    }

    fn remove_pod_include_ports(&mut self, cgroup_id: u64) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.remove_include_ports(cgroup_id)
    }

    fn update_workload_identity(
        &mut self,
        cgroup_id: u64,
        identity: &ferrum_ebpf_common::WorkloadIdentity,
    ) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_workload_identity(cgroup_id, identity)
    }

    fn remove_workload_identity(&mut self, cgroup_id: u64) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.remove_workload_identity(cgroup_id)
    }

    fn attach_sock_ops(&mut self, cgroup_root: &str) -> Result<(), String> {
        if self.sock_ops_link_id.is_some() {
            // Already attached — idempotent, no-op.
            return Ok(());
        }

        let cgroup_fd = File::open(cgroup_root)
            .map_err(|e| format!("Failed to open cgroup root '{cgroup_root}': {e}"))?;

        let bpf = self.bpf_mut()?;

        // Look up the program before we try to attach. The program may
        // not be present (load failed best-effort above) — that's
        // surfaced as a clean error instead of an unwrap panic.
        let Some(prog_ref) = bpf.program_mut(BPF_PROGRAM_SOCK_OPS) else {
            return Err(format!(
                "SOCK_OPS program '{BPF_PROGRAM_SOCK_OPS}' not loaded; cannot attach"
            ));
        };
        let prog: &mut SockOps = prog_ref
            .try_into()
            .map_err(|e| format!("'{BPF_PROGRAM_SOCK_OPS}' is not a SockOps program: {e}"))?;

        let link_id = prog
            .attach(cgroup_fd.as_fd(), CgroupAttachMode::Single)
            .map_err(|e| format!("Failed to attach SOCK_OPS to '{cgroup_root}': {e}"))?;

        // Pin BEFORE storing link_id so a pinning failure can detach the
        // program atomically. Without this, a pinning failure (bpffs not
        // mounted, ENOSPC, permission denied on /sys/fs/bpf/ferrum/) leaves
        // the SOCK_OPS program attached and burning kernel CPU on every TCP
        // socket op cluster-wide, while writing into a ringbuf no userspace
        // process can ever drain. Better to fail closed.
        if let Err(e) = pin_sock_ops_maps(bpf) {
            warn!(
                error = %e,
                "Failed to pin SOCK_OPS maps; detaching program to avoid leaking an unreachable ringbuf"
            );
            // Re-fetch prog_mut because the previous binding's borrow ended
            // when pin_sock_ops_maps returned (it took &mut Ebpf).
            if let Some(prog_ref) = bpf.program_mut(BPF_PROGRAM_SOCK_OPS) {
                if let Ok(prog) = TryInto::<&mut SockOps>::try_into(prog_ref) {
                    if let Err(detach_err) = prog.detach(link_id) {
                        warn!(
                            error = %detach_err,
                            "Best-effort detach of SOCK_OPS after pin failure also failed"
                        );
                    }
                }
            }
            return Err(e);
        }
        // Only record the link_id once pinning has succeeded — keeps the
        // recorded lifecycle state consistent with what's actually live.
        self.sock_ops_link_id = Some(link_id);

        info!(
            cgroup_root,
            pin_path = BPF_SOCK_OPS_EVENTS_PIN_PATH,
            "SOCK_OPS program attached and event ringbuf pinned"
        );
        Ok(())
    }

    fn validate_startup_ready(&self, require_sock_ops: bool) -> Result<(), String> {
        if self.bpf.is_none() {
            return Err("BPF programs are not loaded".to_string());
        }
        let Some(maps) = self.maps.as_ref() else {
            return Err("BPF maps are not initialized".to_string());
        };
        maps.validate_required(require_sock_ops)?;
        if require_sock_ops && self.sock_ops_link_id.is_none() {
            return Err("SOCK_OPS identity bridge is not attached".to_string());
        }
        if require_sock_ops && !self.orig_dst_maps_pinned {
            return Err("original-destination identity maps are not pinned".to_string());
        }
        Ok(())
    }

    fn cleanup_all(&mut self) -> Result<(), String> {
        self.pod_links.clear();
        self.sock_ops_link_id = None;
        self.orig_dst_maps_pinned = false;
        self.maps = None;
        self.bpf = None;
        // Best-effort: unpin the SOCK_OPS and orig-dst maps so a stale pin
        // doesn't mislead a future mesh-proxy start. Missing pin is fine.
        let _ = fs::remove_file(BPF_SOCK_OPS_EVENTS_PIN_PATH);
        let _ = fs::remove_file(BPF_SOCK_OPS_STATS_PIN_PATH);
        let _ = fs::remove_file(BPF_ORIG_DST4_PIN_PATH);
        let _ = fs::remove_file(BPF_ORIG_DST6_PIN_PATH);
        info!("BPF programs and maps cleaned up");
        Ok(())
    }
}

/// Resolve `FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES` with the kernel-default
/// fallback. Invalid (non-numeric / zero / non-power-of-two) values are
/// rejected with a `warn!` and silently fall back to the default so the
/// gateway never refuses to start over an observability tuning knob.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn resolve_sock_ops_ringbuf_bytes() -> u32 {
    let Some(raw) =
        crate::config::conf_file::resolve_ferrum_var("FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES")
    else {
        return SOCK_OPS_RINGBUF_DEFAULT_BYTES;
    };
    // 256 MiB is a generous ceiling for a per-node TCP-event ringbuf.
    // Stops operator typos (e.g., 2147483648 instead of 4194304) from
    // claiming a gigabyte of locked kernel memory on every mesh-proxy
    // node. Plenty of headroom for high-traffic node-waypoints.
    const MAX_BYTES: u32 = 256 * 1024 * 1024;
    match raw.trim().parse::<u32>() {
        Ok(n) if n >= 4096 && n <= MAX_BYTES && n.is_power_of_two() => n,
        Ok(n) if n > MAX_BYTES => {
            warn!(
                value = n,
                max_bytes = MAX_BYTES,
                "FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES exceeds maximum supported size; using default {}",
                SOCK_OPS_RINGBUF_DEFAULT_BYTES
            );
            SOCK_OPS_RINGBUF_DEFAULT_BYTES
        }
        Ok(n) => {
            warn!(
                value = n,
                "FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES must be a power of two between 4096 and {}; using default {}",
                MAX_BYTES,
                SOCK_OPS_RINGBUF_DEFAULT_BYTES
            );
            SOCK_OPS_RINGBUF_DEFAULT_BYTES
        }
        Err(e) => {
            warn!(
                raw = %raw,
                error = %e,
                "FERRUM_BPF_SOCK_OPS_RINGBUF_BYTES is not a valid u32; using default {}",
                SOCK_OPS_RINGBUF_DEFAULT_BYTES
            );
            SOCK_OPS_RINGBUF_DEFAULT_BYTES
        }
    }
}

/// Pin the original-destination maps at their well-known paths so the
/// node-waypoint mesh-proxy can open them by path (GAP-1b). Creates the
/// `/sys/fs/bpf/ferrum` parent if needed; bpffs must already be mounted.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn pin_orig_dst_maps(bpf: &mut Ebpf) -> Result<(), String> {
    if let Some(parent) = std::path::Path::new(BPF_ORIG_DST4_PIN_PATH).parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        return Err(format!(
            "Failed to create pin parent dir '{}': {e}",
            parent.display()
        ));
    }
    pin_map_at(bpf, BPF_MAP_ORIG_DST4, BPF_ORIG_DST4_PIN_PATH)?;
    pin_map_at(bpf, BPF_MAP_ORIG_DST6, BPF_ORIG_DST6_PIN_PATH)?;
    Ok(())
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn pin_sock_ops_maps(bpf: &mut Ebpf) -> Result<(), String> {
    // Ensure the parent dir exists. /sys/fs/bpf must already be mounted
    // (bpffs); we only need to create the /ferrum subdirectory.
    if let Some(parent) = std::path::Path::new(BPF_SOCK_OPS_EVENTS_PIN_PATH).parent()
        && let Err(e) = fs::create_dir_all(parent)
    {
        return Err(format!(
            "Failed to create pin parent dir '{}': {e}",
            parent.display()
        ));
    }
    pin_map_at(bpf, BPF_MAP_SOCK_OPS_EVENTS, BPF_SOCK_OPS_EVENTS_PIN_PATH)?;
    pin_map_at(bpf, BPF_MAP_SOCK_OPS_STATS, BPF_SOCK_OPS_STATS_PIN_PATH)?;
    Ok(())
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
fn pin_map_at(bpf: &mut Ebpf, map_name: &str, pin_path: &str) -> Result<(), String> {
    // If a stale pin exists (e.g. previous run did not clean up), remove
    // it so the new map gets pinned fresh. Best-effort: missing path is
    // fine, only surface real errors.
    if std::path::Path::new(pin_path).exists()
        && let Err(e) = fs::remove_file(pin_path)
    {
        return Err(format!("Failed to remove stale pin '{pin_path}': {e}"));
    }
    let map = bpf
        .map_mut(map_name)
        .ok_or_else(|| format!("BPF map '{map_name}' not found"))?;
    map.pin(pin_path)
        .map_err(|e| format!("Failed to pin '{map_name}' at '{pin_path}': {e}"))
}

/// Live-kernel verification (GAP-2M / connect-side datapath).
///
/// These tests need a real Linux >= 5.7 kernel with cgroup v2 + bpffs and
/// `CAP_BPF`/root, so they are `#[ignore]`d and only run via the dedicated
/// `ebpf-live` CI job (`sudo cargo test --features ebpf --lib -- --ignored`).
/// They self-skip (pass) when the kernel lacks the prerequisites so the job is
/// green on best-effort runners and only red on a genuine load/attach failure.
#[cfg(test)]
mod live_kernel_tests {
    use super::AyaEbpfBackend;
    use crate::ebpf::kernel_probe::probe_kernel;
    use crate::ebpf::{BPF_ORIG_DST4_PIN_PATH, EbpfBackend};
    use aya::maps::{HashMap as BpfHashMap, Map, MapData};
    use ferrum_ebpf_common::{OrigDst4, OrigDstKey, WorkloadIdentity};
    use std::fs;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    const BPF_FS: &str = "/sys/fs/bpf";

    /// A scratch cgroup v2 node, removed on drop. Attaching the
    /// `cgroup_sock_addr` / `sock_ops` programs here (rather than the cgroup
    /// root) keeps the test from perturbing the whole runner.
    struct ScratchCgroup {
        path: PathBuf,
    }

    impl ScratchCgroup {
        fn create() -> std::io::Result<Self> {
            let path =
                PathBuf::from(CGROUP_ROOT).join(format!("ferrum-ebpf-live-{}", std::process::id()));
            fs::create_dir_all(&path)?;
            Ok(Self { path })
        }

        fn path_str(&self) -> String {
            self.path.to_string_lossy().into_owned()
        }

        /// The kernel cgroup id equals the inode of the cgroup v2 directory.
        fn cgroup_id(&self) -> u64 {
            fs::metadata(&self.path).map(|m| m.ino()).unwrap_or(0)
        }
    }

    impl Drop for ScratchCgroup {
        fn drop(&mut self) {
            // cgroup v2 dirs are removed with rmdir once empty.
            let _ = fs::remove_dir(&self.path);
        }
    }

    fn read_orig_dst4_records() -> Result<Vec<(OrigDstKey, OrigDst4)>, String> {
        let data = MapData::from_pin(BPF_ORIG_DST4_PIN_PATH)
            .map_err(|e| format!("open pinned orig_dst4 map: {e}"))?;
        let map = BpfHashMap::<MapData, OrigDstKey, OrigDst4>::try_from(Map::LruHashMap(data))
            .map_err(|e| format!("orig_dst4 pin type mismatch: {e}"))?;
        map.iter()
            .map(|entry| entry.map_err(|e| format!("iterate orig_dst4 map: {e}")))
            .collect()
    }

    #[test]
    #[ignore = "requires root + real Linux >= 5.7 kernel (cgroup v2 + bpffs); run via the ebpf-live CI job"]
    fn programs_load_verify_attach_and_map_round_trip() {
        // Surface loader warnings — including the best-effort SOCK_OPS load,
        // whose error carries the BPF verifier log — in `--nocapture` output so
        // a load/verify failure is diagnosable straight from the CI job log.
        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let probe = probe_kernel(CGROUP_ROOT, BPF_FS);
        if !probe.supports_ebpf() {
            eprintln!(
                "SKIP live-kernel eBPF test: prerequisites unmet (release={}, reason={:?})",
                probe.kernel_release,
                probe.degradation_reason()
            );
            return;
        }

        let mut backend = AyaEbpfBackend::new();
        // Loading runs the in-kernel BPF verifier over every program in the
        // ELF — connect4/6, getpeername4/6, tc_inbound, and the GAP-2M
        // sock_ops cookie bridge. Success here is the core live validation
        // that the (blind-built) kernel code is accepted by a real verifier.
        backend
            .load_programs()
            .expect("load + verify BPF programs on the running kernel");

        let cgroup = ScratchCgroup::create().expect("create scratch cgroup v2 node");

        backend
            .attach_cgroup("live-test", &cgroup.path_str(), "ferrum_connect4")
            .expect("attach connect4 to scratch cgroup");
        backend
            .attach_sock_ops(&cgroup.path_str())
            .expect("attach sock_ops (incl. GAP-2M bridge) to scratch cgroup");

        // Exercise the workload-identity map RW path the connect hooks read to
        // stamp pod_uid — the connect-side half of the node-waypoint identity
        // flow.
        let cgroup_id = cgroup.cgroup_id();
        let identity = WorkloadIdentity::new([7u8; 16], 0xdead_beef_cafe_f00d);
        backend
            .update_workload_identity(cgroup_id, &identity)
            .expect("write workload identity to FERRUM_WORKLOAD_IDENTITY");
        backend
            .remove_workload_identity(cgroup_id)
            .expect("remove workload identity");

        backend.cleanup_all().expect("cleanup BPF state");
    }

    /// Layer-2 datapath verification: a real captured `connect()` is rewritten
    /// by `connect4` to the configured capture port and lands on a local server
    /// — proving the connect-side capture works end to end on a live kernel, not
    /// just that the program loads/attaches. Gated on `--features ebpf` because
    /// it reaches the real backend's map handles (the no-ebpf build has a stub);
    /// runs via the `ebpf-live` CI job, self-skipping when prerequisites are
    /// unmet.
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    #[test]
    #[ignore = "requires root + real Linux >= 5.7 kernel (cgroup v2 + bpffs); run via the ebpf-live CI job"]
    fn connect4_redirects_a_real_captured_connection_to_the_capture_port() {
        use std::time::{Duration, Instant};

        let _ = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::WARN)
            .with_test_writer()
            .try_init();

        let probe = probe_kernel(CGROUP_ROOT, BPF_FS);
        if !probe.supports_ebpf() {
            eprintln!(
                "SKIP connect4-redirect live test: prerequisites unmet (release={}, reason={:?})",
                probe.kernel_release,
                probe.degradation_reason()
            );
            return;
        }

        let mut backend = AyaEbpfBackend::new();
        backend
            .load_programs()
            .expect("load + verify BPF programs on the running kernel");

        let cgroup = ScratchCgroup::create().expect("create scratch cgroup v2 node");
        backend
            .attach_cgroup("live-redirect", &cgroup.path_str(), "ferrum_connect4")
            .expect("attach connect4 to scratch cgroup");
        backend
            .attach_sock_ops(&cgroup.path_str())
            .expect("attach sock_ops to scratch cgroup");

        // Server on an ephemeral loopback port. connect4 rewrites captured egress
        // to exactly this port, so there is no fixed-port collision risk.
        let server = std::net::TcpListener::bind("127.0.0.1:0").expect("bind capture-port server");
        let capture_port = server.local_addr().unwrap().port();
        server.set_nonblocking(true).unwrap();

        // Make connect4 capture this cgroup's egress and rewrite it to
        // `capture_port`. A wildcard `includeOutboundPorts` policy is the most
        // robust trigger: `capture_allowed()` returns true for it immediately,
        // BEFORE the include-CIDR LPM check, so capture does not depend on the
        // CIDR trie. The 0.0.0.0/0 include CIDR is also installed as a second
        // path.
        let cgroup_id = cgroup.cgroup_id();
        backend
            .update_capture_config(&ferrum_ebpf_common::BpfCaptureConfig::new(
                capture_port,
                15008,
            ))
            .expect("set capture config");
        {
            let maps = backend.maps.as_mut().expect("maps loaded");
            maps.insert_cidr_include("0.0.0.0/0")
                .expect("insert 0.0.0.0/0 include CIDR");
            maps.insert_include_ports(cgroup_id, &ferrum_ebpf_common::IncludePortsPolicy::all())
                .expect("insert wildcard include-ports policy");
        }

        // Stamp an identity for this cgroup (connect4 records it into the
        // orig-dst entry; mirrors the production connect-side stamp).
        backend
            .update_workload_identity(
                cgroup_id,
                &WorkloadIdentity::new([9u8; 16], 0x0123_4567_89ab_cdef),
            )
            .expect("stamp workload identity");

        // Move this process into the scratch cgroup so its connect() goes through
        // the connect4 program attached there.
        // On some runners the process can't actually be moved (cgroup
        // namespaces / delegation): the write may succeed yet the PID not
        // appear in the target. Read `cgroup.procs` back and self-skip rather
        // than hard-fail when the move didn't take effect — this layer can only
        // run where it does, and a false failure here would be a flaky red.
        let pid = std::process::id().to_string();
        let procs_path = format!("{}/cgroup.procs", cgroup.path_str());
        if std::fs::write(&procs_path, &pid).is_err() {
            eprintln!("SKIP connect4-redirect: cannot write scratch cgroup.procs");
            backend.cleanup_all().ok();
            return;
        }
        let in_cgroup = std::fs::read_to_string(&procs_path)
            .map(|procs| procs.split_whitespace().any(|p| p == pid))
            .unwrap_or(false);
        if !in_cgroup {
            eprintln!(
                "SKIP connect4-redirect: process did not move into the scratch cgroup \
                 (cgroup namespace / delegation on this runner)"
            );
            let _ = std::fs::write(format!("{CGROUP_ROOT}/cgroup.procs"), &pid);
            backend.cleanup_all().ok();
            return;
        }

        // Connect to an unroutable TEST-NET-1 address (RFC 5737). Uncaptured
        // this would time out; captured, connect4 rewrites it to
        // 127.0.0.1:capture_port and it lands on `server`.
        let (connected_tx, connected_rx) = std::sync::mpsc::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let connect_handle =
            std::thread::spawn(move || {
                match std::net::TcpStream::connect_timeout(
                    &"192.0.2.1:1234".parse().unwrap(),
                    Duration::from_secs(3),
                ) {
                    Ok(stream) => {
                        let _ = connected_tx.send(true);
                        let _ = release_rx.recv_timeout(Duration::from_secs(5));
                        drop(stream);
                        true
                    }
                    Err(_) => {
                        let _ = connected_tx.send(false);
                        false
                    }
                }
            });

        let deadline = Instant::now() + Duration::from_secs(5);
        let mut accepted = false;
        let mut accepted_stream = None;
        while Instant::now() < deadline {
            match server.accept() {
                Ok((stream, _)) => {
                    accepted_stream = Some(stream);
                    accepted = true;
                    break;
                }
                Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                    std::thread::sleep(Duration::from_millis(25));
                }
                Err(e) => panic!("capture-port server accept failed: {e}"),
            }
        }
        let connected = connected_rx
            .recv_timeout(Duration::from_secs(1))
            .unwrap_or(false);
        let orig_dst4_records = if connected && accepted {
            read_orig_dst4_records().expect("read orig-dst4 records while captured socket is open")
        } else {
            Vec::new()
        };
        let expected_orig_ip = Ipv4Addr::new(192, 0, 2, 1);
        let matching_orig_dst4 = orig_dst4_records.iter().find(|(_, record)| {
            Ipv4Addr::from(record.addr.to_ne_bytes()) == expected_orig_ip
                && record.port == 1234
                && record.pod_uid == [9u8; 16]
                && record.workload_spiffe_hash == 0x0123_4567_89ab_cdef
        });

        // Capture diagnostics while still in the scratch cgroup (before moving
        // back) so a genuine failure shows the capture port + cgroup membership.
        let self_cgroup = std::fs::read_to_string("/proc/self/cgroup").unwrap_or_default();

        let _ = release_tx.send(());
        drop(accepted_stream);
        let thread_connected = connect_handle.join().unwrap_or(false);

        // Move back to the cgroup root so the scratch cgroup can be removed, and
        // clean up BPF state — before asserting, so a failed assert still tidies.
        let _ = std::fs::write(format!("{CGROUP_ROOT}/cgroup.procs"), &pid);
        backend.cleanup_all().expect("cleanup BPF state");

        assert!(
            connected && thread_connected && accepted,
            "a captured connect() to an unroutable dst must be redirected by connect4 to the local \
             capture port and accepted (connected={connected}, accepted={accepted}, \
             capture_port={capture_port}, self_cgroup={self_cgroup:?})"
        );
        assert!(
            matching_orig_dst4.is_some(),
            "connect4 must stamp the original IPv4 destination and source identity into \
             FERRUM_ORIG_DST4 while the captured socket is alive \
             (expected_ip={expected_orig_ip}, expected_port=1234, expected_pod_uid=09090909..., \
             expected_hash=0x0123456789abcdef, records={orig_dst4_records:?}, \
             capture_port={capture_port}, self_cgroup={self_cgroup:?})"
        );
    }
}
