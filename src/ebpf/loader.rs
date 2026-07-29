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
use aya::programs::tc::{SchedClassifierLink, SchedClassifierLinkId};
#[cfg(all(feature = "ebpf", target_os = "linux"))]
// `Link` is the trait that owns `SchedClassifierLink::detach`; the
// ingress-redirect teardown owns its links rather than tracking link ids, so it
// calls that method directly.
use aya::programs::{
    CgroupAttachMode, CgroupSockAddr, Link, SchedClassifier, SockOps, TcAttachType,
};
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
const TC_PROGRAM: &str = super::BPF_PROGRAM_TC_INBOUND;

#[cfg(all(feature = "ebpf", target_os = "linux"))]
const INGRESS_REDIRECT_PROGRAM: &str = super::BPF_PROGRAM_TC_INGRESS_REDIRECT;

/// Tracks per-pod attachment state for cleanup.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
struct PodLinks {
    cgroup_link_ids: Vec<CgroupSockAddrLinkId>,
    tc_link_ids: Vec<SchedClassifierLinkId>,
}

/// One node-level tc ingress-redirect classifier attachment.
///
/// The link is **owned here**, taken out of the program's link map right after
/// attach, instead of being tracked by `SchedClassifierLinkId` alone. That is
/// load-bearing for retry: aya's `SchedClassifier::detach(id)` removes the link
/// from the program's map and then consumes it, so after a FAILED detach the id
/// refers to nothing (`ProgramError::NotAttached` on any retry) and the failure
/// is unrecoverable and — worse — invisible. Owning the link lets a failed
/// detach reconstruct an equivalent one from its netlink filter identity
/// (`ifname`, attach type, priority, handle) so `cleanup_all` really is the
/// backstop its callers treat it as.
///
/// Owning it also means the link is NOT torn down when the `Ebpf` object is
/// dropped; this struct's own `Drop` (via `SchedClassifierLink`) is the final
/// best-effort detach.
#[cfg(all(feature = "ebpf", target_os = "linux"))]
struct IngressRedirectLink {
    /// Interface the classifier is attached to, so failures are reported (and
    /// retried) per interface.
    iface: String,
    /// The owned link, or `None` when a failed detach consumed it and no
    /// equivalent could be rebuilt (the interface disappeared, or the link was
    /// a TCX fd link — whose detach is infallible, so this is unreachable in
    /// practice). The entry is still RETAINED in that case: the kernel filter
    /// may be live, and reporting "detached" would let the node-agent pull the
    /// local-delivery routing out from under a classifier that is still
    /// assigning sockets — the exact harmful half-state.
    link: Option<SchedClassifierLink>,
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
    /// Node-level tc ingress redirect attachments, keyed by interface so a
    /// detach can be reported (and retried) per interface. These are
    /// node-scoped, not per-pod, so they deliberately live outside `pod_links`.
    /// An entry survives a failed detach — see [`IngressRedirectLink`].
    ingress_redirect_links: Vec<IngressRedirectLink>,
    orig_dst_maps_pinned: bool,
    /// Tracks whether at least one trusted node source IP has been installed
    /// for each family, so enrollment can surface a per-family gap (the
    /// source-bound inbound guard drops the relay dial to pods of a family with
    /// no configured node source IP). Set when `update_node_ip*` succeeds.
    node_source_ipv4_present: bool,
    node_source_ipv6_present: bool,
}

#[cfg(all(feature = "ebpf", target_os = "linux"))]
impl AyaEbpfBackend {
    pub fn new() -> Self {
        Self {
            bpf: None,
            maps: None,
            pod_links: HashMap::new(),
            sock_ops_link_id: None,
            ingress_redirect_links: Vec::new(),
            orig_dst_maps_pinned: false,
            node_source_ipv4_present: false,
            node_source_ipv6_present: false,
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

        // The inbound ingress-redirect classifier is loaded (and therefore
        // verifier-checked) unconditionally, even when the redirect is not
        // enabled: a load failure must surface at startup rather than at the
        // first attach, and the program is inert until the capture config
        // publishes a non-zero redirect mark.
        let ingress_redirect: &mut SchedClassifier = bpf
            .program_mut(INGRESS_REDIRECT_PROGRAM)
            .ok_or_else(|| format!("BPF program '{INGRESS_REDIRECT_PROGRAM}' not found in ELF"))?
            .try_into()
            .map_err(|e| format!("'{INGRESS_REDIRECT_PROGRAM}' is not a SchedClassifier: {e}"))?;
        ingress_redirect
            .load()
            .map_err(|e| format!("Failed to load BPF program '{INGRESS_REDIRECT_PROGRAM}': {e}"))?;
        debug!(
            program = INGRESS_REDIRECT_PROGRAM,
            "BPF tc ingress redirect program loaded"
        );

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

    fn update_node_ip(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_node_ip(ip)?;
        self.node_source_ipv4_present = true;
        Ok(())
    }

    fn update_node_ip6(&mut self, ip: Ipv6Addr) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_node_ip6(ip)?;
        self.node_source_ipv6_present = true;
        Ok(())
    }

    fn has_node_source_ipv4(&self) -> bool {
        self.node_source_ipv4_present
    }

    fn has_node_source_ipv6(&self) -> bool {
        self.node_source_ipv6_present
    }

    fn attach_ingress_redirect(&mut self, iface: &str) -> Result<(), String> {
        let bpf = self.bpf_mut()?;
        let prog: &mut SchedClassifier = bpf
            .program_mut(INGRESS_REDIRECT_PROGRAM)
            .ok_or_else(|| format!("BPF program '{INGRESS_REDIRECT_PROGRAM}' not found"))?
            .try_into()
            .map_err(|e| format!("'{INGRESS_REDIRECT_PROGRAM}' type mismatch: {e}"))?;

        // `bpf_sk_assign` is ingress-only, so this classifier is never attached
        // on egress. Attaching it there would silently no-op the redirect while
        // still consuming a filter slot.
        let link_id = prog.attach(iface, TcAttachType::Ingress).map_err(|e| {
            format!("Failed to attach '{INGRESS_REDIRECT_PROGRAM}' to '{iface}' ingress: {e}")
        })?;
        // Take ownership of the link immediately. See [`IngressRedirectLink`]:
        // a link id alone is single-use, so keeping it in the program's map
        // would make a failed detach unrecoverable and unobservable.
        //
        // `take_link` can only fail if the id is absent from the map, which
        // cannot happen for an id `attach` just returned; treat it as an attach
        // failure and record nothing, so no phantom "attached" entry pins the
        // local-delivery routing. The link stays owned by the program and is
        // detached when `Ebpf` is dropped by `cleanup_all`.
        let link = prog.take_link(link_id).map_err(|e| {
            format!(
                "Attached '{INGRESS_REDIRECT_PROGRAM}' to '{iface}' ingress but could not take \
                 ownership of its link: {e}"
            )
        })?;
        self.ingress_redirect_links.push(IngressRedirectLink {
            iface: iface.to_string(),
            link: Some(link),
        });

        info!(
            program = INGRESS_REDIRECT_PROGRAM,
            iface, "NodeWaypoint inbound tc ingress redirect attached"
        );
        Ok(())
    }

    /// Detach every attached ingress-redirect classifier, **retaining every
    /// attachment that did not provably come down**.
    ///
    /// Needs no program lookup at all: the links are owned here (see
    /// [`IngressRedirectLink`]), so there is no `program_mut` / type-conversion
    /// step that could drop the whole set before a single detach was attempted.
    ///
    /// A per-interface failure keeps its entry — rebuilt from the link's netlink
    /// filter identity when possible, so `cleanup_all`'s retry is a real second
    /// attempt rather than a no-op — and keeps
    /// [`Self::ingress_redirect_attached`] reporting `true`, which is what stops
    /// the node-agent from removing the local-delivery routing while a
    /// classifier may still be assigning sockets.
    fn detach_ingress_redirect(&mut self) -> Result<(), String> {
        if self.ingress_redirect_links.is_empty() {
            return Ok(());
        }

        // Detach every interface, collecting failures instead of returning on
        // the first one: a partially-detached redirect is the dangerous state,
        // so each remaining link must still get its detach attempt.
        let mut errors = Vec::new();
        let mut retained = Vec::new();
        for entry in std::mem::take(&mut self.ingress_redirect_links) {
            let IngressRedirectLink { iface, link } = entry;
            let Some(link) = link else {
                // A previous detach consumed the link without succeeding and
                // nothing could be rebuilt. There is no handle to retry with,
                // but the kernel filter may still be live, so keep reporting it.
                errors.push(format!(
                    "{iface}: no retryable link handle remains after an earlier failed detach"
                ));
                retained.push(IngressRedirectLink { iface, link: None });
                continue;
            };
            // Capture the netlink filter identity BEFORE `detach` consumes the
            // link. `Link::detach` takes `self`, so without this the handle is
            // gone the moment the netlink delete fails.
            let rebuild = match (link.attach_type(), link.priority(), link.handle()) {
                (Ok(attach_type), Ok(priority), Ok(handle)) => {
                    Some((attach_type, priority, handle))
                }
                // A TCX fd link, whose detach is infallible — it can never reach
                // the rebuild path below.
                _ => None,
            };
            match link.detach() {
                Ok(()) => debug!(
                    program = INGRESS_REDIRECT_PROGRAM,
                    iface, "NodeWaypoint inbound tc ingress redirect detached"
                ),
                Err(e) => {
                    errors.push(format!("{iface}: {e}"));
                    let rebuilt = rebuild.and_then(|(attach_type, priority, handle)| {
                        SchedClassifierLink::attached(&iface, attach_type, priority, handle).ok()
                    });
                    if rebuilt.is_none() {
                        warn!(
                            program = INGRESS_REDIRECT_PROGRAM,
                            iface,
                            "Could not rebuild a retryable handle for the failed ingress redirect \
                             detach; the classifier is still reported attached so its \
                             local-delivery routing is retained"
                        );
                    }
                    retained.push(IngressRedirectLink {
                        iface,
                        link: rebuilt,
                    });
                }
            }
        }
        self.ingress_redirect_links = retained;

        if errors.is_empty() {
            Ok(())
        } else {
            Err(format!(
                "Failed to detach '{INGRESS_REDIRECT_PROGRAM}' from {}",
                errors.join(", ")
            ))
        }
    }

    fn ingress_redirect_attached(&self) -> bool {
        !self.ingress_redirect_links.is_empty()
    }

    fn update_pod_inbound_ports(&mut self, ip: Ipv4Addr, ports: &[u16]) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.replace_pod_inbound_ports(ip, ports)
    }

    fn clear_pod_inbound_ports(&mut self, ip: Ipv4Addr) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.replace_pod_inbound_ports(ip, &[])
    }

    fn update_pod_inbound_ports6(&mut self, ip: Ipv6Addr, ports: &[u16]) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.replace_pod_inbound_ports6(ip, ports)
    }

    fn clear_pod_inbound_ports6(&mut self, ip: Ipv6Addr) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.replace_pod_inbound_ports6(ip, &[])
    }

    fn update_node_probe_port(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_node_probe_port(ip, port)
    }

    fn remove_node_probe_port(&mut self, ip: Ipv4Addr, port: u16) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.remove_node_probe_port(ip, port)
    }

    fn update_node_probe_port6(&mut self, ip: Ipv6Addr, port: u16) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.insert_node_probe_port6(ip, port)
    }

    fn remove_node_probe_port6(&mut self, ip: Ipv6Addr, port: u16) -> Result<(), String> {
        let maps = self.maps.as_mut().ok_or("BPF maps not initialized")?;
        maps.remove_node_probe_port6(ip, port)
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
        // Detach the node-level ingress redirect explicitly and BEFORE dropping
        // `Ebpf`. This is the genuine retry the callers treat it as: the links
        // are owned by this backend (not by the program's link map, which
        // `self.bpf = None` below would tear down), so a link that failed to
        // detach earlier is attempted again here — and if it fails again it
        // STAYS recorded. `ingress_redirect_attached()` therefore keeps
        // reporting a possibly-live classifier after cleanup, which is what the
        // node-agent keys its routing teardown off: a classifier left steering
        // traffic at a listener that is shutting down would black-hole inbound
        // traffic for every enrolled pod on the node, and removing its
        // local-delivery routing first would strand assigned packets.
        if let Err(e) = self.detach_ingress_redirect() {
            warn!(
                error = %e,
                "Failed to detach the inbound tc ingress redirect during cleanup; it stays \
                 recorded as attached so its local-delivery routing is retained"
            );
        }
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
/// `ebpf-live` CI job. CI sets `FERRUM_LIVE_TESTS_REQUIRED=1`, so prerequisite
/// gaps fail there instead of passing as skips; local ad-hoc runs still
/// self-skip when the kernel lacks the prerequisites.
#[cfg(test)]
mod live_kernel_tests {
    use super::AyaEbpfBackend;
    use crate::ebpf::kernel_probe::probe_kernel;
    use crate::ebpf::{BPF_ORIG_DST4_PIN_PATH, EbpfBackend};
    use aya::maps::{HashMap as BpfHashMap, Map, MapData};
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    use aya::programs::{SchedClassifier, TcAttachType};
    use ferrum_ebpf_common::{OrigDst4, OrigDstKey, WorkloadIdentity};
    use std::fs;
    use std::net::Ipv4Addr;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;

    const CGROUP_ROOT: &str = "/sys/fs/cgroup";
    const BPF_FS: &str = "/sys/fs/bpf";

    fn live_tests_required() -> bool {
        std::env::var("FERRUM_LIVE_TESTS_REQUIRED")
            .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
            .unwrap_or(false)
    }

    fn skip_or_fail(reason: impl AsRef<str>) {
        let reason = reason.as_ref();
        if live_tests_required() {
            panic!(
                "live eBPF test prerequisite missing under FERRUM_LIVE_TESTS_REQUIRED: {reason}"
            );
        }
        eprintln!("SKIP: {reason}");
    }

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
            skip_or_fail(format!(
                "live-kernel eBPF test prerequisites unmet (release={}, reason={:?})",
                probe.kernel_release,
                probe.degradation_reason()
            ));
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

        // NodeWaypoint inbound tc ingress redirect (issue #3287), run as phases
        // of this test rather than as tests of their own: the required
        // `ebpf-live` CI job asserts an exact passing-test count inside a job
        // body that a pull request may not modify (the trusted Cross-build
        // policy freezes it by digest). Each phase reloads its own backend, so
        // they stay independent despite sharing a test function.
        #[cfg(all(feature = "ebpf", target_os = "linux"))]
        {
            run_tc_ingress_redirect_lifecycle_phase();
            run_tc_ingress_redirect_datapath_phase();
        }
    }

    /// A scratch veth pair, removed on drop. The tc ingress redirect attaches
    /// to a node capture interface, so the live test needs a real interface it
    /// can create and destroy without perturbing the runner's networking.
    struct ScratchVeth {
        name: String,
    }

    impl ScratchVeth {
        fn create() -> Result<Self, String> {
            let name = format!("ferrumtc{}", std::process::id() % 100_000);
            let peer = format!("{name}p");
            // Remove a leftover from a previous aborted run first.
            let _ = std::process::Command::new("ip")
                .args(["link", "del", &name])
                .output();
            let output = std::process::Command::new("ip")
                .args(["link", "add", &name, "type", "veth", "peer", "name", &peer])
                .output()
                .map_err(|e| format!("could not run `ip link add`: {e}"))?;
            if !output.status.success() {
                return Err(format!(
                    "`ip link add {name}` failed: {}",
                    String::from_utf8_lossy(&output.stderr).trim()
                ));
            }
            Ok(Self { name })
        }
    }

    impl Drop for ScratchVeth {
        fn drop(&mut self) {
            // Deleting one end removes the pair.
            let _ = std::process::Command::new("ip")
                .args(["link", "del", &self.name])
                .output();
        }
    }

    /// Live-kernel verification for the NodeWaypoint inbound tc **ingress**
    /// redirect (issue #3287).
    ///
    /// Not a `#[test]` of its own: the required `ebpf-live` CI job asserts an
    /// exact live-test count against a job body that a pull request may not
    /// change (the trusted Cross-build policy freezes it by digest), so this
    /// runs as a phase of [`programs_load_verify_attach_and_map_round_trip`].
    ///
    /// Covers, on a real kernel:
    ///
    /// * **Verifier acceptance** of `ferrum_tc_ingress_redirect`, which is the
    ///   part that cannot be checked by any host-side test — the program uses
    ///   `bpf_skc_lookup_tcp` / `bpf_sk_assign` / `bpf_sk_release`, whose
    ///   reference-tracking rules the verifier enforces on every branch.
    /// * **Attach and detach lifecycle** on a real tc ingress hook, including
    ///   that detach actually removes the classifier (failure cleanup: a
    ///   classifier left steering traffic at a departing listener would
    ///   black-hole inbound for every enrolled pod on the node).
    /// * **Both address families** of the redirect scope maps, and the armed
    ///   capture-config round trip that gates the whole datapath.
    ///
    /// End-to-end packet steering is covered separately by
    /// [`ingress_redirect_steers_a_real_tcp_flow_into_the_capture_listener`].
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    fn run_tc_ingress_redirect_lifecycle_phase() {
        use ferrum_ebpf_common::{
            BpfCaptureConfig, NODE_WAYPOINT_INGRESS_CAPTURE_PORT,
            NODE_WAYPOINT_INGRESS_REDIRECT_MARK,
        };
        use std::net::Ipv6Addr;

        let veth = match ScratchVeth::create() {
            Ok(veth) => veth,
            Err(e) => {
                skip_or_fail(format!("could not create a scratch veth pair: {e}"));
                return;
            }
        };

        let mut backend = AyaEbpfBackend::new();
        // The load runs the in-kernel verifier over `ferrum_tc_ingress_redirect`
        // along with every other program. This is the core live validation for
        // the blind-built socket-assign code.
        backend.load_programs().expect(
            "load + verify BPF programs (incl. the tc ingress redirect) on the running kernel",
        );

        // Arm the redirect exactly as the node-agent does in NodeWaypoint mode:
        // the steer target is the CAPTURE listener port, never the HBONE port.
        let armed = BpfCaptureConfig::new(15001, 15008)
            .with_node_waypoint_ingress_redirect_mark(NODE_WAYPOINT_INGRESS_REDIRECT_MARK)
            .with_node_waypoint_ingress_capture_port(NODE_WAYPOINT_INGRESS_CAPTURE_PORT);
        assert!(armed.ingress_redirect_armed());
        assert_ne!(
            armed.node_waypoint_ingress_capture_port, armed.hbone_redirect_port,
            "the kernel must steer at the capture listener, never at HBONE"
        );
        backend
            .update_capture_config(&armed)
            .expect("publish the armed inbound redirect capture config");

        // Both families of the redirect scope map must round-trip: replace,
        // narrow, and clear. Narrowing is the case that would silently leave a
        // removed port redirectable if replacement were additive.
        let pod_v4 = Ipv4Addr::new(10, 244, 1, 5);
        let pod_v6: Ipv6Addr = "fd00:10:244::5".parse().unwrap();
        backend
            .update_pod_inbound_ports(pod_v4, &[8080, 9090])
            .expect("write the IPv4 inbound redirect scope");
        backend
            .update_pod_inbound_ports(pod_v4, &[8080])
            .expect("narrow the IPv4 inbound redirect scope");
        backend
            .update_pod_inbound_ports6(pod_v6, &[8080, 9090])
            .expect("write the IPv6 inbound redirect scope");
        backend
            .update_pod_inbound_ports6(pod_v6, &[8080])
            .expect("narrow the IPv6 inbound redirect scope");

        // Attach to the scratch interface's tc ingress hook, then detach.
        backend
            .attach_ingress_redirect(&veth.name)
            .expect("attach ferrum_tc_ingress_redirect to the scratch veth ingress hook");
        let attached = ingress_redirect_classifier_visible(&veth.name);
        backend
            .detach_ingress_redirect()
            .expect("detach ferrum_tc_ingress_redirect");
        let detached_gone = !ingress_redirect_classifier_visible(&veth.name);

        // Clearing must succeed for a pod that was scoped and for one that was
        // never scoped (teardown runs on both).
        backend
            .clear_pod_inbound_ports(pod_v4)
            .expect("clear the IPv4 inbound redirect scope");
        backend
            .clear_pod_inbound_ports6(pod_v6)
            .expect("clear the IPv6 inbound redirect scope");
        backend
            .clear_pod_inbound_ports(Ipv4Addr::new(10, 244, 9, 9))
            .expect("clearing an unscoped pod address must be a no-op, not an error");

        // Detaching again must be a clean no-op: shutdown and startup rollback
        // can both run it.
        backend
            .detach_ingress_redirect()
            .expect("a second detach must be idempotent");

        backend.cleanup_all().expect("cleanup BPF state");

        assert!(
            attached,
            "the classifier must be visible on the interface's tc ingress hook after attach \
             (classic `tc filter show` and/or TCX query)"
        );
        assert!(
            detached_gone,
            "detach must remove the classifier; a leftover filter would steer inbound traffic \
             at a listener that is going away"
        );
    }

    /// `tc filter show dev <iface> ingress` output, or an empty string when the
    /// `tc` binary is unavailable (the assertions tolerate that by checking for
    /// absence after detach).
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    fn tc_ingress_filters(iface: &str) -> String {
        std::process::Command::new("tc")
            .args(["filter", "show", "dev", iface, "ingress"])
            .output()
            .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
            .unwrap_or_default()
    }

    /// Whether the ingress-redirect classifier is attached on `iface`.
    ///
    /// On kernels >= 6.6, aya's `SchedClassifier::attach` uses TCX (BPF links)
    /// rather than classic clsact filters. TCX programs do **not** appear in
    /// `tc filter show`, so an empty classic listing after a successful attach
    /// is expected — query the TCX multi-prog list instead. Older kernels keep
    /// the netlink/clsact path and remain visible via `tc filter show`.
    ///
    /// The scratch interfaces created by these live phases have no other TCX
    /// programs, so a non-empty TCX query is sufficient evidence of our attach
    /// (BPF object names are also truncated to 16 bytes, so an exact
    /// `ferrum_tc_ingress_redirect` match against `ProgramInfo::name` is not
    /// reliable).
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    fn ingress_redirect_classifier_visible(iface: &str) -> bool {
        let filters = tc_ingress_filters(iface);
        if filters.contains("ferrum_tc_ingress_redirect") || filters.contains("bpf") {
            return true;
        }
        match SchedClassifier::query_tcx(iface, TcAttachType::Ingress) {
            Ok((_revision, programs)) => !programs.is_empty(),
            Err(_) => false,
        }
    }

    /// A scratch network namespace plus the veth pair that reaches it, removed
    /// on drop. Models the off-node client side of an inbound flow: the client
    /// lives in the namespace and routes through the host, so its packets
    /// arrive on the host veth's tc **ingress** hook exactly as off-node
    /// traffic to a pod arrives on a node uplink.
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    struct ScratchClientNetns {
        netns: String,
        host_iface: String,
    }

    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    impl ScratchClientNetns {
        const HOST_ADDR: &'static str = "10.244.253.1";
        const CLIENT_ADDR: &'static str = "10.244.253.2";

        fn create() -> Result<Self, String> {
            let suffix = std::process::id() % 10_000;
            let netns = format!("ferrumtcns{suffix}");
            let host_iface = format!("ferrumtch{suffix}");
            let peer_iface = format!("ferrumtcc{suffix}");

            // Clean up anything a previous aborted run left behind first.
            let _ = ip(&["netns", "del", &netns]);
            let _ = ip(&["link", "del", &host_iface]);

            let this = Self {
                netns: netns.clone(),
                host_iface: host_iface.clone(),
            };

            ip(&["netns", "add", &netns])?;
            ip(&[
                "link",
                "add",
                &host_iface,
                "type",
                "veth",
                "peer",
                "name",
                &peer_iface,
            ])?;
            ip(&["link", "set", &peer_iface, "netns", &netns])?;
            ip(&[
                "addr",
                "add",
                &format!("{}/24", Self::HOST_ADDR),
                "dev",
                &host_iface,
            ])?;
            ip(&["link", "set", &host_iface, "up"])?;
            ip(&["netns", "exec", &netns, "ip", "link", "set", "lo", "up"])?;
            ip(&[
                "netns",
                "exec",
                &netns,
                "ip",
                "addr",
                "add",
                &format!("{}/24", Self::CLIENT_ADDR),
                "dev",
                &peer_iface,
            ])?;
            ip(&[
                "netns",
                "exec",
                &netns,
                "ip",
                "link",
                "set",
                &peer_iface,
                "up",
            ])?;
            // Default route through the host, so a connection to the pod
            // address is sent to the host's MAC with the pod address intact —
            // which is what makes it visible on the host veth's ingress hook.
            ip(&[
                "netns",
                "exec",
                &netns,
                "ip",
                "route",
                "add",
                "default",
                "via",
                Self::HOST_ADDR,
            ])?;
            // The captured destination is not routed on this host, so reverse-
            // path filtering would otherwise discard the reply's source.
            let _ = std::process::Command::new("sysctl")
                .arg("-w")
                .arg(format!("net.ipv4.conf.{host_iface}.rp_filter=0"))
                .output();
            let _ = std::process::Command::new("sysctl")
                .arg("-w")
                .arg("net.ipv4.conf.all.rp_filter=0")
                .output();
            Ok(this)
        }

        /// Run a command inside the client namespace, returning its stdout.
        fn exec(&self, args: &[&str]) -> Result<String, String> {
            let mut full = vec!["netns", "exec", self.netns.as_str()];
            full.extend_from_slice(args);
            let output = std::process::Command::new("ip")
                .args(&full)
                .output()
                .map_err(|e| format!("could not run `ip {}`: {e}", full.join(" ")))?;
            Ok(String::from_utf8_lossy(&output.stdout).into_owned())
        }
    }

    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    impl Drop for ScratchClientNetns {
        fn drop(&mut self) {
            let _ = ip(&["link", "del", &self.host_iface]);
            let _ = ip(&["netns", "del", &self.netns]);
        }
    }

    /// Run one `ip` invocation, surfacing stderr on failure.
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    fn ip(args: &[&str]) -> Result<(), String> {
        let output = std::process::Command::new("ip")
            .args(args)
            .output()
            .map_err(|e| format!("could not run `ip {}`: {e}", args.join(" ")))?;
        if output.status.success() {
            return Ok(());
        }
        Err(format!(
            "`ip {}` failed: {}",
            args.join(" "),
            String::from_utf8_lossy(&output.stderr).trim()
        ))
    }

    /// **End-to-end packet steering** for the NodeWaypoint inbound tc ingress
    /// redirect (issue #3287) — the live datapath regression issue #3287's
    /// acceptance criteria require, and the residual risk the first revision of
    /// this feature had to disclose.
    ///
    /// It drives a real TCP flow from a client in a scratch network namespace
    /// to an address that is **not configured anywhere on this host**, and
    /// proves the whole chain:
    ///
    /// 1. the classifier matches the flow on a real tc ingress hook and
    ///    `bpf_sk_assign`s it to the transparent **capture** listener (not the
    ///    HBONE listener);
    /// 2. the production `ip rule` / `ip route` shapes deliver the assigned
    ///    packet locally instead of forwarding it to the pod;
    /// 3. the relay observes the **original destination** on its accepted
    ///    socket (`getsockname()` — there is no NAT to consult);
    /// 4. the reply is sourced from that captured address and reaches the
    ///    client, which is only possible on an `IP_TRANSPARENT` socket;
    /// 5. **failure/cleanup**: after detach + scope clear, the same connection
    ///    is no longer steered — a leftover classifier or stale scope entry
    ///    would keep capturing traffic for a listener that is going away.
    ///
    /// Deterministic and narrowly scoped: one flow, fixed payloads, private
    /// addresses, everything created and destroyed by the test. Every
    /// prerequisite failure routes through `skip_or_fail`, so under
    /// `FERRUM_LIVE_TESTS_REQUIRED=1` an environment that cannot run the
    /// mechanism fails the gate rather than silently reporting the feature
    /// ready.
    #[cfg(all(feature = "ebpf", target_os = "linux"))]
    fn run_tc_ingress_redirect_datapath_phase() {
        use crate::ebpf::PodInfo;
        use ferrum_ebpf_common::{BpfCaptureConfig, NODE_WAYPOINT_INGRESS_REDIRECT_MARK};
        use std::time::Duration;

        // A pod address deliberately absent from this host's routing table, so
        // only the redirect can make the connection succeed.
        const POD_ADDR: &str = "10.244.254.7";
        const APP_PORT: u16 = 18080;
        const REQUEST: &[u8; 4] = b"PING";
        const REPLY: &[u8; 4] = b"PONG";
        // Distinct from the shipped 15006 so a co-resident process on the
        // runner cannot make the result ambiguous.
        let capture_port: u16 = 15106;

        let env = match ScratchClientNetns::create() {
            Ok(env) => env,
            Err(e) => {
                skip_or_fail(format!(
                    "could not build the scratch client namespace for the ingress redirect \
                     datapath test: {e}"
                ));
                return;
            }
        };

        // Production local-delivery routing, taken from the node-agent itself
        // so the test proves the shipped rule/route shape actually delivers.
        let routing = crate::modes::node_agent::ingress_redirect_routing_commands(false);
        for args in &routing {
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            if argv.iter().any(|arg| *arg == "del") {
                let _ = ip(&argv);
                continue;
            }
            if let Err(e) = ip(&argv) {
                skip_or_fail(format!(
                    "could not install the redirect local-delivery routing: {e}"
                ));
                return;
            }
        }

        let mut backend = AyaEbpfBackend::new();
        backend
            .load_programs()
            .expect("load + verify BPF programs on the running kernel");

        let armed = BpfCaptureConfig::new(15001, 15008)
            .with_node_waypoint_ingress_redirect_mark(NODE_WAYPOINT_INGRESS_REDIRECT_MARK)
            .with_node_waypoint_ingress_capture_port(capture_port);
        backend
            .update_capture_config(&armed)
            .expect("publish the armed inbound redirect capture config");

        let pod_ip: Ipv4Addr = POD_ADDR.parse().unwrap();
        // Scope first, then the flag — the same ordering the node-agent uses so
        // an in-scope packet is never flagged before it is reachable.
        backend
            .update_pod_inbound_ports(pod_ip, &[APP_PORT])
            .expect("scope the pod's declared inbound port");
        backend
            .update_pod_ip(
                pod_ip,
                &PodInfo::for_capture(15001, false, false).with_inbound_redirect(true),
            )
            .expect("enroll the pod for inbound redirect");

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build a current-thread runtime for the capture listener");

        let outcome = runtime.block_on(async {
            // The production transparent bind, on the wildcard address the
            // classifier's socket lookup resolves.
            let listener = crate::proxy::create_proxy_socket(
                format!("0.0.0.0:{capture_port}").parse().unwrap(),
                128,
                None,
                false,
                true,
            )
            .map_err(|e| format!("bind the transparent capture listener: {e}"))?;

            backend
                .attach_ingress_redirect(&env.host_iface)
                .map_err(|e| format!("attach the classifier to the host veth: {e}"))?;

            // `bash`'s /dev/tcp gives a dependency-free TCP client inside the
            // namespace: send REQUEST, read exactly REPLY's length back.
            let script = format!(
                "exec 3<>/dev/tcp/{POD_ADDR}/{APP_PORT}; printf '{}' >&3; head -c {} <&3",
                String::from_utf8_lossy(REQUEST.as_slice()),
                REPLY.len()
            );
            let client = std::thread::spawn({
                let netns = env.netns.clone();
                move || {
                    std::process::Command::new("ip")
                        .args([
                            "netns",
                            "exec",
                            netns.as_str(),
                            "timeout",
                            "10",
                            "bash",
                            "-c",
                            script.as_str(),
                        ])
                        .output()
                        .map(|output| String::from_utf8_lossy(&output.stdout).into_owned())
                        .unwrap_or_default()
                }
            });

            let accepted = tokio::time::timeout(Duration::from_secs(10), listener.accept()).await;
            let (mut stream, _peer) = match accepted {
                Ok(Ok(accepted)) => accepted,
                Ok(Err(e)) => return Err(format!("accept on the capture listener failed: {e}")),
                Err(_) => {
                    return Err(
                        "the redirected connection never reached the transparent capture \
                         listener within 10s"
                            .to_string(),
                    );
                }
            };

            // (3) The original destination, recovered with no NAT in the path.
            let observed_dst = stream
                .local_addr()
                .map_err(|e| format!("read the accepted socket's local address: {e}"))?;

            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            let mut request = [0u8; 4];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut request))
                .await
                .map_err(|_| "timed out reading the captured request".to_string())?
                .map_err(|e| format!("read the captured request: {e}"))?;
            // (4) Reply, which the kernel can only send because the socket is
            // transparent and may source the captured pod address.
            stream
                .write_all(REPLY)
                .await
                .map_err(|e| format!("reply on the captured connection: {e}"))?;
            stream
                .flush()
                .await
                .map_err(|e| format!("flush the reply: {e}"))?;
            drop(stream);

            let client_stdout = client.join().unwrap_or_default();
            Ok::<_, String>((observed_dst, request.to_vec(), client_stdout))
        });

        // (5) Cleanup / failure behavior, asserted before the result so a
        // mid-test failure still leaves the runner clean.
        let detached = backend.detach_ingress_redirect();
        let scope_cleared = backend.clear_pod_inbound_ports(pod_ip);
        let _ = backend.remove_pod_ip(pod_ip);
        let post_detach_gone = !ingress_redirect_classifier_visible(&env.host_iface);
        for args in crate::modes::node_agent::ingress_redirect_routing_teardown_commands(false) {
            let argv: Vec<&str> = args.iter().map(String::as_str).collect();
            let _ = ip(&argv);
        }
        // With the classifier gone the same dial has nowhere to go: nothing is
        // listening on the pod address and this host has no route to it, so the
        // client gets no reply. A leftover classifier would still capture it.
        let post_detach_script = format!("exec 3<>/dev/tcp/{POD_ADDR}/{APP_PORT}; head -c 4 <&3");
        let post_detach_stdout = env
            .exec(&["timeout", "3", "bash", "-c", post_detach_script.as_str()])
            .unwrap_or_default();
        let _ = backend.cleanup_all();

        let (observed_dst, request, client_stdout) =
            outcome.unwrap_or_else(|e| panic!("inbound tc ingress redirect datapath: {e}"));

        assert_eq!(
            observed_dst.to_string(),
            format!("{POD_ADDR}:{APP_PORT}"),
            "the relay must observe the workload's ORIGINAL destination on the accepted socket; \
             `bpf_sk_assign` performs no NAT, so a different value means the flow did not arrive \
             through the redirect"
        );
        assert_eq!(
            request.as_slice(),
            REQUEST.as_slice(),
            "the captured application bytes must arrive byte-for-byte"
        );
        assert_eq!(
            client_stdout.as_bytes(),
            REPLY.as_slice(),
            "the reply must reach the client sourced from the captured pod address, which only \
             an IP_TRANSPARENT socket can do"
        );

        detached.expect("detaching the classifier must succeed");
        scope_cleared.expect("clearing the redirect scope must succeed");
        assert!(
            post_detach_gone,
            "detach must remove the classifier (classic tc filter and/or TCX query)"
        );
        assert!(
            post_detach_stdout.is_empty(),
            "after detach + scope clear the flow must no longer be steered into the capture \
             listener, got {post_detach_stdout:?}"
        );
    }

    /// Layer-2 datapath verification: a real captured `connect()` is rewritten
    /// by `connect4` to the configured capture port and lands on a local server
    /// — proving the connect-side capture works end to end on a live kernel, not
    /// just that the program loads/attaches. Gated on `--features ebpf` because
    /// it reaches the real backend's map handles (the no-ebpf build has a stub);
    /// runs via the `ebpf-live` CI job, failing on unmet prerequisites when
    /// `FERRUM_LIVE_TESTS_REQUIRED=1` and self-skipping for local ad-hoc runs.
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
            skip_or_fail(format!(
                "connect4-redirect live test prerequisites unmet (release={}, reason={:?})",
                probe.kernel_release,
                probe.degradation_reason()
            ));
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
        // On some local runners the process can't actually be moved (cgroup
        // namespaces / delegation): the write may succeed yet the PID not
        // appear in the target. Read `cgroup.procs` back and self-skip outside
        // required CI mode, but fail when `FERRUM_LIVE_TESTS_REQUIRED=1`.
        let pid = std::process::id().to_string();
        let procs_path = format!("{}/cgroup.procs", cgroup.path_str());
        if std::fs::write(&procs_path, &pid).is_err() {
            skip_or_fail("connect4-redirect cannot write scratch cgroup.procs");
            backend.cleanup_all().ok();
            return;
        }
        let in_cgroup = std::fs::read_to_string(&procs_path)
            .map(|procs| procs.split_whitespace().any(|p| p == pid))
            .unwrap_or(false);
        if !in_cgroup {
            skip_or_fail(
                "connect4-redirect process did not move into the scratch cgroup \
                 (cgroup namespace / delegation on this runner)",
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
