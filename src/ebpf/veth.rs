#![allow(dead_code)]
//! Host-side veth interface discovery for pod network namespaces.
//!
//! When a pod is enrolled for eBPF capture, the node agent attaches a tc
//! classifier to the host-side veth peer. This module resolves the veth
//! interface name from the pod's network namespace.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::os::fd::AsRawFd;
#[cfg(target_os = "linux")]
use std::os::unix::fs::MetadataExt;
#[cfg(target_os = "linux")]
use std::path::Path;

/// Discover the host-side veth interface for a pod by reading the pod-side
/// interface's peer ifindex from the pod's sysfs view, then resolving that
/// ifindex in the host network namespace.
///
/// The values under a pod-visible sysfs mount are workload-controlled and
/// must not be used as proof that a host interface belongs to that pod. Capture
/// ownership callers use the host route-table resolvers below instead.
///
/// When the Kubernetes watch path does not have an explicit process id, the
/// cgroup path is used to find a live process in the pod cgroup tree.
/// Returns `None` if the interface cannot be determined (non-Linux or missing
/// procfs/sysfs entries).
pub fn discover_veth_for_pod(pod_pid: Option<u32>, cgroup_path: Option<&str>) -> Option<String> {
    #[cfg(test)]
    {
        if let Some(name) = tests::test_override() {
            return Some(name);
        }
    }
    #[cfg(target_os = "linux")]
    {
        if let Some(pid) = pod_pid
            && let Some(iface) = discover_veth_linux(pid)
        {
            return Some(iface);
        }

        cgroup_path.and_then(discover_veth_from_cgroup)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pod_pid;
        let _ = cgroup_path;
        None
    }
}

/// Discover the host-side interface that routes to a local pod IP.
///
/// This host-side route lookup is an ownership source for capture callers.
/// Shared routes are acceptable for eBPF because its destination-pod-IP map
/// narrows classification before any packet is attributed.
pub fn discover_veth_for_pod_ip(pod_ip: std::net::Ipv4Addr) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        resolve_iface_by_ipv4_route(Path::new("/proc/net/route"), pod_ip)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pod_ip;
        None
    }
}

/// Discover the host-side interface that routes to a local pod IPv6 address.
///
/// This is the dual-stack counterpart to [`discover_veth_for_pod_ip`]. Unlike
/// the dedicated capture resolver below, eBPF narrows classification with its
/// destination pod-IP map, so a route through a shared CNI bridge is usable.
pub fn discover_veth_for_pod_ip6(pod_ip: std::net::Ipv6Addr) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        resolve_iface_by_ipv6_route(Path::new("/proc/net/ipv6_route"), pod_ip)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pod_ip;
        None
    }
}

/// Discover a dedicated host-side interface for a local pod IPv4 address.
///
/// Unlike [`discover_veth_for_pod_ip`], this is safe to use as an iptables
/// ingress-interface capture boundary: it accepts only an unambiguous `/32`
/// host route. A broader route can legitimately identify a shared CNI bridge
/// for the eBPF caller above, whose pod-IP map narrows classification, but using
/// that bridge in `iptables -i` would capture traffic from every attached pod.
pub fn discover_dedicated_veth_for_pod_ip(pod_ip: std::net::Ipv4Addr) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        resolve_dedicated_iface_by_ipv4_route(Path::new("/proc/net/route"), pod_ip)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pod_ip;
        None
    }
}

/// Discover a dedicated host-side interface for a local pod IPv6 address.
///
/// The IPv6 counterpart of [`discover_dedicated_veth_for_pod_ip`], and what lets
/// an IPv6-only enrolled pod use a deployment that shares neither host `/proc`
/// nor the `setns` privileges: the IPv4 fallback is keyed on an address such a
/// pod does not have, so without this it could only ever be refused.
///
/// `/proc/net/ipv6_route` is parsed strictly and the answer is fail-closed:
/// only an `RTF_UP` `/128` host route participates, and two DIFFERENT devices
/// claiming it resolve to NOTHING rather than to whichever the kernel happened
/// to print first. A broader subnet route through a shared bridge is not
/// per-pod ownership evidence. A guessed interface is exactly the cross-tenant
/// attribution error the consumer of this lookup exists to prevent, so an
/// ambiguous table is treated like an unresolvable one.
pub fn discover_dedicated_veth_for_pod_ip6(pod_ip: std::net::Ipv6Addr) -> Option<String> {
    #[cfg(target_os = "linux")]
    {
        resolve_dedicated_iface_by_ipv6_route(Path::new("/proc/net/ipv6_route"), pod_ip)
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = pod_ip;
        None
    }
}

#[cfg(target_os = "linux")]
fn discover_veth_linux(pid: u32) -> Option<String> {
    let peer = read_pod_peer_indexes_from_proc_root(pid).or_else(|| read_pod_peer_indexes(pid))?;
    resolve_iface_by_peer(peer)
}

#[cfg(target_os = "linux")]
fn discover_veth_from_cgroup(cgroup_path: &str) -> Option<String> {
    let mut dirs = vec![Path::new(cgroup_path).to_path_buf()];
    let mut scanned_dirs = 0usize;

    while let Some(dir) = dirs.pop() {
        scanned_dirs += 1;
        if scanned_dirs > 1024 {
            break;
        }

        if let Ok(procs) = std::fs::read_to_string(dir.join("cgroup.procs")) {
            for pid in procs.split_whitespace().filter_map(|raw| raw.parse().ok()) {
                if let Some(iface) = discover_veth_linux(pid) {
                    return Some(iface);
                }
            }
        }

        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let descend = entry.file_type().map(|t| t.is_dir()).unwrap_or(true);
            if descend {
                dirs.push(entry.path());
            }
        }
    }

    None
}

#[cfg(target_os = "linux")]
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PodPeerIndexes {
    pod_ifindex: u32,
    host_ifindex: u32,
}

#[cfg(target_os = "linux")]
fn read_pod_peer_indexes(pid: u32) -> Option<PodPeerIndexes> {
    std::thread::spawn(move || {
        let _guard = NetnsGuard::enter_pod_netns(pid)?;
        read_pod_peer_indexes_from_net_class(Path::new("/sys/class/net"))
    })
    .join()
    .ok()
    .flatten()
}

#[cfg(target_os = "linux")]
fn read_pod_peer_indexes_from_proc_root(pid: u32) -> Option<PodPeerIndexes> {
    read_pod_peer_indexes_from_proc_root_at(Path::new("/proc"), pid)
}

#[cfg(target_os = "linux")]
fn read_pod_peer_indexes_from_proc_root_at(proc_root: &Path, pid: u32) -> Option<PodPeerIndexes> {
    read_pod_peer_indexes_from_net_class(
        &proc_root.join(pid.to_string()).join("root/sys/class/net"),
    )
}

/// Read the host peer interface index from the pod's network namespace sysfs.
///
/// `/proc/{pid}/net/*` exposes the pod-side interface index, not the host-side
/// veth peer. The pod-side sysfs `iflink` value points at the peer ifindex, so
/// resolve that value against host `/sys/class/net/*/ifindex`.
#[cfg(target_os = "linux")]
fn read_pod_peer_indexes_from_net_class(net_class: &Path) -> Option<PodPeerIndexes> {
    if let Some(peer) = read_peer_indexes_for_iface(&net_class.join("eth0")) {
        return Some(peer);
    }

    for (_, iface_path) in sorted_non_primary_interfaces(net_class)? {
        if let Some(peer) = read_peer_indexes_for_iface(&iface_path) {
            return Some(peer);
        }
    }
    None
}

#[cfg(target_os = "linux")]
fn read_peer_indexes_for_iface(iface_path: &Path) -> Option<PodPeerIndexes> {
    if !iface_path.exists() {
        return None;
    }
    let pod_ifindex = read_u32_from_file(&iface_path.join("ifindex"))?;
    let host_ifindex = read_u32_from_file(&iface_path.join("iflink"))?;
    if pod_ifindex == host_ifindex {
        return None;
    }
    Some(PodPeerIndexes {
        pod_ifindex,
        host_ifindex,
    })
}

#[cfg(target_os = "linux")]
fn sorted_non_primary_interfaces(net_class: &Path) -> Option<Vec<(String, std::path::PathBuf)>> {
    let mut entries = std::fs::read_dir(net_class)
        .ok()?
        .flatten()
        .filter_map(|entry| {
            let iface_name = entry.file_name().to_string_lossy().to_string();
            (iface_name != "lo" && iface_name != "eth0").then_some((iface_name, entry.path()))
        })
        .collect::<Vec<_>>();
    entries.sort_by(|left, right| left.0.cmp(&right.0));
    Some(entries)
}

#[cfg(target_os = "linux")]
fn read_u32_from_file(path: &Path) -> Option<u32> {
    std::fs::read_to_string(path).ok()?.trim().parse().ok()
}

/// Resolve a network interface name by its ifindex from sysfs.
#[cfg(target_os = "linux")]
fn resolve_iface_by_peer(peer: PodPeerIndexes) -> Option<String> {
    resolve_iface_by_peer_in_sysfs(Path::new("/sys/class/net"), peer)
}

#[cfg(target_os = "linux")]
fn resolve_iface_by_peer_in_sysfs(sysfs_net: &Path, peer: PodPeerIndexes) -> Option<String> {
    let entries = std::fs::read_dir(sysfs_net).ok()?;
    let mut ifindex_match = None;
    for entry in entries.flatten() {
        let iface_name = entry.file_name().to_string_lossy().to_string();
        let iface_path = entry.path();
        if read_u32_from_file(&iface_path.join("ifindex")) != Some(peer.host_ifindex) {
            continue;
        }
        if read_u32_from_file(&iface_path.join("iflink")) == Some(peer.pod_ifindex) {
            return Some(iface_name);
        }
        if ifindex_match.is_none() {
            ifindex_match = Some(iface_name);
        }
    }
    ifindex_match
}

/// Upper bound on a kernel route table this module will parse.
///
/// A truncated read cannot be answered safely: the route that was cut off may be
/// the most specific one, and resolving from the remainder could attribute a pod
/// to a broader device (a CNI bridge, or the node uplink). So an oversized table
/// resolves to nothing, which every caller treats as "unresolved" — for the host
/// UDP capture path that means the pod is refused and its egress stays closed.
#[cfg(target_os = "linux")]
const MAX_ROUTE_TABLE_BYTES: usize = 8 * 1024 * 1024;

/// Read a procfs route table under [`MAX_ROUTE_TABLE_BYTES`].
#[cfg(target_os = "linux")]
fn read_route_table(route_path: &Path) -> Option<String> {
    use std::io::Read;

    let file = File::open(route_path).ok()?;
    let mut routes = String::new();
    // One byte over the cap, so a table exactly AT the cap still reads while an
    // oversized one is detectable rather than silently truncated.
    file.take(MAX_ROUTE_TABLE_BYTES as u64 + 1)
        .read_to_string(&mut routes)
        .ok()?;
    (routes.len() <= MAX_ROUTE_TABLE_BYTES).then_some(routes)
}

#[cfg(target_os = "linux")]
fn resolve_iface_by_ipv4_route(route_path: &Path, pod_ip: Ipv4Addr) -> Option<String> {
    resolve_iface_by_ipv4_route_mode(route_path, pod_ip, false)
}

#[cfg(target_os = "linux")]
fn resolve_dedicated_iface_by_ipv4_route(route_path: &Path, pod_ip: Ipv4Addr) -> Option<String> {
    if pod_ip.is_unspecified() || pod_ip.is_loopback() || pod_ip.is_multicast() {
        return None;
    }
    resolve_iface_by_ipv4_route_mode(route_path, pod_ip, true)
}

#[cfg(target_os = "linux")]
fn resolve_iface_by_ipv4_route_mode(
    route_path: &Path,
    pod_ip: Ipv4Addr,
    require_host_route: bool,
) -> Option<String> {
    let routes = read_route_table(route_path)?;
    let ip_raw = u32::from_le_bytes(pod_ip.octets());
    let mut best: Option<(u32, String)> = None;
    let mut ambiguous = false;

    for line in routes.lines().skip(1) {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 8 {
            continue;
        }

        let iface = fields[0];
        if iface == "lo" || iface == "eth0" {
            continue;
        }

        let (Some(destination), Some(flags), Some(mask)) = (
            parse_route_hex_u32(fields[1]),
            parse_route_hex_u32(fields[3]),
            parse_route_hex_u32(fields[7]),
        ) else {
            continue;
        };
        if flags & 0x1 == 0 || mask == 0 || (require_host_route && mask != u32::MAX) {
            continue;
        }
        if ip_raw & mask != destination & mask {
            continue;
        }

        let prefix_len = mask.count_ones();
        if let Some((best_prefix, best_iface)) = best.as_ref() {
            if require_host_route && prefix_len == *best_prefix {
                ambiguous |= best_iface.as_str() != iface;
            }
            if prefix_len <= *best_prefix {
                continue;
            }
        }
        best = Some((prefix_len, iface.to_string()));
        ambiguous = false;
    }

    if ambiguous {
        None
    } else {
        best.map(|(_, iface)| iface)
    }
}

#[cfg(target_os = "linux")]
fn resolve_dedicated_iface_by_ipv6_route(route_path: &Path, pod_ip: Ipv6Addr) -> Option<String> {
    resolve_iface_by_ipv6_route_inner(route_path, pod_ip, true)
}

#[cfg(target_os = "linux")]
fn resolve_iface_by_ipv6_route(route_path: &Path, pod_ip: Ipv6Addr) -> Option<String> {
    resolve_iface_by_ipv6_route_inner(route_path, pod_ip, false)
}

#[cfg(target_os = "linux")]
fn resolve_iface_by_ipv6_route_inner(
    route_path: &Path,
    pod_ip: Ipv6Addr,
    require_host_route: bool,
) -> Option<String> {
    // An unspecified, loopback, or multicast "pod address" names no single pod
    // interface, so it is refused before the table is consulted rather than
    // being allowed to match a broad route.
    if pod_ip.is_unspecified() || pod_ip.is_loopback() || pod_ip.is_multicast() {
        return None;
    }
    let routes = read_route_table(route_path)?;
    let address = pod_ip.octets();
    let mut best: Option<(u32, String)> = None;
    let mut ambiguous = false;

    // `/proc/net/ipv6_route` rows are
    // `dst plen src srcplen nexthop metric refcnt use flags dev`, with every
    // address printed as 32 unseparated hex digits and no header line.
    for line in routes.lines() {
        let fields = line.split_whitespace().collect::<Vec<_>>();
        if fields.len() < 10 {
            continue;
        }

        let iface = fields[9];
        if iface == "lo" || iface == "eth0" {
            continue;
        }

        let (Some(destination), Some(prefix_len), Some(flags)) = (
            parse_route_hex_ipv6(fields[0]),
            parse_route_hex_u32(fields[1]),
            parse_route_hex_u32(fields[8]),
        ) else {
            continue;
        };
        // A covering subnet route may identify a shared CNI bridge. The eBPF
        // caller can use it because its pod-IP map narrows classification;
        // interface-scoped capture requires the dedicated resolver instead.
        if flags & 0x1 == 0
            || prefix_len == 0
            || prefix_len > 128
            || (require_host_route && prefix_len != 128)
        {
            continue;
        }
        if !ipv6_prefix_matches(&destination, &address, prefix_len) {
            continue;
        }

        if let Some((best_prefix, best_iface)) = best.as_ref() {
            if prefix_len < *best_prefix {
                continue;
            }
            if prefix_len == *best_prefix {
                // Two devices claiming the same longest prefix cannot be told
                // apart, and a guessed interface is exactly the cross-tenant
                // attribution error this lookup must not produce. Remember it
                // and refuse at the end rather than taking the first row.
                ambiguous |= best_iface.as_str() != iface;
                continue;
            }
        }
        best = Some((prefix_len, iface.to_string()));
        ambiguous = false;
    }

    if ambiguous {
        return None;
    }
    best.map(|(_, iface)| iface)
}

/// Whether `destination/prefix_len` covers `address`. `prefix_len` is bounded by
/// `128` at the call site, so both indexes below are in range.
#[cfg(target_os = "linux")]
fn ipv6_prefix_matches(destination: &[u8; 16], address: &[u8; 16], prefix_len: u32) -> bool {
    let whole_bytes = (prefix_len / 8) as usize;
    if destination[..whole_bytes] != address[..whole_bytes] {
        return false;
    }
    let remaining_bits = prefix_len % 8;
    if remaining_bits == 0 {
        return true;
    }
    let mask = 0xffu8 << (8 - remaining_bits);
    destination[whole_bytes] & mask == address[whole_bytes] & mask
}

/// Parse one `%pi6`-formatted procfs address: exactly 32 hex digits, no
/// separators. Anything else is rejected rather than partially decoded.
#[cfg(target_os = "linux")]
fn parse_route_hex_ipv6(raw: &str) -> Option<[u8; 16]> {
    if raw.len() != 32 || !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return None;
    }
    let mut octets = [0u8; 16];
    for (index, octet) in octets.iter_mut().enumerate() {
        *octet = u8::from_str_radix(&raw[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(octets)
}

#[cfg(target_os = "linux")]
fn parse_route_hex_u32(raw: &str) -> Option<u32> {
    u32::from_str_radix(raw, 16).ok()
}

#[cfg(target_os = "linux")]
struct NetnsGuard {
    original: File,
}

#[cfg(target_os = "linux")]
impl NetnsGuard {
    fn enter_pod_netns(pid: u32) -> Option<Self> {
        let original = File::open("/proc/self/ns/net").ok()?;
        let target = File::open(format!("/proc/{pid}/ns/net")).ok()?;
        if same_file(&original, &target) {
            return None;
        }
        setns(target.as_raw_fd())?;
        Some(Self { original })
    }
}

#[cfg(target_os = "linux")]
impl Drop for NetnsGuard {
    fn drop(&mut self) {
        let _ = setns(self.original.as_raw_fd());
    }
}

#[cfg(target_os = "linux")]
fn same_file(left: &File, right: &File) -> bool {
    match (left.metadata(), right.metadata()) {
        (Ok(left), Ok(right)) => left.dev() == right.dev() && left.ino() == right.ino(),
        _ => false,
    }
}

#[cfg(target_os = "linux")]
fn setns(fd: std::os::fd::RawFd) -> Option<()> {
    let rc = unsafe { libc::setns(fd, libc::CLONE_NEWNET) };
    (rc == 0).then_some(())
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use std::cell::RefCell;

    #[cfg(target_os = "linux")]
    use tempfile::tempdir;

    #[cfg(target_os = "linux")]
    fn write(path: &Path, value: &str) {
        std::fs::write(path, value).unwrap();
    }

    #[cfg(target_os = "linux")]
    fn route_hex(ip: &str) -> String {
        format!(
            "{:08X}",
            u32::from_le_bytes(ip.parse::<Ipv4Addr>().unwrap().octets())
        )
    }

    thread_local! {
        /// Test-only override consulted by `discover_veth_for_pod` before
        /// it tries procfs/sysfs. Set via [`TestOverrideGuard`] in tests
        /// that exercise `handle_pod_added` (or any other production code
        /// that calls `discover_veth_for_pod`) on a host that does not
        /// have the pod's network namespace materialised (which is every
        /// machine running `cargo test`). The guard restores the previous
        /// value on drop so concurrent tests stay isolated.
        static TEST_VETH_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// Read the current thread-local override (if any) without taking
    /// ownership. Called from the production path under `#[cfg(test)]`.
    pub(crate) fn test_override() -> Option<String> {
        TEST_VETH_OVERRIDE.with(|cell| cell.borrow().clone())
    }

    /// Drop guard that scopes a test-only veth override to a single test.
    /// Pin one of these on the stack before calling into production code
    /// that may invoke `discover_veth_for_pod`; previous value is restored
    /// when the guard drops, so nested overrides still work correctly.
    pub struct TestOverrideGuard {
        previous: Option<String>,
    }

    impl TestOverrideGuard {
        pub fn new(name: &str) -> Self {
            let previous = TEST_VETH_OVERRIDE.with(|cell| {
                let prev = cell.borrow().clone();
                *cell.borrow_mut() = Some(name.to_string());
                prev
            });
            Self { previous }
        }
    }

    impl Drop for TestOverrideGuard {
        fn drop(&mut self) {
            let previous = self.previous.take();
            TEST_VETH_OVERRIDE.with(|cell| {
                *cell.borrow_mut() = previous;
            });
        }
    }

    #[test]
    fn discover_veth_no_pid_returns_none() {
        assert!(discover_veth_for_pod(None, None).is_none());
    }

    #[test]
    fn discover_veth_nonexistent_pid() {
        assert!(discover_veth_for_pod(Some(999_999_999), None).is_none());
    }

    #[test]
    fn discover_veth_nonexistent_cgroup_returns_none() {
        assert!(discover_veth_for_pod(None, Some("/definitely/not/a/cgroup")).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_pod_peer_ifindex_uses_iflink_not_pod_ifindex() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("lo")).unwrap();
        write(&net.join("lo/ifindex"), "1\n");
        write(&net.join("lo/iflink"), "1\n");

        std::fs::create_dir(net.join("eth0")).unwrap();
        write(&net.join("eth0/ifindex"), "7\n");
        write(&net.join("eth0/iflink"), "42\n");

        assert_eq!(
            read_pod_peer_indexes_from_net_class(net),
            Some(PodPeerIndexes {
                pod_ifindex: 7,
                host_ifindex: 42
            })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_pod_peer_ifindex_skips_non_veth_like_self_links() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("eth0")).unwrap();
        write(&net.join("eth0/ifindex"), "7\n");
        write(&net.join("eth0/iflink"), "7\n");

        assert_eq!(read_pod_peer_indexes_from_net_class(net), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_pod_peer_ifindex_prefers_eth0_over_secondary_interfaces() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("net1")).unwrap();
        write(&net.join("net1/ifindex"), "11\n");
        write(&net.join("net1/iflink"), "99\n");

        std::fs::create_dir(net.join("eth0")).unwrap();
        write(&net.join("eth0/ifindex"), "7\n");
        write(&net.join("eth0/iflink"), "42\n");

        assert_eq!(
            read_pod_peer_indexes_from_net_class(net),
            Some(PodPeerIndexes {
                pod_ifindex: 7,
                host_ifindex: 42
            })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn read_pod_peer_ifindex_uses_proc_root_sysfs_view() {
        let dir = tempdir().unwrap();
        let net = dir.path().join("123/root/sys/class/net");
        std::fs::create_dir_all(net.join("eth0")).unwrap();
        write(&net.join("eth0/ifindex"), "7\n");
        write(&net.join("eth0/iflink"), "42\n");

        assert_eq!(
            read_pod_peer_indexes_from_proc_root_at(dir.path(), 123),
            Some(PodPeerIndexes {
                pod_ifindex: 7,
                host_ifindex: 42
            })
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_iface_by_peer_uses_host_ifindex_and_reciprocal_iflink() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("vethabc")).unwrap();
        write(&net.join("vethabc/ifindex"), "42\n");
        write(&net.join("vethabc/iflink"), "7\n");
        std::fs::create_dir(net.join("cni0")).unwrap();
        write(&net.join("cni0/ifindex"), "9\n");
        write(&net.join("cni0/iflink"), "9\n");

        assert_eq!(
            resolve_iface_by_peer_in_sysfs(
                net,
                PodPeerIndexes {
                    pod_ifindex: 7,
                    host_ifindex: 42
                }
            )
            .as_deref(),
            Some("vethabc")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn resolve_iface_by_peer_accepts_unique_host_ifindex_without_reciprocal_iflink() {
        let dir = tempdir().unwrap();
        let net = dir.path();
        std::fs::create_dir(net.join("vethabc")).unwrap();
        write(&net.join("vethabc/ifindex"), "42\n");
        write(&net.join("vethabc/iflink"), "0\n");

        assert_eq!(
            resolve_iface_by_peer_in_sysfs(
                net,
                PodPeerIndexes {
                    pod_ifindex: 7,
                    host_ifindex: 42
                }
            )
            .as_deref(),
            Some("vethabc")
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv4_route_resolution_preserves_ebpf_scope_but_capture_requires_a_host_route() {
        let dir = tempdir().unwrap();
        let route = dir.path().join("route");
        write(
            &route,
            &format!(
                "\
Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT
eth0 {default} 00000000 0001 0 0 0 {default} 0 0 0
vethdown {pod} 00000000 0000 0 0 0 {host} 0 0 0
cni0 {subnet} 00000000 0001 0 0 0 {mask24} 0 0 0
vethpod {pod} 00000000 0001 0 0 0 {host} 0 0 0
badline
vethother {other} 00000000 0001 0 0 0 {host} 0 0 0
",
                default = route_hex("0.0.0.0"),
                pod = route_hex("10.244.1.5"),
                subnet = route_hex("10.244.1.0"),
                other = route_hex("10.244.1.6"),
                mask24 = route_hex("255.255.255.0"),
                host = route_hex("255.255.255.255"),
            ),
        );

        assert_eq!(
            resolve_iface_by_ipv4_route(&route, "10.244.1.5".parse().unwrap()).as_deref(),
            Some("vethpod")
        );
        assert_eq!(
            resolve_iface_by_ipv4_route(&route, "10.244.1.9".parse().unwrap()),
            Some("cni0".to_string()),
            "the eBPF fallback may attach to a covering bridge because its pod-IP map narrows \
             classification"
        );
        assert_eq!(
            resolve_dedicated_iface_by_ipv4_route(&route, "10.244.1.5".parse().unwrap()).as_deref(),
            Some("vethpod")
        );
        assert_eq!(
            resolve_dedicated_iface_by_ipv4_route(&route, "10.244.1.9".parse().unwrap()),
            None,
            "iptables ingress capture must reject the same shared-bridge route"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dedicated_ipv4_route_refuses_two_host_route_claimants() {
        let dir = tempdir().unwrap();
        let route = dir.path().join("route");
        let pod = route_hex("10.244.1.5");
        let host = route_hex("255.255.255.255");
        write(
            &route,
            &format!(
                "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                 vetha {pod} 00000000 0001 0 0 0 {host} 0 0 0\n\
                 vethb {pod} 00000000 0001 0 0 0 {host} 0 0 0\n"
            ),
        );

        assert_eq!(
            resolve_dedicated_iface_by_ipv4_route(&route, "10.244.1.5".parse().unwrap()),
            None,
            "two devices claiming one pod host route must resolve to nothing"
        );
    }

    #[cfg(target_os = "linux")]
    fn route_hex6(ip: &str) -> String {
        ip.parse::<Ipv6Addr>()
            .unwrap()
            .octets()
            .iter()
            .map(|octet| format!("{octet:02x}"))
            .collect()
    }

    /// `/proc/net/ipv6_route` row: `dst plen src srcplen nexthop metric refcnt
    /// use flags dev`.
    #[cfg(target_os = "linux")]
    fn route6_line(destination: &str, prefix_len: u32, flags: u32, iface: &str) -> String {
        let zero = "0".repeat(32);
        format!(
            "{dst} {prefix_len:02x} {zero} 00 {zero} 00000400 00000001 00000000 \
             {flags:08x} {iface}",
            dst = route_hex6(destination),
        )
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dedicated_ipv6_route_uses_only_an_unambiguous_host_route() {
        let dir = tempdir().unwrap();
        let route = dir.path().join("ipv6_route");
        write(
            &route,
            &format!(
                "{}\n{}\n{}\n{}\nbadline\n{}\n",
                // The default route must never win: it matches every pod.
                route6_line("::", 0, 0x1, "eth0"),
                route6_line("fd00:0:0:1::", 64, 0x1, "cni0"),
                // A down route for the same address is skipped.
                route6_line("fd00:0:0:1::5", 128, 0x0, "vethdown"),
                route6_line("fd00:0:0:1::5", 128, 0x1, "vethpod"),
                route6_line("fd00:0:0:1::6", 128, 0x1, "vethother"),
            ),
        );

        assert_eq!(
            resolve_dedicated_iface_by_ipv6_route(&route, "fd00:0:0:1::5".parse().unwrap())
                .as_deref(),
            Some("vethpod"),
            "an IPv6-only pod must resolve to its own host-side interface, not the CNI bridge \
             route that also covers it"
        );
        assert_eq!(
            resolve_dedicated_iface_by_ipv6_route(&route, "fd00:0:0:1::9".parse().unwrap())
                .as_deref(),
            None,
            "a subnet route through a shared bridge is not per-pod interface evidence"
        );
        assert_eq!(
            resolve_dedicated_iface_by_ipv6_route(&route, "fd00:0:0:2::9".parse().unwrap()),
            None,
            "the default route must not be allowed to attribute a pod to the node uplink"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dedicated_ipv6_route_refuses_two_host_route_claimants() {
        let dir = tempdir().unwrap();
        let route = dir.path().join("ipv6_route");
        write(
            &route,
            &format!(
                "{}\n{}\n",
                route6_line("fd00:0:0:1::5", 128, 0x1, "vetha"),
                route6_line("fd00:0:0:1::5", 128, 0x1, "vethb"),
            ),
        );

        assert_eq!(
            resolve_dedicated_iface_by_ipv6_route(&route, "fd00:0:0:1::5".parse().unwrap()),
            None,
            "two devices tying at the longest prefix must resolve to nothing; picking whichever \
             the kernel printed first would attribute the pod to a guessed interface"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dedicated_ipv6_route_rejects_hostile_rows_and_addresses() {
        let dir = tempdir().unwrap();
        let route = dir.path().join("ipv6_route");
        let zero = "0".repeat(32);
        write(
            &route,
            &format!(
                // Short address field, non-hex prefix length, too few columns.
                "dead 80 {zero} 00 {zero} 00000400 00000001 00000000 00000001 vetha\n\
                 {dst} zz {zero} 00 {zero} 00000400 00000001 00000000 00000001 vethb\n\
                 {dst} 80\n\
                 {ok}\n",
                dst = route_hex6("fd00:0:0:1::5"),
                ok = route6_line("fd00:0:0:1::5", 128, 0x1, "vethpod"),
            ),
        );

        assert_eq!(
            resolve_dedicated_iface_by_ipv6_route(&route, "fd00:0:0:1::5".parse().unwrap())
                .as_deref(),
            Some("vethpod"),
            "malformed rows are skipped, never partially decoded into a match"
        );
        for refused in ["::", "::1", "ff02::1"] {
            assert_eq!(
                resolve_dedicated_iface_by_ipv6_route(&route, refused.parse().unwrap()),
                None,
                "{refused} names no single pod interface"
            );
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn route_table_reads_refuse_an_oversized_table() {
        let dir = tempdir().unwrap();
        let route = dir.path().join("ipv6_route");
        let mut oversized = route6_line("fd00:0:0:1::5", 128, 0x1, "vethpod");
        oversized.push('\n');
        oversized.push_str(&"#".repeat(MAX_ROUTE_TABLE_BYTES));
        write(&route, &oversized);

        assert!(
            read_route_table(&route).is_none(),
            "a truncated route table cannot be resolved safely: the row that was cut off may be \
             the most specific one"
        );
        assert_eq!(
            resolve_dedicated_iface_by_ipv6_route(&route, "fd00:0:0:1::5".parse().unwrap()),
            None,
            "so the lookup refuses rather than answering from the readable remainder"
        );
    }

    #[test]
    fn discover_veth_test_override_takes_precedence() {
        let _guard = TestOverrideGuard::new("vethTEST");
        assert_eq!(
            discover_veth_for_pod(None, None).as_deref(),
            Some("vethTEST")
        );
        assert_eq!(
            discover_veth_for_pod(Some(999_999_999), None).as_deref(),
            Some("vethTEST")
        );
    }
}
