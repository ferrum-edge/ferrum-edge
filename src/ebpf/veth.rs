#![allow(dead_code)]
//! Host-side veth interface discovery for enrolled pods.
//!
//! When a pod is enrolled for eBPF capture, the node agent attaches a tc
//! classifier to the host-side veth peer. Ownership is resolved only from
//! host-side kernel state keyed by the registry-published pod address: an
//! unambiguous `/32` or `/128` host route whose device is a dedicated host-side
//! peer. Anything a pod can write (its own sysfs view, interface metadata in its
//! network namespace) is never ownership evidence.

#[cfg(target_os = "linux")]
use std::fs::File;
#[cfg(target_os = "linux")]
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(target_os = "linux")]
use std::path::Path;

/// Discover the dedicated host-side interface the node agent attaches the
/// inbound tc guard to.
///
/// IPv4 is tried first, then IPv6, each through the dedicated route resolvers
/// below. The resolved device must also be a dedicated host-side peer (a
/// distinct `iflink`, not a bridge). A subnet route names a shared CNI device
/// such as `cni0` or `cilium_host`; frames forwarded between pods on the same
/// bridge never cross it, so a guard there would fail open for every pod it
/// claims to cover. Such pods resolve to `None` and their enrollment is refused.
pub fn discover_dedicated_veth_for_pod(
    pod_ip: Option<std::net::Ipv4Addr>,
    pod_ip6: Option<std::net::Ipv6Addr>,
) -> Option<String> {
    #[cfg(test)]
    {
        if let Some(name) = tests::test_override() {
            return Some(name);
        }
    }
    #[cfg(target_os = "linux")]
    {
        resolve_dedicated_veth(
            Path::new("/proc/net/route"),
            Path::new("/proc/net/ipv6_route"),
            Path::new("/sys/class/net"),
            pod_ip,
            pod_ip6,
        )
    }

    #[cfg(not(target_os = "linux"))]
    {
        let _ = (pod_ip, pod_ip6);
        None
    }
}

/// Discover a dedicated host-side interface for a local pod IPv4 address.
///
/// Only an unambiguous `/32` host route qualifies. A broader route commonly
/// names a shared CNI bridge, and using that device as a capture boundary
/// would cover (or fail to cover) every attached pod rather than this one.
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
/// an IPv6-only enrolled pod resolve at all: the IPv4 lookup is keyed on an
/// address such a pod does not have, so without this it could only ever be
/// refused.
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
fn resolve_dedicated_veth(
    route_path: &Path,
    route6_path: &Path,
    sysfs_net: &Path,
    pod_ip: Option<Ipv4Addr>,
    pod_ip6: Option<Ipv6Addr>,
) -> Option<String> {
    let ipv4 = pod_ip.and_then(|ip| resolve_dedicated_iface_by_ipv4_route(route_path, ip));
    let ipv6 = || pod_ip6.and_then(|ip| resolve_dedicated_iface_by_ipv6_route(route6_path, ip));
    let name = ipv4.or_else(ipv6)?;
    crate::proxy::host_udp_capture::dedicated_host_ifindex(sysfs_net, &name).ok()?;
    Some(name)
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
fn resolve_dedicated_iface_by_ipv4_route(route_path: &Path, pod_ip: Ipv4Addr) -> Option<String> {
    if pod_ip.is_unspecified() || pod_ip.is_loopback() || pod_ip.is_multicast() {
        return None;
    }
    let routes = read_route_table(route_path)?;
    let ip_raw = u32::from_le_bytes(pod_ip.octets());
    let mut resolved: Option<String> = None;
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
        // Only an `RTF_UP` host route is evidence that this device belongs to
        // this pod. A covering subnet route commonly names a shared CNI bridge.
        if flags & 0x1 == 0 || mask != u32::MAX || ip_raw != destination {
            continue;
        }

        match resolved.as_deref() {
            Some(existing) => ambiguous |= existing != iface,
            None => resolved = Some(iface.to_string()),
        }
    }

    if ambiguous { None } else { resolved }
}

#[cfg(target_os = "linux")]
fn resolve_dedicated_iface_by_ipv6_route(route_path: &Path, pod_ip: Ipv6Addr) -> Option<String> {
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
        // Only a host route is evidence that this device belongs to this pod.
        // A covering subnet route commonly names a shared CNI bridge; using that
        // device as a capture boundary would cover every attached pod, and a tc
        // guard there would miss frames forwarded between them.
        if flags & 0x1 == 0 || prefix_len != 128 {
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
        /// Test-only override consulted by `discover_dedicated_veth_for_pod`
        /// before it reads the host route tables. Set via
        /// [`TestOverrideGuard`] in tests that exercise `handle_pod_added`
        /// (or any other production code that resolves the pod veth) on a
        /// host that has no route to the synthetic pod address (which is
        /// every machine running `cargo test`). The guard restores the
        /// previous value on drop so concurrent tests stay isolated.
        static TEST_VETH_OVERRIDE: RefCell<Option<String>> = const { RefCell::new(None) };
    }

    /// Read the current thread-local override (if any) without taking
    /// ownership. Called from the production path under `#[cfg(test)]`.
    pub(crate) fn test_override() -> Option<String> {
        TEST_VETH_OVERRIDE.with(|cell| cell.borrow().clone())
    }

    /// Drop guard that scopes a test-only veth override to a single test.
    /// Pin one of these on the stack before calling into production code
    /// that may invoke `discover_dedicated_veth_for_pod`; previous value is
    /// restored when the guard drops, so nested overrides still work correctly.
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
    fn discover_dedicated_veth_without_pod_addresses_returns_none() {
        assert!(discover_dedicated_veth_for_pod(None, None).is_none());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn ipv4_route_resolution_requires_a_host_route() {
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
            resolve_dedicated_iface_by_ipv4_route(&route, "10.244.1.5".parse().unwrap()).as_deref(),
            Some("vethpod")
        );
        assert_eq!(
            resolve_dedicated_iface_by_ipv4_route(&route, "10.244.1.9".parse().unwrap()),
            None,
            "a covering bridge route is not per-pod ownership evidence"
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

    /// Host sysfs entry for one interface: `ifindex`, `iflink`, and an optional
    /// `bridge/` directory marking a bridge master.
    #[cfg(target_os = "linux")]
    fn sysfs_iface(sysfs: &Path, name: &str, ifindex: u32, iflink: u32, bridge: bool) {
        let iface = sysfs.join(name);
        std::fs::create_dir_all(&iface).unwrap();
        write(&iface.join("ifindex"), &format!("{ifindex}\n"));
        write(&iface.join("iflink"), &format!("{iflink}\n"));
        if bridge {
            std::fs::create_dir(iface.join("bridge")).unwrap();
        }
    }

    /// A bridge CNI (`cni0`), Cilium's default pod-CIDR route through the shared
    /// `cilium_host` device, a self-linked host device (`dummy0`), and one
    /// dedicated per-pod veth per family.
    #[cfg(target_os = "linux")]
    fn shared_and_dedicated_node(dir: &Path) -> (std::path::PathBuf, std::path::PathBuf) {
        let route = dir.join("route");
        write(
            &route,
            &format!(
                "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                 cni0 {subnet} 00000000 0001 0 0 0 {mask24} 0 0 0\n\
                 cilium_host {cilium} 00000000 0001 0 0 0 {mask24} 0 0 0\n\
                 dummy0 {dummy} 00000000 0001 0 0 0 {host} 0 0 0\n\
                 vethpod {pod} 00000000 0001 0 0 0 {host} 0 0 0\n",
                subnet = route_hex("10.244.1.0"),
                cilium = route_hex("10.244.2.0"),
                dummy = route_hex("10.244.1.7"),
                pod = route_hex("10.244.1.5"),
                mask24 = route_hex("255.255.255.0"),
                host = route_hex("255.255.255.255"),
            ),
        );
        let route6 = dir.join("ipv6_route");
        write(
            &route6,
            &format!(
                "{}\n{}\n",
                route6_line("fd00:0:0:1::", 64, 0x1, "cni0"),
                route6_line("fd00:0:0:1::5", 128, 0x1, "vethpod6"),
            ),
        );
        let sysfs = dir.join("sys-class-net");
        sysfs_iface(&sysfs, "cni0", 3, 3, true);
        // `cilium_host` is one end of a host-local veth pair, so only its
        // subnet route keeps it out; the peer check alone would not.
        sysfs_iface(&sysfs, "cilium_host", 4, 5, false);
        sysfs_iface(&sysfs, "dummy0", 6, 6, false);
        sysfs_iface(&sysfs, "vethpod", 42, 7, false);
        sysfs_iface(&sysfs, "vethpod6", 43, 8, false);
        (route, route6)
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn node_agent_resolver_attaches_only_to_a_dedicated_host_peer() {
        let dir = tempdir().unwrap();
        let (route, route6) = shared_and_dedicated_node(dir.path());
        let sysfs = dir.path().join("sys-class-net");
        let resolve = |v4: Option<&str>, v6: Option<&str>| {
            resolve_dedicated_veth(
                &route,
                &route6,
                &sysfs,
                v4.map(|ip| ip.parse().unwrap()),
                v6.map(|ip| ip.parse().unwrap()),
            )
        };

        assert_eq!(
            resolve(Some("10.244.1.5"), None).as_deref(),
            Some("vethpod")
        );
        assert_eq!(
            resolve(None, Some("fd00:0:0:1::5")).as_deref(),
            Some("vethpod6"),
            "an IPv6-only pod resolves through its /128 host route"
        );
        assert_eq!(
            resolve(Some("10.244.1.9"), None),
            None,
            "a pod covered only by the bridge subnet route must not attach to cni0"
        );
        assert_eq!(
            resolve(Some("10.244.2.5"), None),
            None,
            "a pod behind Cilium's pod-CIDR route must not attach to cilium_host"
        );
        assert_eq!(
            resolve(Some("10.244.1.7"), None),
            None,
            "a /32 to a self-linked device is not a dedicated host peer"
        );
        assert_eq!(
            resolve(None, Some("fd00:0:0:1::9")),
            None,
            "an IPv6 subnet route must not be accepted for the node agent"
        );
        assert_eq!(
            resolve(Some("10.244.1.9"), Some("fd00:0:0:1::5")).as_deref(),
            Some("vethpod6"),
            "a dual-stack pod with only an IPv6 host route still resolves its own veth"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn node_agent_resolver_refuses_a_host_route_to_a_bridge_master() {
        let dir = tempdir().unwrap();
        let route = dir.path().join("route");
        write(
            &route,
            &format!(
                "Iface Destination Gateway Flags RefCnt Use Metric Mask MTU Window IRTT\n\
                 cni0 {pod} 00000000 0001 0 0 0 {host} 0 0 0\n",
                pod = route_hex("10.244.1.5"),
                host = route_hex("255.255.255.255"),
            ),
        );
        let sysfs = dir.path().join("sys-class-net");
        // A bridge master can carry a distinct link index; its `bridge/`
        // directory alone must refuse it.
        sysfs_iface(&sysfs, "cni0", 3, 9, true);

        assert_eq!(
            resolve_dedicated_veth(
                &route,
                &dir.path().join("missing-ipv6-route"),
                &sysfs,
                Some("10.244.1.5".parse().unwrap()),
                None,
            ),
            None
        );
    }

    #[test]
    fn discover_veth_test_override_takes_precedence() {
        let _guard = TestOverrideGuard::new("vethTEST");
        assert_eq!(
            discover_dedicated_veth_for_pod(None, None).as_deref(),
            Some("vethTEST")
        );
        assert_eq!(
            discover_dedicated_veth_for_pod(Some("203.0.113.9".parse().unwrap()), None).as_deref(),
            Some("vethTEST")
        );
    }
}
