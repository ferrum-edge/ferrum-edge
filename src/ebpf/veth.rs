#![allow(dead_code)]
//! Host-side veth interface discovery for pod network namespaces.
//!
//! When a pod is enrolled for eBPF capture, the node agent attaches a tc/ingress
//! program to the host-side veth peer to redirect inbound packets. This module
//! resolves the veth interface name from the pod's network namespace.

#[cfg(target_os = "linux")]
use std::fs::File;
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
