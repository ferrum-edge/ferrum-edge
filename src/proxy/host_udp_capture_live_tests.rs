//! Privileged live-kernel gate for Ambient host-network UDP capture (#3705).
//!
//! Exercises the production host-netns TPROXY datapath that
//! [`super::host_udp_capture::ProxyHostUdpBackend`] installs: the exact
//! `IptablesPlan::host_udp_*` scripts, the pktinfo-enabled transparent capture
//! socket, ingress-ifindex attribution, and Ferrum-owned cleanup. Runs under
//! the hosted `ambient-host-udp-live` gate as root with
//! `FERRUM_LIVE_TESTS_REQUIRED=1`, so missing prerequisites fail rather than
//! skip.
//!
//! Topology: one throwaway host-shaped netns (private sysfs) plus two independent
//! workload netns, each linked by its own veth pair with distinct IPv4/IPv6
//! addresses. Capture rules and the shared socket live in the host-shaped
//! namespace — the production placement — while clients send from the workload
//! namespaces.

#![cfg(all(test, target_os = "linux"))]

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::fd::AsRawFd;
use std::path::PathBuf;
use std::process::{Child, Command};
use std::time::{Duration, Instant};

use crate::capture::{
    CaptureConfig, Ip6TablesMode, IptablesPlan, TPROXY_HOST_ROUTE_RULE_PRIORITY,
    TPROXY_HOST_ROUTE_TABLE, UDP_HOST_CAPTURE_CHAIN, UDP_HOST_GUARD_CHAIN_A,
    UDP_HOST_GUARD_CHAIN_B,
};
use crate::identity::spiffe::SpiffeId;
use crate::modes::mesh::hbone::UdpSourceIdentity;
use crate::proxy::host_udp_capture::{
    HostUdpDatagramRefusal, HostUdpIdentityIndex, HostUdpPodBinding, HostUdpRefusal,
    ResolvedInterface, dedicated_host_ifindex, plan_host_udp_bindings,
};
use crate::proxy::mesh_udp_capture::bind_mesh_udp_capture_socket_with_pktinfo;
use crate::proxy::udp_batch::RecvMmsgBatch;

const CAPTURE_PORT: u16 = crate::capture::DEFAULT_UDP_OUTBOUND_PORT;
const REMOTE_V4: Ipv4Addr = Ipv4Addr::new(192, 0, 2, 80);
const REMOTE_V6: Ipv6Addr = Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 0x80);
const DIAL_PORT: u16 = 5300;
const POD_A_V4: Ipv4Addr = Ipv4Addr::new(10, 200, 1, 2);
const POD_B_V4: Ipv4Addr = Ipv4Addr::new(10, 200, 2, 2);
const HOST_A_V4: Ipv4Addr = Ipv4Addr::new(10, 200, 1, 1);
const HOST_B_V4: Ipv4Addr = Ipv4Addr::new(10, 200, 2, 1);
const POD_A_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 2);
const POD_B_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 2, 0, 0, 0, 2);
const HOST_A_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 1, 0, 0, 0, 1);
const HOST_B_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 2, 0, 0, 0, 1);
// Pod C is deliberately UNENROLLED: it gets a netns and a veth pair like the
// others, but its host-side interface is passed to neither the capture ruleset
// nor the identity index.
const POD_C_V4: Ipv4Addr = Ipv4Addr::new(10, 200, 3, 2);
const HOST_C_V4: Ipv4Addr = Ipv4Addr::new(10, 200, 3, 1);
const POD_C_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 3, 0, 0, 0, 2);
const HOST_C_V6: Ipv6Addr = Ipv6Addr::new(0xfd00, 0, 0, 3, 0, 0, 0, 1);
const POD_A_UID: &str = "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa";
const POD_B_UID: &str = "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb";
const DIAG_CAP: usize = 4096;

fn is_root() -> bool {
    // Safety: geteuid is always sound.
    unsafe { libc::geteuid() == 0 }
}

fn live_tests_required() -> bool {
    std::env::var("FERRUM_LIVE_TESTS_REQUIRED")
        .map(|value| value == "1" || value.eq_ignore_ascii_case("true"))
        .unwrap_or(false)
}

fn skip_or_fail(reason: &str) {
    if live_tests_required() {
        panic!("required ambient host-UDP live test prerequisite missing: {reason}");
    }
    eprintln!("SKIP: {reason}");
}

fn redact_diag(raw: &str) -> String {
    // Keep only Ferrum-owned objects, interface indexes, and bind state. Drop
    // anything that looks like a bearer/token/secret fragment.
    let filtered: String = raw
        .lines()
        .filter(|line| {
            let lower = line.to_ascii_lowercase();
            !(lower.contains("token=")
                || lower.contains("secret")
                || lower.contains("bearer")
                || lower.contains("authorization:"))
        })
        .take(80)
        .collect::<Vec<_>>()
        .join("\n");
    filtered.chars().take(DIAG_CAP).collect()
}

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn host_capture_config() -> CaptureConfig {
    let mut config = CaptureConfig::explicit(15006, 15001);
    config.udp_capture_enabled = true;
    config.host_netns = true;
    config.proxy_uid = None;
    config.ip6tables_mode = Ip6TablesMode::Required;
    // Production `host_udp_for_config` emits ip6tables only when a v6 CIDR is
    // configured. The dual-stack live gate must request that scope explicitly —
    // `Required` alone does not synthesize `::/0`.
    config.include_cidrs = vec!["0.0.0.0/0".to_string(), "::/0".to_string()];
    config.include_cidrs_explicit = true;
    config.udp_outbound_port = CAPTURE_PORT;
    config
}

fn identity(uid: &str, sa: &str) -> UdpSourceIdentity {
    let principal = SpiffeId::new(format!("spiffe://cluster.local/ns/ferrum/sa/{sa}"))
        .expect("valid SPIFFE id");
    UdpSourceIdentity::new(principal, uid).expect("valid source identity")
}

fn binding(
    uid: &str,
    sa: &str,
    iface: &str,
    ifindex: u32,
    ipv4: Ipv4Addr,
    ipv6: Ipv6Addr,
) -> HostUdpPodBinding {
    HostUdpPodBinding {
        pod_uid: uid.to_string(),
        iface: iface.to_string(),
        ifindex,
        ipv4: Some(ipv4),
        ipv6: Some(ipv6),
        identity: identity(uid, sa),
    }
}

fn wait_for_sleep_ready(child: &mut Child) -> Result<(), String> {
    let pid = child.id();
    let mut setup_exit = None;
    let mut setup_ready = false;
    for _ in 0..120 {
        std::thread::sleep(Duration::from_millis(50));
        match child.try_wait() {
            Ok(Some(status)) => {
                setup_exit = Some(status);
                break;
            }
            Err(error) => return Err(format!("try_wait errored: {error}")),
            Ok(None) => {
                setup_ready = std::fs::read_to_string(format!("/proc/{pid}/comm"))
                    .is_ok_and(|comm| comm.trim() == "sleep");
                if setup_ready {
                    break;
                }
            }
        }
    }
    if let Some(status) = setup_exit {
        if status.code() == Some(98) {
            return Err(format!(
                "load-bearing host-UDP fixture setup failed (exit 98): {status}"
            ));
        }
        return Err(format!(
            "host-UDP fixture prerequisites unavailable (exit {:?})",
            status.code()
        ));
    }
    if !setup_ready {
        return Err("fixture did not reach sleep readiness marker".to_string());
    }
    Ok(())
}

fn spawn_host_shaped_child() -> Option<Child> {
    let script = "set -e; \
         command -v iptables >/dev/null 2>&1 || exit 97; \
         command -v ip6tables >/dev/null 2>&1 || exit 97; \
         command -v ip >/dev/null 2>&1 || exit 97; \
         command -v mount >/dev/null 2>&1 || exit 97; \
         mount -t sysfs sysfs /sys || exit 98; \
         ip link set lo up || exit 98; \
         printf '1\\n' > /proc/sys/net/ipv4/ip_forward || exit 98; \
         printf '0\\n' > /proc/sys/net/ipv4/conf/all/rp_filter || exit 98; \
         printf '0\\n' > /proc/sys/net/ipv6/conf/all/disable_ipv6 || true; \
         exec sleep 120";
    Command::new("unshare")
        .args([
            "--mount",
            "--net",
            "--propagation",
            "private",
            "sh",
            "-c",
            script,
        ])
        .spawn()
        .ok()
}

fn spawn_pod_child() -> Option<Child> {
    let script = "set -e; command -v ip >/dev/null 2>&1 || exit 97; \
         ip link set lo up 2>/dev/null || true; exec sleep 120";
    Command::new("unshare")
        .args(["--net", "sh", "-c", script])
        .spawn()
        .ok()
}

fn run_checked(cmd: &mut Command) -> Result<(), String> {
    let output = cmd
        .output()
        .map_err(|error| format!("spawn failed: {error}"))?;
    if output.status.success() {
        return Ok(());
    }
    Err(format!(
        "command failed ({:?}): {}",
        output.status.code(),
        redact_diag(&String::from_utf8_lossy(&output.stderr))
    ))
}

fn nsenter_sh(pid: u32, script: &str) -> Result<String, String> {
    let output = Command::new("nsenter")
        .arg(format!("--net=/proc/{pid}/ns/net"))
        .args(["--", "sh", "-c", script])
        .output()
        .map_err(|error| format!("nsenter: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "nsenter script failed ({:?}): {}",
            output.status.code(),
            redact_diag(&String::from_utf8_lossy(&output.stderr))
        ));
    }
    Ok(String::from_utf8_lossy(&output.stdout).into_owned())
}

struct VethPairConfig<'a> {
    host_if: &'a str,
    pod_if: &'a str,
    host_v4: Ipv4Addr,
    pod_v4: Ipv4Addr,
    host_v6: Ipv6Addr,
    pod_v6: Ipv6Addr,
}

fn attach_veth_pair(host_pid: u32, pod_pid: u32, cfg: &VethPairConfig<'_>) -> Result<(), String> {
    let host_if = cfg.host_if;
    let pod_if = cfg.pod_if;
    let host_v4 = cfg.host_v4;
    let pod_v4 = cfg.pod_v4;
    let host_v6 = cfg.host_v6;
    let pod_v6 = cfg.pod_v6;
    let _ = Command::new("ip").args(["link", "del", host_if]).status();
    run_checked(Command::new("ip").args([
        "link", "add", host_if, "type", "veth", "peer", "name", pod_if,
    ]))?;
    run_checked(Command::new("ip").args(["link", "set", host_if, "netns", &host_pid.to_string()]))?;
    run_checked(Command::new("ip").args(["link", "set", pod_if, "netns", &pod_pid.to_string()]))?;

    nsenter_sh(
        host_pid,
        &format!(
            "set -e; \
             ip link set {host_if} up; \
             ip addr add {host_v4}/32 dev {host_if}; \
             ip -6 addr add {host_v6}/128 dev {host_if} nodad; \
             ip route add {pod_v4}/32 dev {host_if}; \
             ip -6 route add {pod_v6}/128 dev {host_if}; \
             printf '0\\n' > /proc/sys/net/ipv4/conf/{host_if}/rp_filter; \
             printf '1\\n' > /proc/sys/net/ipv4/conf/{host_if}/accept_local"
        ),
    )?;

    nsenter_sh(
        pod_pid,
        &format!(
            "set -e; \
             ip link set {pod_if} up; \
             ip addr add {pod_v4}/32 dev {pod_if}; \
             ip -6 addr add {pod_v6}/128 dev {pod_if} nodad; \
             ip route add {host_v4}/32 dev {pod_if}; \
             ip -6 route add {host_v6}/128 dev {pod_if}; \
             ip route add default via {host_v4} dev {pod_if}; \
             ip -6 route add default via {host_v6} dev {pod_if}; \
             ip neigh add {REMOTE_V4} lladdr 02:00:00:00:00:aa dev {pod_if} nud permanent || true; \
             ip -6 neigh add {REMOTE_V6} lladdr 02:00:00:00:00:aa dev {pod_if} nud permanent || true; \
             ip route add {REMOTE_V4}/32 via {host_v4} dev {pod_if}; \
             ip -6 route add {REMOTE_V6}/128 via {host_v6} dev {pod_if}"
        ),
    )?;
    Ok(())
}

fn run_in_netns<T, F>(pid: u32, operation: F) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T, String> + Send + 'static,
{
    std::thread::spawn(move || {
        let ns = std::fs::File::open(format!("/proc/{pid}/ns/net"))
            .map_err(|error| format!("open netns: {error}"))?;
        // Safety: ns is owned by this throwaway thread.
        if unsafe { libc::setns(ns.as_raw_fd(), libc::CLONE_NEWNET) } != 0 {
            return Err(format!("setns failed: {}", std::io::Error::last_os_error()));
        }
        operation()
    })
    .join()
    .map_err(|_| "netns thread panicked".to_string())?
}

fn install_production_host_capture(host_pid: u32, ifaces: &[String]) -> Result<(), String> {
    let config = host_capture_config();
    let guard = IptablesPlan::host_udp_guard_script(&config, ifaces)
        .map_err(|error| format!("guard script: {error}"))?;
    let capture = IptablesPlan::host_udp_setup_script(&config, ifaces)
        .map_err(|error| format!("capture script: {error}"))?;
    let release = IptablesPlan::host_udp_guard_release_script();
    run_in_netns(host_pid, move || {
        for (label, script) in [
            ("guard", guard.as_str()),
            ("capture", capture.as_str()),
            ("release", release.as_str()),
        ] {
            if script.is_empty() {
                continue;
            }
            let output = Command::new("sh")
                .arg("-c")
                .arg(script)
                .output()
                .map_err(|error| format!("{label} spawn: {error}"))?;
            if !output.status.success() {
                return Err(format!(
                    "{label} install failed ({:?}): {}",
                    output.status.code(),
                    redact_diag(&String::from_utf8_lossy(&output.stderr))
                ));
            }
        }
        Ok(())
    })
}

fn teardown_production_host_capture(host_pid: u32) -> Result<(), String> {
    let script = IptablesPlan::host_udp_teardown_script();
    run_in_netns(host_pid, move || {
        let output = Command::new("sh")
            .arg("-c")
            .arg(&script)
            .output()
            .map_err(|error| format!("teardown spawn: {error}"))?;
        if !output.status.success() {
            return Err(format!(
                "teardown failed ({:?}): {}",
                output.status.code(),
                redact_diag(&String::from_utf8_lossy(&output.stderr))
            ));
        }
        Ok(())
    })
}

fn bounded_host_diag(host_pid: u32) -> String {
    let script = format!(
        "echo '=== ip rule ==='; ip rule show | head -n 40; \
         echo '=== ip -6 rule ==='; ip -6 rule show | head -n 40; \
         echo '=== table {TPROXY_HOST_ROUTE_TABLE} ==='; \
         ip route show table {TPROXY_HOST_ROUTE_TABLE} 2>/dev/null | head -n 20; \
         ip -6 route show table {TPROXY_HOST_ROUTE_TABLE} 2>/dev/null | head -n 20; \
         echo '=== Ferrum iptables mangle ==='; \
         iptables-save -t mangle 2>/dev/null | grep -E 'FERRUM_MESH_UDP_HOST|FERRUM_UDP' | head -n 40; \
         echo '=== Ferrum ip6tables mangle ==='; \
         ip6tables-save -t mangle 2>/dev/null | grep -E 'FERRUM_MESH_UDP_HOST|FERRUM_UDP' | head -n 40; \
         echo '=== ifindexes ==='; \
         for i in /sys/class/net/*/ifindex; do echo \"$i=$(cat \"$i\")\"; done | head -n 20; \
         echo '=== udp binds ==='; \
         (cat /proc/net/udp /proc/net/udp6 2>/dev/null || true) | head -n 20"
    );
    match nsenter_sh(host_pid, &script) {
        Ok(out) => redact_diag(&out),
        Err(error) => redact_diag(&error),
    }
}

fn recv_one(
    capture_fd: i32,
    deadline: Instant,
) -> Result<(Vec<u8>, SocketAddr, Option<SocketAddr>, u32), String> {
    let mut batch = RecvMmsgBatch::new(8, true);
    loop {
        match batch.recv(capture_fd, 8) {
            Ok(n) if n > 0 => {
                let (payload, source) = batch.datagram(0);
                let source = crate::util::client_identity::canonical_socket_addr(source);
                let orig = batch
                    .orig_dst(0)
                    .map(crate::util::client_identity::canonical_socket_addr);
                let local = batch
                    .local_addr(0)
                    .ok_or_else(|| "captured datagram carried no IP_PKTINFO".to_string())?;
                return Ok((payload.to_vec(), source, orig, local.ifindex));
            }
            _ if Instant::now() >= deadline => {
                return Err("capture socket received no datagram within the deadline".to_string());
            }
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

/// Drain the capture socket for a bounded window and fail if `needle` appears.
///
/// Absence is the assertion here, so the window must be DRAINED rather than
/// sampled once: a single non-blocking `recv` races the kernel queueing the
/// datagram and would report a false negative for a datagram that really was
/// redirected.
fn assert_not_captured(capture_fd: i32, needle: &[u8], window: Duration) -> Result<(), String> {
    let mut batch = RecvMmsgBatch::new(8, true);
    let deadline = Instant::now() + window;
    loop {
        match batch.recv(capture_fd, 8) {
            Ok(n) if n > 0 => {
                for index in 0..n {
                    let (payload, source) = batch.datagram(index);
                    if payload == needle {
                        return Err(format!(
                            "capture socket received a datagram it must never see (from {source})"
                        ));
                    }
                }
                // Stay bounded even under a steady stream of other datagrams.
                if Instant::now() >= deadline {
                    return Ok(());
                }
            }
            _ if Instant::now() >= deadline => return Ok(()),
            _ => std::thread::sleep(Duration::from_millis(20)),
        }
    }
}

fn send_from_pod(
    pod_pid: u32,
    bind: SocketAddr,
    dst: SocketAddr,
    payload: &'static [u8],
) -> Result<(), String> {
    run_in_netns(pod_pid, move || {
        let socket = std::net::UdpSocket::bind(bind)
            .map_err(|error| format!("bind client {bind}: {error}"))?;
        socket
            .send_to(payload, dst)
            .map_err(|error| format!("send_to {dst}: {error}"))?;
        Ok(())
    })
}

/// Bind a receiver inside `pod_pid`'s netns and wait (bounded) for one datagram.
fn spawn_reply_waiter(
    pod_pid: u32,
    bind: SocketAddr,
) -> std::thread::JoinHandle<Result<(Vec<u8>, SocketAddr), String>> {
    std::thread::spawn(move || {
        run_in_netns(pod_pid, move || {
            let socket = std::net::UdpSocket::bind(bind)
                .map_err(|error| format!("bind reply waiter {bind}: {error}"))?;
            socket
                .set_read_timeout(Some(Duration::from_secs(3)))
                .map_err(|error| format!("timeout: {error}"))?;
            let mut buf = [0u8; 64];
            let (n, from) = socket
                .recv_from(&mut buf)
                .map_err(|error| format!("recv reply: {error}"))?;
            Ok((buf[..n].to_vec(), from))
        })
    })
}

/// Reply from the host netns SOURCED FROM the captured original destination,
/// exactly as the production return path does: a non-locally bound
/// `IP_TRANSPARENT` socket, so the client sees the address it dialed.
fn transparent_reply(
    host_pid: u32,
    captured_destination: SocketAddr,
    client: SocketAddr,
    payload: &'static [u8],
) -> Result<(), String> {
    run_in_netns(host_pid, move || {
        let domain = if captured_destination.is_ipv4() {
            socket2::Domain::IPV4
        } else {
            socket2::Domain::IPV6
        };
        let socket =
            socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))
                .map_err(|error| format!("reply socket: {error}"))?;
        socket
            .set_reuse_address(true)
            .map_err(|error| format!("SO_REUSEADDR: {error}"))?;
        if captured_destination.is_ipv4() {
            crate::socket_opts::set_ip_transparent(socket.as_raw_fd())
                .map_err(|error| format!("IP_TRANSPARENT: {error}"))?;
        } else {
            crate::socket_opts::set_ipv6_transparent(socket.as_raw_fd())
                .map_err(|error| format!("IPV6_TRANSPARENT: {error}"))?;
        }
        socket
            .bind(&captured_destination.into())
            .map_err(|error| format!("non-local bind {captured_destination}: {error}"))?;
        let std_socket: std::net::UdpSocket = socket.into();
        std_socket
            .send_to(payload, client)
            .map_err(|error| format!("reply send: {error}"))?;
        Ok(())
    })
}

fn assert_no_ferrum_host_state(host_pid: u32) -> Result<(), String> {
    let netfilter = nsenter_sh(
        host_pid,
        "iptables-save -t mangle; ip6tables-save -t mangle",
    )?;
    for owned in [
        UDP_HOST_CAPTURE_CHAIN,
        UDP_HOST_GUARD_CHAIN_A,
        UDP_HOST_GUARD_CHAIN_B,
    ] {
        if netfilter.contains(owned) {
            return Err(format!(
                "Ferrum-owned host UDP state still present after teardown ({owned}): {}",
                redact_diag(&netfilter)
            ));
        }
    }

    let policy_rules = nsenter_sh(host_pid, "ip rule show; ip -6 rule show")?;
    let owned_lookup = format!("lookup {TPROXY_HOST_ROUTE_TABLE}");
    if policy_rules.contains(&owned_lookup) {
        return Err(format!(
            "Ferrum-owned host UDP policy rule still present after teardown: {}",
            redact_diag(&policy_rules)
        ));
    }

    let routes = nsenter_sh(
        host_pid,
        &format!(
            "ip route show table {TPROXY_HOST_ROUTE_TABLE} 2>/dev/null; \
             ip -6 route show table {TPROXY_HOST_ROUTE_TABLE} 2>/dev/null"
        ),
    )?;
    if !routes.trim().is_empty() {
        return Err(format!(
            "Ferrum-owned host UDP routes still present after teardown: {}",
            redact_diag(&routes)
        ));
    }
    Ok(())
}

fn install_unrelated_sentinel(host_pid: u32) -> Result<(), String> {
    nsenter_sh(
        host_pid,
        "set -e; \
         iptables -t mangle -N FERRUM_LIVE_UNRELATED; \
         iptables -t mangle -A FERRUM_LIVE_UNRELATED -j RETURN; \
         ip6tables -t mangle -N FERRUM_LIVE_UNRELATED; \
         ip6tables -t mangle -A FERRUM_LIVE_UNRELATED -j RETURN; \
         ip rule add priority 32001 lookup 33134; \
         ip -6 rule add priority 32001 lookup 33134",
    )
    .map(|_| ())
}

fn assert_unrelated_sentinel_present(host_pid: u32) -> Result<(), String> {
    let state = nsenter_sh(
        host_pid,
        "iptables-save -t mangle; ip6tables-save -t mangle; ip rule show; ip -6 rule show",
    )?;
    let chain_mentions = state.matches("FERRUM_LIVE_UNRELATED").count();
    let route_mentions = state.matches("32001:").count();
    if chain_mentions < 4 || route_mentions < 2 {
        return Err(format!(
            "host teardown changed unrelated netfilter/routing state: {}",
            redact_diag(&state)
        ));
    }
    Ok(())
}

struct LiveTopology {
    _host: ChildGuard,
    _pod_a: ChildGuard,
    _pod_b: ChildGuard,
    _pod_c: ChildGuard,
    host_pid: u32,
    pod_a_pid: u32,
    pod_b_pid: u32,
    /// Unenrolled workload: never passed to the capture ruleset or the index.
    pod_c_pid: u32,
    host_sysfs: PathBuf,
    if_a: String,
    if_b: String,
    pod_if_a: String,
    ifindex_a: u32,
    ifindex_b: u32,
    ifindex_c: u32,
}

/// Spawn one netns child and wrap it in a guard as soon as it is ready, so every
/// later failure unwinds through `Drop` instead of a hand-written kill cascade.
fn spawn_ready_pod(label: &str) -> Result<(ChildGuard, u32), String> {
    let mut child = spawn_pod_child().ok_or_else(|| format!("{label} unshare unavailable"))?;
    if let Err(error) = wait_for_sleep_ready(&mut child) {
        let _ = child.kill();
        let _ = child.wait();
        return Err(error);
    }
    let pid = child.id();
    Ok((ChildGuard(child), pid))
}

impl LiveTopology {
    fn create() -> Result<Self, String> {
        let mut host =
            spawn_host_shaped_child().ok_or_else(|| "`unshare` unavailable".to_string())?;
        if let Err(error) = wait_for_sleep_ready(&mut host) {
            let _ = host.kill();
            let _ = host.wait();
            return Err(error);
        }
        let host_pid = host.id();
        let host = ChildGuard(host);

        let (pod_a, pod_a_pid) = spawn_ready_pod("pod A")?;
        let (pod_b, pod_b_pid) = spawn_ready_pod("pod B")?;
        let (pod_c, pod_c_pid) = spawn_ready_pod("pod C")?;

        let suffix = format!("{:x}", std::process::id());
        let suffix = &suffix[suffix.len().saturating_sub(6)..];
        let if_a = format!("ha{suffix}");
        let if_b = format!("hb{suffix}");
        let if_c = format!("hc{suffix}");
        let pod_if_a = format!("pa{suffix}");
        let pod_if_b = format!("pb{suffix}");
        let pod_if_c = format!("pc{suffix}");

        attach_veth_pair(
            host_pid,
            pod_a_pid,
            &VethPairConfig {
                host_if: &if_a,
                pod_if: &pod_if_a,
                host_v4: HOST_A_V4,
                pod_v4: POD_A_V4,
                host_v6: HOST_A_V6,
                pod_v6: POD_A_V6,
            },
        )?;

        // Give node-originated traffic a real output route. Pod egress reaches
        // PREROUTING first and is captured before this route; host traffic uses
        // OUTPUT and must leave without ever reaching the capture socket.
        nsenter_sh(
            host_pid,
            &format!(
                "set -e; ip route add {REMOTE_V4}/32 dev {if_a}; \
                 ip -6 route add {REMOTE_V6}/128 dev {if_a}"
            ),
        )?;
        attach_veth_pair(
            host_pid,
            pod_b_pid,
            &VethPairConfig {
                host_if: &if_b,
                pod_if: &pod_if_b,
                host_v4: HOST_B_V4,
                pod_v4: POD_B_V4,
                host_v6: HOST_B_V6,
                pod_v6: POD_B_V6,
            },
        )?;
        attach_veth_pair(
            host_pid,
            pod_c_pid,
            &VethPairConfig {
                host_if: &if_c,
                pod_if: &pod_if_c,
                host_v4: HOST_C_V4,
                pod_v4: POD_C_V4,
                host_v6: HOST_C_V6,
                pod_v6: POD_C_V6,
            },
        )?;

        let host_sysfs = PathBuf::from(format!("/proc/{host_pid}/root/sys/class/net"));
        let ifindex_a = dedicated_host_ifindex(&host_sysfs, &if_a)
            .map_err(|error| format!("validate {if_a}: {error}"))?;
        let ifindex_b = dedicated_host_ifindex(&host_sysfs, &if_b)
            .map_err(|error| format!("validate {if_b}: {error}"))?;
        let ifindex_c = dedicated_host_ifindex(&host_sysfs, &if_c)
            .map_err(|error| format!("validate {if_c}: {error}"))?;

        Ok(Self {
            _host: host,
            _pod_a: pod_a,
            _pod_b: pod_b,
            _pod_c: pod_c,
            host_pid,
            pod_a_pid,
            pod_b_pid,
            pod_c_pid,
            host_sysfs,
            if_a,
            if_b,
            pod_if_a,
            ifindex_a,
            ifindex_b,
            ifindex_c,
        })
    }
}

fn publish_index(topo: &LiveTopology) -> HostUdpIdentityIndex {
    let index = HostUdpIdentityIndex::new();
    index.publish(&[
        binding(
            POD_A_UID,
            "pod-a",
            &topo.if_a,
            topo.ifindex_a,
            POD_A_V4,
            POD_A_V6,
        ),
        binding(
            POD_B_UID,
            "pod-b",
            &topo.if_b,
            topo.ifindex_b,
            POD_B_V4,
            POD_B_V6,
        ),
    ]);
    index
}

#[test]
#[ignore = "requires root + dual-stack netns + iptables/ip6tables TPROXY + iproute2"]
fn host_udp_live_kernel_multi_pod_dual_stack_attribution_and_replies() {
    if !is_root() {
        skip_or_fail("not root; cannot create host/pod netns or install TPROXY");
        return;
    }
    for binary in [
        "unshare",
        "nsenter",
        "ip",
        "iptables",
        "ip6tables",
        "iptables-save",
        "ip6tables-save",
    ] {
        let present = Command::new("sh")
            .args(["-c", &format!("command -v {binary} >/dev/null 2>&1")])
            .status()
            .is_ok_and(|status| status.success());
        if !present {
            skip_or_fail(&format!("`{binary}` is unavailable"));
            return;
        }
    }

    let topo = match LiveTopology::create() {
        Ok(topo) => topo,
        Err(error) if error.contains("exit 98") || error.contains("load-bearing") => {
            panic!("host-UDP live fixture failed closed on load-bearing setup: {error}");
        }
        Err(error) => {
            skip_or_fail(&error);
            return;
        }
    };

    // Seed unrelated state before production setup so install, restart, and
    // teardown all have to preserve it.
    install_unrelated_sentinel(topo.host_pid).expect("install unrelated cleanup sentinel");

    if let Err(error) =
        install_production_host_capture(topo.host_pid, &[topo.if_a.clone(), topo.if_b.clone()])
    {
        panic!(
            "production host UDP capture install failed: {error}\n{}",
            bounded_host_diag(topo.host_pid)
        );
    }

    let index = publish_index(&topo);
    let host_pid = topo.host_pid;
    let ifindex_a = topo.ifindex_a;
    let ifindex_b = topo.ifindex_b;

    let observed = run_in_netns(host_pid, move || {
        let bind = SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), CAPTURE_PORT);
        let (capture, _, v4_ok, v6_ok) = bind_mesh_udp_capture_socket_with_pktinfo(bind, true)
            .map_err(|error| format!("bind production host capture socket: {error}"))?;
        if !v4_ok || !v6_ok {
            return Err(format!(
                "production socket must enable both orig-dst families (v4={v4_ok} v6={v6_ok})"
            ));
        }
        let fd = capture.as_raw_fd();

        // Keep the socket alive across the send/recv window by returning it.
        Ok((capture, fd))
    });
    let (capture, capture_fd) = match observed {
        Ok(pair) => pair,
        Err(error) => panic!("bind failed: {error}\n{}", bounded_host_diag(host_pid)),
    };
    let _capture = capture;

    // IPv4 from pod A.
    send_from_pod(
        topo.pod_a_pid,
        SocketAddr::new(IpAddr::V4(POD_A_V4), 40001),
        SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT),
        b"host-udp-a4",
    )
    .expect("pod A IPv4 send");
    let (payload, source, orig, ifindex) =
        recv_one(capture_fd, Instant::now() + Duration::from_secs(3)).unwrap_or_else(|error| {
            panic!("{error}\n{}", bounded_host_diag(host_pid));
        });
    assert_eq!(payload, b"host-udp-a4");
    assert_eq!(source.ip(), IpAddr::V4(POD_A_V4));
    assert_eq!(
        orig,
        Some(SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT))
    );
    assert_eq!(ifindex, ifindex_a);
    index
        .authorize(Some(ifindex), source.ip())
        .expect("pod A IPv4 must attribute");
    assert_eq!(
        index
            .identity_for(Some(ifindex), source.ip())
            .expect("pod A identity")
            .pod_uid,
        POD_A_UID
    );

    // IPv6 from pod B.
    send_from_pod(
        topo.pod_b_pid,
        SocketAddr::new(IpAddr::V6(POD_B_V6), 40002),
        SocketAddr::new(IpAddr::V6(REMOTE_V6), DIAL_PORT),
        b"host-udp-b6",
    )
    .expect("pod B IPv6 send");
    let (payload, source, orig, ifindex) =
        recv_one(capture_fd, Instant::now() + Duration::from_secs(3)).unwrap_or_else(|error| {
            panic!("{error}\n{}", bounded_host_diag(host_pid));
        });
    assert_eq!(payload, b"host-udp-b6");
    assert_eq!(source.ip(), IpAddr::V6(POD_B_V6));
    assert_eq!(
        orig,
        Some(SocketAddr::new(IpAddr::V6(REMOTE_V6), DIAL_PORT))
    );
    assert_eq!(ifindex, ifindex_b);
    index
        .authorize(Some(ifindex), source.ip())
        .expect("pod B IPv6 must attribute");
    assert_eq!(
        index
            .identity_for(Some(ifindex), source.ip())
            .expect("pod B identity")
            .pod_uid,
        POD_B_UID
    );

    // IPv6 transparent reply sourced from the captured destination reaches
    // pod B. This separately proves IPV6_TRANSPARENT and the return route; an
    // IPv6 capture-only assertion would not exercise the reply contract.
    let captured_v6_dst = SocketAddr::new(IpAddr::V6(REMOTE_V6), DIAL_PORT);
    let pod_b_reply = SocketAddr::new(IpAddr::V6(POD_B_V6), 43002);
    let waiter = spawn_reply_waiter(topo.pod_b_pid, pod_b_reply);
    std::thread::sleep(Duration::from_millis(100));
    transparent_reply(host_pid, captured_v6_dst, pod_b_reply, b"reply-b6").unwrap_or_else(
        |error| {
            panic!(
                "IPv6 transparent reply failed: {error}\n{}",
                bounded_host_diag(host_pid)
            );
        },
    );
    let got = waiter
        .join()
        .expect("IPv6 reply waiter thread")
        .expect("pod B must receive transparent IPv6 reply");
    assert_eq!(got.0, b"reply-b6");
    assert_eq!(got.1.ip(), IpAddr::V6(REMOTE_V6));

    // Identical 4-tuple isolation by ingress interface: both pods use the same
    // source port and destination, remaining distinct by ifindex.
    send_from_pod(
        topo.pod_a_pid,
        SocketAddr::new(IpAddr::V4(POD_A_V4), 41000),
        SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT),
        b"tuple-a",
    )
    .expect("tuple A");
    let (_, _, _, if_a_seen) =
        recv_one(capture_fd, Instant::now() + Duration::from_secs(3)).expect("tuple A recv");
    send_from_pod(
        topo.pod_b_pid,
        SocketAddr::new(IpAddr::V4(POD_B_V4), 41000),
        SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT),
        b"tuple-b",
    )
    .expect("tuple B");
    let (_, _, _, if_b_seen) =
        recv_one(capture_fd, Instant::now() + Duration::from_secs(3)).expect("tuple B recv");
    assert_eq!(if_a_seen, ifindex_a);
    assert_eq!(if_b_seen, ifindex_b);
    assert_ne!(if_a_seen, if_b_seen);

    // Transparent reply sourced from the captured destination reaches pod A.
    let captured_dst = SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT);
    let pod_a_reply = SocketAddr::new(IpAddr::V4(POD_A_V4), 43001);
    let waiter = spawn_reply_waiter(topo.pod_a_pid, pod_a_reply);
    std::thread::sleep(Duration::from_millis(100));
    transparent_reply(host_pid, captured_dst, pod_a_reply, b"reply-a").unwrap_or_else(|error| {
        panic!(
            "transparent reply failed: {error}\n{}",
            bounded_host_diag(host_pid)
        );
    });
    let got = waiter
        .join()
        .expect("reply waiter thread")
        .expect("pod A must receive transparent reply");
    assert_eq!(got.0, b"reply-a");
    assert_eq!(got.1.ip(), IpAddr::V4(REMOTE_V4));

    // Source spoofing: assign pod B's IPv4 onto pod A and send; ingress ifindex
    // remains A's, so attribution must refuse.
    nsenter_sh(
        topo.pod_a_pid,
        &format!("ip addr add {POD_B_V4}/32 dev {} || true", topo.pod_if_a),
    )
    .expect("assign spoofed source onto pod A");
    send_from_pod(
        topo.pod_a_pid,
        SocketAddr::new(IpAddr::V4(POD_B_V4), 42000),
        SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT),
        b"spoof",
    )
    .expect("spoofed send");
    let (_, spoof_source, _, spoof_ifindex) =
        recv_one(capture_fd, Instant::now() + Duration::from_secs(3)).expect("spoof recv");
    assert_eq!(spoof_ifindex, ifindex_a);
    assert_eq!(spoof_source.ip(), IpAddr::V4(POD_B_V4));
    let refusal = index
        .authorize(Some(spoof_ifindex), spoof_source.ip())
        .expect_err("spoofed source must be refused");
    assert_eq!(refusal, HostUdpDatagramRefusal::SourceAddressMismatch);

    // Missing/zero pktinfo fail closed at the identity boundary.
    assert_eq!(
        index.authorize(None, IpAddr::V4(POD_A_V4)),
        Err(HostUdpDatagramRefusal::NoIngressInterface)
    );
    assert_eq!(
        index.authorize(Some(0), IpAddr::V4(POD_A_V4)),
        Err(HostUdpDatagramRefusal::NoIngressInterface)
    );

    // Unenrolled interface.
    assert_eq!(
        index.authorize(Some(ifindex_a + 1000), IpAddr::V4(POD_A_V4)),
        Err(HostUdpDatagramRefusal::UnenrolledInterface)
    );

    // Ambiguous / shared interface: the planner refuses BOTH claimants rather
    // than first-wins. An empty published index then attributes nothing.
    let shared = ResolvedInterface {
        name: topo.if_a.clone(),
        ifindex: topo.ifindex_a,
    };
    let targets = [
        crate::proxy::netns_capture::PodCaptureTarget {
            pod_uid: POD_A_UID.to_string(),
            cgroup_path: "/sys/fs/cgroup/pod-a".to_string(),
            source_identity: Some(identity(POD_A_UID, "pod-a")),
            source_ips: crate::proxy::netns_capture::PodCaptureSourceIps {
                ipv4: Some(POD_A_V4),
                ipv6: Some(POD_A_V6),
            },
        },
        crate::proxy::netns_capture::PodCaptureTarget {
            pod_uid: POD_B_UID.to_string(),
            cgroup_path: "/sys/fs/cgroup/pod-b".to_string(),
            source_identity: Some(identity(POD_B_UID, "pod-b")),
            source_ips: crate::proxy::netns_capture::PodCaptureSourceIps {
                ipv4: Some(POD_B_V4),
                ipv6: Some(POD_B_V6),
            },
        },
    ];
    let mut resolved = std::collections::HashMap::new();
    resolved.insert(POD_A_UID.to_string(), shared.clone());
    resolved.insert(POD_B_UID.to_string(), shared);
    let planned = plan_host_udp_bindings(&targets, &resolved);
    assert!(
        planned.bindings.is_empty(),
        "shared interface must capture neither pod"
    );
    assert_eq!(planned.refused.len(), 2);
    assert!(
        planned
            .refused
            .iter()
            .all(|(_, reason)| *reason == HostUdpRefusal::AmbiguousInterface)
    );

    // Node-originated / hostNetwork traffic: send from the host-shaped netns
    // itself. No OUTPUT chain exists, so the capture socket must not receive it.
    run_in_netns(host_pid, || {
        let socket = std::net::UdpSocket::bind((HOST_A_V4, 0))
            .map_err(|error| format!("host bind: {error}"))?;
        socket
            .send_to(
                b"node-origin",
                SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT),
            )
            .map_err(|error| format!("host send: {error}"))?;
        Ok(())
    })
    .expect("node-originated control datagram must be sent successfully");
    let absence_window = Duration::from_millis(500);
    if let Err(error) = assert_not_captured(capture_fd, b"node-origin", absence_window) {
        panic!(
            "node-originated traffic must not be captured: {error}\n{}",
            bounded_host_diag(host_pid)
        );
    }

    // Inbound-to-pod: deliver toward the pod address from the host-shaped
    // netns. That traffic leaves via the pod's host-side interface (OUTPUT /
    // forward out) and never matches `PREROUTING -i <pod iface>` for that pod's
    // egress, so it must not land on the capture socket.
    run_in_netns(host_pid, || {
        let socket = std::net::UdpSocket::bind("0.0.0.0:0")
            .map_err(|error| format!("inbound bind: {error}"))?;
        socket
            .send_to(b"inbound-to-pod", SocketAddr::new(IpAddr::V4(POD_A_V4), 9))
            .map_err(|error| format!("inbound send: {error}"))?;
        Ok(())
    })
    .expect("inbound-to-pod control datagram must be sent successfully");
    if let Err(error) = assert_not_captured(capture_fd, b"inbound-to-pod", absence_window) {
        panic!(
            "inbound-to-pod traffic must not be captured on the host UDP path: {error}\n{}",
            bounded_host_diag(host_pid)
        );
    }

    // Unenrolled workload: pod C has a real netns, a real veth pair, and a route
    // to the same remote destination, but its host-side interface is in neither
    // the capture ruleset nor the identity index. Prove BOTH halves executably —
    // the kernel never redirects its egress onto the proxy's capture socket, and
    // the identity boundary refuses to attribute it — rather than asserting the
    // interface-scoping argument in a comment.
    send_from_pod(
        topo.pod_c_pid,
        SocketAddr::new(IpAddr::V4(POD_C_V4), 44001),
        SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT),
        b"unenrolled-c",
    )
    .expect("unenrolled pod C send");
    let unenrolled_window = Duration::from_millis(750);
    if let Err(error) = assert_not_captured(capture_fd, b"unenrolled-c", unenrolled_window) {
        panic!(
            "an unenrolled workload must not be redirected or captured: {error}\n{}",
            bounded_host_diag(host_pid)
        );
    }
    assert_eq!(
        index.authorize(Some(topo.ifindex_c), IpAddr::V4(POD_C_V4)),
        Err(HostUdpDatagramRefusal::UnenrolledInterface),
        "an unenrolled workload must not be attributable"
    );
    assert!(
        index
            .identity_for(Some(topo.ifindex_c), IpAddr::V4(POD_C_V4))
            .is_none(),
        "an unenrolled workload must carry no identity"
    );

    // Restart/reconciliation: tear down, prove nothing Ferrum-owned survives,
    // reinstall, and then prove the DATA PLANE recovered — a fresh captured
    // datagram with exact attribution plus a transparent reply. Lifecycle-only
    // coverage would pass even if reinstall produced rules that divert nothing.
    teardown_production_host_capture(host_pid)
        .unwrap_or_else(|error| panic!("restart teardown: {error}"));
    assert_no_ferrum_host_state(host_pid)
        .unwrap_or_else(|error| panic!("post-restart-teardown: {error}"));
    install_production_host_capture(host_pid, &[topo.if_a.clone(), topo.if_b.clone()])
        .unwrap_or_else(|error| panic!("restart install: {error}"));

    send_from_pod(
        topo.pod_a_pid,
        SocketAddr::new(IpAddr::V4(POD_A_V4), 45001),
        SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT),
        b"post-restart-a4",
    )
    .expect("post-restart pod A send");
    let (payload, source, orig, ifindex) =
        recv_one(capture_fd, Instant::now() + Duration::from_secs(3)).unwrap_or_else(|error| {
            panic!(
                "capture did not recover after reinstall: {error}\n{}",
                bounded_host_diag(host_pid)
            );
        });
    assert_eq!(payload, b"post-restart-a4");
    assert_eq!(source.ip(), IpAddr::V4(POD_A_V4));
    assert_eq!(
        orig,
        Some(SocketAddr::new(IpAddr::V4(REMOTE_V4), DIAL_PORT))
    );
    assert_eq!(ifindex, ifindex_a);
    index
        .authorize(Some(ifindex), source.ip())
        .expect("post-restart pod A must still attribute");

    let pod_a_restart_reply = SocketAddr::new(IpAddr::V4(POD_A_V4), 45001);
    let waiter = spawn_reply_waiter(topo.pod_a_pid, pod_a_restart_reply);
    std::thread::sleep(Duration::from_millis(100));
    transparent_reply(
        host_pid,
        captured_dst,
        pod_a_restart_reply,
        b"post-restart-reply",
    )
    .unwrap_or_else(|error| {
        panic!(
            "post-restart transparent reply failed: {error}\n{}",
            bounded_host_diag(host_pid)
        );
    });
    let recovered = waiter
        .join()
        .expect("post-restart reply waiter thread")
        .expect("pod A must receive the post-restart transparent reply");
    assert_eq!(recovered.0, b"post-restart-reply");
    assert_eq!(recovered.1.ip(), IpAddr::V4(REMOTE_V4));

    // Final exact Ferrum-owned cleanup.
    teardown_production_host_capture(host_pid)
        .unwrap_or_else(|error| panic!("final teardown: {error}\n{}", bounded_host_diag(host_pid)));
    assert_no_ferrum_host_state(host_pid)
        .unwrap_or_else(|error| panic!("{error}\n{}", bounded_host_diag(host_pid)));
    assert_unrelated_sentinel_present(host_pid)
        .unwrap_or_else(|error| panic!("{error}\n{}", bounded_host_diag(host_pid)));

    // Self-linked loopback must still fail the dedicated-peer check through the
    // child's private sysfs.
    assert!(
        dedicated_host_ifindex(&topo.host_sysfs, "lo").is_err(),
        "loopback must not pass the dedicated host-peer validator"
    );
}

#[test]
#[ignore = "requires root + netns + iptables to prove fail-closed prerequisite and partial-install posture"]
fn host_udp_live_kernel_fail_closed_prerequisites_and_partial_install() {
    // Script-contract half of the live gate: these assertions do not need a live
    // netns. Under required mode they still run on every supported runner.
    let config = host_capture_config();
    let setup = IptablesPlan::host_udp_setup_script(&config, &[])
        .expect("empty iface set is a valid no-capture plan");
    assert!(
        setup.contains("command -v ip"),
        "setup must fatally preflight iproute2 before installing jumps"
    );
    assert!(
        setup.contains("ip6tables") && setup.contains("ip -6"),
        "dual-stack Required host capture must emit IPv6 mangle + routing commands: {setup}"
    );
    let jump_pos = setup.find("-A PREROUTING");
    let ip_pos = setup.find("command -v ip");
    if let (Some(ip_pos), Some(jump_pos)) = (ip_pos, jump_pos) {
        assert!(
            ip_pos < jump_pos,
            "ip preflight must precede PREROUTING jumps"
        );
    }

    // Guard-without-capture is the documented partial-install posture: retain
    // DROP rather than a half-live datapath.
    let guard =
        IptablesPlan::host_udp_guard_script(&config, &["vethx".to_string()]).expect("guard script");
    assert!(
        guard.contains("-j DROP") || guard.contains("DROP"),
        "guard must drop enrolled scope during rebuild/partial install"
    );
    assert!(
        guard.contains("ip6tables"),
        "dual-stack Required host guard must cover the IPv6 capture scope: {guard}"
    );
    let capture_teardown = IptablesPlan::host_udp_capture_rules_teardown_script();
    assert!(
        !capture_teardown.contains("GUARD"),
        "capture-rules teardown must leave the DROP guard in place"
    );

    // Stale readiness / manager restart contracts are pinned by the integration
    // suite; this live gate asserts the scripts those restarts invoke never
    // name foreign tables.
    let teardown = IptablesPlan::host_udp_teardown_script();
    for foreign in ["33133", "33134", "table 133", "flush table"] {
        assert!(
            !teardown.contains(foreign),
            "host teardown must not name foreign object {foreign}"
        );
    }
    for owned in [
        UDP_HOST_CAPTURE_CHAIN,
        UDP_HOST_GUARD_CHAIN_A,
        UDP_HOST_GUARD_CHAIN_B,
        &TPROXY_HOST_ROUTE_TABLE.to_string(),
        &TPROXY_HOST_ROUTE_RULE_PRIORITY.to_string(),
    ] {
        assert!(
            teardown.contains(owned),
            "host teardown must address owned object {owned}"
        );
    }
}
