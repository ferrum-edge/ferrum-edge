//! cgroup/connect6 — outbound IPv6 traffic capture.
//!
//! Same logic as connect4 but for IPv6. Rewrites destination to [::1]:15001.

use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::programs::SockAddrContext;
use aya_ebpf::EbpfContext;

use crate::maps::{
    FERRUM_BYPASS_UIDS, FERRUM_CAPTURE_CONFIG, FERRUM_CIDR_EXCLUDE6, FERRUM_CIDR_INCLUDE6,
    FERRUM_INCLUDE_PORTS, FERRUM_ORIG_DST6, FERRUM_PORT_EXCLUDE, FERRUM_WORKLOAD_IDENTITY,
};
use ferrum_ebpf_common::{
    host_port_to_sock_addr_user_port, sock_addr_user_port_to_host, CidrKey6, IncludePortsPolicy,
    OrigDst6, OrigDstKey, WorkloadIdentity, FERRUM_CAPTURE_CONFIG_KEY, IPV6_LOOPBACK_NBO,
    OUTBOUND_CAPTURE_PORT,
};

#[cgroup_sock_addr(connect6)]
pub fn ferrum_connect6(ctx: SockAddrContext) -> i32 {
    match try_connect6(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_connect6(ctx: &SockAddrContext) -> Result<i32, i64> {
    let sock_addr = unsafe { &*ctx.sock_addr };

    let uid = (aya_ebpf::helpers::bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    if unsafe { FERRUM_BYPASS_UIDS.get(&uid) }.is_some() {
        return Ok(1);
    }

    // Read the IPv6 destination element-by-element. The cgroup/connect6 ctx
    // (`bpf_sock_addr`) only permits direct scalar field loads at constant
    // offsets; copying `user_ip6` as a whole `[u32; 4]` makes LLVM take the
    // array base (ctx+8) into a register, and the verifier rejects the
    // resulting "modified ctx ptr" dereference. Per-element reads fold the
    // offset into each load (ctx+8/12/16/20), which the verifier accepts.
    let dst_ip = [
        sock_addr.user_ip6[0],
        sock_addr.user_ip6[1],
        sock_addr.user_ip6[2],
        sock_addr.user_ip6[3],
    ];
    // `bpf_sock_addr.user_port`: network-order port in the LOW 16 bits (see
    // connect4 / `sock_addr_user_port_to_host`), NOT the sock_ops high half.
    let dst_port = sock_addr_user_port_to_host(sock_addr.user_port);

    if unsafe { FERRUM_PORT_EXCLUDE.get(&dst_port) }.is_some() {
        return Ok(1);
    }

    let exclude_key = LpmKey::new(128, CidrKey6::host(dst_ip));
    if FERRUM_CIDR_EXCLUDE6.get(&exclude_key).is_some() {
        return Ok(1);
    }

    let include_key = LpmKey::new(128, CidrKey6::host(dst_ip));
    let include_cidr_match = FERRUM_CIDR_INCLUDE6.get(&include_key).is_some();

    // When a pod has explicit includeOutboundPorts entries (non-wildcard),
    // that per-cgroup policy narrows capture and must not be widened by the
    // node-global implicit include CIDR default.
    if !capture_allowed(dst_port, include_cidr_match) {
        return Ok(1);
    }

    // Optional fail-closed valve: when configured, DENY a captured IPv6
    // connection — return 0 so the kernel fails the `connect()` with EPERM —
    // instead of redirecting it. NodeWaypoint keeps this flag clear now that the
    // proxy opens an IPv6 pod-loopback listener; if that listener is not ready,
    // the redirect to [::1]:<port> fails closed by connection refusal.
    if ipv6_outbound_deny() {
        return Ok(0);
    }

    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    let key = OrigDstKey { cookie };
    // Stamp the source pod's identity onto the orig-dst record (see connect4
    // for the rationale). Absent entry → all-zero sentinel = fail-closed.
    let identity = source_workload_identity();
    let orig = OrigDst6 {
        addr: dst_ip,
        port: dst_port as u32,
        _pad: 0,
        pod_uid: identity.pod_uid,
        workload_spiffe_hash: identity.workload_spiffe_hash,
    };
    let _ = FERRUM_ORIG_DST6.insert(&key, &orig, 0);

    let sock_addr = unsafe { &mut *ctx.sock_addr };
    // Per-element store for the same verifier reason as the read above.
    sock_addr.user_ip6[0] = IPV6_LOOPBACK_NBO[0];
    sock_addr.user_ip6[1] = IPV6_LOOPBACK_NBO[1];
    sock_addr.user_ip6[2] = IPV6_LOOPBACK_NBO[2];
    sock_addr.user_ip6[3] = IPV6_LOOPBACK_NBO[3];
    sock_addr.user_port = host_port_to_sock_addr_user_port(outbound_capture_port() as u16);

    Ok(1)
}

/// Look up the source pod's identity for the current cgroup. See the connect4
/// helper for the full rationale; returns the all-zero sentinel when the
/// node-agent has not enrolled this cgroup.
#[inline(always)]
fn source_workload_identity() -> WorkloadIdentity {
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    match unsafe { FERRUM_WORKLOAD_IDENTITY.get(&cgroup_id) } {
        Some(identity) => *identity,
        None => WorkloadIdentity::unknown(),
    }
}

#[inline(always)]
fn outbound_capture_port() -> u32 {
    let key = FERRUM_CAPTURE_CONFIG_KEY;
    match unsafe { FERRUM_CAPTURE_CONFIG.get(&key) } {
        Some(config) if config.outbound_capture_port != 0 => config.outbound_capture_port & 0xffff,
        _ => OUTBOUND_CAPTURE_PORT as u32,
    }
}

/// Whether captured IPv6 egress should fail closed before redirect. Absent
/// config → `false` (redirect as normal), so non-NodeWaypoint capture is
/// unaffected.
#[inline(always)]
fn ipv6_outbound_deny() -> bool {
    let key = FERRUM_CAPTURE_CONFIG_KEY;
    match unsafe { FERRUM_CAPTURE_CONFIG.get(&key) } {
        Some(config) => config.ipv6_outbound_deny != 0,
        None => false,
    }
}

/// Decide whether this connection should be captured for proxying.
///
/// Same semantics as the connect4 helper — see its doc comment for the
/// full precedence rules.
#[inline(always)]
fn capture_allowed(dst_port: u16, include_cidr_match: bool) -> bool {
    let cgroup_id = unsafe { aya_ebpf::helpers::bpf_get_current_cgroup_id() };
    let Some(policy) = (unsafe { FERRUM_INCLUDE_PORTS.get(&cgroup_id) }) else {
        return include_cidr_match;
    };

    if policy.all_ports != 0 {
        return true;
    }

    let count = policy.port_count as usize;
    if count == 0 {
        return include_cidr_match;
    }

    policy_admits_port(policy, dst_port)
}

/// Check whether `dst_port` appears in the policy's explicit port list.
///
/// Callers (`capture_allowed`) must handle `all_ports` and `count == 0`
/// before calling — this function only walks the port array.
#[inline(always)]
fn policy_admits_port(policy: &IncludePortsPolicy, dst_port: u16) -> bool {
    let count = policy.port_count as usize;
    let mut i = 0;
    while i < count && i < policy.ports.len() {
        if policy.ports[i] == dst_port {
            return true;
        }
        i += 1;
    }
    false
}
