//! cgroup/connect4 — outbound IPv4 traffic capture.
//!
//! Intercepts `connect()` syscalls for IPv4 TCP from enrolled pods:
//! 1. Skip if calling UID is in the bypass set (proxy UID 1337)
//! 2. Skip if destination port is excluded
//! 3. Skip if destination IP matches an exclude CIDR
//! 4. Skip if include CIDRs are configured and destination doesn't match
//! 5. Skip if pod has `includeOutboundPorts` and dest port is NOT in the list
//! 6. Store original destination in `FERRUM_ORIG_DST4` keyed by socket cookie
//! 7. Rewrite destination to 127.0.0.1:15001 (outbound capture port)

use aya_ebpf::macros::cgroup_sock_addr;
use aya_ebpf::maps::lpm_trie::Key as LpmKey;
use aya_ebpf::programs::SockAddrContext;
use aya_ebpf::EbpfContext;

use crate::maps::{
    FERRUM_BYPASS_UIDS, FERRUM_CAPTURE_CONFIG, FERRUM_CIDR_EXCLUDE4, FERRUM_CIDR_INCLUDE4,
    FERRUM_INCLUDE_PORTS, FERRUM_ORIG_DST4, FERRUM_PORT_EXCLUDE,
};
use ferrum_ebpf_common::{
    CidrKey4, IncludePortsPolicy, OrigDst4, OrigDstKey, FERRUM_CAPTURE_CONFIG_KEY,
    IPV4_LOOPBACK_NBO, OUTBOUND_CAPTURE_PORT,
};

#[cgroup_sock_addr(connect4)]
pub fn ferrum_connect4(ctx: SockAddrContext) -> i32 {
    match try_connect4(&ctx) {
        Ok(ret) => ret,
        Err(_) => 1,
    }
}

#[inline(always)]
fn try_connect4(ctx: &SockAddrContext) -> Result<i32, i64> {
    let sock_addr = unsafe { &*ctx.sock_addr };

    let uid = (aya_ebpf::helpers::bpf_get_current_uid_gid() & 0xFFFFFFFF) as u32;
    if unsafe { FERRUM_BYPASS_UIDS.get(&uid) }.is_some() {
        return Ok(1);
    }

    let dst_ip = sock_addr.user_ip4;
    let dst_port = (sock_addr.user_port >> 16) as u16;

    if unsafe { FERRUM_PORT_EXCLUDE.get(&dst_port) }.is_some() {
        return Ok(1);
    }

    let exclude_key = LpmKey::new(32, CidrKey4::host(dst_ip));
    if FERRUM_CIDR_EXCLUDE4.get(&exclude_key).is_some() {
        return Ok(1);
    }

    let include_key = LpmKey::new(32, CidrKey4::host(dst_ip));
    let include_cidr_match = FERRUM_CIDR_INCLUDE4.get(&include_key).is_some();

    // When a pod has explicit includeOutboundPorts entries (non-wildcard),
    // that per-cgroup policy narrows capture and must not be widened by the
    // node-global implicit include CIDR default (0.0.0.0/0).
    if !capture_allowed(dst_port, include_cidr_match) {
        return Ok(1);
    }

    let cookie = unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) };
    let key = OrigDstKey { cookie };
    let orig = OrigDst4 {
        addr: dst_ip,
        port: dst_port as u32,
        pod_uid: [0; 16],
        workload_spiffe_hash: 0,
    };
    let _ = FERRUM_ORIG_DST4.insert(&key, &orig, 0);

    let sock_addr = unsafe { &mut *ctx.sock_addr };
    sock_addr.user_ip4 = IPV4_LOOPBACK_NBO;
    sock_addr.user_port = outbound_capture_port() << 16;

    Ok(1)
}

#[inline(always)]
fn outbound_capture_port() -> u32 {
    let key = FERRUM_CAPTURE_CONFIG_KEY;
    match unsafe { FERRUM_CAPTURE_CONFIG.get(&key) } {
        Some(config) if config.outbound_capture_port != 0 => config.outbound_capture_port & 0xffff,
        _ => OUTBOUND_CAPTURE_PORT as u32,
    }
}

/// Decide whether this connection should be captured for proxying.
///
/// When a per-cgroup `includeOutboundPorts` policy exists with explicit
/// ports, the port list takes precedence over the node-global include CIDR
/// (which typically contains the implicit `0.0.0.0/0`). Without this
/// narrowing, the CIDR match short-circuits port-level restrictions and
/// overcaptures traffic the operator intended to exclude.
///
/// Precedence:
///   1. No per-cgroup policy → fall back to CIDR match (normal path).
///   2. Wildcard policy (`all_ports`) → always capture.
///   3. Empty port list (no wildcard) → fall back to CIDR match.
///   4. Explicit port list → capture only if port matches.
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
