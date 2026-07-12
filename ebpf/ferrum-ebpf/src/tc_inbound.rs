//! tc ingress/egress — direct-pod guard for enrolled destination pods.
//!
//! Attached to the host-side veth interface of enrolled pods. Parses each
//! IPv4/IPv6 packet and checks whether the destination IP is enrolled in
//! `FERRUM_POD_IPS` / `FERRUM_POD_IPS6`. Direct TCP connection attempts to
//! enrolled pod IPs are dropped unless they come from an explicitly trusted
//! local-node source and carry the NodeWaypoint relay's authorized socket
//! mark; non-initial TCP packets are allowed so replies for
//! intentionally bypassed outbound flows can return to the pod. Direct UDP is
//! failed closed for NodeWaypoint because there is no authorized relay path yet,
//! except DNS responses from source port 53 to high pod-originated client ports
//! (>=32768).
//! Explicitly configured local node source IPs can only bypass this guard with
//! the relay mark, or for enrolled Kubernetes probe ports without the mark.
//! The same classifier closes Ambient UDP enrollment: pod-IP metadata is
//! inserted with UDP-not-ready before registry publication, so pod-originated
//! UDP is dropped until the per-netns producer publishes readiness after its
//! TPROXY socket and rules are live.

use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use ferrum_ebpf_common::{
    CidrKey6, NodeProbePortKey4, NodeProbePortKey6, FERRUM_CAPTURE_CONFIG_KEY,
};

use crate::maps::{
    FERRUM_CAPTURE_CONFIG, FERRUM_NODE_IPS, FERRUM_NODE_IPS6, FERRUM_NODE_PROBE_PORTS,
    FERRUM_NODE_PROBE_PORTS6, FERRUM_POD_IPS, FERRUM_POD_IPS6,
};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;
const IPPROTO_FRAGMENT: u8 = 44;
const IPPROTO_ESP: u8 = 50;
const IPPROTO_AH: u8 = 51;
const TCP_FLAG_SYN: u8 = 0x02;
const TCP_FLAG_ACK: u8 = 0x10;
const DNS_PORT: u16 = 53;
const MIN_DNS_CLIENT_PORT: u16 = 32768;

#[classifier]
pub fn ferrum_tc_inbound(ctx: TcContext) -> i32 {
    match try_tc_inbound(&ctx) {
        Ok(ret) => ret,
        Err(_) => TC_ACT_OK,
    }
}

#[inline(always)]
fn try_tc_inbound(ctx: &TcContext) -> Result<i32, i64> {
    let eth_type: u16 = ctx.load(12).map_err(|_| -1i64)?;
    match u16::from_be(eth_type) {
        ETH_P_IP => guard_ipv4(ctx),
        ETH_P_IPV6 => guard_ipv6(ctx),
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn guard_ipv4(ctx: &TcContext) -> Result<i32, i64> {
    // Load `protocol` first and keep the pod-source UDP not-ready SHOT check
    // ahead of the `dst` early-return (pod→external UDP must stay droppable
    // during the enrollment window). Defer the `src_ip` load into the UDP arm so
    // the common non-pod-destined TCP packet early-returns after a single
    // `dst_ip` load — as it did before the readiness guard was added — instead
    // of paying an unconditional source-IP load on every classified packet.
    let protocol: u8 = ctx.load(ETH_HDR_LEN + 9).map_err(|_| -1i64)?;
    if protocol == IPPROTO_UDP {
        let src_ip: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?;
        if matches!(
            unsafe { FERRUM_POD_IPS.get(&src_ip) },
            Some(info) if info.udp_capture_not_ready()
        ) {
            return Ok(TC_ACT_SHOT);
        }
    }

    let dst_ip: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?;
    if unsafe { FERRUM_POD_IPS.get(&dst_ip) }.is_none() {
        return Ok(TC_ACT_OK);
    }

    // Reaching here means the destination is enrolled; the source IP is needed
    // for the node-source and authorization checks below on both protocols.
    let src_ip: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?;
    let source_is_node = unsafe { FERRUM_NODE_IPS.get(&src_ip) }.is_some();
    match protocol {
        IPPROTO_TCP => {
            let (dst_port, flags) = match tcp_dst_port_and_flags4(ctx) {
                Ok(parsed) => parsed,
                Err(_) => return guard_enrolled_destination(ctx, source_is_node),
            };
            if source_is_node && node_probe_port4_allowed(dst_ip, dst_port) {
                return Ok(TC_ACT_OK);
            }
            if enrolled_destination_authorized(ctx, source_is_node) {
                return Ok(TC_ACT_PIPE);
            }
            if !tcp_initial_syn(flags) {
                return Ok(TC_ACT_OK);
            }
            guard_enrolled_destination(ctx, source_is_node)
        }
        IPPROTO_UDP => match udp_ports4(ctx) {
            Ok((src_port, dst_port)) if dns_response_allowed(src_port, dst_port) => Ok(TC_ACT_OK),
            _ => drop_unsupported_enrolled_destination(),
        },
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn guard_ipv6(ctx: &TcContext) -> Result<i32, i64> {
    let src_ip = CidrKey6 {
        addr: [
            ctx.load(ETH_HDR_LEN + 8).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 20).map_err(|_| -1i64)?,
        ],
    };
    let next_header: u8 = ctx.load(ETH_HDR_LEN + 6).map_err(|_| -1i64)?;
    // Resolve bounded IPv6 extension chains before applying the source-side
    // UDP readiness gate. Treating any first extension header as UDP would
    // black-hole valid TCP/ICMPv6 with Hop-by-Hop/Routing/Destination Options;
    // a malformed or overlong chain still fails closed for a not-ready source.
    let source_is_udp = match ipv6_transport_protocol(ctx, next_header) {
        Ok(protocol) => protocol == IPPROTO_UDP,
        Err(_) => true,
    };
    if source_is_udp
        && matches!(
            unsafe { FERRUM_POD_IPS6.get(&src_ip) },
            Some(info) if info.udp_capture_not_ready()
        )
    {
        return Ok(TC_ACT_SHOT);
    }

    let dst_ip = CidrKey6 {
        addr: [
            ctx.load(ETH_HDR_LEN + 24).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 28).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 32).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 36).map_err(|_| -1i64)?,
        ],
    };

    if unsafe { FERRUM_POD_IPS6.get(&dst_ip) }.is_none() {
        return Ok(TC_ACT_OK);
    }

    let source_is_node = unsafe { FERRUM_NODE_IPS6.get(&src_ip) }.is_some();
    match next_header {
        IPPROTO_TCP => {
            let (dst_port, flags) = match tcp_dst_port_and_flags6(ctx) {
                Ok(parsed) => parsed,
                Err(_) => return guard_enrolled_destination(ctx, source_is_node),
            };
            if source_is_node && node_probe_port6_allowed(dst_ip.addr, dst_port) {
                return Ok(TC_ACT_OK);
            }
            if enrolled_destination_authorized(ctx, source_is_node) {
                return Ok(TC_ACT_PIPE);
            }
            if !tcp_initial_syn(flags) {
                return Ok(TC_ACT_OK);
            }
            guard_enrolled_destination(ctx, source_is_node)
        }
        IPPROTO_UDP => match udp_ports6(ctx) {
            Ok((src_port, dst_port)) if dns_response_allowed(src_port, dst_port) => Ok(TC_ACT_OK),
            _ => drop_unsupported_enrolled_destination(),
        },
        header if ipv6_extension_header(header) => drop_unsupported_enrolled_destination(),
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn guard_enrolled_destination(ctx: &TcContext, source_is_node: bool) -> Result<i32, i64> {
    let Some(config) = (unsafe { FERRUM_CAPTURE_CONFIG.get(&FERRUM_CAPTURE_CONFIG_KEY) }) else {
        return Ok(TC_ACT_SHOT);
    };
    if config.node_waypoint_inbound_auth_mark == 0 {
        return Ok(TC_ACT_OK);
    }
    if source_is_node && skb_mark(ctx) == config.node_waypoint_inbound_auth_mark {
        return Ok(TC_ACT_PIPE);
    }
    Ok(TC_ACT_SHOT)
}

#[inline(always)]
fn enrolled_destination_authorized(ctx: &TcContext, source_is_node: bool) -> bool {
    if !source_is_node {
        return false;
    }
    let Some(config) = (unsafe { FERRUM_CAPTURE_CONFIG.get(&FERRUM_CAPTURE_CONFIG_KEY) }) else {
        return false;
    };
    config.node_waypoint_inbound_auth_mark != 0
        && skb_mark(ctx) == config.node_waypoint_inbound_auth_mark
}

#[inline(always)]
fn drop_unsupported_enrolled_destination() -> Result<i32, i64> {
    let Some(config) = (unsafe { FERRUM_CAPTURE_CONFIG.get(&FERRUM_CAPTURE_CONFIG_KEY) }) else {
        return Ok(TC_ACT_SHOT);
    };
    if config.node_waypoint_inbound_auth_mark == 0 {
        return Ok(TC_ACT_OK);
    }
    Ok(TC_ACT_SHOT)
}

#[inline(always)]
fn node_probe_port4_allowed(dst_ip: u32, port: u16) -> bool {
    let key = NodeProbePortKey4::new(dst_ip, port);
    unsafe { FERRUM_NODE_PROBE_PORTS.get(&key) }.is_some()
}

#[inline(always)]
fn node_probe_port6_allowed(dst_ip: [u32; 4], port: u16) -> bool {
    let key = NodeProbePortKey6::new(dst_ip, port);
    unsafe { FERRUM_NODE_PROBE_PORTS6.get(&key) }.is_some()
}

#[inline(always)]
fn tcp_dst_port_and_flags4(ctx: &TcContext) -> Result<(u16, u8), i64> {
    let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| -1i64)?;
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Err(-1i64);
    }
    let port: u16 = ctx.load(ETH_HDR_LEN + ihl + 2).map_err(|_| -1i64)?;
    let flags: u8 = ctx.load(ETH_HDR_LEN + ihl + 13).map_err(|_| -1i64)?;
    Ok((u16::from_be(port), flags))
}

#[inline(always)]
fn tcp_dst_port_and_flags6(ctx: &TcContext) -> Result<(u16, u8), i64> {
    let port: u16 = ctx.load(ETH_HDR_LEN + 40 + 2).map_err(|_| -1i64)?;
    let flags: u8 = ctx.load(ETH_HDR_LEN + 40 + 13).map_err(|_| -1i64)?;
    Ok((u16::from_be(port), flags))
}

#[inline(always)]
fn udp_ports4(ctx: &TcContext) -> Result<(u16, u16), i64> {
    let version_ihl: u8 = ctx.load(ETH_HDR_LEN).map_err(|_| -1i64)?;
    let ihl = ((version_ihl & 0x0f) as usize) * 4;
    if ihl < 20 {
        return Err(-1i64);
    }
    let src_port: u16 = ctx.load(ETH_HDR_LEN + ihl).map_err(|_| -1i64)?;
    let dst_port: u16 = ctx.load(ETH_HDR_LEN + ihl + 2).map_err(|_| -1i64)?;
    Ok((u16::from_be(src_port), u16::from_be(dst_port)))
}

#[inline(always)]
fn udp_ports6(ctx: &TcContext) -> Result<(u16, u16), i64> {
    let src_port: u16 = ctx.load(ETH_HDR_LEN + 40).map_err(|_| -1i64)?;
    let dst_port: u16 = ctx.load(ETH_HDR_LEN + 40 + 2).map_err(|_| -1i64)?;
    Ok((u16::from_be(src_port), u16::from_be(dst_port)))
}

#[inline(always)]
fn dns_response_allowed(src_port: u16, dst_port: u16) -> bool {
    src_port == DNS_PORT && dst_port >= MIN_DNS_CLIENT_PORT
}

#[inline(always)]
fn tcp_initial_syn(flags: u8) -> bool {
    flags & TCP_FLAG_SYN != 0 && flags & TCP_FLAG_ACK == 0
}

#[inline(always)]
fn ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140 | 253 | 254
    )
}

/// Resolve the transport protocol behind a bounded IPv6 extension chain.
///
/// Six headers comfortably cover legitimate chains while keeping verifier
/// state bounded. ESP is opaque and is returned as non-UDP; malformed,
/// truncated, or still-extended chains return an error so the readiness caller
/// can fail closed without misclassifying valid extension-header TCP.
#[inline(always)]
fn ipv6_transport_protocol(ctx: &TcContext, first_header: u8) -> Result<u8, i64> {
    let mut protocol = first_header;
    let mut offset = ETH_HDR_LEN + 40;
    let mut parsed = 0u8;
    while parsed < 6 {
        match protocol {
            // Hop-by-Hop, Routing, Destination Options, Mobility, HIP, Shim6,
            // and the two experimental extension-header values share the
            // 8-octet-unit Hdr Ext Len shape.
            0 | 43 | 60 | 135 | 139 | 140 | 253 | 254 => {
                protocol = ctx.load(offset).map_err(|_| -1i64)?;
                let extension_len: u8 = ctx.load(offset + 1).map_err(|_| -1i64)?;
                offset += (extension_len as usize + 1) * 8;
            }
            IPPROTO_FRAGMENT => {
                protocol = ctx.load(offset).map_err(|_| -1i64)?;
                offset += 8;
            }
            IPPROTO_AH => {
                protocol = ctx.load(offset).map_err(|_| -1i64)?;
                let payload_len: u8 = ctx.load(offset + 1).map_err(|_| -1i64)?;
                offset += (payload_len as usize + 2) * 4;
            }
            IPPROTO_ESP => return Ok(IPPROTO_ESP),
            _ => return Ok(protocol),
        }
        parsed += 1;
    }
    if ipv6_extension_header(protocol) {
        Err(-1i64)
    } else {
        Ok(protocol)
    }
}

#[inline(always)]
fn skb_mark(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).mark }
}
