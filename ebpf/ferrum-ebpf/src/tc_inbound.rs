//! tc ingress/egress — direct-pod guard for enrolled destination pods.
//!
//! Attached to the host-side veth interface of enrolled pods. Parses each
//! IPv4/IPv6 packet and checks whether the destination IP is enrolled in
//! `FERRUM_POD_IPS` / `FERRUM_POD_IPS6`. Direct TCP traffic to enrolled pod IPs
//! is dropped unless it carries the NodeWaypoint relay's authorized socket mark;
//! direct UDP is failed closed for NodeWaypoint because there is no authorized
//! relay path yet. Local node source IPs are exempt so kubelet probes remain
//! reachable.

use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_PIPE, TC_ACT_SHOT};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;
use ferrum_ebpf_common::{CidrKey6, FERRUM_CAPTURE_CONFIG_KEY};

use crate::maps::{
    FERRUM_CAPTURE_CONFIG, FERRUM_NODE_IPS, FERRUM_NODE_IPS6, FERRUM_POD_IPS, FERRUM_POD_IPS6,
};

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const ETH_P_IPV6: u16 = 0x86DD;
const IPPROTO_TCP: u8 = 6;
const IPPROTO_UDP: u8 = 17;

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
    let dst_ip: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?;
    if unsafe { FERRUM_POD_IPS.get(&dst_ip) }.is_none() {
        return Ok(TC_ACT_OK);
    }

    let src_ip: u32 = ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?;
    if unsafe { FERRUM_NODE_IPS.get(&src_ip) }.is_some() {
        return Ok(TC_ACT_OK);
    }

    let protocol: u8 = ctx.load(ETH_HDR_LEN + 9).map_err(|_| -1i64)?;
    match protocol {
        IPPROTO_TCP => guard_enrolled_destination(ctx),
        IPPROTO_UDP => drop_unsupported_enrolled_destination(),
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn guard_ipv6(ctx: &TcContext) -> Result<i32, i64> {
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

    let src_ip = CidrKey6 {
        addr: [
            ctx.load(ETH_HDR_LEN + 8).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 12).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?,
            ctx.load(ETH_HDR_LEN + 20).map_err(|_| -1i64)?,
        ],
    };
    if unsafe { FERRUM_NODE_IPS6.get(&src_ip) }.is_some() {
        return Ok(TC_ACT_OK);
    }

    let next_header: u8 = ctx.load(ETH_HDR_LEN + 6).map_err(|_| -1i64)?;
    match next_header {
        IPPROTO_TCP => guard_enrolled_destination(ctx),
        IPPROTO_UDP => drop_unsupported_enrolled_destination(),
        header if ipv6_extension_header(header) => drop_unsupported_enrolled_destination(),
        _ => Ok(TC_ACT_OK),
    }
}

#[inline(always)]
fn guard_enrolled_destination(ctx: &TcContext) -> Result<i32, i64> {
    let Some(config) = (unsafe { FERRUM_CAPTURE_CONFIG.get(&FERRUM_CAPTURE_CONFIG_KEY) }) else {
        return Ok(TC_ACT_SHOT);
    };
    if config.node_waypoint_inbound_auth_mark == 0 {
        return Ok(TC_ACT_OK);
    }
    if skb_mark(ctx) == config.node_waypoint_inbound_auth_mark {
        return Ok(TC_ACT_PIPE);
    }
    Ok(TC_ACT_SHOT)
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
fn ipv6_extension_header(next_header: u8) -> bool {
    matches!(
        next_header,
        0 | 43 | 44 | 50 | 51 | 60 | 135 | 139 | 140 | 253 | 254
    )
}

#[inline(always)]
fn skb_mark(ctx: &TcContext) -> u32 {
    unsafe { (*ctx.skb.skb).mark }
}
