//! tc/ingress — inbound packet classification for enrolled pods.
//!
//! Attached to the host-side veth interface of enrolled pods. Parses the
//! IPv4 header and checks whether the destination IP is in `FERRUM_POD_IPS`.
//! When matched, drops the packet (`TC_ACT_SHOT`) so inbound traffic cannot
//! bypass Ferrum policy enforcement when redirect wiring is unavailable.
//!
//! A future phase will replace this fail-closed behavior with an in-BPF
//! destination rewrite to the HBONE listener.
//!
//! Only IPv4 TCP packets are considered. IPv6 and non-TCP traffic passes
//! through unmodified.

use aya_ebpf::bindings::{TC_ACT_OK, TC_ACT_SHOT};
use aya_ebpf::macros::classifier;
use aya_ebpf::programs::TcContext;

use crate::maps::FERRUM_POD_IPS;

const ETH_HDR_LEN: usize = 14;
const ETH_P_IP: u16 = 0x0800;
const IPPROTO_TCP: u8 = 6;

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
    if u16::from_be(eth_type) != ETH_P_IP {
        return Ok(TC_ACT_OK);
    }

    let protocol: u8 = ctx.load(ETH_HDR_LEN + 9).map_err(|_| -1i64)?;
    if protocol != IPPROTO_TCP {
        return Ok(TC_ACT_OK);
    }

    let dst_ip: u32 = ctx.load(ETH_HDR_LEN + 16).map_err(|_| -1i64)?;

    if unsafe { FERRUM_POD_IPS.get(&dst_ip) }.is_some() {
        return Ok(TC_ACT_SHOT);
    }

    Ok(TC_ACT_OK)
}
