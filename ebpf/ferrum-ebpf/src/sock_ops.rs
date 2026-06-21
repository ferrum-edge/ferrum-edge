//! sock_ops — TCP-layer event capture for node-waypoint observability.
//!
//! Attached once at the cgroup root by the node-agent. Hooks:
//!
//! | BPF_SOCK_OPS op            | Userspace event             |
//! |----------------------------|-----------------------------|
//! | `TCP_CONNECT_CB`           | `Connect` + connect-ts stash |
//! | `ACTIVE_ESTABLISHED_CB`    | `SynToAckLatency` (when ts present) |
//! | `PASSIVE_ESTABLISHED_CB`   | `AcceptEstablished`         |
//! | `STATE_CB` (FIN_WAIT1)     | `Fin { Sent }`              |
//! | `STATE_CB` (CLOSE_WAIT)    | `Fin { Received }`          |
//! | `STATE_CB` (* → CLOSE)     | `Rst { Received }` (heuristic — see below) |
//! | `RTT_CB`                   | `RttSample { srtt_us }`     |
//!
//! Records are written to the `FERRUM_SOCK_OPS_EVENTS` ringbuf. When the
//! ringbuf is full, `__sync_fetch_and_add` bumps
//! `FERRUM_SOCK_OPS_STATS[SOCK_OPS_STATS_EVENTS_DROPPED]` so the userspace
//! consumer can detect overrun without per-event log spam.
//!
//! ## GAP-2M accept-side cookie bridge
//!
//! The `ACTIVE_ESTABLISHED` and `PASSIVE_ESTABLISHED` callbacks also drive the
//! node-waypoint cookie bridge (IPv4 and IPv6). `connect4`/`connect6` stamp the
//! original destination into `FERRUM_ORIG_DST4`/`FERRUM_ORIG_DST6` keyed by the
//! *connecting* socket's cookie, but the proxy resolves by the *accepted*
//! socket's cookie. At active-established (local port now assigned) the
//! connect-side record is re-keyed by `(netns cookie, connection tuple)` into
//! `FERRUM_ORIG_DST_BY_TUPLE4`/`FERRUM_ORIG_DST_BY_TUPLE6`; at passive-established
//! the mirror tuple is looked up and the record re-stamped under the accept-side
//! cookie. The netns cookie is the preferred discriminator: captured connections
//! all target `127.0.0.1:15001` / `[::1]:15001`, so the tuple alone collapses to
//! loopback + an ephemeral port that can collide across pods in this one global
//! map. Live NodeWaypoint CI exposed one more kernel/runtime wrinkle: because
//! the proxy accepts on a socket originally bound in the workload netns but the
//! accept syscall runs on the proxy task, some passive sock-ops callbacks report
//! the accepting task's netns cookie rather than the workload socket's netns
//! cookie. For that case the bridge publishes and probes a secondary
//! `netns_cookie = 0` key. Userspace validates the resolved pod UID against the
//! pod-specific in-netns listener before admitting traffic, so an any-netns hit
//! can only repair the active/passive join; it cannot silently authorize a
//! different pod.
//!
//! The two callbacks can arrive in either order for local loopback:
//! active-first stores the original destination until passive consumes it, while
//! passive-first stores the accept-side cookie until active stamps it. See
//! [`bridge_active_established`] / [`bridge_passive_established`]. A byte-order
//! or tuple mismatch leaves resolution fail-closed (unchanged from pre-GAP-2M).
//!
//! The IPv6 address fields are read element-by-element via a **volatile**
//! per-`u32` ctx load ([`read_ctx_u32`]) at the four explicit `local_ip6` /
//! `remote_ip6` offsets. aya's SockOpsContext `local_ip6`/`remote_ip6`
//! accessors copy the whole `[u32; 4]` out of the ctx, which the BPF verifier
//! rejects as a modified-ctx-ptr dereference; the per-element volatile loads
//! fold the constant offset into each access (the same technique `connect6`
//! already uses for the `bpf_sock_addr` v6 fields), so IPv6 node-waypoint cookie
//! resolution now resolves on the same footing as IPv4.
//!
//! ## RST attribution caveat
//!
//! `BPF_SOCK_OPS_STATE_CB` reports state transitions but does not directly
//! distinguish RST-sent vs RST-received. For the first cut we treat every
//! transition into `TCP_CLOSE` that did NOT go through the FIN_WAIT /
//! LAST_ACK / CLOSING ladder as a received RST. Refining via
//! `bpf_skc_to_tcp_sock(sk)->sk_err == ECONNRESET` is a future-work item.

use aya_ebpf::helpers::bpf_ktime_get_ns;
use aya_ebpf::macros::sock_ops;
use aya_ebpf::programs::SockOpsContext;
use aya_ebpf::EbpfContext;
use ferrum_ebpf_common::{
    sock_ops_peer_port_host_order, ConnTuple4, ConnTuple6, OrigDst4, OrigDst6, OrigDstKey,
    SockOpsRecord, SOCK_OPS_DIRECTION_RECEIVED, SOCK_OPS_DIRECTION_SENT,
    SOCK_OPS_EVENT_ACCEPT_ESTABLISHED, SOCK_OPS_EVENT_CONNECT, SOCK_OPS_EVENT_FIN,
    SOCK_OPS_EVENT_RST, SOCK_OPS_EVENT_RTT_SAMPLE, SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY,
    SOCK_OPS_STATS_EVENTS_DROPPED,
};

use crate::maps::{
    FERRUM_ACCEPT_COOKIE_BY_TUPLE4, FERRUM_ACCEPT_COOKIE_BY_TUPLE6, FERRUM_ORIG_DST4,
    FERRUM_ORIG_DST6, FERRUM_ORIG_DST_BY_TUPLE4, FERRUM_ORIG_DST_BY_TUPLE6,
    FERRUM_SOCK_OPS_CONNECT_TS, FERRUM_SOCK_OPS_EVENTS, FERRUM_SOCK_OPS_STATS,
};

// Address families from <bits/socket.h>; `bpf_sock_ops.family` carries the
// value. The GAP-2M cookie bridge handles both: IPv4 reads the `local_ip4` /
// `remote_ip4` ctx words, IPv6 reads the four `local_ip6` / `remote_ip6` ctx
// words element-by-element with verifier-safe volatile loads (see
// `read_ctx_u32`). Any other family is ignored by the bridge.
const AF_INET: u32 = 2;
const AF_INET6: u32 = 10;

// Operation discriminants — values from `include/uapi/linux/bpf.h`
// (`bpf_sock_ops_op`). aya-ebpf does not re-export these, so we mirror them
// here. Stable since 4.13; only additive changes have happened.
const BPF_SOCK_OPS_TCP_CONNECT_CB: u32 = 3;
const BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB: u32 = 4;
const BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB: u32 = 5;
const BPF_SOCK_OPS_STATE_CB: u32 = 10;
const BPF_SOCK_OPS_RTT_CB: u32 = 12;

// TCP states — values from `include/net/tcp_states.h`. Used to interpret
// `STATE_CB` arguments.
const TCP_ESTABLISHED: u32 = 1;
const TCP_FIN_WAIT1: u32 = 4;
const TCP_CLOSE: u32 = 7;
const TCP_CLOSE_WAIT: u32 = 8;

// `BPF_SOCK_OPS_STATE_CB_FLAG` and `BPF_SOCK_OPS_RTT_CB_FLAG` from
// `bpf_sock_ops_cb_flags`. We OR them into the sock-op callback flags so
// STATE_CB and RTT_CB actually fire.
const BPF_SOCK_OPS_STATE_CB_FLAG: i32 = 1 << 2;
const BPF_SOCK_OPS_RTT_CB_FLAG: i32 = 1 << 3;
const ALL_SOCK_OPS_CB_FLAGS: i32 = BPF_SOCK_OPS_STATE_CB_FLAG | BPF_SOCK_OPS_RTT_CB_FLAG;

#[sock_ops]
pub fn ferrum_sock_ops(ctx: SockOpsContext) -> u32 {
    handle_sock_ops(&ctx);
    // Sock-ops return value is opaque to the verifier; 1 is the standard
    // "ok, continue" value used by every example program we ship.
    1
}

#[inline(always)]
fn handle_sock_ops(ctx: &SockOpsContext) {
    let op = ctx.op();
    match op {
        BPF_SOCK_OPS_TCP_CONNECT_CB => {
            // Enable the optional callbacks so STATE_CB / RTT_CB fire for
            // this socket. set_cb_flags only mutates the per-socket flags
            // attached to *this* `tcp_sock` — no global side effect.
            let _ = ctx.set_cb_flags(ALL_SOCK_OPS_CB_FLAGS);
            stash_connect_ts(ctx);
            emit(SockOpsRecord {
                event_type: SOCK_OPS_EVENT_CONNECT,
                direction: 0,
                drop_reason: 0,
                _pad: 0,
                value: 0,
            });
        }
        BPF_SOCK_OPS_ACTIVE_ESTABLISHED_CB => {
            let _ = ctx.set_cb_flags(ALL_SOCK_OPS_CB_FLAGS);
            // GAP-2M: the connecting socket now has its local port; re-key its
            // connect-side orig-dst record by the connection tuple (v4 or v6).
            bridge_active_established(ctx);
            if let Some(syn_to_ack_us) = drain_connect_ts(ctx) {
                emit(SockOpsRecord {
                    event_type: SOCK_OPS_EVENT_SYN_TO_ACK_LATENCY,
                    direction: 0,
                    drop_reason: 0,
                    _pad: 0,
                    value: syn_to_ack_us,
                });
            }
        }
        BPF_SOCK_OPS_PASSIVE_ESTABLISHED_CB => {
            // Server side accepted the connection; enable callbacks so we
            // capture FIN/RST/RTT for inbound connections too.
            let _ = ctx.set_cb_flags(ALL_SOCK_OPS_CB_FLAGS);
            // GAP-2M: re-stamp the orig-dst record under this accept-side
            // socket's cookie so the node-waypoint proxy can resolve it.
            bridge_passive_established(ctx);
            emit(SockOpsRecord {
                event_type: SOCK_OPS_EVENT_ACCEPT_ESTABLISHED,
                direction: 0,
                drop_reason: 0,
                _pad: 0,
                value: 0,
            });
        }
        BPF_SOCK_OPS_STATE_CB => {
            // The kernel passes args[0] = old_state, args[1] = new_state
            // (`tcp_set_state` → `tcp_call_bpf_2arg(sk, STATE_CB, oldstate,
            // state)`). Reading them in the other order both reverses the
            // FIN/RST transition metrics AND means the TCP_CLOSE cleanup below
            // never fires on a real close (it would test old_state).
            let old_state = ctx.arg(0);
            let new_state = ctx.arg(1);
            // On terminal close, drop this socket's orig-dst record so a closed
            // connection's cookie does not linger in FERRUM_ORIG_DST4/6 until
            // LRU pressure evicts it. The node-waypoint resolver mirrors these
            // maps and treats a present cookie as a live connection, so a stale
            // record would keep a removed pod's lazy identity (and policy scope)
            // pinned indefinitely on a low-churn node where the LRU never fills.
            if new_state == TCP_CLOSE {
                cleanup_orig_dst_on_close(ctx);
            }
            emit_state_transition(old_state, new_state);
        }
        BPF_SOCK_OPS_RTT_CB => {
            // The kernel passes args[0] = the latest *measured* RTT sample
            // (mrtt_us) and args[1] = the updated *smoothed* RTT (`srtt_us >> 3`)
            // (`tcp_call_bpf_2arg(sk, RTT_CB, mrtt_us, tp->srtt_us >> 3)`). The
            // userspace metric is the smoothed RTT (`srtt_sample_*`), so emit
            // args[1]; reading args[0] would feed per-sample RTT into an SRTT
            // metric and mislead dashboards.
            let srtt_us = ctx.arg(1) as u64;
            if srtt_us > 0 {
                emit(SockOpsRecord {
                    event_type: SOCK_OPS_EVENT_RTT_SAMPLE,
                    direction: 0,
                    drop_reason: 0,
                    _pad: 0,
                    value: srtt_us,
                });
            }
        }
        _ => {
            // Other ops (TIMEOUT_INIT, RWND_INIT, NEEDS_ECN, …) are not
            // observability events; ignore.
        }
    }
}

#[inline(always)]
fn emit_state_transition(old_state: u32, new_state: u32) {
    match new_state {
        TCP_FIN_WAIT1 => {
            // Local close — we sent the FIN.
            emit(SockOpsRecord {
                event_type: SOCK_OPS_EVENT_FIN,
                direction: SOCK_OPS_DIRECTION_SENT,
                drop_reason: 0,
                _pad: 0,
                value: 0,
            });
        }
        TCP_CLOSE_WAIT => {
            // Peer closed first — we received the FIN.
            emit(SockOpsRecord {
                event_type: SOCK_OPS_EVENT_FIN,
                direction: SOCK_OPS_DIRECTION_RECEIVED,
                drop_reason: 0,
                _pad: 0,
                value: 0,
            });
        }
        TCP_CLOSE => {
            // ESTABLISHED → CLOSE without traversing the FIN ladder is
            // treated as an abnormal close (RST). FIN-ladder transitions
            // (FIN_WAIT1, FIN_WAIT2, CLOSING, TIME_WAIT, LAST_ACK,
            // CLOSE_WAIT) always pass through ESTABLISHED first, then go
            // to a non-ESTABLISHED state before reaching CLOSE — so the
            // ESTABLISHED check is sufficient. Without inspecting
            // `tcp_sock->sk_err`, sent-vs-received is unknown; surface
            // as Received per first-cut heuristic (refining via
            // `bpf_skc_to_tcp_sock` is future work, called out in the
            // module-level comment).
            if old_state == TCP_ESTABLISHED {
                emit(SockOpsRecord {
                    event_type: SOCK_OPS_EVENT_RST,
                    direction: SOCK_OPS_DIRECTION_RECEIVED,
                    drop_reason: 0,
                    _pad: 0,
                    value: 0,
                });
            }
        }
        _ => {}
    }
}

#[inline(always)]
fn socket_cookie(ctx: &SockOpsContext) -> u64 {
    // Safety: `bpf_get_socket_cookie` is a BPF helper that is safe to call
    // on any sock context; the verifier checks the context type. The
    // pointer comes from `EbpfContext::as_ptr`, which is the sock_ops
    // context the program runs on.
    unsafe { aya_ebpf::helpers::bpf_get_socket_cookie(ctx.as_ptr()) }
}

#[inline(always)]
fn socket_netns_cookie(ctx: &SockOpsContext) -> u64 {
    // Safety: `bpf_get_netns_cookie` is a BPF helper valid on a sock_ops
    // context (the kernel registers `bpf_get_netns_cookie_sock_ops_proto`);
    // the verifier checks the context type.
    unsafe { aya_ebpf::helpers::bpf_get_netns_cookie(ctx.as_ptr()) }
}

// `bpf_sock_ops` field byte offsets (uapi/linux/bpf.h). Each must be read as an
// independent 4-byte ctx access; the verifier rejects a wider load. aya's
// scalar accessors normally emit standalone loads, but reading several adjacent
// fields together (the bridge tuple needs remote_ip4@24, local_ip4@28,
// remote_port@64, local_port@68) lets LLVM coalesce neighbors into an 8-byte
// load the verifier refuses ("invalid bpf_context access off=24 size=8").
const SK_OPS_REMOTE_IP4_OFF: usize = 24;
const SK_OPS_LOCAL_IP4_OFF: usize = 28;
const SK_OPS_REMOTE_PORT_OFF: usize = 64;
const SK_OPS_LOCAL_PORT_OFF: usize = 68;

// IPv6 address words. `struct bpf_sock_ops` lays them out immediately after the
// v4 addresses: `__u32 remote_ip6[4]` at 32 (words 32/36/40/44) and
// `__u32 local_ip6[4]` at 48 (words 48/52/56/60), with `remote_port` / `local_port`
// following at 64 / 68 (shared with the v4 path). Each word is read with the same
// per-element volatile `read_ctx_u32` load so the verifier rewrites it as a
// standalone ctx access (a whole-`[u32; 4]` copy is rejected). The kernel stores
// these in network byte order, matching the v4 `*_ip4` words.
const SK_OPS_REMOTE_IP6_OFF: [usize; 4] = [32, 36, 40, 44];
const SK_OPS_LOCAL_IP6_OFF: [usize; 4] = [48, 52, 56, 60];

/// Read one `u32` `bpf_sock_ops` ctx field with a **volatile** load.
///
/// Volatile loads cannot be widened or coalesced by LLVM, so each field stays a
/// standalone `*(u32*)(ctx + off)` access the verifier rewrites per field. The
/// offset is a compile-time constant, so it folds into the load instruction
/// (not a modified-ctx-ptr dereference).
#[inline(always)]
fn read_ctx_u32(ctx: &SockOpsContext, byte_off: usize) -> u32 {
    // Safety: `byte_off` is a valid `bpf_sock_ops` field offset (4-byte aligned,
    // within bounds); the verifier validates the ctx access at load time.
    unsafe { core::ptr::read_volatile((ctx.as_ptr() as *const u8).add(byte_off) as *const u32) }
}

/// Read a 128-bit `bpf_sock_ops` IPv6 address as four independent `u32` ctx
/// loads. Reading `local_ip6` / `remote_ip6` as a whole `[u32; 4]` makes LLVM
/// take the array base into a register and dereference it, which the verifier
/// rejects ("dereference of modified ctx ptr"); each [`read_ctx_u32`] folds its
/// constant offset into a standalone volatile load the verifier accepts. The
/// returned words stay in **network byte order** (how the kernel stores them),
/// matching `OrigDst6::addr` / the connect6-stamped record and the v4 `*_ip4`
/// words — so the tuple key bytes are identical on both ends of a connection.
#[inline(always)]
fn read_ctx_ip6(ctx: &SockOpsContext, offsets: [usize; 4]) -> [u32; 4] {
    [
        read_ctx_u32(ctx, offsets[0]),
        read_ctx_u32(ctx, offsets[1]),
        read_ctx_u32(ctx, offsets[2]),
        read_ctx_u32(ctx, offsets[3]),
    ]
}

/// GAP-2M (active side). The connecting (client) socket has reached
/// ESTABLISHED, so its ephemeral local port is now assigned. Look up the
/// connect-side original-destination record (stamped by `connect4`/`connect6`
/// under this socket's cookie) and re-key it by the connection tuple so the
/// proxy's accept-side socket can recover it in [`bridge_passive_established`].
/// All steps are best-effort: a miss leaves node-waypoint resolution
/// fail-closed, exactly as before GAP-2M. Dispatches by address family; any
/// non-IP family is ignored.
#[inline(always)]
fn bridge_active_established(ctx: &SockOpsContext) {
    match ctx.family() {
        AF_INET => bridge_active_established_v4(ctx),
        AF_INET6 => bridge_active_established_v6(ctx),
        _ => {}
    }
}

#[inline(always)]
fn bridge_active_established_v4(ctx: &SockOpsContext) {
    let cookie = socket_cookie(ctx);
    // Active side: the local socket addr/port is the client, the rewritten
    // remote addr/port is the loopback capture endpoint (the server). The netns
    // cookie disambiguates pods that share the loopback 4-tuple.
    if let Some(orig) = unsafe { FERRUM_ORIG_DST4.get(&OrigDstKey { cookie }) }.copied() {
        let tuple = active_tuple4(ctx);
        let any_tuple = tuple.any_netns();
        let _ = FERRUM_ORIG_DST_BY_TUPLE4.insert(&tuple, &orig, 0);
        let _ = FERRUM_ORIG_DST_BY_TUPLE4.insert(&any_tuple, &orig, 0);
        if let Some(accept_cookie) = accept_cookie_for_tuple4(&tuple, &any_tuple) {
            stamp_accept_orig_dst4(accept_cookie, &orig);
            cleanup_tuple4(&tuple);
            cleanup_tuple4(&any_tuple);
        }
    }
}

/// IPv6 mirror of [`bridge_active_established_v4`]. Identical key discipline:
/// the netns cookie discriminates pods sharing the `[::1]:15001` loopback tuple,
/// the v6 addresses are read element-by-element (network byte order, like the v4
/// `*_ip4` words), and the ports use the same host-order normalization. A miss
/// leaves resolution fail-closed.
#[inline(always)]
fn bridge_active_established_v6(ctx: &SockOpsContext) {
    let cookie = socket_cookie(ctx);
    if let Some(orig) = unsafe { FERRUM_ORIG_DST6.get(&OrigDstKey { cookie }) }.copied() {
        let tuple = active_tuple6(ctx);
        let any_tuple = tuple.any_netns();
        let _ = FERRUM_ORIG_DST_BY_TUPLE6.insert(&tuple, &orig, 0);
        let _ = FERRUM_ORIG_DST_BY_TUPLE6.insert(&any_tuple, &orig, 0);
        if let Some(accept_cookie) = accept_cookie_for_tuple6(&tuple, &any_tuple) {
            stamp_accept_orig_dst6(accept_cookie, &orig);
            cleanup_tuple6(&tuple);
            cleanup_tuple6(&any_tuple);
        }
    }
}

/// GAP-2M (passive side). The accepted (server-side) socket now exists with
/// the cookie the node-waypoint proxy reads via `getsockopt(SO_COOKIE)`.
/// Recover the original-destination record by the mirror connection tuple and
/// re-stamp it under this accept-side cookie, so the proxy's existing
/// `FERRUM_ORIG_DST4`/`FERRUM_ORIG_DST6` lookup resolves the source identity.
/// The tuple entry is consumed on a hit. Dispatches by address family; any
/// non-IP family is ignored.
#[inline(always)]
fn bridge_passive_established(ctx: &SockOpsContext) {
    match ctx.family() {
        AF_INET => bridge_passive_established_v4(ctx),
        AF_INET6 => bridge_passive_established_v6(ctx),
        _ => {}
    }
}

#[inline(always)]
fn bridge_passive_established_v4(ctx: &SockOpsContext) {
    let cookie = socket_cookie(ctx);
    // Passive side mirrors the active tuple: the remote socket addr/port is the
    // client, the local addr/port is the loopback server. The netns cookie is
    // the same as the active side for a same-netns connection; the any-netns
    // fallback covers kernels that report the accepting task's netns here.
    let tuple = passive_tuple4(ctx);
    let any_tuple = tuple.any_netns();
    if let Some(orig) = orig_dst_for_tuple4(&tuple, &any_tuple) {
        stamp_accept_orig_dst4(cookie, &orig);
        cleanup_tuple4(&tuple);
        cleanup_tuple4(&any_tuple);
    } else {
        let _ = FERRUM_ACCEPT_COOKIE_BY_TUPLE4.insert(&tuple, &cookie, 0);
        let _ = FERRUM_ACCEPT_COOKIE_BY_TUPLE4.insert(&any_tuple, &cookie, 0);
    }
}

/// IPv6 mirror of [`bridge_passive_established_v4`]. The tuple swaps client and
/// server exactly as the v4 path does, reads the v6 addresses element-by-element
/// in the same byte order, and re-stamps `FERRUM_ORIG_DST6` under the accept-side
/// cookie. A miss leaves resolution fail-closed.
#[inline(always)]
fn bridge_passive_established_v6(ctx: &SockOpsContext) {
    let cookie = socket_cookie(ctx);
    let tuple = passive_tuple6(ctx);
    let any_tuple = tuple.any_netns();
    if let Some(orig) = orig_dst_for_tuple6(&tuple, &any_tuple) {
        stamp_accept_orig_dst6(cookie, &orig);
        cleanup_tuple6(&tuple);
        cleanup_tuple6(&any_tuple);
    } else {
        let _ = FERRUM_ACCEPT_COOKIE_BY_TUPLE6.insert(&tuple, &cookie, 0);
        let _ = FERRUM_ACCEPT_COOKIE_BY_TUPLE6.insert(&any_tuple, &cookie, 0);
    }
}

#[inline(always)]
fn accept_cookie_for_tuple4(tuple: &ConnTuple4, any_tuple: &ConnTuple4) -> Option<u64> {
    if let Some(cookie) = unsafe { FERRUM_ACCEPT_COOKIE_BY_TUPLE4.get(tuple) }.copied() {
        return Some(cookie);
    }
    unsafe { FERRUM_ACCEPT_COOKIE_BY_TUPLE4.get(any_tuple) }.copied()
}

#[inline(always)]
fn accept_cookie_for_tuple6(tuple: &ConnTuple6, any_tuple: &ConnTuple6) -> Option<u64> {
    if let Some(cookie) = unsafe { FERRUM_ACCEPT_COOKIE_BY_TUPLE6.get(tuple) }.copied() {
        return Some(cookie);
    }
    unsafe { FERRUM_ACCEPT_COOKIE_BY_TUPLE6.get(any_tuple) }.copied()
}

#[inline(always)]
fn orig_dst_for_tuple4(tuple: &ConnTuple4, any_tuple: &ConnTuple4) -> Option<OrigDst4> {
    if let Some(orig) = unsafe { FERRUM_ORIG_DST_BY_TUPLE4.get(tuple) }.copied() {
        return Some(orig);
    }
    unsafe { FERRUM_ORIG_DST_BY_TUPLE4.get(any_tuple) }.copied()
}

#[inline(always)]
fn orig_dst_for_tuple6(tuple: &ConnTuple6, any_tuple: &ConnTuple6) -> Option<OrigDst6> {
    if let Some(orig) = unsafe { FERRUM_ORIG_DST_BY_TUPLE6.get(tuple) }.copied() {
        return Some(orig);
    }
    unsafe { FERRUM_ORIG_DST_BY_TUPLE6.get(any_tuple) }.copied()
}

#[inline(always)]
fn cleanup_tuple4(tuple: &ConnTuple4) {
    let _ = FERRUM_ORIG_DST_BY_TUPLE4.remove(tuple);
    let _ = FERRUM_ACCEPT_COOKIE_BY_TUPLE4.remove(tuple);
}

#[inline(always)]
fn cleanup_tuple6(tuple: &ConnTuple6) {
    let _ = FERRUM_ORIG_DST_BY_TUPLE6.remove(tuple);
    let _ = FERRUM_ACCEPT_COOKIE_BY_TUPLE6.remove(tuple);
}

#[inline(always)]
fn active_tuple4(ctx: &SockOpsContext) -> ConnTuple4 {
    ConnTuple4::new(
        socket_netns_cookie(ctx),
        read_ctx_u32(ctx, SK_OPS_LOCAL_IP4_OFF),
        read_ctx_u32(ctx, SK_OPS_LOCAL_PORT_OFF) as u16,
        read_ctx_u32(ctx, SK_OPS_REMOTE_IP4_OFF),
        sock_ops_peer_port_host_order(read_ctx_u32(ctx, SK_OPS_REMOTE_PORT_OFF)),
    )
}

#[inline(always)]
fn passive_tuple4(ctx: &SockOpsContext) -> ConnTuple4 {
    ConnTuple4::new(
        socket_netns_cookie(ctx),
        read_ctx_u32(ctx, SK_OPS_REMOTE_IP4_OFF),
        sock_ops_peer_port_host_order(read_ctx_u32(ctx, SK_OPS_REMOTE_PORT_OFF)),
        read_ctx_u32(ctx, SK_OPS_LOCAL_IP4_OFF),
        read_ctx_u32(ctx, SK_OPS_LOCAL_PORT_OFF) as u16,
    )
}

#[inline(always)]
fn active_tuple6(ctx: &SockOpsContext) -> ConnTuple6 {
    ConnTuple6::new(
        socket_netns_cookie(ctx),
        read_ctx_ip6(ctx, SK_OPS_LOCAL_IP6_OFF),
        read_ctx_u32(ctx, SK_OPS_LOCAL_PORT_OFF) as u16,
        read_ctx_ip6(ctx, SK_OPS_REMOTE_IP6_OFF),
        sock_ops_peer_port_host_order(read_ctx_u32(ctx, SK_OPS_REMOTE_PORT_OFF)),
    )
}

#[inline(always)]
fn passive_tuple6(ctx: &SockOpsContext) -> ConnTuple6 {
    ConnTuple6::new(
        socket_netns_cookie(ctx),
        read_ctx_ip6(ctx, SK_OPS_REMOTE_IP6_OFF),
        sock_ops_peer_port_host_order(read_ctx_u32(ctx, SK_OPS_REMOTE_PORT_OFF)),
        read_ctx_ip6(ctx, SK_OPS_LOCAL_IP6_OFF),
        read_ctx_u32(ctx, SK_OPS_LOCAL_PORT_OFF) as u16,
    )
}

#[inline(always)]
fn stamp_accept_orig_dst4(accept_cookie: u64, orig: &OrigDst4) {
    let _ = FERRUM_ORIG_DST4.insert(
        &OrigDstKey {
            cookie: accept_cookie,
        },
        orig,
        0,
    );
}

#[inline(always)]
fn stamp_accept_orig_dst6(accept_cookie: u64, orig: &OrigDst6) {
    let _ = FERRUM_ORIG_DST6.insert(
        &OrigDstKey {
            cookie: accept_cookie,
        },
        orig,
        0,
    );
}

/// Remove this socket's original-destination record from
/// `FERRUM_ORIG_DST4`/`FERRUM_ORIG_DST6` on terminal close. Records inserted on
/// connect (`connect4`/`connect6`) and re-stamped on accept
/// ([`bridge_passive_established`]) otherwise outlive the connection and are
/// evicted only under LRU pressure, so on a low-churn node the node-waypoint
/// resolver — which mirrors these maps and treats a present cookie as a live
/// connection — keeps a removed pod's lazy identity and policy scope pinned.
/// Best-effort and ENOENT-tolerant: sockets that never carried a record
/// (non-captured traffic) simply miss. The socket cookie is globally unique
/// across address families, so only the family-matching map can hold it.
#[inline(always)]
fn cleanup_orig_dst_on_close(ctx: &SockOpsContext) {
    let key = OrigDstKey {
        cookie: socket_cookie(ctx),
    };
    if ctx.family() == AF_INET {
        let _ = FERRUM_ORIG_DST4.remove(&key);
        let active = active_tuple4(ctx);
        let passive = passive_tuple4(ctx);
        let any_active = active.any_netns();
        let any_passive = passive.any_netns();
        cleanup_tuple4(&active);
        cleanup_tuple4(&passive);
        cleanup_tuple4(&any_active);
        cleanup_tuple4(&any_passive);
    } else if ctx.family() == AF_INET6 {
        let _ = FERRUM_ORIG_DST6.remove(&key);
        let active = active_tuple6(ctx);
        let passive = passive_tuple6(ctx);
        let any_active = active.any_netns();
        let any_passive = passive.any_netns();
        cleanup_tuple6(&active);
        cleanup_tuple6(&passive);
        cleanup_tuple6(&any_active);
        cleanup_tuple6(&any_passive);
    }
}

#[inline(always)]
fn stash_connect_ts(ctx: &SockOpsContext) {
    let cookie = socket_cookie(ctx);
    let now_ns = unsafe { bpf_ktime_get_ns() };
    // LRU insert is best-effort; loss is acceptable (only blanks the
    // SynToAck sample for that socket).
    let _ = FERRUM_SOCK_OPS_CONNECT_TS.insert(&cookie, &now_ns, 0);
}

#[inline(always)]
fn drain_connect_ts(ctx: &SockOpsContext) -> Option<u64> {
    let cookie = socket_cookie(ctx);
    let started_ns = unsafe { FERRUM_SOCK_OPS_CONNECT_TS.get(&cookie).copied()? };
    // Best-effort delete — if it fails the LRU will reclaim.
    let _ = FERRUM_SOCK_OPS_CONNECT_TS.remove(&cookie);
    let now_ns = unsafe { bpf_ktime_get_ns() };
    let delta_ns = now_ns.saturating_sub(started_ns);
    // Convert ns → us. Drop measurements >1 hour to keep the histogram
    // sane in the unlikely event of clock skew or socket reuse.
    let delta_us = delta_ns / 1_000;
    if delta_us == 0 || delta_us > 3_600_000_000 {
        None
    } else {
        Some(delta_us)
    }
}

#[inline(always)]
fn emit(record: SockOpsRecord) {
    match FERRUM_SOCK_OPS_EVENTS.reserve::<SockOpsRecord>(0) {
        Some(mut entry) => {
            entry.write(record);
            entry.submit(0);
        }
        None => {
            // Ringbuf full — bump the per-CPU kernel-side dropped counter
            // so the userspace consumer can flip into the overrun regime.
            // PerCpuArray slots are CPU-local, so a non-atomic increment
            // is safe (no other CPU touches this slot until userspace
            // reads). Userspace sums across CPUs when polling.
            if let Some(slot) = FERRUM_SOCK_OPS_STATS.get_ptr_mut(SOCK_OPS_STATS_EVENTS_DROPPED) {
                // Safety: `slot` points into a per-CPU array slot the
                // verifier already proved valid for the current CPU.
                unsafe {
                    *slot = (*slot).wrapping_add(1);
                }
            }
        }
    }
}
