//! Ferrum Edge eBPF programs for ambient mesh traffic capture.
//!
//! Seven programs implement transparent traffic interception plus TCP-layer
//! observability:
//!
//! | Program             | Hook              | Purpose                              |
//! |---------------------|-------------------|--------------------------------------|
//! | `ferrum_connect4`   | cgroup/connect4   | Rewrite outbound IPv4 to loopback    |
//! | `ferrum_connect6`   | cgroup/connect6   | Rewrite outbound IPv6 to loopback    |
//! | `ferrum_getpeername4` | cgroup/getpeername4 | Return original IPv4 destination   |
//! | `ferrum_getpeername6` | cgroup/getpeername6 | Return original IPv6 destination   |
//! | `ferrum_tc_inbound` | tc ingress/egress (pod veth) | Guard enrolled destination pod traffic |
//! | `ferrum_tc_ingress_redirect` | tc ingress (node capture iface) | Steer enrolled inbound TCP into the local NodeWaypoint relay (`bpf_sk_assign`) |
//! | `ferrum_sock_ops`   | sock_ops (cgroup) | TCP-layer events (connect/accept/FIN/RST/RTT) + GAP-2M accept-side cookie bridge |
//!
//! Build: `cargo +nightly build --target bpfel-unknown-none -Z build-std=core --release`

#![no_std]
#![no_main]

mod connect4;
mod connect6;
mod getpeername4;
mod getpeername6;
mod maps;
mod sock_ops;
mod sock_ops_emit;
mod tc_inbound;
mod tc_ingress_redirect;

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
