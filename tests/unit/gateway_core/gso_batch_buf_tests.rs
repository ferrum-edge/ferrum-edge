//! Tests for `GsoBatchBuf` — the UDP GSO (Generic Segmentation Offload)
//! accumulator used on the UDP proxy reply path.
//!
//! Linux-only because the non-Linux target has only an empty stub struct
//! (UDP GSO is a kernel feature).

#![cfg(target_os = "linux")]

use ferrum_edge::proxy::udp_batch::{GsoBatchBuf, SendMmsgBatch};
use std::net::SocketAddr;

fn dest() -> SocketAddr {
    "127.0.0.1:9999".parse().unwrap()
}

#[test]
fn new_is_empty() {
    let buf = GsoBatchBuf::new(1024);
    assert!(buf.is_empty());
}

#[test]
fn push_first_datagram_sets_segment_size_and_succeeds() {
    let mut buf = GsoBatchBuf::new(1024);
    assert!(buf.push(&[1u8; 50]));
    assert!(!buf.is_empty());
}

#[test]
fn push_same_size_datagram_succeeds() {
    let mut buf = GsoBatchBuf::new(1024);
    assert!(buf.push(&[1u8; 50]));
    assert!(buf.push(&[2u8; 50]));
    assert!(buf.push(&[3u8; 50]));
    assert!(!buf.is_empty());
}

#[test]
fn push_different_size_datagram_returns_false_without_touching_buffer() {
    let mut buf = GsoBatchBuf::new(1024);
    assert!(buf.push(&[1u8; 50]));
    assert!(buf.push(&[2u8; 50]));
    // Drain the 2-datagram state into a sendmmsg batch to observe the segment
    // count before attempting the mismatched push.
    let snapshot_empty_before = buf.is_empty();
    assert!(!snapshot_empty_before);

    // Different size — refuse.
    assert!(!buf.push(&[9u8; 40]));
    // Buffer must still hold the original 2 datagrams; prove it by draining.
    let mut sendmmsg = SendMmsgBatch::new(8);
    let drained = buf.drain_to_sendmmsg(&mut sendmmsg, dest(), None);
    assert_eq!(drained, 2, "mismatched push must not corrupt prior state");
    assert!(buf.is_empty());
}

#[test]
fn push_over_max_bytes_returns_false_without_touching_buffer() {
    // max_bytes = 100, segment = 50 — second 50-byte push fits (100 total) but
    // a third would exceed 100.
    let mut buf = GsoBatchBuf::new(100);
    assert!(buf.push(&[1u8; 50]));
    assert!(buf.push(&[2u8; 50]));
    assert!(!buf.push(&[3u8; 50]), "push over max_bytes must refuse");
    let mut sendmmsg = SendMmsgBatch::new(8);
    let drained = buf.drain_to_sendmmsg(&mut sendmmsg, dest(), None);
    assert_eq!(drained, 2);
}

#[test]
fn push_empty_slice_is_noop_returns_true() {
    let mut buf = GsoBatchBuf::new(1024);
    assert!(buf.push(&[]));
    assert!(buf.is_empty());
    // Followed by a real push: must behave like a fresh buffer.
    assert!(buf.push(&[1u8; 30]));
    assert!(!buf.is_empty());
}

#[test]
fn drain_to_sendmmsg_splits_contiguous_buffer_by_segment_size() {
    let mut buf = GsoBatchBuf::new(1024);
    for _ in 0..5 {
        assert!(buf.push(&[0xaa; 32]));
    }
    let mut sendmmsg = SendMmsgBatch::new(16);
    let drained = buf.drain_to_sendmmsg(&mut sendmmsg, dest(), None);
    assert_eq!(
        drained, 5,
        "5 pushed datagrams must drain to 5 sendmmsg slots"
    );
    assert!(buf.is_empty(), "full drain must leave the gso buffer empty");
}

/// `extract_gro_segment_size` parses a UDP_GRO cmsg out of a `libc::msghdr`.
/// We hand-build a msghdr with a cmsg buffer containing a UDP_GRO record and
/// verify the parser extracts the u16 segment size.
///
/// Linux-only because `extract_gro_segment_size` takes `&libc::msghdr` on
/// Linux and `&()` on non-Linux.
#[test]
fn extract_gro_segment_size_returns_segment_size_from_cmsg() {
    use ferrum_edge::socket_opts::extract_gro_segment_size;

    const UDP_GRO: libc::c_int = 104;
    let expected_segment: u16 = 1400;

    // Allocate a buffer large enough for one cmsg carrying a u16.
    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cbuf.len() as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null());
        (*cmsg).cmsg_level = libc::SOL_UDP;
        (*cmsg).cmsg_type = UDP_GRO;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
        let data_ptr = libc::CMSG_DATA(cmsg);
        std::ptr::copy_nonoverlapping(
            &expected_segment as *const u16 as *const u8,
            data_ptr,
            std::mem::size_of::<u16>(),
        );
    }

    let got = extract_gro_segment_size(&msg);
    assert_eq!(got, Some(expected_segment));
}

#[test]
fn extract_gro_segment_size_returns_none_when_no_cmsg() {
    use ferrum_edge::socket_opts::extract_gro_segment_size;
    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    // msg_control null + msg_controllen = 0 → no cmsgs.
    msg.msg_control = std::ptr::null_mut();
    msg.msg_controllen = 0;
    assert_eq!(extract_gro_segment_size(&msg), None);
}

#[test]
fn extract_gro_segment_size_ignores_unrelated_cmsg() {
    use ferrum_edge::socket_opts::extract_gro_segment_size;

    let space = unsafe { libc::CMSG_SPACE(std::mem::size_of::<u16>() as u32) } as usize;
    let mut cbuf = vec![0u8; space];

    let mut msg: libc::msghdr = unsafe { std::mem::zeroed() };
    msg.msg_control = cbuf.as_mut_ptr() as *mut libc::c_void;
    msg.msg_controllen = cbuf.len() as _;

    unsafe {
        let cmsg = libc::CMSG_FIRSTHDR(&msg);
        assert!(!cmsg.is_null());
        // Wrong level — SOL_IP with a totally unrelated cmsg_type.
        (*cmsg).cmsg_level = libc::IPPROTO_IP;
        (*cmsg).cmsg_type = 42;
        (*cmsg).cmsg_len = libc::CMSG_LEN(std::mem::size_of::<u16>() as u32) as _;
    }

    assert_eq!(extract_gro_segment_size(&msg), None);
}

#[test]
fn drain_to_sendmmsg_partial_drain_leaves_residual() {
    // SendMmsgBatch capacity 2 while GSO buffer holds 5 datagrams => partial drain.
    let mut buf = GsoBatchBuf::new(4096);
    for _ in 0..5 {
        assert!(buf.push(&[0xbb; 32]));
    }
    let mut sendmmsg = SendMmsgBatch::new(2);
    let drained = buf.drain_to_sendmmsg(&mut sendmmsg, dest(), None);
    assert_eq!(
        drained, 2,
        "sendmmsg capacity 2 must cause drain to stop after 2 pushes"
    );
    assert!(
        !buf.is_empty(),
        "partial drain must leave remaining datagrams in the GSO buffer"
    );

    // The second drain (after flushing sendmmsg) should pick up where we left off.
    // Since we aren't flushing a real socket, just reuse a fresh sendmmsg.
    let mut sendmmsg2 = SendMmsgBatch::new(16);
    let drained2 = buf.drain_to_sendmmsg(&mut sendmmsg2, dest(), None);
    assert_eq!(
        drained2, 3,
        "second drain must consume the 3 remaining datagrams"
    );
    assert!(buf.is_empty());
}
