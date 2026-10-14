//! External unit + memory-contract coverage for `BackendRecvBatch`
//! (issue #6672): lazy slot buffers, whole-datagram batch receive on a
//! connected socket, adaptive offer ramp, and `WouldBlock` on an empty
//! queue.
//!
//! Linux-only because the non-Linux target exposes only an empty stub.

#![cfg(target_os = "linux")]

use ferrum_edge::proxy::udp_batch::{BACKEND_RECV_BATCH_CAPACITY, BackendRecvBatch};
use std::io::ErrorKind;
use std::net::UdpSocket;
use std::os::fd::AsRawFd;

/// Historical eager footprint the frontend batch still pays per listener:
/// 64 slots × 65535 bytes ≈ 4.2 MiB. A per-session batch must stay far
/// below it until slots are actually touched.
const LEGACY_EAGER_BYTES: usize = 64 * 65535;

fn connected_pair() -> (UdpSocket, UdpSocket) {
    let backend = UdpSocket::bind("127.0.0.1:0").expect("bind backend");
    let peer = UdpSocket::bind("127.0.0.1:0").expect("bind peer");
    backend
        .connect(peer.local_addr().expect("peer addr"))
        .expect("connect backend socket");
    backend.set_nonblocking(true).expect("nonblocking");
    (backend, peer)
}

#[test]
fn new_batch_allocates_no_datagram_slot_buffers() {
    let batch = BackendRecvBatch::new(BACKEND_RECV_BATCH_CAPACITY);
    assert_eq!(
        batch.datagram_buffer_capacity_bytes(),
        0,
        "fresh BackendRecvBatch must not eagerly reserve per-slot datagram buffers"
    );
    assert_eq!(batch.capacity(), BACKEND_RECV_BATCH_CAPACITY);
    assert_eq!(batch.count(), 0);
    assert!(
        batch.datagram_buffer_capacity_bytes() < LEGACY_EAGER_BYTES,
        "contract: must stay far below the legacy 4.2 MiB eager footprint"
    );
}

#[test]
fn empty_connected_socket_returns_would_block_and_allocates_one_slot() {
    let (backend, _peer) = connected_pair();
    let mut batch = BackendRecvBatch::new(8);
    let err = batch
        .recv(backend.as_raw_fd(), 8)
        .expect_err("empty queue must not succeed");
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
    assert_eq!(batch.count(), 0);
}

#[test]
fn receives_whole_datagrams_in_order_with_adaptive_offer_ramp() {
    let (backend, peer) = connected_pair();
    let peer_addr = backend.local_addr().expect("backend addr");
    peer.send_to(b"one", peer_addr).expect("send one");
    peer.send_to(b"twotwo", peer_addr).expect("send two");
    peer.send_to(&vec![0x5au8; 4096], peer_addr)
        .expect("send three");

    let mut batch = BackendRecvBatch::new(8);
    // Loopback delivery is not instantaneous; poll briefly for the burst.
    // The adaptive offer starts at one slot and doubles when filled, so a
    // three-datagram burst arrives as 1 + 2 across two calls, in order.
    let mut got: Vec<Vec<u8>> = Vec::new();
    for _ in 0..200 {
        if got.len() == 3 {
            break;
        }
        match batch.recv(backend.as_raw_fd(), 8) {
            Ok(n) => {
                assert!(
                    n >= 1,
                    "a successful recv always returns at least one datagram"
                );
                for i in 0..n {
                    got.push(batch.datagram(i).to_vec());
                }
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => panic!("recv failed: {e}"),
        }
    }
    assert_eq!(got.len(), 3);
    assert_eq!(got[0], b"one");
    assert_eq!(got[1], b"twotwo");
    assert_eq!(got[2], vec![0x5au8; 4096]);
    // Only slots the ramp actually offered (1, then 2) were reserved.
    assert_eq!(
        batch.datagram_buffer_capacity_bytes(),
        2 * 65535,
        "reservation follows offered slots, not the caller's burst bound"
    );
    let mut single = BackendRecvBatch::new(8);
    let _ = single.recv(backend.as_raw_fd(), 1);
    assert_eq!(
        single.datagram_buffer_capacity_bytes(),
        65535,
        "offering one slot must reserve only one slot"
    );
}

#[test]
fn max_count_bounds_each_call_and_the_remainder_stays_queued() {
    let (backend, peer) = connected_pair();
    let peer_addr = backend.local_addr().expect("backend addr");
    for i in 0..5u8 {
        peer.send_to(&[i; 16], peer_addr).expect("send burst");
    }
    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut batch = BackendRecvBatch::new(8);
    // max_count caps every call regardless of the adaptive offer.
    let mut got: Vec<u8> = Vec::new();
    while got.len() < 5 {
        let n = batch
            .recv(backend.as_raw_fd(), 2)
            .expect("bounded recv must succeed while datagrams are queued");
        assert!(n <= 2, "call exceeded its max_count bound");
        for i in 0..n {
            got.push(batch.datagram(i)[0]);
        }
    }
    assert_eq!(got, vec![0, 1, 2, 3, 4], "order preserved, nothing lost");
}

#[test]
fn oversized_datagram_is_never_truncated() {
    let (backend, peer) = connected_pair();
    let peer_addr = backend.local_addr().expect("backend addr");
    let big = vec![0xa5u8; 60_000];
    peer.send_to(&big, peer_addr).expect("send big datagram");
    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut batch = BackendRecvBatch::new(4);
    let n = batch.recv(backend.as_raw_fd(), 4).expect("recv big");
    assert_eq!(n, 1);
    assert_eq!(batch.datagram(0), big.as_slice());
}

#[test]
fn zero_max_count_is_would_block_without_a_syscall_result() {
    let (backend, _peer) = connected_pair();
    let mut batch = BackendRecvBatch::new(4);
    let err = batch
        .recv(backend.as_raw_fd(), 0)
        .expect_err("zero bound must not succeed");
    assert_eq!(err.kind(), ErrorKind::WouldBlock);
    assert_eq!(batch.count(), 0);
    assert_eq!(batch.datagram_buffer_capacity_bytes(), 0);
}
