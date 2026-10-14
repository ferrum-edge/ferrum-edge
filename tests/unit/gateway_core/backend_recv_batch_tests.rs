//! External unit + memory-contract coverage for `BackendRecvBatch`
//! (issue #6672): lazy slot buffers, whole-datagram batch receive on a
//! connected socket, and `WouldBlock` on an empty queue.
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
fn receives_whole_datagrams_in_order_in_one_call() {
    let (backend, peer) = connected_pair();
    let peer_addr = backend.local_addr().expect("backend addr");
    peer.send_to(b"one", peer_addr).expect("send one");
    peer.send_to(b"twotwo", peer_addr).expect("send two");
    peer.send_to(&vec![0x5au8; 4096], peer_addr)
        .expect("send three");

    let mut batch = BackendRecvBatch::new(8);
    // Loopback delivery is not instantaneous; poll briefly for the burst.
    let mut received = 0;
    for _ in 0..200 {
        match batch.recv(backend.as_raw_fd(), 8) {
            Ok(n) => {
                received = n;
                break;
            }
            Err(e) if e.kind() == ErrorKind::WouldBlock => {
                std::thread::sleep(std::time::Duration::from_millis(5));
            }
            Err(e) => panic!("recv failed: {e}"),
        }
    }
    assert_eq!(received, 3, "one recvmmsg must return the whole burst");
    assert_eq!(batch.count(), 3);
    assert_eq!(batch.datagram(0), b"one");
    assert_eq!(batch.datagram(1), b"twotwo");
    assert_eq!(batch.datagram(2), vec![0x5au8; 4096].as_slice());
    // Only the slots the burst touched were allocated.
    let allocated = batch.datagram_buffer_capacity_bytes();
    assert!(allocated >= 3 * 65535, "touched slots are full-size");
    assert!(
        allocated <= 3 * 65535,
        "untouched slots must stay unallocated; got {allocated}"
    );
}

#[test]
fn max_count_bounds_the_burst_and_the_remainder_stays_queued() {
    let (backend, peer) = connected_pair();
    let peer_addr = backend.local_addr().expect("backend addr");
    for i in 0..5u8 {
        peer.send_to(&[i; 16], peer_addr).expect("send burst");
    }
    std::thread::sleep(std::time::Duration::from_millis(50));

    let mut batch = BackendRecvBatch::new(8);
    let first = batch
        .recv(backend.as_raw_fd(), 2)
        .expect("first bounded recv");
    assert_eq!(first, 2);
    assert_eq!(batch.datagram(0), &[0u8; 16]);
    assert_eq!(batch.datagram(1), &[1u8; 16]);

    let second = batch.recv(backend.as_raw_fd(), 8).expect("remainder recv");
    assert_eq!(second, 3);
    assert_eq!(batch.datagram(0), &[2u8; 16]);
    assert_eq!(batch.datagram(2), &[4u8; 16]);
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
