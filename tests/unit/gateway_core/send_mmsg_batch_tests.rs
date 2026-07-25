//! External unit + performance-contract coverage for `SendMmsgBatch`
//! (issue #2961): lazy/bounded slot buffers and the oversize direct-send
//! escape hatch.
//!
//! Linux-only because the non-Linux target exposes only empty stubs.

#![cfg(target_os = "linux")]

use ferrum_edge::proxy::udp_batch::{
    GsoBatchBuf, SEND_MMSG_SLOT_SIZE, SendMmsgBatch, SendMmsgPushResult,
};
use std::net::SocketAddr;

fn dest() -> SocketAddr {
    "127.0.0.1:5353".parse().expect("valid socket addr")
}

/// Historical eager footprint: 64 slots × 65535 bytes ≈ 4.2 MiB.
const LEGACY_EAGER_BYTES: usize = 64 * 65535;

#[test]
fn new_batch_allocates_no_datagram_slot_buffers() {
    let batch = SendMmsgBatch::new(64);
    assert_eq!(
        batch.datagram_buffer_capacity_bytes(),
        0,
        "fresh SendMmsgBatch must not eagerly reserve per-slot datagram buffers"
    );
    assert_eq!(batch.slot_size(), SEND_MMSG_SLOT_SIZE);
    assert!(
        batch.datagram_buffer_capacity_bytes() < LEGACY_EAGER_BYTES,
        "contract: must stay far below the legacy 4.2 MiB eager footprint"
    );
}

#[test]
fn ordinary_datagrams_allocate_only_preferred_slot_size() {
    let mut batch = SendMmsgBatch::new(64);
    let payload = vec![0xab_u8; 1200];

    for _ in 0..64 {
        assert_eq!(
            batch.push_with_local(&payload, dest(), None),
            SendMmsgPushResult::Queued
        );
    }

    let allocated = batch.datagram_buffer_capacity_bytes();
    assert!(
        allocated > 0,
        "touching slots must allocate lazily on first use"
    );
    assert!(
        allocated <= 64 * SEND_MMSG_SLOT_SIZE,
        "ordinary ~MTU datagrams must not grow slots past SEND_MMSG_SLOT_SIZE; got {allocated}"
    );
    assert!(
        allocated < LEGACY_EAGER_BYTES / 10,
        "filled ordinary batch ({allocated} bytes) must remain << legacy eager footprint"
    );

    let stats = batch.pending_stats();
    assert_eq!(stats.datagrams, 64);
    assert_eq!(stats.bytes, 64 * 1200);
}

#[test]
fn repeated_pushes_into_same_slot_do_not_grow_capacity() {
    // Flush is not available without a real fd; emulate reuse by constructing
    // a capacity-1 batch and observing capacity after the first push only
    // grows once.
    let mut batch = SendMmsgBatch::new(1);
    let small = [0u8; 100];
    assert_eq!(
        batch.push_with_local(&small, dest(), None),
        SendMmsgPushResult::Queued
    );
    let after_first = batch.datagram_buffer_capacity_bytes();
    assert_eq!(after_first, SEND_MMSG_SLOT_SIZE);

    // Batch is full; further pushes must not allocate.
    assert_eq!(
        batch.push_with_local(&small, dest(), None),
        SendMmsgPushResult::Full
    );
    assert_eq!(batch.datagram_buffer_capacity_bytes(), after_first);
}

#[test]
fn oversize_datagram_is_refused_without_consuming_a_slot() {
    let mut batch = SendMmsgBatch::new(4);
    let oversize = vec![0u8; SEND_MMSG_SLOT_SIZE + 1];

    assert_eq!(
        batch.push_with_local(&oversize, dest(), None),
        SendMmsgPushResult::Oversized,
        "datagrams larger than the slot cap must take the direct-send escape path"
    );
    assert!(batch.is_empty());
    assert_eq!(
        batch.datagram_buffer_capacity_bytes(),
        0,
        "oversized refuse must not allocate a slot buffer"
    );
    assert_eq!(batch.pending_stats().datagrams, 0);
    assert_eq!(batch.pending_stats().bytes, 0);
}

#[test]
fn full_udp_max_datagram_is_classified_oversized_for_direct_send() {
    // Full valid UDP datagram (65535) must remain deliverable via the
    // direct-send escape hatch — SendMmsgBatch refuses rather than truncating.
    let mut batch = SendMmsgBatch::new(2);
    let max_dgram = vec![0u8; 65535];
    assert_eq!(
        batch.push_with_local(&max_dgram, dest(), None),
        SendMmsgPushResult::Oversized
    );
    assert!(batch.is_empty());
}

#[test]
fn slot_boundary_datagram_still_queues() {
    let mut batch = SendMmsgBatch::new(2);
    let exact = vec![0u8; SEND_MMSG_SLOT_SIZE];
    assert_eq!(
        batch.push_with_local(&exact, dest(), None),
        SendMmsgPushResult::Queued
    );
    assert_eq!(batch.pending_stats().bytes, SEND_MMSG_SLOT_SIZE);
}

#[test]
fn gso_drain_stops_on_oversized_segments_for_direct_send_escape() {
    // Segment size > sendmmsg slot: drain must not queue, leaving the GSO
    // buffer intact so the reply path can take_front + direct-send.
    let mut gso = GsoBatchBuf::new(65535);
    let segment = vec![0xcc_u8; SEND_MMSG_SLOT_SIZE + 512];
    assert!(gso.push(&segment));
    assert!(gso.push(&segment));

    let mut sendmmsg = SendMmsgBatch::new(8);
    let drained = gso.drain_to_sendmmsg(&mut sendmmsg, dest(), None);
    assert_eq!(drained, 0, "oversized GSO segments must not enter sendmmsg");
    assert!(sendmmsg.is_empty());
    assert!(!gso.is_empty());

    let first = gso
        .take_front_datagram()
        .expect("front segment available for direct-send");
    assert_eq!(first.len(), segment.len());
    assert!(!gso.is_empty(), "second oversized segment remains");

    let second = gso.take_front_datagram().expect("second segment");
    assert_eq!(second.len(), segment.len());
    assert!(gso.is_empty());
}

#[test]
fn gso_empty_datagram_still_refuses_for_direct_send_escape() {
    let mut gso = GsoBatchBuf::new(1024);
    assert!(
        !gso.push(&[]),
        "empty datagrams remain GSO-incompatible and must use direct-send"
    );
    assert!(gso.is_empty());
}

#[test]
fn with_slot_size_honors_custom_bound() {
    let mut batch = SendMmsgBatch::with_slot_size(2, 64);
    assert_eq!(batch.slot_size(), 64);
    assert_eq!(
        batch.push_with_local(&[0u8; 64], dest(), None),
        SendMmsgPushResult::Queued
    );
    assert_eq!(
        batch.push_with_local(&[0u8; 65], dest(), None),
        SendMmsgPushResult::Oversized
    );
}
