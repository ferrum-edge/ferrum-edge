//! Batched framed-datagram tunnel writes on the mesh UDP path (issue #5048):
//! `FrameBatch` bounds, FIFO drain of already-queued datagrams, byte-reservation
//! release, exact partial-write accounting, and the write deadline.

use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::{Bytes, BytesMut};
use ferrum_edge::proxy::mesh_udp_capture::{QueueDrain, drain_queued_datagrams};
use ferrum_edge::proxy::mesh_udp_frame::{
    BatchWriteFailureKind, FrameBatch, MAX_BATCH_DATAGRAMS, MAX_BATCH_WIRE_BYTES,
    MAX_FRAME_PAYLOAD, read_datagram,
};
use tokio::io::AsyncWrite;

/// Decode every whole frame in `wire` (no I/O) and return the payloads.
fn decode_all(wire: &[u8]) -> Vec<Vec<u8>> {
    let mut out = Vec::new();
    let mut rest = wire;
    while rest.len() >= 2 {
        let len = u16::from_be_bytes([rest[0], rest[1]]) as usize;
        assert!(rest.len() >= 2 + len, "truncated frame in batch");
        out.push(rest[2..2 + len].to_vec());
        rest = &rest[2 + len..];
    }
    assert!(rest.is_empty(), "trailing partial bytes in batch");
    out
}

/// Sink that accepts writes in `chunk` byte slices, fails after `fail_after`
/// accepted bytes (`None` = never), and can be told to stall (return Pending
/// forever) once `stall_after` bytes were accepted.
struct ScriptedSink {
    written: Vec<u8>,
    chunk: usize,
    fail_after: Option<usize>,
    stall_after: Option<usize>,
}

impl ScriptedSink {
    fn new(chunk: usize) -> Self {
        Self {
            written: Vec::new(),
            chunk,
            fail_after: None,
            stall_after: None,
        }
    }
}

impl AsyncWrite for ScriptedSink {
    fn poll_write(
        mut self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let done = self.written.len();
        if let Some(limit) = self.stall_after
            && done >= limit
        {
            return Poll::Pending;
        }
        if let Some(limit) = self.fail_after
            && done >= limit
        {
            return Poll::Ready(Err(std::io::Error::new(
                std::io::ErrorKind::BrokenPipe,
                "scripted failure",
            )));
        }
        let mut n = buf.len().min(self.chunk);
        if let Some(limit) = self.fail_after {
            n = n.min(limit - done);
        }
        if let Some(limit) = self.stall_after {
            n = n.min(limit - done);
        }
        self.written.extend_from_slice(&buf[..n]);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

#[test]
fn frame_batch_first_datagram_always_joins_even_when_oversize_for_the_bound() {
    let mut batch = FrameBatch::new();
    assert!(batch.is_empty());
    let big = vec![0xAB; MAX_FRAME_PAYLOAD];
    assert!(batch.accepts(big.len()));
    batch.push(&big).expect("max datagram");
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.wire_bytes(), 2 + MAX_FRAME_PAYLOAD);
    assert_eq!(batch.payload_bytes(), MAX_FRAME_PAYLOAD);
    // Now over the wire bound: nothing further joins, not even an empty one.
    assert!(!batch.accepts(0));
}

#[test]
fn frame_batch_respects_wire_byte_bound_exactly() {
    let mut batch = FrameBatch::new();
    let payload = vec![1u8; 1022]; // 1024 wire bytes per datagram
    let per_batch = MAX_BATCH_WIRE_BYTES / 1024;
    for _ in 0..per_batch {
        assert!(batch.accepts(payload.len()));
        batch.push(&payload).expect("push");
    }
    assert_eq!(batch.wire_bytes(), MAX_BATCH_WIRE_BYTES);
    assert!(!batch.accepts(0), "a full batch admits nothing more");
    // One byte less than full admits a zero-length datagram (2 wire bytes)
    // only if it fits exactly.
    let mut batch = FrameBatch::new();
    batch
        .push(&vec![0u8; MAX_BATCH_WIRE_BYTES - 4])
        .expect("push");
    assert!(batch.accepts(0));
    assert!(!batch.accepts(1));
}

#[test]
fn frame_batch_respects_datagram_count_bound() {
    let mut batch = FrameBatch::new();
    for _ in 0..MAX_BATCH_DATAGRAMS {
        assert!(batch.accepts(0));
        batch.push(b"").expect("push");
    }
    assert_eq!(batch.len(), MAX_BATCH_DATAGRAMS);
    assert!(!batch.accepts(0));
    assert_eq!(batch.wire_bytes(), 2 * MAX_BATCH_DATAGRAMS);
}

#[test]
fn frame_batch_rejects_oversize_push_and_stays_unchanged() {
    let mut batch = FrameBatch::new();
    batch.push(b"ok").expect("push");
    let err = batch
        .push(&vec![0u8; MAX_FRAME_PAYLOAD + 1])
        .expect_err("oversize");
    assert_eq!(err.kind(), std::io::ErrorKind::InvalidInput);
    assert_eq!(batch.len(), 1);
    assert_eq!(batch.wire_bytes(), 4);
    assert_eq!(batch.payload_bytes(), 2);
}

#[tokio::test]
async fn frame_batch_write_is_decodable_across_arbitrary_fragmentation() {
    let mut batch = FrameBatch::new();
    let datagrams: Vec<Vec<u8>> = vec![
        b"one".to_vec(),
        Vec::new(),
        vec![7u8; 300],
        b"four".to_vec(),
        Vec::new(),
    ];
    for d in &datagrams {
        batch.push(d).expect("push");
    }
    for chunk in [1usize, 2, 3, 7, 64, usize::MAX] {
        let mut sink = ScriptedSink::new(chunk);
        batch
            .write_to(&mut sink, Duration::from_secs(5))
            .await
            .expect("write");
        assert_eq!(decode_all(&sink.written), datagrams);
        // And the production decoder recovers the same boundaries.
        let mut reader = &sink.written[..];
        let mut buf = BytesMut::new();
        let mut decoded = Vec::new();
        while let Some(p) = read_datagram(&mut reader, &mut buf).await.expect("decode") {
            decoded.push(p.to_vec());
        }
        assert_eq!(decoded, datagrams);
    }
}

#[tokio::test]
async fn frame_batch_partial_write_reports_exact_committed_prefix() {
    let mut batch = FrameBatch::new();
    batch.push(&[1u8; 10]).expect("push"); // wire 0..12
    batch.push(&[2u8; 20]).expect("push"); // wire 12..34
    batch.push(&[3u8; 30]).expect("push"); // wire 34..66
    // Fail after 40 accepted bytes: datagrams 1 and 2 are whole, datagram 3
    // was split (6 of its 32 wire bytes) and must NOT count as committed.
    let mut sink = ScriptedSink::new(7);
    sink.fail_after = Some(40);
    let failure = batch
        .write_to(&mut sink, Duration::from_secs(5))
        .await
        .expect_err("scripted failure");
    assert_eq!(failure.committed_datagrams, 2);
    assert_eq!(failure.committed_payload_bytes, 30);
    assert!(matches!(failure.kind, BatchWriteFailureKind::Io(_)));
    assert_eq!(sink.written.len(), 40);

    // Failing before the first datagram completes commits nothing.
    let mut sink = ScriptedSink::new(5);
    sink.fail_after = Some(11);
    let failure = batch
        .write_to(&mut sink, Duration::from_secs(5))
        .await
        .expect_err("scripted failure");
    assert_eq!(failure.committed_datagrams, 0);
    assert_eq!(failure.committed_payload_bytes, 0);

    // Failing exactly on a boundary commits everything up to it.
    let mut sink = ScriptedSink::new(usize::MAX);
    sink.fail_after = Some(34);
    let failure = batch
        .write_to(&mut sink, Duration::from_secs(5))
        .await
        .expect_err("scripted failure");
    assert_eq!(failure.committed_datagrams, 2);
    assert_eq!(failure.committed_payload_bytes, 30);
}

#[tokio::test]
async fn frame_batch_zero_length_write_is_a_failure_not_a_spin() {
    let mut batch = FrameBatch::new();
    batch.push(b"x").expect("push");
    let mut sink = ScriptedSink::new(0);
    let failure = batch
        .write_to(&mut sink, Duration::from_secs(5))
        .await
        .expect_err("zero write");
    assert_eq!(failure.committed_datagrams, 0);
    match failure.kind {
        BatchWriteFailureKind::Io(e) => assert_eq!(e.kind(), std::io::ErrorKind::WriteZero),
        other => panic!("unexpected {other:?}"),
    }
}

#[tokio::test(start_paused = true)]
async fn frame_batch_stalled_write_hits_deadline_with_committed_prefix() {
    let mut batch = FrameBatch::new();
    batch.push(&[1u8; 10]).expect("push"); // wire 0..12
    batch.push(&[2u8; 10]).expect("push"); // wire 12..24
    let mut sink = ScriptedSink::new(usize::MAX);
    sink.stall_after = Some(12);
    let failure = batch
        .write_to(&mut sink, Duration::from_secs(30))
        .await
        .expect_err("stall");
    assert!(matches!(failure.kind, BatchWriteFailureKind::Stalled));
    assert_eq!(failure.committed_datagrams, 1);
    assert_eq!(failure.committed_payload_bytes, 10);
}

#[tokio::test]
async fn frame_batch_clear_retains_nothing_but_capacity() {
    let mut batch = FrameBatch::new();
    batch.push(b"abc").expect("push");
    batch.clear();
    assert!(batch.is_empty());
    assert_eq!(batch.len(), 0);
    assert_eq!(batch.wire_bytes(), 0);
    assert_eq!(batch.payload_bytes(), 0);
    batch.push(b"z").expect("push");
    let mut sink = ScriptedSink::new(usize::MAX);
    batch
        .write_to(&mut sink, Duration::from_secs(1))
        .await
        .expect("write");
    assert_eq!(decode_all(&sink.written), vec![b"z".to_vec()]);
}

#[tokio::test]
async fn drain_takes_only_already_queued_datagrams_in_fifo_order() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let queued = Arc::new(AtomicUsize::new(0));
    let payloads: Vec<Bytes> = (0u8..5)
        .map(|i| Bytes::from(vec![i; 10 + i as usize]))
        .collect();
    for p in &payloads {
        queued.fetch_add(p.len(), Ordering::Relaxed);
        tx.send(p.clone()).await.expect("send");
    }
    let first = rx.recv().await.expect("first");
    queued.fetch_sub(first.len(), Ordering::Relaxed);

    let mut batch = FrameBatch::new();
    let mut held = None;
    let outcome = drain_queued_datagrams(&mut rx, first, &mut batch, &mut held, &queued);
    assert_eq!(outcome, QueueDrain::Idle);
    assert!(held.is_none());
    assert_eq!(batch.len(), 5);
    assert_eq!(
        queued.load(Ordering::Relaxed),
        0,
        "every dequeued reservation released"
    );

    let mut sink = ScriptedSink::new(usize::MAX);
    batch
        .write_to(&mut sink, Duration::from_secs(1))
        .await
        .expect("write");
    let expected: Vec<Vec<u8>> = payloads.iter().map(|p| p.to_vec()).collect();
    assert_eq!(decode_all(&sink.written), expected);
    // The producer is alive and the queue is empty: the drain did not block.
    assert!(rx.try_recv().is_err());
    drop(tx);
}

#[tokio::test]
async fn drain_holds_the_datagram_that_does_not_fit_and_keeps_fifo() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let queued = Arc::new(AtomicUsize::new(0));
    let big = Bytes::from(vec![9u8; MAX_BATCH_WIRE_BYTES - 100]);
    let overflow = Bytes::from(vec![8u8; 200]);
    let after = Bytes::from_static(b"after");
    for p in [&big, &overflow, &after] {
        queued.fetch_add(p.len(), Ordering::Relaxed);
        tx.send(p.clone()).await.expect("send");
    }
    let first = rx.recv().await.expect("first");
    queued.fetch_sub(first.len(), Ordering::Relaxed);

    let mut batch = FrameBatch::new();
    let mut held = None;
    let outcome = drain_queued_datagrams(&mut rx, first, &mut batch, &mut held, &queued);
    assert_eq!(outcome, QueueDrain::Idle);
    assert_eq!(batch.len(), 1, "the overflow datagram did not join");
    assert_eq!(held.as_deref(), Some(&overflow[..]));
    // The held datagram's reservation was released when it was dequeued.
    assert_eq!(queued.load(Ordering::Relaxed), after.len());

    // Next pass opens with the held datagram, then drains `after`: FIFO intact.
    let first = held.take().expect("held");
    let outcome = drain_queued_datagrams(&mut rx, first, &mut batch, &mut held, &queued);
    assert_eq!(outcome, QueueDrain::Idle);
    assert!(held.is_none());
    assert_eq!(batch.len(), 2);
    assert_eq!(queued.load(Ordering::Relaxed), 0);
    let mut sink = ScriptedSink::new(usize::MAX);
    batch
        .write_to(&mut sink, Duration::from_secs(1))
        .await
        .expect("write");
    assert_eq!(
        decode_all(&sink.written),
        vec![overflow.to_vec(), after.to_vec()]
    );
    drop(tx);
}

#[tokio::test]
async fn drain_reports_disconnect_after_taking_the_remaining_datagrams() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let queued = Arc::new(AtomicUsize::new(0));
    for p in [b"a".as_slice(), b"b", b"c"] {
        queued.fetch_add(p.len(), Ordering::Relaxed);
        tx.send(Bytes::copy_from_slice(p)).await.expect("send");
    }
    drop(tx);
    let first = rx.recv().await.expect("first");
    queued.fetch_sub(first.len(), Ordering::Relaxed);

    let mut batch = FrameBatch::new();
    let mut held = None;
    let outcome = drain_queued_datagrams(&mut rx, first, &mut batch, &mut held, &queued);
    assert_eq!(outcome, QueueDrain::Disconnected);
    assert_eq!(
        batch.len(),
        3,
        "queued datagrams are still flushed on shutdown"
    );
    assert_eq!(queued.load(Ordering::Relaxed), 0);
}

#[tokio::test]
async fn drain_keeps_zero_length_datagrams_distinct() {
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Bytes>(64);
    let queued = Arc::new(AtomicUsize::new(0));
    for p in [Bytes::new(), Bytes::from_static(b"x"), Bytes::new()] {
        tx.send(p).await.expect("send");
    }
    let first = rx.recv().await.expect("first");
    let mut batch = FrameBatch::new();
    let mut held = None;
    drain_queued_datagrams(&mut rx, first, &mut batch, &mut held, &queued);
    assert_eq!(batch.len(), 3);
    let mut sink = ScriptedSink::new(usize::MAX);
    batch
        .write_to(&mut sink, Duration::from_secs(1))
        .await
        .expect("write");
    assert_eq!(
        decode_all(&sink.written),
        vec![Vec::new(), b"x".to_vec(), Vec::new()]
    );
    drop(tx);
}
