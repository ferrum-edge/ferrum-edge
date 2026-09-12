//! Lazy response coalescing (issue #5040).
//!
//! `proxy::body::Coalescing` is the ONE adapter behind every coalesced
//! streaming response — reqwest HTTP/1.1 + HTTP/2, direct-H2 / gRPC, and
//! native HTTP/3. It used to reserve its aggregation buffer (up to the 128 KiB
//! `COALESCE_TARGET`) in the constructor and copy every sub-target frame into
//! it, so the common one-frame response paid an allocation and a full payload
//! copy it never needed, and an idle body paid the reservation for nothing.
//!
//! These tests pin the lazy contract on the production adapter through
//! `_test_support::CoalesceProbe`: the first frame is HELD, not copied, and the
//! `BytesMut` appears only once a second frame must be merged into it. Every
//! documented behavior around that is asserted unchanged — target-size flush,
//! flush-on-`Pending`, the HTTP/3 timed flush, trailer and error stashing,
//! `size_hint`/`is_end_stream`, the large-frame bypass, and empty frames.
//!
//! `response_coalescing_allocation_tests` carries the allocator-level proof.

use std::sync::atomic::Ordering;
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::_test_support::{CoalesceProbe, CoalesceStep, default_coalesce_target_bytes};

/// The native-HTTP/3 coalesce window these tests use: flush target and
/// aggregation capacity alike.
const WINDOW: usize = 16 * 1024;

/// A distinct heap payload: a copy shows up as a pointer change rather than as
/// an allocator coincidence.
fn payload(byte: u8, len: usize) -> Bytes {
    Bytes::from(vec![byte; len])
}

/// Identity of the storage behind a `Bytes` — never its contents.
fn storage_id(bytes: &Bytes) -> usize {
    bytes.as_ptr() as usize
}

/// A trailer map with one gRPC status, the shape the gRPC streaming response
/// path carries past the coalescer.
fn grpc_trailers() -> http::HeaderMap {
    let mut trailers = http::HeaderMap::new();
    trailers.insert("grpc-status", "0".parse().expect("static header value"));
    trailers
}

#[test]
fn construction_reserves_no_aggregation_buffer() {
    let steps = vec![CoalesceStep::Data(payload(0x11, 64)), CoalesceStep::End];
    let mut probe = CoalesceProbe::new(steps, default_coalesce_target_bytes(), None);
    probe.construct();

    assert_eq!(probe.buffer_state(), "empty");
    assert_eq!(probe.buffered_len(), 0);
    assert_eq!(
        probe.aggregation_capacity(),
        0,
        "a constructed-but-unpolled body must reserve nothing"
    );
    assert_eq!(
        probe.source_polls().load(Ordering::Acquire),
        0,
        "construction must not poll the backend"
    );
}

#[test]
fn single_data_frame_then_eof_reaches_the_client_on_the_backend_storage() {
    let data = payload(0x11, 64);
    let source = storage_id(&data);
    let steps = vec![CoalesceStep::Data(data), CoalesceStep::End];
    let mut probe = CoalesceProbe::new(steps, default_coalesce_target_bytes(), None);

    let outcome = probe.poll_once();
    let delivered = outcome.data().expect("expected the held DATA frame");
    assert_eq!(delivered.len(), 64);
    assert_eq!(
        storage_id(delivered),
        source,
        "a one-frame response must not be copied into an aggregation buffer"
    );
    assert_eq!(
        probe.aggregation_capacity(),
        0,
        "one frame must never allocate an aggregation buffer"
    );
    assert_eq!(probe.retained_region_capacity(), 0);
    assert!(probe.is_end_stream());
    assert_eq!(probe.poll_once().name(), "end");
}

#[test]
fn a_merged_flush_retains_its_region_for_the_next_merge() {
    // Before #5040 the adapter kept ONE region and `split()` it per flush, so a
    // stream that flushes below the target did not allocate a region per flush.
    // Lazy allocation must not give that up: only the FIRST merge allocates.
    let steps = vec![
        CoalesceStep::Data(payload(0xd1, 8)),
        CoalesceStep::Data(payload(0xd2, 8)),
        CoalesceStep::Pending,
        CoalesceStep::Data(payload(0xd3, 8)),
        CoalesceStep::Data(payload(0xd4, 8)),
        CoalesceStep::Pending,
    ];
    let mut probe = CoalesceProbe::new(steps, 4_096, None);

    assert_eq!(probe.poll_once().data().map(Bytes::len), Some(16));
    let retained = probe.retained_region_capacity();
    assert!(
        retained > 0,
        "a merged flush must keep the region's tail for the next merge"
    );

    assert_eq!(probe.poll_once().data().map(Bytes::len), Some(16));
    assert!(
        probe.retained_region_capacity() < retained,
        "the next merge must consume the retained region, not a fresh one"
    );
}

#[test]
fn single_data_frame_then_pending_flushes_without_copying() {
    let data = payload(0x22, 128);
    let source = storage_id(&data);
    let steps = vec![
        CoalesceStep::Data(data),
        CoalesceStep::Pending,
        CoalesceStep::Pending,
    ];
    let mut probe = CoalesceProbe::new(steps, 1_000, None);

    let outcome = probe.poll_once();
    let delivered = outcome.data().expect("Pending must flush what is held");
    assert_eq!(
        storage_id(delivered),
        source,
        "flush-on-Pending must hand back the backend's own storage"
    );
    assert_eq!(probe.buffer_state(), "empty");
    assert_eq!(probe.poll_once().name(), "pending");
}

#[test]
fn single_data_frame_then_trailers_flushes_data_first_without_copying() {
    let data = payload(0x33, 96);
    let source = storage_id(&data);
    let steps = vec![
        CoalesceStep::Data(data),
        CoalesceStep::Trailers(grpc_trailers()),
        CoalesceStep::End,
    ];
    let mut probe = CoalesceProbe::new(steps, 1_000, None);

    let outcome = probe.poll_once();
    let delivered = outcome.data().expect("data must flush before trailers");
    assert_eq!(
        storage_id(delivered),
        source,
        "a stashed trailer must not force the held frame through a copy"
    );
    assert!(
        !probe.is_end_stream(),
        "a stashed trailer must still be delivered"
    );

    let outcome = probe.poll_once();
    let stashed = outcome.trailers().expect("expected the stashed trailer");
    assert_eq!(stashed.get("grpc-status").expect("grpc-status"), "0");
    assert_eq!(probe.poll_once().name(), "end");
}

#[test]
fn single_data_frame_then_error_flushes_data_first_without_copying() {
    let data = payload(0x44, 96);
    let source = storage_id(&data);
    let steps = vec![
        CoalesceStep::Data(data),
        CoalesceStep::Error("backend reset".to_string()),
    ];
    let mut probe = CoalesceProbe::new(steps, 1_000, None);

    let outcome = probe.poll_once();
    let delivered = outcome.data().expect("data must flush before the error");
    assert_eq!(
        storage_id(delivered),
        source,
        "a stashed error must not force the held frame through a copy"
    );
    assert!(
        !probe.is_end_stream(),
        "a stashed error must still be delivered"
    );
    assert_eq!(probe.poll_once().error(), Some("backend reset"));
}

#[test]
fn trailers_with_nothing_held_are_emitted_immediately() {
    let steps = vec![CoalesceStep::Trailers(grpc_trailers()), CoalesceStep::End];
    let mut probe = CoalesceProbe::new(steps, 1_000, None);

    assert!(probe.poll_once().trailers().is_some());
    assert_eq!(probe.aggregation_capacity(), 0);
    assert_eq!(probe.poll_once().name(), "end");
}

#[test]
fn frames_below_the_target_still_merge_into_one_flushed_frame() {
    let steps = vec![
        CoalesceStep::Data(payload(1, 4)),
        CoalesceStep::Data(payload(2, 4)),
        CoalesceStep::Data(payload(3, 4)),
        CoalesceStep::End,
    ];
    let mut probe = CoalesceProbe::new(steps, 10, None);

    let outcome = probe.poll_once();
    let merged = outcome.data().expect("expected one merged frame");
    assert_eq!(merged.len(), 12);
    assert_eq!(&merged[..], &[1, 1, 1, 1, 2, 2, 2, 2, 3, 3, 3, 3][..]);
    assert_eq!(probe.poll_once().name(), "end");
}

#[test]
fn a_frame_at_the_target_bypasses_the_buffer_entirely() {
    let data = payload(0x55, 1_024);
    let source = storage_id(&data);
    let steps = vec![CoalesceStep::Data(data), CoalesceStep::End];
    let mut probe = CoalesceProbe::new(steps, 1_024, None);

    let outcome = probe.poll_once();
    let delivered = outcome.data().expect("expected the bypassed frame");
    assert_eq!(
        storage_id(delivered),
        source,
        "the large-frame bypass must forward the backend's own storage"
    );
    assert_eq!(
        probe.aggregation_capacity(),
        0,
        "the bypass must not allocate an aggregation buffer"
    );
    assert_eq!(probe.buffer_state(), "empty");
}

#[test]
fn empty_frames_are_dropped_and_never_create_an_accumulator() {
    let steps = vec![
        CoalesceStep::Data(Bytes::new()),
        CoalesceStep::Data(Bytes::new()),
        CoalesceStep::End,
    ];
    let mut probe = CoalesceProbe::new(steps, 1_000, None);

    assert_eq!(
        probe.poll_once().name(),
        "end",
        "empty frames must not be emitted as DATA"
    );
    assert_eq!(probe.buffer_state(), "empty");
    assert_eq!(probe.aggregation_capacity(), 0);
}

#[test]
fn size_hint_and_end_stream_semantics_are_unchanged() {
    let steps = vec![CoalesceStep::Data(payload(0x66, 7)), CoalesceStep::End];
    let mut declared = CoalesceProbe::new(steps, 1_000, Some(7));
    declared.construct();
    assert_eq!(declared.size_hint_exact(), Some(7));
    assert!(!declared.is_end_stream());
    assert_eq!(declared.poll_once().data().map(Bytes::len), Some(7));
    assert!(declared.is_end_stream());

    let steps = vec![CoalesceStep::Data(payload(0x77, 7)), CoalesceStep::End];
    let mut streamed = CoalesceProbe::new(steps, 1_000, None);
    streamed.construct();
    assert_eq!(
        streamed.size_hint_exact(),
        None,
        "an undeclared length must not become an exact size hint"
    );
}

#[tokio::test]
async fn a_held_sub_target_frame_stays_uncopied_until_a_second_frame_merges() {
    // A long flush interval keeps the timer from firing, so each poll reports
    // the accumulator state the H3 path parks in between backend chunks.
    let first = payload(0xa1, 48);
    // Held so the first frame's storage cannot be freed and its address reused
    // by the aggregation buffer, which would make the copy assertion ambiguous.
    let retained = first.clone();
    let source = storage_id(&retained);
    let steps = vec![
        CoalesceStep::Data(first),
        CoalesceStep::Pending,
        CoalesceStep::Data(payload(0xa2, 32)),
        CoalesceStep::Pending,
    ];
    let interval = Duration::from_secs(60);
    let mut probe = CoalesceProbe::with_flush_after(steps, WINDOW, WINDOW, None, interval);

    assert_eq!(probe.poll_once().name(), "pending");
    assert_eq!(
        probe.buffer_state(),
        "single",
        "one held frame must not allocate an aggregation buffer"
    );
    assert_eq!(probe.buffered_len(), 48);
    assert_eq!(probe.aggregation_capacity(), 0);

    assert_eq!(probe.poll_once().name(), "pending");
    assert_eq!(
        probe.buffer_state(),
        "merged",
        "the second frame is what allocates the aggregation buffer"
    );
    assert_eq!(probe.buffered_len(), 80);
    assert!(probe.aggregation_capacity() >= WINDOW);

    // The scripted source is out of steps, which replays as end-of-stream, so
    // this poll flushes without waiting on the (deliberately long) timer. The
    // merged payload is both frames in order, on storage of its own: the copy
    // happens exactly once, on merge.
    let outcome = probe.poll_once();
    let flushed = outcome.data().expect("EOF must flush what is held");
    assert_eq!(flushed.len(), 80);
    assert_ne!(storage_id(flushed), source);
    assert_eq!(&flushed[..48], &[0xa1u8; 48][..]);
    assert_eq!(&flushed[48..], &[0xa2u8; 32][..]);
    drop(retained);
}

#[tokio::test]
async fn the_h3_timed_flush_still_releases_a_held_frame_without_copying() {
    let data = payload(0xb1, 64);
    let source = storage_id(&data);
    let steps = vec![CoalesceStep::Data(data), CoalesceStep::Pending];
    let interval = Duration::from_millis(2);
    let mut probe = CoalesceProbe::with_flush_after(steps, WINDOW, WINDOW, None, interval);

    assert_eq!(
        probe.poll_once().name(),
        "pending",
        "a sub-target frame is held until the flush interval elapses"
    );
    assert_eq!(probe.buffer_state(), "single");

    // Real-time margin; Tokio timers never fire early.
    tokio::time::sleep(Duration::from_millis(20)).await;

    let outcome = probe.poll_once();
    let delivered = outcome.data().expect("expected a timer-driven flush");
    assert_eq!(
        storage_id(delivered),
        source,
        "the timed flush must hand back the backend's own storage"
    );
}

#[tokio::test]
async fn empty_frames_do_not_arm_the_flush_timer_or_hold_state() {
    let steps = vec![CoalesceStep::Data(Bytes::new()), CoalesceStep::Pending];
    let interval = Duration::from_millis(2);
    let mut probe = CoalesceProbe::with_flush_after(steps, WINDOW, WINDOW, None, interval);

    assert_eq!(probe.poll_once().name(), "pending");
    assert_eq!(
        probe.buffer_state(),
        "empty",
        "an empty frame must leave the accumulator empty"
    );
    assert_eq!(probe.aggregation_capacity(), 0);
}

#[tokio::test]
async fn cancelling_a_body_with_a_held_frame_drops_the_source_and_stops_polling() {
    let held = payload(0xc1, 64);
    let steps = vec![CoalesceStep::Data(held), CoalesceStep::Pending];
    let interval = Duration::from_secs(60);
    let mut probe = CoalesceProbe::with_flush_after(steps, WINDOW, WINDOW, None, interval);

    assert_eq!(probe.poll_once().name(), "pending");
    assert_eq!(probe.buffer_state(), "single");

    let polls = probe.source_polls();
    let dropped = probe.source_dropped();
    let polls_at_cancel = polls.load(Ordering::Acquire);
    assert!(!dropped.load(Ordering::Acquire));

    drop(probe);

    assert!(
        dropped.load(Ordering::Acquire),
        "cancelling the body must drop the backend source"
    );
    assert_eq!(
        polls.load(Ordering::Acquire),
        polls_at_cancel,
        "a cancelled body must not poll the backend again"
    );
}
