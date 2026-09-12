//! Allocator-level proof for lazy response coalescing (issue #5040).
//!
//! The audit's isolated release-build probe measured this on the pre-fix
//! `proxy::body::Coalescing`:
//!
//! ```text
//! 64-byte DATA + EOF, target=131072:
//!   construction: 1 allocation, 131072 requested bytes
//!   through returned DATA: 2 allocations, 131112 requested bytes
//!   original payload storage reused: false
//! constructed but unpolled body: 1 allocation, 131072 requested bytes
//! 128-KiB bypass DATA: 1 allocation, 131072 requested bytes
//! ```
//!
//! These tests reproduce that probe against the PRODUCTION adapter through
//! `_test_support::CoalesceProbe`. Counting is thread-local, so a parallel test
//! thread cannot pollute a window, and every assertion is on the delta across a
//! measured window rather than on any process-wide total — the allocator is a
//! thin wrapper over `System`, which stays the backing allocator, so numbers
//! outside those windows are whatever the rest of the binary happens to do.
//!
//! A `#[global_allocator]` is per binary, so this installs the counter for all
//! of `unit_gateway_core_tests`. It adds two thread-local counter updates per
//! allocation and changes no allocation behavior.
//!
//! These are allocation REQUESTS, not resident memory and not throughput.
//! `response_coalescing_lazy_tests` carries the behavioral contract.

use std::alloc::{GlobalAlloc, Layout, System};
use std::cell::Cell;

use bytes::Bytes;
use ferrum_edge::_test_support::{CoalesceProbe, CoalesceStep, default_coalesce_target_bytes};

thread_local! {
    /// Allocation requests made on this thread.
    static ALLOC_COUNT: Cell<usize> = const { Cell::new(0) };
    /// Bytes those requests asked for.
    static ALLOC_BYTES: Cell<usize> = const { Cell::new(0) };
}

struct CountingAllocator;

// SAFETY: every method forwards to `System` unchanged — the same allocator the
// test binaries already use — and the accounting it adds first is two
// thread-local `Cell<usize>` updates, which allocate nothing and so cannot
// re-enter the allocator. `try_with` keeps a TLS access during thread teardown
// from unwinding out of `alloc`.
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc(layout) }
    }

    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        record(layout.size());
        unsafe { System.alloc_zeroed(layout) }
    }

    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, new_size: usize) -> *mut u8 {
        record(new_size);
        unsafe { System.realloc(ptr, layout, new_size) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static COUNTING_ALLOCATOR: CountingAllocator = CountingAllocator;

/// Record one allocation request against this thread's counters.
fn record(size: usize) {
    let _ = ALLOC_COUNT.try_with(|count| count.set(count.get() + 1));
    let _ = ALLOC_BYTES.try_with(|bytes| bytes.set(bytes.get() + size));
}

/// Allocation requests made by `body` on THIS thread: `(count, bytes)`.
fn measure<T>(body: impl FnOnce() -> T) -> ((usize, usize), T) {
    let count_before = ALLOC_COUNT.with(Cell::get);
    let bytes_before = ALLOC_BYTES.with(Cell::get);
    let value = body();
    let count = ALLOC_COUNT.with(Cell::get) - count_before;
    let bytes = ALLOC_BYTES.with(Cell::get) - bytes_before;
    ((count, bytes), value)
}

/// Pay for any first-touch lazy state on this test's thread before a measured
/// window opens. Each `#[test]` runs on its own thread and the counters are
/// thread-local, so this cannot leak into another test.
fn warm_up() {
    let payload = Bytes::from_static(&[7u8; 64]);
    let steps = vec![CoalesceStep::Data(payload), CoalesceStep::End];
    let mut probe = CoalesceProbe::new(steps, default_coalesce_target_bytes(), None);
    probe.construct();
    assert!(probe.poll_once().data().is_some());
}

#[test]
fn constructing_a_default_target_coalescer_allocates_nothing() {
    warm_up();
    let payload = Bytes::from_static(&[7u8; 64]);
    let steps = vec![CoalesceStep::Data(payload), CoalesceStep::End];
    let mut probe = CoalesceProbe::new(steps, default_coalesce_target_bytes(), None);

    // The pre-fix adapter reserved one 128 KiB aggregation buffer right here,
    // whether or not the body was ever polled.
    let ((count, bytes), ()) = measure(|| probe.construct());

    assert_eq!(count, 0, "construction must not allocate");
    assert_eq!(bytes, 0, "construction must reserve no bytes");
    assert_eq!(probe.aggregation_capacity(), 0);
}

#[test]
fn a_one_frame_response_allocates_nothing_and_reuses_the_payload_storage() {
    warm_up();
    let payload = Bytes::from_static(&[7u8; 64]);
    let source_ptr = payload.as_ptr() as usize;
    let steps = vec![CoalesceStep::Data(payload), CoalesceStep::End];
    let mut probe = CoalesceProbe::new(steps, default_coalesce_target_bytes(), None);

    // Pre-fix: 2 allocations and 131112 requested bytes through the returned
    // DATA frame, with the backend's own payload storage NOT reused.
    let ((count, bytes), outcome) = measure(|| {
        probe.construct();
        probe.poll_once()
    });

    let delivered = outcome.data().expect("expected one coalesced DATA frame");
    let delivered_ptr = delivered.as_ptr() as usize;
    assert_eq!(delivered_ptr, source_ptr, "storage must be reused");
    assert_eq!(count, 0, "a one-frame response must not allocate");
    assert_eq!(bytes, 0, "a one-frame response must copy nothing");
}

#[test]
fn the_large_frame_bypass_allocates_nothing() {
    warm_up();
    let target = default_coalesce_target_bytes();
    // Built before the window: the payload's own allocation is the backend's,
    // not the coalescer's.
    let payload = Bytes::from(vec![9u8; target]);
    let source_ptr = payload.as_ptr() as usize;
    let steps = vec![CoalesceStep::Data(payload), CoalesceStep::End];
    let mut probe = CoalesceProbe::new(steps, target, None);

    let ((count, bytes), outcome) = measure(|| {
        probe.construct();
        probe.poll_once()
    });

    let delivered = outcome.data().expect("expected the bypassed DATA frame");
    let delivered_ptr = delivered.as_ptr() as usize;
    assert_eq!(delivered_ptr, source_ptr, "storage must be reused");
    assert_eq!(count, 0, "the bypass must not allocate");
    assert_eq!(bytes, 0, "the bypass must copy nothing");
}

#[test]
fn merging_frames_allocates_one_aggregation_buffer_not_one_per_frame() {
    warm_up();
    let steps = vec![
        CoalesceStep::Data(Bytes::from_static(&[1u8; 8])),
        CoalesceStep::Data(Bytes::from_static(&[2u8; 8])),
        CoalesceStep::Data(Bytes::from_static(&[3u8; 8])),
        CoalesceStep::End,
    ];
    let mut probe = CoalesceProbe::new(steps, 4_096, None);
    probe.construct();

    // Merging is where the copy is paid for, deliberately: one target-sized
    // aggregation buffer for the whole batch. `freeze()` may or may not take a
    // second allocation depending on the `bytes` internals, so the bound is
    // what matters — never one allocation per frame.
    let ((count, bytes), outcome) = measure(|| probe.poll_once());

    let merged = outcome.data().expect("expected one merged DATA frame");
    assert_eq!(merged.len(), 24);
    assert!((1..=2).contains(&count), "one merge, one buffer");
    assert!(bytes >= 4_096, "the buffer is target-sized");
}

#[test]
fn repeated_sub_target_flushes_reuse_one_aggregation_region() {
    warm_up();
    let steps = vec![
        CoalesceStep::Data(Bytes::from_static(&[1u8; 8])),
        CoalesceStep::Data(Bytes::from_static(&[2u8; 8])),
        CoalesceStep::Pending,
        CoalesceStep::Data(Bytes::from_static(&[3u8; 8])),
        CoalesceStep::Data(Bytes::from_static(&[4u8; 8])),
        CoalesceStep::Pending,
        CoalesceStep::Data(Bytes::from_static(&[5u8; 8])),
        CoalesceStep::Data(Bytes::from_static(&[6u8; 8])),
        CoalesceStep::Pending,
    ];
    let mut probe = CoalesceProbe::new(steps, 4_096, None);
    probe.construct();

    // Flush-on-`Pending` with two sub-target frames per poll: the pre-#5040
    // adapter allocated ONE region and split it per flush. Lazy allocation must
    // keep that — the first merge pays for the region, later merges reuse it.
    let ((first_count, first_bytes), first) = measure(|| probe.poll_once());
    assert_eq!(first.data().map(Bytes::len), Some(16));
    assert!(first_count >= 1, "the first merge allocates a region");
    assert!(first_bytes >= 4_096, "the region is target-sized");

    let ((second_count, _), second) = measure(|| probe.poll_once());
    assert_eq!(second.data().map(Bytes::len), Some(16));
    assert_eq!(second_count, 0, "the second merge reuses the region");

    let ((third_count, _), third) = measure(|| probe.poll_once());
    assert_eq!(third.data().map(Bytes::len), Some(16));
    assert_eq!(third_count, 0, "the region keeps being reused");
}
