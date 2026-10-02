use std::alloc::{GlobalAlloc, Layout};
use std::collections::VecDeque;
use std::future::Future;
use std::io::{self, IoSlice};
use std::pin::Pin;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};

use bytes::Bytes;
use ferrum_edge::h1_profile::io::{Layer, ObservedIo, RecordParser};
use ferrum_edge::h1_profile::{
    ForwardingAllocator, Scope, current_thread_counters, in_scope, schema,
};
use futures_util::task::noop_waker;
use tokio::io::AsyncWrite;

#[test]
fn h1_profile_library_does_not_claim_global_allocator_installation() {
    // This test executable links the library but has no forwarding global
    // allocator. No test registers/resets process state; parallel tests that
    // exercise local ForwardingAllocator instances cannot change this claim.
    assert!(
        ferrum_edge::h1_profile::render_prometheus()
            .lines()
            .any(|line| line == "ferrum_h1_profile_allocator_installed 0")
    );
}

#[cfg(not(windows))]
#[test]
fn h1_profile_forwards_actual_jemalloc_and_failed_realloc() {
    struct RejectResize;
    // SAFETY: allocations/deallocations forward unchanged to Jemalloc; null
    // realloc leaves the original allocation owned by the caller.
    unsafe impl GlobalAlloc for RejectResize {
        unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
            unsafe { tikv_jemallocator::Jemalloc.alloc(layout) }
        }
        unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
            unsafe { tikv_jemallocator::Jemalloc.dealloc(ptr, layout) }
        }
        unsafe fn realloc(&self, _: *mut u8, _: Layout, _: usize) -> *mut u8 {
            std::ptr::null_mut()
        }
    }
    let allocator = ForwardingAllocator(RejectResize);
    let layout = Layout::from_size_align(32, 16).unwrap();
    let before = current_thread_counters();
    unsafe {
        let pointer = allocator.alloc_zeroed(layout);
        assert!(!pointer.is_null());
        assert_eq!(pointer as usize % 16, 0);
        assert_eq!(std::slice::from_raw_parts(pointer, 32), &[0; 32]);
        pointer.write(42);
        assert!(allocator.realloc(pointer, layout, 64).is_null());
        assert_eq!(pointer.read(), 42);
        allocator.dealloc(pointer, layout);
    }
    let after = current_thread_counters();
    assert_eq!(after[1] - before[1], 1);
    assert_eq!(after[2] - before[2], 1);
    assert_eq!(after[3] - before[3], 1);
    assert_eq!(after[4] - before[4], 96);
    assert_eq!(after[5] - before[5], 32);
    assert_eq!(after[6] - before[6], 1);
    assert_eq!(after[7] - before[7], 32);
    assert_eq!(after[8] - before[8], 64);
    assert_eq!(after[9] - before[9], 32);
}

#[cfg(not(windows))]
#[test]
fn h1_profile_successful_forwarding_preserves_alignment_and_realloc_prefix() {
    let allocator = ForwardingAllocator(tikv_jemallocator::Jemalloc);
    let layout = Layout::from_size_align(32, 16).unwrap();
    let before = current_thread_counters();
    unsafe {
        let pointer = allocator.alloc(layout);
        assert!(!pointer.is_null());
        assert_eq!(pointer as usize % 16, 0);
        std::ptr::write_bytes(pointer, 0x7b, 32);
        let resized = allocator.realloc(pointer, layout, 96);
        assert!(!resized.is_null());
        assert_eq!(resized as usize % 16, 0);
        assert_eq!(std::slice::from_raw_parts(resized, 32), &[0x7b; 32]);
        allocator.dealloc(resized, Layout::from_size_align(96, 16).unwrap());
    }
    let after = current_thread_counters();
    assert_eq!(after[0] - before[0], 1);
    assert_eq!(after[2] - before[2], 1);
    assert_eq!(after[5] - before[5], 128);
    assert_eq!(after[6] - before[6], 0);
}

struct Failing;
// SAFETY: always failing is a valid allocator. No pointer is ever returned.
unsafe impl GlobalAlloc for Failing {
    unsafe fn alloc(&self, _: Layout) -> *mut u8 {
        std::ptr::null_mut()
    }
    unsafe fn dealloc(&self, _: *mut u8, _: Layout) {
        unreachable!("failing allocator never owns an allocation");
    }
}

fn fail_allocation() {
    let allocator = ForwardingAllocator(Failing);
    assert!(unsafe { allocator.alloc(Layout::from_size_align(7, 1).unwrap()) }.is_null());
}

#[test]
fn h1_profile_nested_scopes_are_inclusive_once_and_exclusive_at_top() {
    let before = current_thread_counters();
    in_scope(Scope::BodyOutput, || {
        fail_allocation();
        in_scope(Scope::BodyInput, fail_allocation);
        in_scope(Scope::BodyOutput, fail_allocation);
    });
    fail_allocation();
    let after = current_thread_counters();
    assert_eq!(after[0] - before[0], 4);
    assert_eq!(after[6] - before[6], 4);
    assert_eq!(after[10] - before[10], 3); // inclusive output
    assert_eq!(after[20] - before[20], 1); // inclusive input
    assert_eq!(after[50] - before[50], 2); // exclusive output
    assert_eq!(after[60] - before[60], 1); // exclusive input
}

struct TwoPolls(bool);
impl Future for TwoPolls {
    type Output = ();
    fn poll(mut self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<()> {
        fail_allocation();
        if self.0 {
            Poll::Ready(())
        } else {
            self.0 = true;
            Poll::Pending
        }
    }
}

#[test]
fn h1_profile_scope_is_restored_on_pending_and_migrated_poll() {
    let task = std::thread::spawn(|| {
        let mut future = TwoPolls(false);
        let before = current_thread_counters();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(in_scope(Scope::BodyInput, || Pin::new(&mut future).poll(&mut cx)).is_pending());
        fail_allocation(); // another task on the same worker
        let after = current_thread_counters();
        assert_eq!(after[20] - before[20], 1);
        assert_eq!(after[0] - before[0], 2);
        future
    })
    .join()
    .unwrap();
    std::thread::spawn(move || {
        let mut future = task;
        let before = current_thread_counters();
        let waker = noop_waker();
        let mut cx = Context::from_waker(&waker);
        assert!(in_scope(Scope::BodyInput, || Pin::new(&mut future).poll(&mut cx)).is_ready());
        fail_allocation();
        let after = current_thread_counters();
        assert_eq!(after[20] - before[20], 1);
        assert_eq!(after[0] - before[0], 2);
    })
    .join()
    .unwrap();
}

#[derive(Clone, Copy)]
enum Step {
    Accept(usize),
    Pending,
    Error,
}

struct Writer {
    steps: VecDeque<Step>,
    seen: Arc<Mutex<Vec<Vec<usize>>>>,
    accepted: Arc<Mutex<Vec<u8>>>,
    vectored: bool,
}

impl AsyncWrite for Writer {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        self.poll_write_vectored(cx, &[IoSlice::new(buf)])
    }

    fn poll_write_vectored(
        mut self: Pin<&mut Self>,
        _: &mut Context<'_>,
        bufs: &[IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        self.seen
            .lock()
            .unwrap()
            .push(bufs.iter().map(|b| b.len()).collect());
        match self.steps.pop_front().unwrap() {
            Step::Pending => Poll::Pending,
            Step::Error => Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe))),
            Step::Accept(length) => {
                let mut remaining = length;
                for buf in bufs {
                    let n = remaining.min(buf.len());
                    self.accepted.lock().unwrap().extend_from_slice(&buf[..n]);
                    remaining -= n;
                }
                assert_eq!(remaining, 0);
                Poll::Ready(Ok(length))
            }
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.vectored
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write(cx, &[]).map(|r| r.map(|_| ()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_write(cx, &[]).map(|r| r.map(|_| ()))
    }
}

fn drive(mut writer: impl AsyncWrite + Unpin) {
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let first = [23, 3];
    let second = [3, 0, 3, 10, 11, 12];
    let bufs = [
        IoSlice::new(&first),
        IoSlice::new(&[]),
        IoSlice::new(&second),
    ];
    assert!(writer.is_write_vectored());
    assert!(matches!(
        Pin::new(&mut writer).poll_write_vectored(&mut cx, &bufs),
        Poll::Ready(Ok(3))
    ));
    assert!(
        Pin::new(&mut writer)
            .poll_write(&mut cx, &second[1..])
            .is_pending()
    );
    let error = Pin::new(&mut writer).poll_write(&mut cx, &second[1..]);
    assert!(matches!(error, Poll::Ready(Err(e)) if e.kind() == io::ErrorKind::BrokenPipe));
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut cx, &second[1..]),
        Poll::Ready(Ok(1))
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_write(&mut cx, &second[2..]),
        Poll::Ready(Ok(4))
    ));
    assert!(Pin::new(&mut writer).poll_flush(&mut cx).is_pending());
    assert!(matches!(
        Pin::new(&mut writer).poll_flush(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_flush(&mut cx),
        Poll::Ready(Ok(()))
    ));
    assert!(Pin::new(&mut writer).poll_shutdown(&mut cx).is_pending());
    assert!(matches!(
        Pin::new(&mut writer).poll_shutdown(&mut cx),
        Poll::Ready(Err(_))
    ));
    assert!(matches!(
        Pin::new(&mut writer).poll_shutdown(&mut cx),
        Poll::Ready(Ok(()))
    ));
}

#[test]
fn h1_profile_io_preserves_partial_vectors_pending_errors_and_control_polls() {
    let mut outputs = Vec::new();
    let before = current_thread_counters();
    for observed in [false, true] {
        let seen = Arc::new(Mutex::new(Vec::new()));
        let accepted = Arc::new(Mutex::new(Vec::new()));
        let writer = Writer {
            vectored: true,
            steps: VecDeque::from([
                Step::Accept(3),
                Step::Pending,
                Step::Error,
                Step::Accept(1),
                Step::Accept(4),
                Step::Pending,
                Step::Error,
                Step::Accept(0),
                Step::Pending,
                Step::Error,
                Step::Accept(0),
            ]),
            seen: seen.clone(),
            accepted: accepted.clone(),
        };
        if observed {
            drive(ObservedIo::new(writer, Layer::TlsWireMixed));
        } else {
            drive(writer);
        }
        outputs.push((
            seen.lock().unwrap().clone(),
            accepted.lock().unwrap().clone(),
        ));
    }
    assert_eq!(outputs[0], outputs[1]);
    assert_eq!(outputs[1].0[0], [2, 0, 6]);
    assert_eq!(outputs[1].1, [23, 3, 3, 0, 3, 10, 11, 12]);
    let after = current_thread_counters();
    let base = schema::IO_BASE + 3 * schema::IO_FIELDS;
    assert_eq!(after[base + 13] - before[base + 13], 1);
    assert_eq!(after[base + 14] - before[base + 14], 8);
    assert_eq!(after[base + 15] - before[base + 15], 0);
    assert_eq!(after[base + 3] - before[base + 3], 8);
    assert_eq!(after[base + 4] - before[base + 4], 2);
    assert_eq!(after[base + 5] - before[base + 5], 1);
    assert_eq!(after[base + 6] - before[base + 6], 1);
    for offset in [7, 10] {
        assert_eq!(after[base + offset] - before[base + offset], 3);
        assert_eq!(after[base + offset + 1] - before[base + offset + 1], 1);
        assert_eq!(after[base + offset + 2] - before[base + offset + 2], 1);
    }
}

#[test]
fn h1_profile_tls_parser_fragmentation_empty_records_fault_and_incomplete() {
    let before = current_thread_counters();
    let mut parser = RecordParser::default();
    for byte in [23, 3, 3, 0, 1, 42, 22, 3, 3, 0, 0] {
        parser.observe(&[byte]);
    }
    assert!(!parser.incomplete());
    parser.observe(&[23, 3]);
    assert!(parser.incomplete());
    parser.observe(&[3, 255, 255]);
    parser.observe(&[23, 3, 3, 0, 0]); // failed parsers stay failed
    let after = current_thread_counters();
    let base = schema::IO_BASE + 3 * schema::IO_FIELDS;
    assert_eq!(after[base + 13] - before[base + 13], 2);
    assert_eq!(after[base + 15] - before[base + 15], 1);
}

#[test]
fn h1_profile_terminal_partial_record_is_reported() {
    let before = current_thread_counters();
    let writer = Writer {
        vectored: true,
        steps: VecDeque::from([Step::Accept(2)]),
        seen: Arc::new(Mutex::new(Vec::new())),
        accepted: Arc::new(Mutex::new(Vec::new())),
    };
    let mut observed = ObservedIo::new(writer, Layer::TlsWireMixed);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let result = Pin::new(&mut observed).poll_write(&mut cx, &[23, 3, 3, 0, 3]);
    assert!(matches!(result, Poll::Ready(Ok(2))));
    drop(observed);
    let after = current_thread_counters();
    let base = schema::IO_BASE + 3 * schema::IO_FIELDS;
    assert_eq!(after[base + 16] - before[base + 16], 1);
    assert_eq!(after[base + 13] - before[base + 13], 0);
}

#[test]
fn h1_profile_io_preserves_false_vectored_flag_and_read_passthrough() {
    use tokio::io::{AsyncRead, ReadBuf};

    let writer = Writer {
        vectored: false,
        steps: VecDeque::new(),
        seen: Arc::new(Mutex::new(Vec::new())),
        accepted: Arc::new(Mutex::new(Vec::new())),
    };
    assert!(!ObservedIo::new(writer, Layer::ClearMixed).is_write_vectored());
    let mut observed = ObservedIo::new(&b"unchanged"[..], Layer::TlsWireMixed);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let mut storage = [0; 16];
    let mut buf = ReadBuf::new(&mut storage);
    assert!(matches!(
        Pin::new(&mut observed).poll_read(&mut cx, &mut buf),
        Poll::Ready(Ok(()))
    ));
    assert_eq!(buf.filled(), b"unchanged");
}

#[test]
fn h1_profile_body_boundaries_preserve_all_poll_results() {
    use ferrum_edge::h1_profile::ObservedStream;
    use futures_util::Stream;
    use http_body::Frame;

    type FramePoll = Poll<Option<Result<Frame<Bytes>, io::Error>>>;
    let mut steps: VecDeque<FramePoll> = VecDeque::from([
        Poll::Pending,
        Poll::Ready(Some(Ok(Frame::data(Bytes::new())))),
        Poll::Ready(Some(Ok(Frame::data(Bytes::from_static(b"hello"))))),
        Poll::Ready(Some(Ok(Frame::trailers(http::HeaderMap::new())))),
        Poll::Ready(Some(Err(io::Error::from(io::ErrorKind::UnexpectedEof)))),
        Poll::Ready(None),
    ]);
    let stream = futures_util::stream::poll_fn(move |_| steps.pop_front().unwrap());
    let mut observed = ObservedStream::new(stream, 0);
    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let before = current_thread_counters();
    assert!(Pin::new(&mut observed).poll_next(&mut cx).is_pending());
    for _ in 0..3 {
        assert!(matches!(
            Pin::new(&mut observed).poll_next(&mut cx),
            Poll::Ready(Some(Ok(_)))
        ));
    }
    assert!(matches!(
        Pin::new(&mut observed).poll_next(&mut cx),
        Poll::Ready(Some(Err(e))) if e.kind() == io::ErrorKind::UnexpectedEof
    ));
    assert!(matches!(
        Pin::new(&mut observed).poll_next(&mut cx),
        Poll::Ready(None)
    ));
    let after = current_thread_counters();
    let base = schema::BODY_BASE;
    for (offset, amount) in [
        (0, 6),
        (1, 2),
        (2, 5),
        (3, 1),
        (4, 1),
        (5, 1),
        (6, 1),
        (7, 1),
        (8, 1),
    ] {
        assert_eq!(after[base + offset] - before[base + offset], amount);
    }
}

#[test]
fn h1_profile_body_input_observer_counts_only_an_h1_boundary() {
    // The direct HTTP/1.1 pool streams a hyper body, not a reqwest stream; its
    // input boundary must count like `ObservedStream` and forward the body's
    // framing signals unchanged, while an HTTP/2 body (`None`) stays uncounted.
    use ferrum_edge::h1_profile::ObservedBody;
    use http_body::Body;

    let waker = noop_waker();
    let mut cx = Context::from_waker(&waker);
    let base = schema::BODY_BASE + schema::BODY_FIELDS;

    let before = current_thread_counters();
    let body = http_body_util::Full::new(Bytes::from_static(b"hello"));
    let mut observed = ObservedBody::new(body, Some(1));
    assert_eq!(observed.size_hint().exact(), Some(5));
    assert!(!observed.is_end_stream());
    let Poll::Ready(Some(Ok(frame))) = Pin::new(&mut observed).poll_frame(&mut cx) else {
        panic!("first poll must yield the DATA frame");
    };
    assert_eq!(frame.into_data().unwrap(), Bytes::from_static(b"hello"));
    assert!(observed.is_end_stream());
    assert!(matches!(
        Pin::new(&mut observed).poll_frame(&mut cx),
        Poll::Ready(None)
    ));
    let after = current_thread_counters();
    for (offset, amount) in [(0, 2), (1, 1), (2, 5), (5, 1), (8, 1)] {
        assert_eq!(after[base + offset] - before[base + offset], amount);
    }
    let direct = schema::BODY_BASE;
    assert_eq!(after[direct + 2], before[direct + 2]);

    let before = current_thread_counters();
    let body = http_body_util::Full::new(Bytes::from_static(b"h2"));
    let mut unobserved = ObservedBody::new(body, None);
    assert!(matches!(
        Pin::new(&mut unobserved).poll_frame(&mut cx),
        Poll::Ready(Some(Ok(_)))
    ));
    let after = current_thread_counters();
    for boundary in [schema::BODY_BASE, base] {
        assert_eq!(after[boundary], before[boundary]);
        assert_eq!(after[boundary + 2], before[boundary + 2]);
    }
}

#[test]
fn h1_profile_copy_sites_count_payload_copies_only() {
    use ferrum_edge::_test_support::{CoalesceProbe, CoalesceStep};
    let before = current_thread_counters();
    let data = Bytes::from_static(b"abc");
    let mut single = CoalesceProbe::new(
        vec![CoalesceStep::Data(data.clone()), CoalesceStep::End],
        100,
        None,
    );
    assert_eq!(single.poll_once().data().unwrap().as_ptr(), data.as_ptr());
    let after_single = current_thread_counters();
    assert_eq!(
        after_single[schema::COPY_PROMOTE],
        before[schema::COPY_PROMOTE]
    );
    let mut merged = CoalesceProbe::new(
        vec![
            CoalesceStep::Data(data.clone()),
            CoalesceStep::Data(data.clone()),
            CoalesceStep::Data(data),
            CoalesceStep::End,
        ],
        100,
        None,
    );
    assert_eq!(merged.poll_once().data().unwrap().len(), 9);
    let after = current_thread_counters();
    assert_eq!(
        after[schema::COPY_PROMOTE] - before[schema::COPY_PROMOTE],
        6
    );
    assert_eq!(after[schema::COPY_MERGE] - before[schema::COPY_MERGE], 3);
}
