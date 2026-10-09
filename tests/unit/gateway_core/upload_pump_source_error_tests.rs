//! Direct upload-pump regressions for Hyper 1.10's explicit inbound H2 errors.
//!
//! Loaded by upload_pump.rs in the library test target so these exercise the
//! private production relay without widening its API or adding a test shim.
//! The strict backend wire and early-response lease controls live in
//! functional::scripted_backend_h2_tests.

use std::collections::VecDeque;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use bytes::Bytes;
use http_body::Frame;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

use super::{BoxError, PUMP_CANCELLED, PUMP_SOURCE_ERROR, PUMP_SOURCE_RESET};
use super::{UploadPumpJoin, UploadPumpOutcome, UploadPumpSource};
use super::{
    is_h2_source_cancel, source_already_reset, source_reset_probe_polls, spawn_upload_pump,
    spawn_upload_pump_with_deferred_write, upload_pump_error_message,
};

const PRIVATE_DETAIL: &str = "private client detail: CANCEL credential=must-not-escape";

#[derive(Default)]
struct BodyState {
    polls: AtomicUsize,
    releases: AtomicUsize,
}

struct ProbeBody<E> {
    frames: VecDeque<Result<Frame<Bytes>, E>>,
    state: Arc<BodyState>,
    clean_end: bool,
}

impl<E> Drop for ProbeBody<E> {
    fn drop(&mut self) {
        self.state.releases.fetch_add(1, Ordering::Release);
    }
}

impl<E: Unpin> http_body::Body for ProbeBody<E> {
    type Data = Bytes;
    type Error = E;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, E>>> {
        let body = self.get_mut();
        body.state.polls.fetch_add(1, Ordering::Relaxed);
        Poll::Ready(body.frames.pop_front())
    }

    fn is_end_stream(&self) -> bool {
        self.clean_end && self.frames.is_empty()
    }

    fn size_hint(&self) -> http_body::SizeHint {
        // A terminal must preserve the advertised byte that was never sent.
        http_body::SizeHint::with_exact(7)
    }
}

fn error_body<E>(error: E) -> (ProbeBody<E>, Arc<BodyState>) {
    let state = Arc::new(BodyState::default());
    let body = ProbeBody {
        frames: VecDeque::from([Err(error)]),
        state: Arc::clone(&state),
        clean_end: false,
    };
    (body, state)
}

#[derive(Debug)]
struct WrappedError(BoxError);

impl std::fmt::Display for WrappedError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(PRIVATE_DETAIL)
    }
}

impl std::error::Error for WrappedError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(self.0.as_ref())
    }
}

// Accept the server's SETTINGS write, then fault while it reads the preface.
#[derive(Debug)]
struct CancelReadIo {
    releases: Arc<AtomicUsize>,
}

impl Drop for CancelReadIo {
    fn drop(&mut self) {
        self.releases.fetch_add(1, Ordering::Release);
    }
}

impl AsyncRead for CancelReadIo {
    fn poll_read(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        _buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Poll::Ready(Err(io::Error::other(h2::Error::from(h2::Reason::CANCEL))))
    }
}

impl AsyncWrite for CancelReadIo {
    fn poll_write(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Poll::Ready(Ok(buf.len()))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }

    fn poll_shutdown(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
}

async fn assert_terminal(
    mut source: UploadPumpSource,
    join: UploadPumpJoin,
    state: &BodyState,
    expected_cancel: bool,
) {
    let error = std::future::poll_fn(|cx| source.poll_frame(cx))
        .await
        .expect("one non-clean terminal")
        .expect_err("a source error cannot become clean EOF");
    assert_eq!(
        source.terminal.load(Ordering::Acquire),
        if expected_cancel {
            PUMP_SOURCE_RESET
        } else {
            PUMP_SOURCE_ERROR
        },
        "publish the source-error terminal before closing the bridge"
    );
    assert_eq!(join.join().await, Some(UploadPumpOutcome::SourceError));
    assert_eq!(state.releases.load(Ordering::Acquire), 1);

    if expected_cancel {
        assert_eq!(
            error.downcast_ref::<h2::Error>().unwrap().reason(),
            Some(h2::Reason::CANCEL)
        );
    } else {
        assert!(error.downcast_ref::<h2::Error>().is_none());
        assert_eq!(
            error.to_string(),
            upload_pump_error_message(UploadPumpOutcome::SourceError)
        );
    }
    assert!(error.source().is_none(), "never retain the source error");
    assert!(!error.to_string().contains(PRIVATE_DETAIL));
    assert!(
        !source.is_end_stream(),
        "no END_STREAM on a truncated upload"
    );
    assert_eq!(source.size_hint().exact(), Some(7 - source.delivered));
    let fused = std::future::poll_fn(|cx| source.poll_frame(cx)).await;
    assert!(fused.is_none());
    assert!(!source.is_end_stream(), "fusing the error is not clean EOF");
}

async fn assert_source_error<E>(error: E, require_end_stream: bool, expected_cancel: bool)
where
    E: Into<BoxError> + Send + Unpin + 'static,
{
    let (body, state) = error_body(error);
    let (source, join) = spawn_upload_pump_with_deferred_write(body, None, 0, require_end_stream);
    assert_terminal(source, join, &state, expected_cancel).await;
    assert_eq!(state.polls.load(Ordering::Relaxed), 1);
}

#[tokio::test]
async fn explicit_cancel_requires_the_incoming_h2_end_stream_gate() {
    assert_source_error(h2::Error::from(h2::Reason::CANCEL), true, true).await;
    assert_source_error(h2::Error::from(h2::Reason::CANCEL), false, false).await;

    let (body, state) = error_body(h2::Error::from(h2::Reason::CANCEL));
    let (source, join) = spawn_upload_pump(body, None, 0, false);
    assert_terminal(source, join, &state, false).await;
}

#[tokio::test]
async fn consumer_armed_pump_carries_the_h2_end_stream_gate() {
    // Issue #6022: the direct-H2 pool installs the consumer-armed pump on a
    // size-limited or authenticated non-gRPC upload. An HTTP/2 frontend's
    // masked reset and explicit CANCEL must end non-clean there too.
    let (mut body, state) = error_body(h2::Error::from(h2::Reason::CANCEL));
    body.frames.clear();
    let (source, join) = spawn_upload_pump(body, None, 0, true);
    assert_terminal(source, join, &state, true).await;

    let (body, state) = error_body(h2::Error::from(h2::Reason::CANCEL));
    let (source, join) = spawn_upload_pump(body, None, 0, true);
    assert_terminal(source, join, &state, true).await;
}

#[tokio::test]
async fn wrapped_cancel_preserves_the_reason_and_discards_private_details() {
    let cause = h2::Error::from(h2::Reason::CANCEL);
    let wrapped = WrappedError(Box::new(WrappedError(Box::new(cause))));
    assert_source_error(wrapped, true, true).await;
    let wrapped = std::io::Error::other(h2::Error::from(h2::Reason::CANCEL));
    assert_source_error(wrapped, true, true).await;
}

#[tokio::test]
async fn noncancel_reasons_and_cancel_text_remain_generic_redacted_source_errors() {
    for reason in [
        h2::Reason::NO_ERROR,
        h2::Reason::INTERNAL_ERROR,
        h2::Reason::PROTOCOL_ERROR,
    ] {
        assert_source_error(h2::Error::from(reason), true, false).await;
        let wrapped = WrappedError(Box::new(h2::Error::from(reason)));
        assert_source_error(wrapped, true, false).await;
    }
    // A typed outer H2 I/O error has no reset reason. A deeper CANCEL must
    // not override that authoritative non-reset error.
    tokio::time::timeout(Duration::from_secs(5), async {
        let releases = Arc::new(AtomicUsize::new(0));
        let io = CancelReadIo {
            releases: Arc::clone(&releases),
        };
        let error = h2::server::handshake(io)
            .await
            .expect_err("read failure must fail the public H2 handshake");
        assert!(error.is_io());
        assert_eq!(error.reason(), None);
        assert!(!error.is_reset());
        let nested = error
            .get_io()
            .expect("H2 transport error")
            .get_ref()
            .expect("typed inner error")
            .downcast_ref::<h2::Error>()
            .expect("nested H2 CANCEL");
        assert_eq!(nested.reason(), Some(h2::Reason::CANCEL));
        assert_eq!(releases.load(Ordering::Acquire), 1);
        assert_source_error(error, true, false).await;
    })
    .await
    .expect("H2 I/O source error proof must finish");
    assert_source_error(PRIVATE_DETAIL.to_string(), true, false).await;
    assert_source_error(std::io::Error::other(PRIVATE_DETAIL), true, false).await;
    let boxed: BoxError = PRIVATE_DETAIL.into();
    assert_source_error(boxed, true, false).await;
}

#[tokio::test]
async fn cancel_after_initial_data_releases_the_source_and_never_polls_later_data() {
    let (mut body, state) = error_body(h2::Error::from(h2::Reason::CANCEL));
    let initial = Bytes::from_static(&[0, 0, 0, 0, 1, b'x']);
    body.frames.push_front(Ok(Frame::data(initial)));
    let later = Bytes::from_static(b"must not forward");
    body.frames.push_back(Ok(Frame::data(later)));
    let (mut source, join) = spawn_upload_pump_with_deferred_write(body, None, 0, true);
    let initial = std::future::poll_fn(|cx| source.poll_frame(cx))
        .await
        .expect("initial DATA")
        .expect("initial DATA result");
    assert_eq!(initial.data_ref().unwrap().as_ref(), [0, 0, 0, 0, 1, b'x']);
    assert!(!source.is_end_stream());
    assert_eq!(source.size_hint().exact(), Some(1));
    assert_terminal(source, join, &state, true).await;
    assert_eq!(state.polls.load(Ordering::Relaxed), 2);
}

#[tokio::test]
async fn masked_reset_is_still_nonclean_but_terminal_trailers_complete_normally() {
    let (mut body, state) = error_body(h2::Error::from(h2::Reason::CANCEL));
    body.frames.clear();
    let (source, join) = spawn_upload_pump_with_deferred_write(body, None, 0, true);
    assert_terminal(source, join, &state, true).await;

    let state = Arc::new(BodyState::default());
    let mut trailers = http::HeaderMap::new();
    trailers.insert("x-upload-complete", http::HeaderValue::from_static("yes"));
    let body = ProbeBody::<std::convert::Infallible> {
        frames: VecDeque::from([
            Ok(Frame::data(Bytes::from_static(b"payload"))),
            Ok(Frame::trailers(trailers.clone())),
        ]),
        state: Arc::clone(&state),
        clean_end: true,
    };
    let (mut source, join) = spawn_upload_pump_with_deferred_write(body, None, 0, true);
    let data = std::future::poll_fn(|cx| source.poll_frame(cx))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(data.data_ref().unwrap().as_ref(), b"payload");
    assert!(!source.is_end_stream());
    let last = std::future::poll_fn(|cx| source.poll_frame(cx))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(last.trailers_ref(), Some(&trailers));
    assert!(source.is_end_stream());
    let ended = std::future::poll_fn(|cx| source.poll_frame(cx)).await;
    assert!(ended.is_none());
    assert_eq!(join.join().await, Some(UploadPumpOutcome::Completed));
    assert_eq!(state.releases.load(Ordering::Acquire), 1);
}

/// A client body whose reset has arrived but has not been polled yet: it is
/// `Pending` until `reset` is set, then yields the reset.
struct LateResetBody {
    reset: Arc<AtomicBool>,
    state: Arc<BodyState>,
}

impl Drop for LateResetBody {
    fn drop(&mut self) {
        self.state.releases.fetch_add(1, Ordering::Release);
    }
}

impl http_body::Body for LateResetBody {
    type Data = Bytes;
    type Error = h2::Error;

    fn poll_frame(
        self: Pin<&mut Self>,
        _cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, h2::Error>>> {
        self.state.polls.fetch_add(1, Ordering::Relaxed);
        if self.reset.load(Ordering::Acquire) {
            Poll::Ready(Some(Err(h2::Error::from(h2::Reason::CANCEL))))
        } else {
            Poll::Pending
        }
    }
}

/// Issue #6038: hyper's frontend stream task drops the direct-H2 handler, and
/// with it a `cancel_on_drop` join, as soon as it sees the client's
/// RST_STREAM. That cancellation can reach the pump before the pump polls the
/// body carrying the same reset. The reset must still reach the backend as
/// CANCEL, not as the gateway's own cancellation, which hyper's writer sends
/// as INTERNAL_ERROR. Without a reset, or without the HTTP/2 end-of-stream
/// gate, the cancellation stays the gateway's own.
#[tokio::test]
async fn dispatcher_cancel_racing_a_client_reset_keeps_the_reset() {
    for (client_reset, require_end_stream, expected) in [
        (true, true, PUMP_SOURCE_RESET),
        (false, true, PUMP_CANCELLED),
        (true, false, PUMP_CANCELLED),
    ] {
        let reset = Arc::new(AtomicBool::new(false));
        let state = Arc::new(BodyState::default());
        let body = LateResetBody {
            reset: Arc::clone(&reset),
            state: Arc::clone(&state),
        };
        // No plan and no write bound: the pump runs on its own task, as a
        // direct-H2 pump does once the response head has arrived.
        let (mut source, join) = spawn_upload_pump(body, None, 0, require_end_stream);
        for _ in 0..8 {
            tokio::task::yield_now().await;
        }
        assert!(
            state.polls.load(Ordering::Relaxed) >= 1,
            "the pump is parked on the client body"
        );
        // The reset arrives, then the handler drop cancels the pump before
        // its task runs again.
        reset.store(client_reset, Ordering::Release);
        assert_eq!(
            join.cancel_and_join().await,
            Some(UploadPumpOutcome::Cancelled)
        );
        assert_eq!(state.releases.load(Ordering::Acquire), 1);
        assert_eq!(source.terminal.load(Ordering::Acquire), expected);

        let error = std::future::poll_fn(|cx| source.poll_frame(cx))
            .await
            .expect("one non-clean terminal")
            .expect_err("a cancelled upload cannot end cleanly");
        if expected == PUMP_SOURCE_RESET {
            let typed = error.downcast_ref::<h2::Error>().expect("a typed reset");
            assert_eq!(typed.reason(), Some(h2::Reason::CANCEL));
        } else {
            assert!(error.downcast_ref::<h2::Error>().is_none());
            assert_eq!(
                error.to_string(),
                upload_pump_error_message(UploadPumpOutcome::Cancelled)
            );
        }
    }
}

#[test]
fn cyclic_source_chains_fail_closed() {
    #[derive(Debug)]
    struct CyclicError;

    impl std::fmt::Display for CyclicError {
        fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            f.write_str(PRIVATE_DETAIL)
        }
    }

    impl std::error::Error for CyclicError {
        fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
            Some(self)
        }
    }

    assert!(!is_h2_source_cancel(Box::new(CyclicError)));
}

#[test]
fn production_incoming_and_infallible_bodies_satisfy_both_spawn_bounds() {
    fn accepts<B>()
    where
        B: http_body::Body<Data = Bytes> + Send + Unpin + 'static,
        B::Error: Into<BoxError> + Send,
    {
        let _ = spawn_upload_pump::<B>;
        let _ = spawn_upload_pump_with_deferred_write::<B>;
    }

    accepts::<hyper::body::Incoming>();
    accepts::<http_body_util::Full<Bytes>>();
    accepts::<http_body_util::Empty<Bytes>>();
    accepts::<ProbeBody<BoxError>>();
    accepts::<ProbeBody<std::io::Error>>();
}

/// How a probed client body ends after its buffered DATA.
#[derive(Clone, Copy, Debug)]
enum ProbeEnd {
    /// An explicit `RST_STREAM(CANCEL)`.
    Cancel,
    /// A masked `RST_STREAM(NO_ERROR)`: EOF without END_STREAM.
    MaskedReset,
    /// The client's own END_STREAM.
    EndStream,
}

/// `frames` DATA frames of `frame_len` bytes, already received, then `end`.
fn buffered_upload(
    frames: usize,
    frame_len: usize,
    end: ProbeEnd,
) -> (ProbeBody<h2::Error>, Arc<BodyState>) {
    let state = Arc::new(BodyState::default());
    let chunk = Bytes::from(vec![0u8; frame_len]);
    let mut queued = VecDeque::with_capacity(frames + 1);
    for _ in 0..frames {
        queued.push_back(Ok(Frame::data(chunk.clone())));
    }
    if matches!(end, ProbeEnd::Cancel) {
        queued.push_back(Err(h2::Error::from(h2::Reason::CANCEL)));
    }
    let body = ProbeBody {
        frames: queued,
        state: Arc::clone(&state),
        clean_end: matches!(end, ProbeEnd::EndStream),
    };
    (body, state)
}

#[test]
fn reset_probe_budget_is_sized_from_the_stream_window() {
    // One poll per 4 KiB of window plus 16 slack polls; the old fixed bound
    // was 16 polls at every window.
    assert_eq!(source_reset_probe_polls(65_535), 16 + 16);
    assert_eq!(source_reset_probe_polls(256 * 1024), 64 + 16);
    assert_eq!(source_reset_probe_polls(8 * 1024 * 1024), 2_048 + 16);
    // Capped at one window of 16 KiB frames at the 128 MiB maximum.
    assert_eq!(source_reset_probe_polls(128 * 1024 * 1024), 8_192 + 16);
    assert_eq!(source_reset_probe_polls(u32::MAX), 8_192 + 16);
}

/// Issue #6038 (from the #6043 review): a client that filled its window while
/// the backend stalled has a full window of DATA buffered ahead of its
/// RST_STREAM. With the default 256 KiB window and 16 KiB frames that is 16
/// frames, and the old 16-poll probe stopped one short of the reset, so the
/// backend got INTERNAL_ERROR instead of the client's CANCEL. The probe must
/// reach the reset behind a full window at every window size and frame size it
/// budgets for.
#[test]
fn reset_probe_reaches_a_reset_behind_a_full_window() {
    for window in [65_535u32, 256 * 1024, 1024 * 1024, 8 * 1024 * 1024] {
        for frame_len in [16_384usize, 8_192, 4_096] {
            let window_len = usize::try_from(window).unwrap();
            let frames = window_len / frame_len;
            for end in [ProbeEnd::Cancel, ProbeEnd::MaskedReset] {
                let (mut body, state) = buffered_upload(frames, frame_len, end);
                assert!(
                    source_already_reset(&mut body, window),
                    "window {window}, {frames} x {frame_len} B, {end:?}"
                );
                assert_eq!(state.polls.load(Ordering::Relaxed), frames + 1);
            }
            let (mut body, _) = buffered_upload(frames, frame_len, ProbeEnd::EndStream);
            assert!(
                !source_already_reset(&mut body, window),
                "a clean END_STREAM is not a reset (window {window}, {frame_len} B)"
            );
        }
    }
}

#[test]
fn reset_probe_stops_after_one_window_of_a_live_upload() {
    // More DATA than one window cannot all be buffered ahead of a reset: the
    // client is still streaming on released credit. The probe stops on the
    // frame that overruns the window instead of draining the live upload.
    let window = 256 * 1024;
    let (mut body, state) = buffered_upload(17, 16_384, ProbeEnd::Cancel);
    assert!(!source_already_reset(&mut body, window));
    assert_eq!(state.polls.load(Ordering::Relaxed), 17);
    assert_eq!(
        body.frames.len(),
        1,
        "the reset after the overrun is not read"
    );
}

#[test]
fn reset_probe_poll_budget_bounds_tiny_frames() {
    // Documented gap: a full window of frames smaller than the budget assumes
    // reaches the backend as the gateway's own cancellation. Still a reset.
    let window = 256 * 1024;
    let budget = source_reset_probe_polls(window);
    let (mut body, state) = buffered_upload(budget, 1_024, ProbeEnd::Cancel);
    assert!(!source_already_reset(&mut body, window));
    assert_eq!(state.polls.load(Ordering::Relaxed), budget);
}

#[test]
fn reset_probe_never_waits_for_data_not_yet_received() {
    let reset = Arc::new(AtomicBool::new(false));
    let state = Arc::new(BodyState::default());
    let mut body = LateResetBody {
        reset: Arc::clone(&reset),
        state: Arc::clone(&state),
    };
    assert!(!source_already_reset(&mut body, 256 * 1024));
    assert_eq!(state.polls.load(Ordering::Relaxed), 1);
    reset.store(true, Ordering::Release);
    assert!(source_already_reset(&mut body, 256 * 1024));
}

/// End to end through a pump parked on a stalled backend: the bridge holds one
/// frame, so the rest of a full window of 8 KiB frames plus the client's
/// CANCEL are still buffered when the dispatcher cancels. The pump must report
/// the client's reset; the old 16-poll probe stopped 15 frames short of it.
#[tokio::test]
async fn cancelled_pump_behind_a_stalled_backend_keeps_the_clients_reset() {
    // The published window is the 256 KiB default in this process: 32 frames
    // of 8 KiB fill it.
    let (body, state) = buffered_upload(32, 8_192, ProbeEnd::Cancel);
    let (source, join) = spawn_upload_pump(body, None, 0, true);
    for _ in 0..8 {
        tokio::task::yield_now().await;
    }
    let polled = state.polls.load(Ordering::Relaxed);
    assert!(
        (1..32).contains(&polled),
        "the pump is parked on the full bridge ({polled} polls)"
    );
    assert_eq!(
        join.cancel_and_join().await,
        Some(UploadPumpOutcome::Cancelled)
    );
    assert_eq!(state.releases.load(Ordering::Acquire), 1);
    assert_eq!(source.terminal.load(Ordering::Acquire), PUMP_SOURCE_RESET);
}
