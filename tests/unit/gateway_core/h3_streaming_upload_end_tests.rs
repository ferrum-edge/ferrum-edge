//! Issue #6022: a streamed HTTP/3 upload ends at the request stream's own end.
//!
//! `recv_data` also ends at a trailer section, which ends the body but not the
//! request stream. A client that sends its trailers and then resets the stream
//! (any code, `H3_NO_ERROR` included) or loses its connection cancelled the
//! request. Every streaming-upload path must therefore read on to the stream's
//! end before it finishes the backend upload, and report the reset as a client
//! disconnect, never as malformed trailers or a backend fault.
//!
//! The four paths are the native-H3 pool upload (`do_request_streaming_body`),
//! the native-H3 gRPC upload pump, the H3-to-gRPC bridge pump, and the plain
//! H3-to-HTTP bridge reader. All four wait for the stream's end through
//! `recv_trailers`; the plain bridge reader takes it as a second read after its
//! `recv_data` loop.
//!
//! h3's error variants cannot be built outside the crate, so the read and
//! classification guards are structural. The plain bridge's streamed body,
//! which decides whether the backend upload ends cleanly, is driven directly.
//! On-the-wire proof: the `h3_streamed_upload_*` tests in
//! `functional_h3_drain_refusal_hooks_test.rs`.

use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use bytes::Bytes;
use ferrum_edge::http3::cross_protocol::{self as bridge, PlainUploadBodySignals};
use futures_util::StreamExt;
use tokio::sync::Notify;

const STREAM_UTIL: &str = include_str!("../../../src/http3/stream_util.rs");
const CLIENT: &str = include_str!("../../../src/http3/client.rs");
const SERVER: &str = include_str!("../../../src/http3/server.rs");
const CROSS_PROTOCOL: &str = include_str!("../../../src/http3/cross_protocol.rs");

/// The text between `start` and the first `end` after it.
fn region<'a>(src: &'a str, start: &str, end: &str) -> &'a str {
    let after_start = src
        .split(start)
        .nth(1)
        .unwrap_or_else(|| panic!("missing {start:?}"));
    after_start
        .split(end)
        .next()
        .unwrap_or_else(|| panic!("unbounded region after {start:?}"))
}

/// The byte offset of `needle` at or after `from` in `src`.
fn find_after(src: &str, from: usize, needle: &str) -> usize {
    src[from..]
        .find(needle)
        .map(|at| from + at)
        .unwrap_or_else(|| panic!("missing {needle:?} after offset {from}"))
}

#[test]
fn every_peer_reset_and_peer_close_is_a_client_abort() {
    // Issue #6772: the read failure is classified positively. A peer reset or a
    // connection the peer closed or lost is the client's abort; a framing
    // violation is malformed; everything else is the gateway's own close.
    let helper = region(
        STREAM_UTIL,
        "pub(crate) fn classify_h3_request_read_error(",
        "\n}\n",
    );
    assert!(
        helper
            .contains("StreamError::RemoteTerminate { .. } => H3RequestReadFailure::ClientAbort,"),
        "a peer reset with any code, H3_NO_ERROR included, is a client abort"
    );
    assert!(
        helper.contains("ConnectionErrorIncoming::ApplicationClose { .. } => {"),
        "a close the peer sent is a client abort"
    );
    assert!(
        helper.contains(
            "ConnectionError::Timeout { .. } => H3RequestReadFailure::GatewayTerminated,"
        ) && helper.contains(
            "ConnectionErrorIncoming::Timeout | ConnectionErrorIncoming::InternalError(_) => {"
        ),
        "an idle-timeout expiry is local and unproven, never a client abort"
    );
    assert!(
        helper.contains(
            "if h3_code_is_peer_protocol_violation(*code) => H3RequestReadFailure::Malformed,"
        ),
        "only a protocol-violation close is malformed input"
    );
    assert!(
        helper.contains("StreamError::HeaderTooBig { .. } => H3RequestReadFailure::Malformed,"),
        "an oversized trailer section is malformed input"
    );
    assert!(
        helper
            .trim_end()
            .ends_with("_ => H3RequestReadFailure::GatewayTerminated,\n    }"),
        "every other read error is the gateway's own close, never a client abort"
    );
    assert!(
        !helper.contains("is_h3_no_error"),
        "the gateway's own graceful H3_NO_ERROR close is not a client abort"
    );
    let quic = region(
        STREAM_UTIL,
        "fn classify_undefined_connection_error(",
        "\n}\n",
    );
    assert!(
        !quic.contains("LocallyClosed"),
        "Quinn's LocallyClosed (the gateway's own close) is never a client abort"
    );
    for peer in ["ApplicationClosed(_)", "ConnectionClosed(_)", "Reset"] {
        assert!(quic.contains(peer), "{peer} is the peer's close");
    }
    assert!(
        !quic.contains("TimedOut"),
        "an idle-timeout expiry fires locally even for a reachable client"
    );
}

#[test]
fn the_native_h3_upload_finishes_the_backend_only_after_the_stream_ends() {
    let upload = region(CLIENT, "async fn do_request_streaming_body(", "\n    }\n");
    let end_of_stream = find_after(upload, 0, "frontend_stream.recv_trailers().await");
    // Issue #6772: the arm classifies the failed end-of-stream read with the
    // shared classifier; a framing violation there is malformed trailers.
    let classified = find_after(upload, end_of_stream, "h3_client_upload_read_error(");
    let trailers = find_after(
        upload,
        classified,
        "H3ClientRequestFault::MalformedTrailers",
    );
    let finish = find_after(upload, end_of_stream, "upload.stream.finish()");
    assert!(
        classified < trailers && trailers < finish,
        "a failed read after the trailers must return its typed fault before the backend FIN"
    );
    let helper = region(CLIENT, "fn h3_client_upload_read_error(", "\n}\n");
    let abort = find_after(helper, 0, "H3RequestReadFailure::ClientAbort =>");
    find_after(
        helper,
        abort,
        "\"client disconnected while sending request body: {}\"",
    );
    find_after(helper, abort, "\"malformed client request trailers: {}\"");
    find_after(helper, abort, "H3RequestReadFailure::GatewayTerminated =>");
}

#[test]
fn the_native_h3_grpc_pump_reports_a_reset_after_the_trailers_as_a_client_abort() {
    let pump = region(SERVER, "async fn run_h3_grpc_upload_pump(", "\n}\n");
    let end_of_stream = find_after(pump, 0, "frontend_recv.recv_trailers()");
    let classified = find_after(pump, end_of_stream, "H3GrpcUploadFault::from_read_error(");
    let trailers = find_after(pump, classified, "H3GrpcUploadFault::MalformedTrailers");
    let finish = find_after(pump, end_of_stream, "backend_send.finish()");
    assert!(
        classified < trailers && trailers < finish,
        "a failed read after the trailers must publish its classified fault before the \
         pump could FIN the backend"
    );
    let from_read_error = region(SERVER, "fn from_read_error(", "\n    }\n");
    assert!(
        from_read_error.contains("H3RequestReadFailure::ClientAbort => Self::ClientAbort,")
            && from_read_error.contains("H3RequestReadFailure::Malformed => malformed,"),
        "a reset after the trailers is ClientAbort; only a framing violation is malformed"
    );
}

#[test]
fn the_grpc_bridge_pump_flags_a_reset_after_the_trailers_as_a_client_abort() {
    let pump = region(
        CROSS_PROTOCOL,
        "result = recv_half.recv_trailers() => result,",
        "crate::http3::stream_util::halt_request_body(&mut recv_half);",
    );
    let error_arm = find_after(pump, 0, "Err(e) => {");
    let published = find_after(pump, error_arm, "pump_frontend_fault.store(");
    let classified = find_after(pump, published, "grpc_bridge_upload_fault(&e, true)");
    let reset_backend = find_after(pump, classified, "tx.send(Err(()))");
    assert!(
        error_arm < published && published < classified && classified < reset_backend,
        "every trailer-phase failure publishes ONE classified fault before it fails the \
         upload and resets the backend"
    );
    let classifier = region(CROSS_PROTOCOL, "fn grpc_bridge_upload_fault(", "\n}\n");
    assert!(
        classifier.contains("H3RequestReadFailure::ClientAbort => GRPC_BRIDGE_UPLOAD_CLIENT_ABORT,")
            && classifier
                .contains("H3RequestReadFailure::Malformed if trailers => GRPC_BRIDGE_UPLOAD_MALFORMED_TRAILERS,"),
        "a reset after the trailers is a client abort; only a framing violation is malformed"
    );
}

#[test]
fn the_plain_bridge_reader_reads_to_the_end_of_the_stream_before_the_body_ends() {
    let reader = region(
        CROSS_PROTOCOL,
        "let reader_future = async {",
        "// Race resolution:",
    );
    let body_end = find_after(reader, 0, "Ok(None) => {");
    // `recv_trailers`, not a second `recv_data`: a second `recv_data` takes an
    // empty DATA frame or a second HEADERS frame after the trailers as a clean
    // end.
    let end_of_stream = find_after(reader, body_end, "end = stream.recv_trailers() => end,");
    let abort = find_after(reader, end_of_stream, "if end.is_err() {");
    let flag = find_after(
        reader,
        abort,
        "reader_reset_flag.store(true, Ordering::Release);",
    );
    let finish = find_after(reader, flag, "finish_reader();");
    assert!(
        body_end < end_of_stream && end_of_stream < abort && flag < finish,
        "the reader must confirm the stream's own end, and flag anything else as an \
         abort, before it lets the body end"
    );
}

#[test]
fn the_plain_bridge_aborts_the_upload_on_every_gateway_terminal_before_the_halt() {
    // The response-cancel watcher (STOP_SENDING or a lost connection), the
    // connection-closed signal, the response-header wait and the upload
    // deadline can each win the dispatch race before the reader sees its own
    // read error. Each must abort the backend upload, and the abort must be
    // published before the halt that makes the reader finish.
    let dispatch = region(
        CROSS_PROTOCOL,
        "async fn dispatch_plain<S>(",
        "let bytes_sent = bytes_read.load(Ordering::Relaxed);",
    );
    let race = find_after(dispatch, 0, "let resolved = loop {");
    let backend_arm = find_after(dispatch, race, "result = &mut send_future => {");
    assert_eq!(
        dispatch[race..backend_arm]
            .matches("abort_backend_upload = true;")
            .count(),
        4,
        "every gateway terminal ahead of the backend arm must abort the upload"
    );
    let publish = find_after(dispatch, backend_arm, "if abort_backend_upload {");
    let store = find_after(
        dispatch,
        publish,
        "reader_peer_reset.store(true, Ordering::Release);",
    );
    let notify = find_after(dispatch, store, "reader_done_notify.notify_waiters();");
    let halt = find_after(
        dispatch,
        notify,
        "if halt_reader_after_loop && !reader_done {",
    );
    assert!(
        publish < store && store < notify && notify < halt,
        "the abort must reach the body stream before the halted reader finishes"
    );
    let body = find_after(dispatch, 0, "let body_stream = plain_upload_body_stream(");
    find_after(
        dispatch,
        body,
        "upload_aborted: Arc::clone(&reader_peer_reset),",
    );
    find_after(
        dispatch,
        0,
        "let reader_reset_flag = Arc::clone(&reader_peer_reset);",
    );
}

// ── Behaviour of the plain bridge's streamed request body ──────────────────

struct BodySignals {
    finished: Arc<AtomicBool>,
    notify: Arc<Notify>,
    write_timed_out: Arc<AtomicBool>,
    consuming: Arc<AtomicBool>,
    aborted: Arc<AtomicBool>,
}

impl BodySignals {
    fn new() -> Self {
        Self {
            finished: Arc::new(AtomicBool::new(false)),
            notify: Arc::new(Notify::new()),
            write_timed_out: Arc::new(AtomicBool::new(false)),
            consuming: Arc::new(AtomicBool::new(false)),
            aborted: Arc::new(AtomicBool::new(false)),
        }
    }

    fn shared(&self) -> PlainUploadBodySignals {
        PlainUploadBodySignals {
            reader_finished: Arc::clone(&self.finished),
            reader_done_notify: Arc::clone(&self.notify),
            write_timed_out: Arc::clone(&self.write_timed_out),
            transport_consuming: Arc::clone(&self.consuming),
            upload_aborted: Arc::clone(&self.aborted),
        }
    }

    /// The reader's clean finish: the client's FIN was seen.
    fn finish(&self) {
        self.finished.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }

    /// An abort published by the reader or the dispatch loop.
    fn abort(&self) {
        self.aborted.store(true, Ordering::Release);
        self.notify.notify_waiters();
    }
}

type BodyItem = Option<Result<Bytes, std::io::Error>>;

/// The next body item, or `None` when the stream is still waiting.
async fn next_within<S>(stream: &mut S, wait: Duration) -> Option<BodyItem>
where
    S: futures_util::Stream<Item = Result<Bytes, std::io::Error>> + Unpin,
{
    tokio::time::timeout(wait, stream.next()).await.ok()
}

const SETTLE: Duration = Duration::from_millis(50);
const WAKE: Duration = Duration::from_secs(5);

fn assert_aborted(item: Option<BodyItem>) {
    match item {
        Some(Some(Err(error))) => {
            assert_eq!(error.kind(), std::io::ErrorKind::ConnectionAborted);
        }
        Some(Some(Ok(_))) => panic!("an aborted upload yielded more body"),
        Some(None) => panic!("an aborted upload ended cleanly"),
        None => panic!("an aborted upload was never woken"),
    }
}

#[tokio::test]
async fn the_plain_body_ends_cleanly_only_after_the_reader_finishes() {
    let signals = BodySignals::new();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let body = bridge::plain_upload_body_stream_for_test(rx, signals.shared());
    let mut body = Box::pin(body);
    tx.send(Ok(Bytes::from_static(b"chunk"))).await.unwrap();
    let first = next_within(&mut body, WAKE).await;
    assert!(matches!(first, Some(Some(Ok(ref chunk))) if &chunk[..] == b"chunk"));
    assert!(
        signals.consuming.load(Ordering::Acquire),
        "the first poll marks the transport as consuming the upload"
    );
    assert!(
        next_within(&mut body, SETTLE).await.is_none(),
        "a drained channel is not the end of the body until the reader finishes"
    );
    signals.finish();
    assert!(matches!(next_within(&mut body, WAKE).await, Some(None)));
    drop(tx);
}

#[tokio::test]
async fn the_plain_body_aborts_when_the_channel_closes_without_a_clean_finish() {
    let signals = BodySignals::new();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let body = bridge::plain_upload_body_stream_for_test(rx, signals.shared());
    let mut body = Box::pin(body);
    assert!(next_within(&mut body, SETTLE).await.is_none());
    drop(tx);
    assert_aborted(next_within(&mut body, WAKE).await);
}

#[tokio::test]
async fn the_plain_body_ends_cleanly_when_the_channel_closes_after_a_clean_finish() {
    let signals = BodySignals::new();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let body = bridge::plain_upload_body_stream_for_test(rx, signals.shared());
    let mut body = Box::pin(body);
    assert!(next_within(&mut body, SETTLE).await.is_none());
    // Finished without a wake-up, then the channel closes: the close is what
    // the waiting body sees, and the reader's clean finish makes it a clean end.
    signals.finished.store(true, Ordering::Release);
    drop(tx);
    assert!(matches!(next_within(&mut body, WAKE).await, Some(None)));
}

#[tokio::test]
async fn the_plain_body_aborts_on_a_published_abort_while_it_waits() {
    let signals = BodySignals::new();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let body = bridge::plain_upload_body_stream_for_test(rx, signals.shared());
    let mut body = Box::pin(body);
    assert!(next_within(&mut body, SETTLE).await.is_none());
    // The dispatch loop's order: abort, then the halted reader's finish.
    signals.abort();
    signals.finish();
    assert_aborted(next_within(&mut body, WAKE).await);
    drop(tx);
}

#[tokio::test]
async fn the_plain_body_abort_wins_over_queued_chunks_and_a_finished_reader() {
    let signals = BodySignals::new();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    tx.send(Ok(Bytes::from_static(b"queued"))).await.unwrap();
    signals.abort();
    signals.finish();
    let body = bridge::plain_upload_body_stream_for_test(rx, signals.shared());
    let mut body = Box::pin(body);
    assert_aborted(next_within(&mut body, WAKE).await);
    drop(tx);
}

#[tokio::test]
async fn the_plain_body_reports_a_write_timeout_as_a_timeout() {
    let signals = BodySignals::new();
    let (tx, rx) = tokio::sync::mpsc::channel(4);
    let body = bridge::plain_upload_body_stream_for_test(rx, signals.shared());
    let mut body = Box::pin(body);
    assert!(next_within(&mut body, SETTLE).await.is_none());
    signals.write_timed_out.store(true, Ordering::Release);
    signals.finish();
    match next_within(&mut body, WAKE).await {
        Some(Some(Err(error))) => assert_eq!(error.kind(), std::io::ErrorKind::TimedOut),
        _ => panic!("a write timeout must end the body with a timeout error"),
    }
    drop(tx);
}
