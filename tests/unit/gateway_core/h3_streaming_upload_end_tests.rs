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
//! H3-to-HTTP bridge reader. The first three already wait for the stream's end
//! through `recv_trailers`; these guards pin how they classify a reset there.
//! The plain bridge reads with `recv_data` only, so it must take a second read.
//!
//! h3's error variants cannot be built outside the crate, so the guards are
//! structural. On-the-wire proof for the plain bridge:
//! `h3_streamed_upload_aborts_the_backend_body_on_a_reset_after_the_trailer_section`.

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
fn every_reset_and_every_lost_connection_is_a_client_abort() {
    let helper = region(
        STREAM_UTIL,
        "pub(crate) fn h3_request_read_error_is_client_abort(",
        "\n}\n",
    );
    assert!(
        helper.contains("h3::error::StreamError::RemoteTerminate { .. } => true,"),
        "a peer reset with any code, H3_NO_ERROR included, is a client abort"
    );
    assert!(
        helper.contains("!matches!(connection, h3::error::ConnectionError::Local { .. })"),
        "a remote close or a timed-out connection is a client abort"
    );
    assert!(
        helper.contains("|| connection.is_h3_no_error()"),
        "the gateway's own graceful close is not a malformed request"
    );
    assert!(
        helper.contains("_ => false,"),
        "every other read error stays a malformed request"
    );
}

#[test]
fn the_native_h3_upload_finishes_the_backend_only_after_the_stream_ends() {
    let upload = region(CLIENT, "async fn do_request_streaming_body(", "\n    }\n");
    let end_of_stream = find_after(upload, 0, "frontend_stream.recv_trailers().await");
    let abort_arm = find_after(
        upload,
        end_of_stream,
        "Err(e) if crate::http3::stream_util::h3_request_read_error_is_client_abort(&e) => {",
    );
    let abort_error = find_after(
        upload,
        abort_arm,
        "\"client disconnected while sending request body: {}\"",
    );
    let malformed_error = find_after(
        upload,
        abort_arm,
        "\"malformed client request trailers: {}\"",
    );
    let finish = find_after(upload, end_of_stream, "upload.stream.finish()");
    assert!(
        abort_error < malformed_error && malformed_error < finish,
        "a reset after the trailers must take the client-disconnect arm before the \
         malformed-trailer arm, and both must return before the backend FIN"
    );
}

#[test]
fn the_native_h3_grpc_pump_reports_a_reset_after_the_trailers_as_a_client_abort() {
    let pump = region(SERVER, "async fn run_h3_grpc_upload_pump(", "\n}\n");
    let end_of_stream = find_after(pump, 0, "frontend_recv.recv_trailers()");
    let abort_guard = find_after(
        pump,
        end_of_stream,
        "crate::http3::stream_util::h3_request_read_error_is_client_abort(&error)",
    );
    let abort_fault = find_after(pump, abort_guard, "H3GrpcUploadFault::ClientAbort");
    let malformed_fault = find_after(pump, abort_guard, "H3GrpcUploadFault::MalformedTrailers");
    let finish = find_after(pump, end_of_stream, "backend_send.finish()");
    assert!(
        abort_fault < malformed_fault && malformed_fault < finish,
        "a reset after the trailers must publish ClientAbort, not MalformedTrailers, \
         before the pump could FIN the backend"
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
    let guard = find_after(
        pump,
        error_arm,
        "if !h3_request_read_error_is_client_abort(&e) {",
    );
    let malformed = find_after(
        pump,
        guard,
        "pump_frontend_malformed.store(true, Ordering::Release);",
    );
    let failed = find_after(
        pump,
        malformed,
        "pump_frontend_failed.store(true, Ordering::Release);",
    );
    let reset_backend = find_after(pump, failed, "tx.send(Err(()))");
    assert!(
        error_arm < guard && guard < malformed && malformed < failed && failed < reset_backend,
        "only a malformed trailer section may be flagged malformed; every trailer-phase \
         failure still fails the upload and resets the backend"
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
    let end_of_stream = find_after(reader, body_end, "end = stream.recv_data() => end,");
    let clean_end = find_after(reader, end_of_stream, "if !matches!(end, Ok(None)) {");
    let abort = find_after(
        reader,
        clean_end,
        "reader_reset_flag.store(true, Ordering::Release);",
    );
    let finish = find_after(reader, abort, "finish_reader();");
    assert!(
        body_end < end_of_stream && end_of_stream < clean_end && abort < finish,
        "the reader must confirm the stream's own end, and flag anything else as an \
         abort, before it lets the body end"
    );
}

#[test]
fn the_plain_bridge_body_ends_with_an_error_on_an_aborted_upload() {
    let body = region(
        CROSS_PROTOCOL,
        "let body_stream = futures_util::stream::unfold(",
        "let req_body = reqwest::Body::wrap_stream(body_stream);",
    );
    let finished = find_after(
        body,
        0,
        "let finished = reader_finished.load(Ordering::Acquire);",
    );
    let aborted = find_after(
        body,
        finished,
        "if upload_aborted.load(Ordering::Acquire) {",
    );
    let error = find_after(body, aborted, "std::io::ErrorKind::ConnectionAborted");
    let clean_end = find_after(body, error, "if finished && rx.is_empty() {");
    assert!(
        finished < aborted && aborted < error && error < clean_end,
        "the abort flag must be read after the reader's finish and win over the clean end"
    );
    assert!(
        !body.contains("reader_finished.load(Ordering::Acquire) && rx.is_empty()"),
        "a clean end decided without the abort flag would complete a truncated upload"
    );
    let upload_aborted = "let body_stream_upload_aborted = Arc::clone(&reader_peer_reset);";
    let reset_flag = "let reader_reset_flag = Arc::clone(&reader_peer_reset);";
    assert!(
        CROSS_PROTOCOL.contains(upload_aborted) && CROSS_PROTOCOL.contains(reset_flag),
        "the body stream must watch the flag the reader sets"
    );
}
