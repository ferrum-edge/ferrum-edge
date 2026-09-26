frame: drain buffered bytes before propagating QUIC connection error

Fixes #338.

## Problem

When a QUIC stack delivers stream data and a connection close in the same receive batch (for example a coalesced `STREAM` + `CONNECTION_CLOSE(H3_NO_ERROR)` on Linux with batched `recvmsg`), `FrameStream` could read the connection error while complete frames or DATA body bytes were already sitting in `BufRecvStream`'s buffer. The error was propagated with `?` and those bytes were thrown away, so a response that was already on the wire came back as a connection error. `H3_NO_ERROR` is the RFC 9114 §8.1 code for a graceful shutdown, so backends that close correctly (request limits, draining, rolling deploys) showed up as failures.

Quinn is not at fault: it hands out buffered stream chunks before it reports the connection state. The loss happens in h3's frame layer.

## Design

Updated to current `master` with a merge. `poll_next` on `master` already decodes buffered frames before it polls the transport (#344), so the remaining gap is `poll_data`, and what happens after it.

- **Drain buffered frames and body before a connection error.** When `poll_data` reads a connection error (`StreamErrorIncoming::ConnectionErrorIncoming`) it stores it on `FrameStream` and keeps returning buffered body bytes. `poll_next` keeps decoding buffered frames (for example trailers that were in the same chunk). The transport is not polled again while an error is pending.
- **Surface the stored error exactly once.** The first `poll_next` or `poll_data` that finds nothing buffered returns the stored error and clears it. A connection error that truncates a DATA frame delivers the buffered part of the body and then returns the connection error, not `UnexpectedEnd`.
- **Never defer a stream reset.** A peer `RESET_STREAM` (`StreamTerminated`), and any other stream-level error, surfaces on the poll that reads it, ahead of buffered bytes, as stock h3 does. Quinn reports a reset once and frees the stream, and RFC 9114 §7.1 only makes a truncated frame a connection error when the stream terminates cleanly. Deferring a reset would turn a DATA frame it truncated into `UnexpectedEnd`, which the request stream escalates to a connection-level `H3_FRAME_ERROR` that tears down every other stream on the connection. `FrameStreamError::is_connection_error` decides what can be deferred.

The non-error path is unchanged. Public API is unchanged: one private field on `FrameStream` and one private helper on `FrameStreamError`.

## Credit

Thanks to @Streetblock for the review. They found that the first version kept the deferred error in a poll-local variable, so it was lost once `poll_data` returned the body, and that the HEADERS test did not really read the error with the frame buffered. This update stores the error on `FrameStream`, following their fix in Streetblock/h3@b24e0af. It is adapted to `master`'s decode-first `poll_next` and to the stream-reset rule above, and credited with a `Co-authored-by` trailer.

## Tests

All in `h3/src/frame.rs`. `FakeRecv` gains `chunk_then_error`, which makes the transport report an error after its last chunk instead of end of stream.

- `poll_next_drains_buffered_headers_before_quic_close`: `poll_data` reads the connection error while the DATA body and a complete trailing HEADERS frame are buffered. The body and the trailers are delivered, the error follows exactly once without another transport poll, and later polls go back to the transport.
- `poll_data_drains_buffered_body_before_quic_close`: the buffered body is delivered and the next `poll_next` returns `Err(FrameStreamError::Quic(_))` (the assertion from the review).
- `poll_data_surfaces_quic_close_over_a_truncated_buffered_body`: a connection error that truncates a DATA frame delivers the buffered part, then the connection error rather than `UnexpectedEnd`.
- `poll_data_surfaces_stream_reset_over_a_truncated_buffered_body`: a reset that truncates a DATA frame whose tail is still buffered surfaces as the reset, with its code.
- `poll_data_surfaces_stream_reset_over_a_buffered_frame`: a reset read while whole frames are buffered surfaces as the reset, with its code.

## Downstream context

Ferrum Edge ships the same fix in a vendored copy (ferrum-edge/ferrum-edge#5741), including the stream-reset exemption. The gateway hit the reset case as a client reading a response cut mid-frame, and as a server reading a request body reset mid-frame.

## Refs

- RFC 9114 §7.1 (frame layout and truncated frames), §8.1 (error codes)
- RFC 9000 §3.2 (receive-stream states on reset)
- #338
