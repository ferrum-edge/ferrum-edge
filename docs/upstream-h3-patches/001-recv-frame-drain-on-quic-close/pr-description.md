# frame: drain buffered bytes before propagating QUIC connection error

Fixes #338.

## Problem

`FrameStream::try_recv` propagates a connection-level error from
`BufRecvStream::poll_read` via `?` before the frame decoder gets to run
against bytes that may already be sitting in `BufRecvStream::buf` from
a previous wake. When a QUIC stack delivers stream data and a
`CONNECTION_CLOSE` (or other connection error) in the same recv batch —
common on Linux with io_uring's batched recvmsg and coalesced UDP
datagrams — buffered HEADERS / DATA bytes are discarded and clients
see `StreamError::ConnectionError` instead of the response that was
already on the wire.

The QUIC layer is innocent here: quinn-proto's per-stream assembler is
not flushed by `close_common`, and `Chunks::next()` returns buffered
chunks before checking connection state. The discard is purely at
h3's frame layer.

`H3_NO_ERROR` is RFC 9114 §8.1's "graceful shutdown without an error"
code. Today, a backend that uses it correctly (per-connection request
limits, drain/rolling deploy, stateless backends) produces 502s at the
client.

## Fix

Hoist the QUIC error out of `try_recv`'s `?` path. When `poll_read`
returns an error, cache it for the current iteration; let
`decoder.decode(self.stream.buf_mut())` run once against whatever is
already buffered. If the decoder produces a frame, surface it normally.
If `decoder.decode` returns `None`, surface the cached error.

Same shape applied to `FrameStream::poll_data` so DATA frame body
bytes that were buffered before the error are not stranded.

### Termination

Each iteration consumes its own cached error in the same iteration it
was observed. A partial-frame buffer that the decoder cannot resolve
exits the loop with the cached error in the `None` arm of the match —
no opportunity for an infinite loop.

### Forward progress

When the decoder DOES produce a frame on the cached-error iteration,
the next poll re-issues `poll_read`, which returns the same error.
The buffered bytes have shrunk by the consumed frame's length, so
iterations are bounded by the buffer size.

## Tests

Two new tests in `frame.rs::tests`:

- `poll_next_drains_buffered_headers_before_quic_close` — synthesizes a
  HEADERS frame followed by an `ApplicationClose { error_code: 0x100 }`
  via `FakeRecv::chunk_then_error`. First poll yields the frame, second
  poll surfaces the error.
- `poll_data_drains_buffered_body_before_quic_close` — same shape on
  the body path. `poll_next` yields the DATA frame header, `poll_data`
  drains the buffered 4-byte body even though the next poll would
  return the connection error.

`FakeRecv` is extended with a `chunk_then_error` helper that queues a
synthetic `StreamErrorIncoming::ConnectionErrorIncoming` for the next
poll after a chunk drains. This is the smallest model of the recv-batch
race that a unit test can construct without a live QUIC backend.

The existing tests in `frame.rs` still pass (the change is a no-op for
the non-error path).

## Compatibility

- Public API: unchanged. `poll_next` and `poll_data` keep the same
  signatures and the same return-shape contract — successful frames
  continue to win, errors continue to surface, the only difference is
  the ordering when both are pending.
- Internal API: no callers outside `frame.rs` are affected.
- Behavioral compat: a backend that intentionally aborts a stream with
  a non-`NO_ERROR` code mid-frame will now have its buffered partial
  data delivered before the error fires. This is arguably more correct
  (the bytes WERE received before the abort) but worth flagging in case
  any downstream depends on the prior "discard on error" semantic.

## Downstream context

This is the root-cause fix for the recv_response analog of [#NNN
(predecessor PR for recv_data graceful close)]. The recv_data path was
worked around at the application layer in commit `dbc9e09` via a
`drain_h3_response_body` helper that re-implemented buffer-aware
recovery one level up. With this PR, that helper can be simplified —
the underlying decoder will already drain on its own — but I've kept
the helper unmodified to keep the change here minimal. Happy to follow
up with simplification once this lands if maintainers prefer.

The recv_response path is the one this PR specifically fixes: at that
boundary the application has no buffered bytes of its own to fall back
on, so the only fix is at h3's frame layer.

## Refs

- RFC 9114 §8.1 — H3 error codes
- Issue #338 — bug report with reproducer and rationale
- Downstream consumer: [ferrum-edge#506](https://github.com/ferrum-edge/ferrum-edge/pull/506) — gateway-side suppression of capability-downgrade for graceful closes (treats the symptom while we await this upstream fix)
