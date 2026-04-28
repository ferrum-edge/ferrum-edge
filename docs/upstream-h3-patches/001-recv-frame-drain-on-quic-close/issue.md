# `FrameStream::poll_next` / `poll_data` discards already-buffered bytes when QUIC connection error arrives in same recv batch

## Summary

When the underlying QUIC stack delivers stream data **and** a `CONNECTION_CLOSE` (or other connection-level error) in the same recv batch, [`FrameStream::try_recv`](https://github.com/hyperium/h3/blob/master/h3/src/frame.rs) propagates the connection error via `?` before [`FrameDecoder::decode`](https://github.com/hyperium/h3/blob/master/h3/src/frame.rs) gets a chance to consume bytes already sitting in `BufRecvStream::buf`. The application sees `StreamError::ConnectionError(...)` instead of the response it would otherwise have parsed.

The same shape exists in `FrameStream::poll_data`, where partially buffered DATA frame body bytes are stranded.

## Reproducer (sketch)

```text
   QUIC recv batch (single io_uring submission):
     ┌─────────────────────────────────────────┐
     │ STREAM(stream_id=0, FIN=1, data=[H3...]) │
     │ CONNECTION_CLOSE(error_code=H3_NO_ERROR) │
     └─────────────────────────────────────────┘

   Application timeline:
     poll #N   → BufRecvStream::poll_read pulls STREAM bytes into buf
     poll #N+1 → BufRecvStream::poll_read returns Err(ConnectionLost(NO_ERROR))
                 try_recv `?` propagates error
                 decoder.decode never runs against buffered HEADERS frame
                 recv_response → StreamError::ConnectionError
```

This is platform-and-kernel sensitive but reproducible on Linux + io_uring with quinn-udp's batched recv: a fast backend that completes its response and immediately tears down with `H3_NO_ERROR` produces the coalesced datagram that triggers it.

## Why it's a bug

The QUIC layer (quinn-proto / quinn) DOES preserve buffered stream data after CONNECTION_CLOSE — the per-stream assembler is not flushed in `close_common`, and `Chunks::next()` returns buffered chunks before checking connection state. The race is purely at h3's frame layer: `try_recv` assumes `poll_read` is the only source of "more decodable bytes," but on coalesced batches the bytes pulled into `BufRecvStream::buf` on a previous poll are still valid input for the decoder.

`H3_NO_ERROR` is RFC 9114 §8.1's "graceful shutdown without an error" code. A backend that uses it correctly today produces a 502 at the client because of this discarding; the result is functionally equivalent to misclassifying TCP FIN as RST.

## Existing partial fix

[Hyperium PR #NNN](https://github.com/hyperium/h3/pull/NNN) (commit `dbc9e09` in our downstream tree) recovered the recv_data case for response bodies via a `drain_h3_response_body` helper that re-buffers bytes at the application level and detects "graceful close after complete body." That change works around the symptom one layer up but doesn't fix the underlying frame-layer discard. The recv_response path (no headers parsed yet) cannot be similarly worked around because the application has no buffered bytes at that point — only h3 does.

## Proposed fix

Hoist the QUIC error out of `try_recv`'s `?` path. When `poll_read` returns an error, cache it for the current iteration; let `decoder.decode(self.stream.buf_mut())` run once. If the decoder produces a frame, return it normally. If the decoder returns `None` from buffered bytes, surface the cached error.

Same shape in `poll_data`: don't strand partial body bytes.

The fix terminates: each iteration consumes its own cached error, so partial-frame buffers cannot trigger an infinite loop. Forward progress is bounded by the size of the buffered bytes, which can only shrink.

A working diff plus two new regression tests (using an extended `FakeRecv` that supports `chunk_then_error`) accompanies this issue as PR. The tests exercise both the headers and body paths against a synthetic `ConnectionErrorIncoming::ApplicationClose { error_code: 0x100 }`.

## Impact

- HTTP/3 gateways / clients on Linux + io_uring see spurious 502s for backends that use `H3_NO_ERROR` correctly (per-connection request limits, drain/rolling deploys, stateless backends).
- Protocols/products affected: any consumer of `RequestStream::recv_response()` and `recv_data()` on the client side; the analogous server-side path likely has the same shape.
- Severity: clean shutdowns mis-classified as transport errors — wrong behavior, but worked around in some downstream stacks (e.g., ours via [our recv_response gateway-side suppression](https://github.com/ferrum-edge/ferrum-edge/pull/506)) by surfacing the 502 without penalizing the backend's H3 capability.

## Versions

- `h3 = 0.0.8`
- `h3-quinn = 0.0.10`
- `quinn = 0.11.9`
- `quinn-proto = 0.11.14`

But the bug is structural — same shape exists on `master`. The proposed PR forward-ports cleanly.

## References

- RFC 9114 §8.1 — H3 error codes (`H3_NO_ERROR = 0x100`)
- RFC 9000 §10.2 — QUIC connection close
- Downstream context (Ferrum Edge): [PR #506](https://github.com/ferrum-edge/ferrum-edge/pull/506) and [PR #505](https://github.com/ferrum-edge/ferrum-edge/pull/505) handle the symptom; this issue is the root-cause report.
