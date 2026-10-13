# Observe peer STOP_SENDING without exclusive send-stream access

## Summary

`h3` servers that wait on a backend (or any other future) after request HEADERS
have no way to notice that the client sent `STOP_SENDING` on the response
direction unless they take `&mut` on the send stream. That exclusive borrow
conflicts with polling the receive half of an unsplit bidi `RequestStream`.

## Why this matters

HTTP/3 connections are multiplexed. A client can cancel one request stream
(`STOP_SENDING` on the server's send half, and/or reset the request direction)
while keeping the QUIC connection open for other streams. A gateway that is
blocked on backend response headers is not polling H3 frames, so the
cancellation is invisible until the backend answers — holding in-flight
accounting for a request the client already abandoned.

Quinn already exposes `SendStream::stopped(&self) -> impl Future + 'static`.
h3 does not forward that capability, so applications cannot race it against a
backend wait without splitting the stream or introducing concurrent `&mut`
access to one half.

## Proposed API

Add an optional trait such as:

```rust
pub trait SendStreamStopped {
    fn stopped(&self) -> impl Future<Output = Result<Option<u64>, StreamErrorIncoming>> + Send + 'static;
}
```

Forward it through `BufRecvStream`, `FrameStream`, the shared inner
`RequestStream`, and the public **server** `RequestStream` — that is the
scope the applied Ferrum patch implements, because the Ferrum use case is a
server observing client cancellation. The public client `RequestStream`
facade has no `stopped` forwarder in the applied patch (its inner field is
private to the client module); adding client forwarding is additional
proposed work, not part of the implemented server scope. Implementations
must take `&self` (not `&mut self`) so the future can be `'static` and must
not borrow the send stream. Return a statically dispatched future via stable
RPITIT, not an associated-type `impl Trait` and not a boxed trait object.

`Ok(Some(code))` is peer `STOP_SENDING`. `Ok(None)` means the local side
already finished and the peer acknowledged the stream. `Err` covers both
connection loss (mapped to `StreamErrorIncoming::ConnectionErrorIncoming`)
and rejected 0-RTT for the early-data stream (Quinn
`StoppedError::ZeroRttRejected`, mapped by h3-quinn to
`StreamErrorIncoming::Unknown`).

## Notes

This is not a replacement for polling `poll_ready` / `send_data`. It is a
watch for peer cancellation of the send direction while the application is
doing something else.
