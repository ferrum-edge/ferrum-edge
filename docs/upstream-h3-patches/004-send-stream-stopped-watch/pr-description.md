# Summary

- add `quic::SendStreamStopped` so transports can expose peer `STOP_SENDING` as a `&self` + `'static` return-position `impl Future`
- forward the method through `BufRecvStream`, `FrameStream`, and `server::RequestStream` (server scope only; the public client `RequestStream` facade gets no forwarder in this change)
- document `Err` as connection loss or rejected 0-RTT (`StoppedError::ZeroRttRejected` → `StreamErrorIncoming::Unknown` in h3-quinn), distinct from `Ok(Some(code))` peer `STOP_SENDING` and `Ok(None)` local finish acknowledged
- do not take exclusive send-stream access, so an unsplit bidi stream can still poll the receive half
- do not box a trait-object future per call

Fixes #NNN.

# Motivation

A server that waits on a backend after request HEADERS is not polling H3 frames.
Clients can `STOP_SENDING` one response stream while keeping the multiplexed
QUIC connection open. Quinn already provides `SendStream::stopped(&self)` with a
`'static` future; h3 needs a trait so `RequestStream` can race that signal
without `&mut` on the send half.

# Testing

- `cargo test -p h3`
