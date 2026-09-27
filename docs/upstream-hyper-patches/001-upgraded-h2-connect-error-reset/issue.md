# Upgraded HTTP/2 CONNECT streams cannot be reset, so a failed tunnel looks like a clean close

<!-- DRAFT, not filed. Filing in hyperium/hyper needs the Ferrum Edge owner's
     approval. Once filed, record the issue number in the patch README, the
     dependency-policy inventory row, and docs/vendored-patch-lifecycle.json. -->

## Summary

A server that accepts an HTTP/2 `CONNECT` (or extended `CONNECT`) gets the
tunnel from `hyper::upgrade::on` as an `Upgraded`. hyper offers no way to end
that stream with an error. Dropping the `Upgraded`, or shutting it down, always
sends a clean `END_STREAM`. A proxy whose tunnelled connection fails therefore
cannot tell the client, and the client cannot tell a failed tunnel from a
complete one.

RFC 9113, section 8.5:

> A proxy treats any error in the TCP connection, which includes receiving a
> TCP segment with the RST bit set, as a stream error (Section 5.4.2) of type
> `CONNECT_ERROR`.

The same applies to a client-side `Upgraded` whose local end fails.

Versions: hyper 1.9.0. `master` (1.11.1) has the same code.

## Mechanism

- `proto::h2::upgrade::pair` splits the stream. `H2Upgraded` keeps the
  `RecvStream` and an mpsc sender. The `SendStream` moves into
  `UpgradedSendStreamTask`, which the executor runs.
- `H2Upgraded::poll_shutdown` closes the channel. Dropping `H2Upgraded` drops
  the sender, which also closes it.
- `UpgradedSendStreamTask::tick` answers a closed channel with
  `send_data(SendBuf::None, true)`, which is `END_STREAM`.
- `H2Upgraded` is `pub(super)` in the private `proto` module, so
  `Upgraded::downcast` cannot reach it, and the `SendStream` is owned by the
  task anyway.

So there is no path from user code to `SendStream::send_reset`.

## Reproduction

1. Serve HTTP/2 with hyper and accept a `CONNECT`; respond `200` and await
   `hyper::upgrade::on(req)`.
2. Relay the `Upgraded` to a TCP connection, and have the remote end of that
   TCP connection reset (for example `SO_LINGER=0` then close).
3. The relay sees `ECONNRESET` and drops the `Upgraded`.
4. The h2 client's response body ends with `None` (`END_STREAM`), exactly as it
   would after a normal FIN. It never sees an error.

## Proposed fix

A small method on `Upgraded` that queues `RST_STREAM(CONNECT_ERROR)` for an
HTTP/2 upgrade and returns whether it did, for example
`Upgraded::reset_with_connect_error(&mut self) -> bool`. It is a no-op that
returns `false` for an HTTP/1 upgrade. Internally a oneshot carries the reason
to `UpgradedSendStreamTask`, which checks it before reading the data channel,
so a reset queued just before a drop still wins over the `END_STREAM`.

A version that takes any error code (`h2::Reason` is not public in hyper, so a
`u32` or a new hyper type) would also work; `CONNECT_ERROR` is the code the RFC
names for this case. We carry the patch in a vendored copy and can send a PR.
