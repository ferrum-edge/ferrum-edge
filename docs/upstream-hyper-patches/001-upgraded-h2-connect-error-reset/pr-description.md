# feat(upgrade): allow resetting an HTTP/2 upgrade with CONNECT_ERROR

<!-- Filed as hyperium/hyper#4210 on 2026-09-28; kept as the record of what was filed (the PR itself is authoritative for later edits). -->

Closes #4209

## Problem

Dropping or shutting down an `Upgraded` that came from an HTTP/2 `CONNECT`
always ends the stream with `END_STREAM`. `H2Upgraded` holds only the data
channel into `UpgradedSendStreamTask`, which owns the `SendStream`, and
`H2Upgraded` is private, so user code cannot reach `SendStream::send_reset`.

A proxy whose tunnelled TCP connection fails therefore has no way to follow
RFC 9113 section 8.5, which treats any error in that TCP connection as a
stream error of type `CONNECT_ERROR`.
The client sees a clean close and cannot tell a failed tunnel from a complete
one.

## Change

Add one public method:

```rust
impl Upgraded {
    /// Resets an HTTP/2 upgrade's stream with `RST_STREAM(CONNECT_ERROR)`.
    ///
    /// Returns `true` if the reset was requested. A send task that is
    /// already finishing the stream with `END_STREAM` still wins, so `true`
    /// does not guarantee a reset reaches the wire. Returns `false` and does
    /// nothing if this is not an HTTP/2 upgrade, if a reset was already
    /// queued, or if the stream's send side has already finished.
    #[cfg(all(any(feature = "client", feature = "server"), feature = "http2"))]
    pub fn reset_with_connect_error(&mut self) -> bool;
}
```

- `proto::h2::upgrade::pair` creates a second oneshot. `H2Upgraded` keeps the
  sender (`H2Upgraded::reset`); `UpgradedSendStreamTask` polls the receiver
  after its `poll_reset` check and before it reads the data channel. On a
  reason it calls `send_reset(reason)` and ends. On a dropped sender it clears
  the receiver and carries on as before.
- Because the reset is polled first, a reset immediately followed by a drop
  still sends `RST_STREAM`, not `END_STREAM`.
- `Upgraded` reaches `H2Upgraded` with a `&mut` form of the existing `TypeId`
  downcast (modeled on `std::error::Error::downcast_mut`) via `Rewind::get_mut`,
  which was already present but commented out. `H2Upgraded` becomes
  `pub(crate)`.

The method takes no error code, because `h2::Reason` is not part of hyper's
public API and `CONNECT_ERROR` is the code the RFC assigns to this case. A
variant taking a code is easy to add if preferred.

Cost: one more small allocation per HTTP/2 upgrade (the oneshot) and one
oneshot poll per wake of the send task. Nothing changes for a stream that is
never reset.

## Tests

In `src/proto/h2/upgrade.rs`. Every test but the last runs a real h2 client
and server over `tokio::io::duplex`, with the server side wrapped in
`Upgraded`:

- a reset, then an immediate drop, reaches the client as
  `RST_STREAM(CONNECT_ERROR)`; a second reset returns `false`;
- a reset after data has reached the client;
- a plain drop still sends `END_STREAM`;
- after a completed `poll_shutdown`, the reset returns `false` and the client
  sees `END_STREAM`;
- a non-HTTP/2 upgrade returns `false` and still downcasts.
