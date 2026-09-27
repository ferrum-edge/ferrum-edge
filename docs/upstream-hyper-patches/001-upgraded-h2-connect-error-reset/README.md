# hyper: reset an upgraded HTTP/2 CONNECT stream with `CONNECT_ERROR`

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.9.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork, not yet filed upstream, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
The upstream issue and PR texts are drafted in [`issue.md`](issue.md) and
[`pr-description.md`](pr-description.md). Filing them in `hyperium/hyper`
needs the owner's approval; when they are filed, record the numbers here, in
the inventory row, and in `docs/vendored-patch-lifecycle.json`. Owner: Ferrum
Edge maintainers. This patch fixes Ferrum issue
[#5781](https://github.com/ferrum-edge/ferrum-edge/issues/5781), a follow-up
to #5765.

## The problem

An HBONE tunnel is an HTTP/2 `CONNECT` stream. The destination gateway gets
it from hyper as `hyper::upgrade::Upgraded` and relays it to a TCP backend
(the byte-stream relay) or a local UDP socket (the datagram relay). When the
relay ends, the gateway drops the `Upgraded`, or the byte-stream copy shuts
it down after the backend's FIN.

In hyper 1.9.0 (`src/proto/h2/upgrade.rs`), both paths end the stream with a
clean `END_STREAM`:

- `H2Upgraded` holds only an mpsc sender. The `h2::SendStream` belongs to a
  spawned `UpgradedSendStreamTask`.
- `poll_shutdown` and drop both close that channel, and the task answers a
  closed channel with `send_data(SendBuf::None, true)`.
- `H2Upgraded` is `pub(super)` inside the private `mod proto`, so
  `Upgraded::downcast` cannot reach it, and no public API resets the stream.

A relay that ended because the backend reset the connection, or because the
datagram relay's socket failed, therefore looked the same on the wire as a
normal close. For the byte-stream relay that reads as a complete response.
RFC 9113 section 8.5 has a proxy treat any error in the tunnelled TCP
connection as a stream error of type `CONNECT_ERROR`. #5765 recorded the
cause in the gateway's transaction log, but the client could not see it.

hyper `master` (1.11.1 when this was written) has the same limitation.

## Patch

The base is the crates.io `hyper` 1.9.0 source (package checksum
`6299f016b246a94207e63da54dbe807655bf9e00044f73ded42c3ac5305fbcca`, upstream
commit `0d6c7d5469baa09e2fb127ee3758a79b3271a4f0`). Only three files under
`src/` differ; the unified diff is
[`hyper-upgraded-h2-connect-error-reset.patch`](hyper-upgraded-h2-connect-error-reset.patch).
The crate's `Cargo.lock`, `Cargo.toml.orig` and `.cargo_vcs_info.json` are not
vendored.

- **`Upgraded::reset_with_connect_error(&mut self) -> bool`** (new public
  method, `src/upgrade.rs`, gated on `http2` plus `client` or `server`). For
  an HTTP/2 upgrade it queues `RST_STREAM(CONNECT_ERROR)` in place of the
  `END_STREAM` and returns `true`. It returns `false` and does nothing for an
  HTTP/1 upgrade, for a second call, or once the stream's send side has
  finished (after a completed shutdown, or after the send task saw a peer
  reset). It reaches the inner `H2Upgraded` with a `&mut` form of the existing
  `TypeId` downcast (`__hyper_downcast_mut`, modeled on
  `std::error::Error::downcast_mut`), through `Rewind::get_mut`, which was
  already written but commented out.
- **`src/proto/h2/upgrade.rs`**: `H2Upgraded` becomes `pub(crate)`. A second
  oneshot channel carries the reset reason from `H2Upgraded` to
  `UpgradedSendStreamTask`. The task polls it after its `poll_reset` check and
  before it reads the data channel. So a reset queued just before a drop
  still wins over the `END_STREAM` a closed channel would send, and the task
  calls `SendStream::send_reset(reason)` and ends. A dropped sender (no
  reset) clears the receiver, and the task then behaves as before.

A reset discards data that was written but not yet handed to h2; RST_STREAM
discards it on the wire anyway.

Hot path cost: one extra poll of a `futures_channel::oneshot::Receiver` per
wake of the send task (an atomic check), and one more allocation per upgrade
for the oneshot. There is no change for a stream that is never reset.

## Ferrum call sites

`src/proxy/hbone_proxy.rs` lends the `TokioIo<Upgraded>` to the relay instead
of moving it in, then ends the stream in `end_hbone_connect_stream`:

- **Byte-stream relay** (`bidirectional_copy_for_fenced_relay`): resets when
  the relay recorded any first failure other than the idle window: a socket
  error, a backend read/write deadline (#5858), the half-close cap (#5858), or
  a fence revocation (#5858). `hbone_relay_failure_resets_stream` decides.
- **Datagram relay** (`relay_hbone_udp`): resets for every ending except
  `tunnel_closed` and `idle_timeout`: the four socket-error endings
  (`tunnel_read_error`, `tunnel_write_error`, `app_send_error`,
  `app_recv_error`), plus `tunnel_write_stalled` and `revoked` (#5858).
  `HboneUdpRelayEnd::resets_stream` decides. The relay's `from_app` pump no
  longer half-closes the tunnel on its way out: every one of its endings is
  an error, and a half-close would queue `END_STREAM` ahead of the reset.

Every other ending (a peer close, an idle expiry) drops the stream and keeps
the clean `END_STREAM` it had before.
A failure after the byte-stream relay has already half-closed the stream
toward the client (the backend sent FIN first) cannot be signalled: the send
side has finished, so `reset_with_connect_error` returns `false`.

## Regression coverage

In the vendored crate:

- `proto::h2::upgrade::ferrum_connect_error_reset_tests`. Every test but the
  last runs a real h2 client and server over an in-memory pipe, with the
  server side wrapped in hyper's `Upgraded` and its send task spawned:
  - `reset_sends_rst_stream_connect_error`: a reset followed at once by a drop
    reaches the client as `RST_STREAM(CONNECT_ERROR)`, and a second reset
    returns `false`.
  - `reset_after_data_sends_rst_stream_connect_error`: a reset after data
    reached the client.
  - `drop_without_reset_ends_the_stream_cleanly`: a plain drop still sends
    `END_STREAM`.
  - `reset_after_completed_shutdown_does_nothing`: after a completed shutdown
    the reset returns `false` and the client sees `END_STREAM`.
  - `reset_ignores_non_h2_upgrades`: a non-HTTP/2 upgrade is left alone and
    still downcasts.

The `Vendored Patch Regressions` CI job runs them with

```bash
cargo test --manifest-path vendor/hyper-1.9.0-ferrum-patched/Cargo.toml --features full --lib ferrum_connect_error_reset
```

End to end, `tests/integration/mesh_hbone_tests.rs` drives real HBONE
CONNECTs through the gateway with a raw h2 client:

- `hbone_relay_backend_reset_sends_rst_stream_connect_error` and
  `hbone_relay_backend_close_still_ends_stream_cleanly` (byte-stream relay,
  backend RST vs. FIN).
- `egress_udp_relay_socket_error_sends_rst_stream_connect_error` and
  `egress_udp_relay_tunnel_close_still_ends_stream_cleanly` (datagram relay,
  refused destination socket vs. client close).

## Retirement plan

Retire when a hyper release can reset an upgraded HTTP/2 stream with a chosen
error code (the API proposed in [`pr-description.md`](pr-description.md), or
an equivalent). Then:

1. Move `end_hbone_connect_stream` in `src/proxy/hbone_proxy.rs` to the
   upstream API.
2. Remove the `hyper` line from `[patch.crates-io]` in `Cargo.toml`,
   `fuzz/Cargo.toml` and `tests/performance/mesh/Cargo.toml`.
3. `git rm -r vendor/hyper-1.9.0-ferrum-patched/`, and restore the registry
   `source`/`checksum` lines in `Cargo.lock`, `fuzz/Cargo.lock` and
   `tests/performance/mesh/Cargo.lock` with a normal lockfile update.
4. Remove the inventory row and the lifecycle entry, drop the CI step, and
   regenerate `vendor/VENDOR_INTEGRITY.sha256`.
