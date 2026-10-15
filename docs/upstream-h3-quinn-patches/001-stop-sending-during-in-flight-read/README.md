# Patch 001 - h3-quinn `stop_sending` during an in-flight read

## Status

| Field | Value |
|---|---|
| Patch ID | 001-stop-sending-during-in-flight-read |
| Target crate | `h3-quinn` |
| Target version | 0.0.10 (latest published as of 2026-08-06) |
| State | **Applied via vendored crate at `vendor/h3-quinn-0.0.10-ferrum-patched`** |
| Upstream issue | _Deliberate fork — unfiled upstream (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Upstream PR | _Deliberate fork — unfiled_ |
| Tracks | Ferrum Edge full-duplex native-H3 gRPC streaming (#3283) |

## Why this directory exists

`h3_quinn::RecvStream` moves its `quinn::RecvStream` **into** a
`ReusableBoxFuture` for the duration of a pending `read_chunk`, leaving its own
field as `None`:

```rust
pub struct RecvStream {
    stream: Option<quinn::RecvStream>,
    read_chunk_fut: ReadChunkFuture,
}

fn poll_data(&mut self, cx: &mut task::Context<'_>) -> Poll<...> {
    if let Some(mut stream) = self.stream.take() {
        self.read_chunk_fut.set(async move { ... });
    };
    let (stream, chunk) = ready!(self.read_chunk_fut.poll(cx));
    self.stream = Some(stream);
    ...
}

fn stop_sending(&mut self, error_code: u64) {
    self.stream.as_mut().unwrap().stop(...)   // <-- panics while parked
}
```

Once `poll_data` has returned `Pending`, the stream is unreachable until the
read resolves — and the read only resolves when the *peer* sends something. So
`quic::RecvStream::stop_sending` panics on exactly the shape an HTTP/3 server
needs it for: **the request-body read is cancelled because the response is
complete, and the server wants to tell the client to stop uploading.**

For Ferrum Edge this is the headline case of full-duplex gRPC over HTTP/3
(#3283): the backend returns its terminal `grpc-status` trailer while the client
is still streaming request messages. The gateway retires its request-upload
pump, which cancels a `recv_data()` mid-poll, and must then emit
`STOP_SENDING(H3_NO_ERROR)`.

There is no gateway-side workaround:

- `quinn::Connection` exposes no connection-level STOP_SENDING for an existing
  stream id, and `quinn::RecvStream::stop` needs `&mut self` — which lives
  inside the boxed future.
- Not calling `stop_sending` is not "graceful": dropping the receive half makes
  `quinn::RecvStream::drop` emit `STOP_SENDING(0)`. `0x0` is not an HTTP/3 error
  code (RFC 9114 §8.1 assigns `H3_NO_ERROR = 0x0100`), so clients log a spurious
  remote reset on an RPC that *succeeded*.
- Waiting for the parked read to resolve before halting is unbounded: an idle
  bidirectional client may legitimately send nothing more.

## The fix

Own the `quinn::RecvStream` inline and build the `read_chunk` future per poll:

```rust
pub struct RecvStream {
    stream: quinn::RecvStream,
}

fn poll_data(&mut self, cx: &mut task::Context<'_>) -> Poll<...> {
    let chunk = {
        let mut read_chunk_fut = pin!(self.stream.read_chunk(usize::MAX, true));
        ready!(read_chunk_fut.as_mut().poll(cx))
    };
    ...
}

fn stop_sending(&mut self, error_code: u64) {
    self.stream.stop(VarInt::from_u64(error_code).expect("invalid error_code")).ok();
}
```

`quinn::RecvStream::read_chunk` is documented **cancel-safe** and its `ReadChunk`
future holds no state beyond the `&mut RecvStream` borrow (`poll` forwards
straight to the stream's own `poll_read_chunk`), so recreating it on each poll is
behaviourally identical to the boxed form. Read position, `all_data_read`
bookkeeping, and waker registration all live on the stream, not on the future.

Secondary benefits: no `ReusableBoxFuture` allocation at all (the upstream form
allocates once per receive stream), and `recv_id()` loses its second `unwrap()`.

`tokio-util` is deliberately **left** in the vendored `Cargo.toml` even though the
import is gone, so the resolved dependency graph — and therefore `Cargo.lock` —
is identical to the published crate's.

## Files

| File | Purpose |
|---|---|
| `issue.md` | Bug report draft for hyperium/h3. |
| `pr-description.md` | PR description draft for the fix. |
| `h3-quinn-stop-sending-in-flight-read.patch` | Unified diff for the vendored `h3-quinn` source change. |

## Hand-off - how to file upstream

1. Open an upstream issue in `hyperium/h3` using `issue.md`.
2. Replace the `Fixes #NNN` placeholder in `pr-description.md`.
3. Apply `h3-quinn-stop-sending-in-flight-read.patch` to an h3 checkout and run
   `cargo test -p h3-quinn` plus the h3 integration suite.
4. Push a fork branch, for example `fix/stop-sending-during-in-flight-read`.
5. Open the PR with `pr-description.md` and update this README, the inventory row
   in [`docs/dependency-policy.md`](../../dependency-policy.md), and
   [`docs/vendored-patch-lifecycle.json`](../../vendored-patch-lifecycle.json)
   with the issue and PR numbers.

## Regression coverage (must survive retirement)

These tests do not all prove the same thing; do not read them as proof of
every cancellation exit or of the wire stop code:

- **Source-shape checks** (string assertions over source text, not runtime
  behavior):
  - `tests/unit/gateway_core/http3_server_dispatch_tests.rs` —
    `h3_quinn_vendored_recv_stream_can_stop_sending_during_an_in_flight_read`
    checks inline ownership (`stream: quinn::RecvStream`), absence of
    `ReusableBoxFuture` and of `unwrap()` inside `stop_sending`, and the
    per-poll `pin!(self.stream.read_chunk(usize::MAX, true))` expression, so
    the old `Option` ownership hazard cannot silently return.
  - `tests/unit/gateway_core/http3_server_dispatch_tests.rs` —
    `h3_native_grpc_upload_pump_halts_the_frontend_receive_half_gracefully` and
    `h3_cross_protocol_grpc_upload_pump_halts_the_frontend_receive_half_gracefully`
    check source text: both request-upload pumps call
    `halt_request_body(...)` (the graceful `STOP_SENDING(H3_NO_ERROR)` helper)
    unconditionally rather than an idle-gated variant.
- **Functional early-response scenario** (ignored, end-to-end):
  `tests/functional/scripted_backend_h3_tests.rs` —
  `h3_native_grpc_bidi_server_responds_before_client_half_close` asserts the
  response arrives before client half-close, the response body/trailers, and
  that the native backend received the request DATA. It does not synchronize
  a pending frontend read and does not assert the `STOP_SENDING` error code
  on the wire. Stronger behavioral coverage — a deterministic pending-read
  barrier plus an observable stop code — would be a separate focused test.

## Retirement

Once `hyperium/h3` releases an `h3-quinn` whose `stop_sending` is correct while a
read is in flight:

1. Bump the workspace `h3-quinn` dependency to that release.
2. Keep the vendored crate until patch 002 is also retired (they share one vendor directory).
3. When both active h3-quinn patches are available upstream, remove the
   `h3-quinn` `[patch.crates-io]` entry from `Cargo.toml` and the
   mirrored entries in `fuzz/Cargo.toml` and
   `tests/performance/mesh/Cargo.toml`, then regenerate `Cargo.lock`,
   `fuzz/Cargo.lock` and `tests/performance/mesh/Cargo.lock`.
4. Delete `vendor/h3-quinn-0.0.10-ferrum-patched/` and regenerate
   `vendor/VENDOR_INTEGRITY.sha256` with `scripts/update_vendor_integrity.sh`.
5. Drop this patch's row from `docs/dependency-policy.md` and its entry from
   `docs/vendored-patch-lifecycle.json`.
6. Move this directory under
   `docs/upstream-h3-quinn-patches/_retired/001-stop-sending-during-in-flight-read/`
   with a `STATUS.md` noting the upstream merge and release.
7. Keep the Ferrum behavioral regression tests above, minus the vendored-shape
   contract test, which retires with the vendor copy.
