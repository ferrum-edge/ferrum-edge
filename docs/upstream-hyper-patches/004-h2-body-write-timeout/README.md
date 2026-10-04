# hyper: bound how long an HTTP/2 request body may wait to be written

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.10.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. Part of Ferrum issue
[#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588).

## The problem

`backend_write_timeout_ms` bounds how long the backend may stop taking a
request body. For an HTTP/2 backend, the stall happens inside hyper's body pipe
(`PipeToSendStream`, `src/proto/h2/mod.rs`). When the backend stops granting
flow-control window, the pipe parks in `SendStream::poll_capacity`, and it
waits for capacity before it polls the request body. So nothing the gateway
puts in the body can observe the stall, because a parked pipe polls nothing.

Ferrum therefore moved every bounded HTTP/2 upload into a gateway-owned "upload
pump": a separate future that owns the client body, relays it to hyper through
a one-frame channel, and runs the timer on its own side of the channel. It
works, but every frame crosses a task boundary and a channel. On the native
gRPC path that cost about 3.5% of gateway CPU per request at 10 KiB, plus a
cross-task wakeup per frame. The direct-HTTP/2 passthrough arm (no
request-size limit) skipped the pump to avoid that cost, so it enforced no
write timeout at all.

nginx enforces the same bound (`grpc_send_timeout`, "between two successive
write operations") as a timer on the upstream write event, armed only while a
write is blocked, including when the request body is blocked by HTTP/2 flow
control (`request_body_blocked` in `ngx_http_upstream.c`). Envoy has no
request-body write timeout. It relies on its stream idle timeout (5 minutes by
default).

## Patch

The unified diff is
[`hyper-h2-body-write-timeout.patch`](hyper-h2-body-write-timeout.patch),
against the published hyper 1.10.0 crate with patches 001–003 applied.
Apply [the complete ordered stack](../README.md); patch 002 supplies the
pending-body foundation and permits progress at every positive capacity.
Patch 004 never requires or restores the former fixed 1 KiB threshold.

- **`hyper::ext::Http2BodyWriteTimeout`** (new, `src/ext/h2_body_write_timeout.rs`)
  is a request extension. It holds a duration and a shared `expired` flag that
  every clone reads. The HTTP/2 client removes it from the request before
  sending.
- **`ClientTask`** (`src/proto/h2/client.rs`) keeps the connection's
  `Timer`, which it previously used only for keep-alive pings, and attaches the
  extension's bound to that request's body pipe. A request that carries the
  extension on a connection built without a timer fails with a body-write
  error instead of running unbounded.
- **`PipeToSendStream`** (`src/proto/h2/mod.rs`) runs the timer only while it
  holds a polled chunk that it cannot yet hand to h2. That happens when the
  stream or connection window is exhausted, or when h2's send buffer is full
  (h2 assigns no capacity past it). Every chunk handed to `send_data` disarms
  the timer. A stall only records its start time. The one sleep, allocated on
  the first stall, is left alone between stalls. If it fires during a later
  stall, the pipe creates a fresh sleep for the rest of that stall, rather
  than relying on `Timer::reset`, which a custom `Timer` may leave as a no-op.
  A bound too large to add to an `Instant` never fires. When the timer fires
  for real, the pipe sets the flag, sends
  `RST_STREAM(CANCEL)` and fails the body. Dropping the pipe releases the
  request body.
- **With a bound configured, the pipe polls the body before waiting for
  capacity**, so time spent waiting for the client to send more is never
  counted as a write stall. It holds at most one chunk, as stock hyper already
  does when a 1-byte claim admits a whole chunk. Without the extension the pipe
  behaves exactly as before.

Ferrum attaches the extension instead of installing the pump on two paths:

- the fully streamed native gRPC upload, when the request has no authorization
  lifetime (`UploadSource::for_streaming_grpc_upload`);
- the direct-HTTP/2 passthrough arm.

On both, an expiry before response headers maps to the existing write-timeout
terminal: grpc-status 4 / `read_write_timeout` for gRPC, and 504 /
`backend_timeout` / `read_write_timeout` for HTTP/2. An upload with an
authorization lifetime keeps the pump, whose absolute deadline must release
the client body even while the pipe is parked.

## Measured effect

All runs use Ferrum's protocol benchmark: 30 s per cell, 200 streams, two
iterations, with Envoy 1.39.1 as the anchor on the same runner.

- **Native gRPC** (the upload pump removed) was faster than a `main` image
  built in the same job, in every cell of both iterations:
  - +4.1% to +8.3% in run
    [36974026712](https://github.com/ferrum-edge/ferrum-edge/actions/runs/36974026712)
    (first revision);
  - +0.4% to +5.6% in run
    [36985819539](https://github.com/ferrum-edge/ferrum-edge/actions/runs/36985819539)
    (the lazy timer below).

  10 KiB moved from 0.93–0.99× Envoy to 0.96–1.04×.
- **Direct-HTTP/2 passthrough** (which gains a write bound it did not have)
  costs about 1–2.5%. In the same-image run
  [36998884115](https://github.com/ferrum-edge/ferrum-edge/actions/runs/36998884115),
  against an arm that attaches no timeout, the median ratios at 10 KiB / 70 KiB
  / 512 KiB / 1 MiB / 5 MiB were −2.4 / +0.2 / −1.6 / −3.7 / −2.2%.
  Individual iterations swung ±4–7%.
  - About half of that comes from polling the body before waiting for
    capacity. Keeping stock ordering measured −1.4 / +0.5 / −0.8 / −1.5 /
    −0.6%, but it would leave a pipe parked on a fully exhausted window with
    no chunk in hand, and so no running timer. That is exactly the stall the
    bound exists for.
  - A route can opt out with `backend_write_timeout_ms: 0`.

The first revision armed the timer on every stall. A window-limited upload
stalls once per WINDOW_UPDATE round trip, and that per-stall arming cost
HTTP/2 up to about 16% in one iteration. The current timer is lazy:

- A stall only records its start time.
- The one sleep is re-armed at most once per timeout period. It can only fire
  early, and then re-checks the real deadline.

### What the bound cannot see

h2 accepts each chunk into the stream's send buffer while the stream holds
capacity, and it exposes no count of buffered-but-unsent bytes. It grants
capacity up to the lower of the peer's window and the connection's send-buffer
limit (`max_send_buf_size`, 1 MiB by default for a hyper client). Beyond that
sit h2's write buffer (about 64 KiB with h2 patch 001) and the kernel's socket
buffers.

So against a backend that advertises a large window and then stops reading,
that much is accepted before a chunk stalls and the timer starts. After the
last chunk there is nothing left to bound, and the response wait is bounded by
`backend_read_timeout_ms`.

The pump had the same limits. It measured how long hyper took to accept each
frame, and its post-end-of-stream drain check needs a socket that multiplexed
HTTP/2 connections never publish.

### After response headers

The bound keeps running after the response headers arrive. An expiry then
resets the stream, which ends the response as well. The client sees a
mid-response stream error, classified like any other backend reset, not as
`read_write_timeout` / grpc-status 4: those terminals apply only before
headers. nginx's send timeout behaves the same way, since it closes the
upstream.

For the direct-HTTP/2 passthrough arm this is new: a backend that answers and
then stops reading the upload for `backend_write_timeout_ms` is now cut. For
native gRPC it replaces the pump. After headers, a pump whose timer fired
stopped reading the client, but it could not make a pipe parked on flow
control reset the stream.

## Regression tests

The `proto::h2::ferrum_body_write_timeout_tests` in the vendored crate run a
real `hyper::client::conn::http2` connection against an in-process h2 server.
Run them with:

```bash
cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_body_write_timeout
```

They cover five cases:

- a backend that stops reading gets `RST_STREAM(CANCEL)`, and the flag reports
  it;
- a slow client never trips the bound, even while the stream window is
  exhausted, however long it pauses;
- a backend that opens a one-chunk window sooner than the bound after every
  chunk completes a 12-chunk upload lasting several bounds. Every chunk
  stalls, and the test asserts that at least one early fire was re-armed
  rather than expired;
- a bound too large to represent never fires and never panics;
- a request that carries the extension on a connection without a timer fails.

Gateway coverage, run with `--ignored`:

- `grpc_streaming_backend_write_timeout_maps_to_deadline_exceeded` and
  `h2_direct_passthrough_backend_write_timeout_maps_to_504`, in
  `tests/functional/scripted_backend_h2_tests.rs`. Both assert the
  `write_bound="h2_pipe"` warning, which only the hyper path emits (the pump's
  warning says `upload_pump`). Both also assert that the backend saw
  `RST_STREAM(CANCEL)` on the request stream.
- `grpc_streaming_zero_write_timeout_is_not_cut`: with
  `backend_write_timeout_ms: 0`, the same stalled upload runs to the read
  timeout.
- the source guards in `tests/unit/gateway_core/stream_auth_lifetime_tests.rs`
  and `tests/unit/gateway_core/proxy_tests.rs`.

## Filing upstream

Before proposing this to hyper:

- Rewrite the `let ... else` in `WriteTimeout::poll_stalled`
  (`src/proto/h2/mod.rs`) as a `match`. `let`-`else` needs Rust 1.65, and hyper
  declares `rust-version = "1.63"`. Ferrum's toolchain is far newer, so the
  vendored copy is unaffected.
- Drop the Ferrum-specific `REARMS` test counter, or replace it with a check
  that does not need crate-level test state.

## Retirement

Retire together with [patch 002](../002-min-data-frame-capacity/README.md#retirement-plan)
when Ferrum adopts an equivalent upstream per-request HTTP/2 body write-stall
bound that preserves progress at every positive assigned capacity, or when
Ferrum's HTTP/2 client moves off hyper. The shared pending-body implementation
belongs to the `hyper-h2-body-progress-and-timeout` co-retirement group.
Hosted replacement tests must cover small legal windows, the final connection
byte, empty end-of-stream handling and write-stall bounds. No compatible
replacement release has been selected or tested.

Hyper #4212 closed unmerged; it is not an adoption path for this extension.
Until a replacement is adopted, the extension is Ferrum-only API. The owner
must file a current upstream proposal or record a dated reaffirmation in this
README and the lifecycle inventory before the deliberate-fork checkpoint.
