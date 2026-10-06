# hyper: coalesce DATA frames cut from small HTTP/2 window increments

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.10.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. Ferrum issue
[#6033](https://github.com/ferrum-edge/ferrum-edge/issues/6033), from the
2026-10-06 audit of [patch 002](../002-min-data-frame-capacity/README.md)
(Ferrum #6001).

## The problem

Patch 002 removed the old fixed 1 KiB send-capacity gate because it could
deadlock a legal peer window. Since then a ready body chunk is handed to h2 as
soon as any capacity is assigned. h2 cuts each DATA frame from whatever
capacity is assigned when it writes. So when a peer opens its window a few
bytes at a time, every increment leaves as its own DATA frame.

That reproduces deterministically. In
`proto::h2::ferrum_h2_small_window_coalescing_tests`, a raw peer spends the
initial 65,535-byte connection window and then sends 128 connection
`WINDOW_UPDATE`s of 32 bytes. Without this patch, nearly every increment
becomes a separate 32-byte DATA frame.

Two details decide when this happens:

- h2 reads every frame already queued on the socket before it writes. A
  burst of increments in one TCP segment therefore produces one frame.
  Increments that arrive spread out in time each produce a frame.
- The pattern sustains itself. A peer that releases window as its
  application reads, which is what hyper and tonic do, grants back exactly the
  size of each frame it consumed. One small frame causes a small grant, which
  causes another small frame. On a pooled connection with many streams, the
  remainders that split connection capacity between streams keep seeding new
  small frames.

An h2 0.4.16+ receiver (tonic, axum, hyper) charges every non-final DATA frame
under 256 bytes against a connection-wide budget. It answers an exhausted
budget with `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")`, which fails
every stream on the connection. Ferrum's own receiver has
[h2 patch 002](../../upstream-h2-patches/002-runtime-data-frame-budget/README.md);
unpatched backends and clients do not. The old 1 KiB gate never fully covered
this either: it applied only to the first frame of each chunk, and h2 cut the
rest of the chunk from later increments.

## Patch

The unified diff is
[`hyper-h2-small-window-coalescing.patch`](hyper-h2-small-window-coalescing.patch),
against the published hyper 1.10.0 crate with patches 001–004 applied. Apply
[the complete ordered stack](../README.md).

- **`PipeToSendStream`** (`src/proto/h2/mod.rs`) can carry a `Coalesce` state,
  enabled by `with_coalescing(timer)` only when the connection has a `Timer`.
  While a ready chunk holds positive capacity smaller than
  `min(remaining bytes in the chunk, 256)`, the pipe waits for more, for at
  most `MAX_COALESCE_WAIT` (2 ms). Then it hands h2 exactly the assigned
  capacity. A chunk larger than the capacity is split with
  `Buf::copy_to_bytes`, which for `Bytes` is a zero-copy split. The split head
  is sent through a new `SendBuf::Bytes` variant, so h2 never buffers bytes it
  would later cut into small frames.
- The 256-byte minimum is h2's `DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD`. Frames
  at or above it are never charged against a receiver's budget.
- **The client** (`src/proto/h2/client.rs`) enables coalescing on every
  request body pipe, using the connection's timer.
- **The server** (`src/proto/h2/server.rs`) passes its timer to each stream
  and enables coalescing on every response body pipe.
- Without a timer, the pipe behaves exactly as with patch 002 alone.

Ferrum builds every HTTP/2 client connection with a timer: the gRPC pool, the
direct HTTP/2 pool, reqwest, the mesh mTLS pool and the Unix-socket backend.
The frontend HTTP/2 server builders in `src/proxy/mod.rs` now set one too, so
responses to HTTP/2 clients coalesce as well.

### Progress with every legal window

The wait is bounded, so this patch cannot reintroduce the 1 KiB gate's
deadlock:

- **Small peer windows.** A peer stream window under 256 bytes, or a peer that
  opens its window only after it has received the bytes held here, gets the
  smaller frame once the 2 ms wait ends.
- **End of a chunk.** A chunk that fits the assigned capacity is sent at
  once; the pipe never waits for the next chunk. A tail smaller than the
  coalescing threshold that does not fit is held for at most 2 ms.
- **512-byte windows.** A 512-byte stream window grants at least 256 bytes per
  increment, so it is never held.
- **Bounded hold.** Held capacity stays assigned to the stream for at most one
  wait. A hold is not a write stall: patch 004's timer still runs only while
  assigned capacity is zero.

### Cost

- **Ample capacity.** When capacity covers the chunk, the pipe takes the same
  path as before: one comparison, no timer and no split.
- **Window-limited streams.** Only these reach the coalescing state. The one
  sleep is allocated on a stream's first hold and then reset in place
  (hyper-util's `TokioTimer` resets without allocating). A timer whose `reset`
  does nothing gets a fresh sleep for the rest of the hold, so every hold ends
  by its deadline with any `Timer`.
- **Per stream.** Each body pipe clones the connection's `Time` handle, an
  `Arc` increment.
- **Worst-case latency.** One 2 ms wait per round trip, and only against a
  peer whose window never reaches 256 bytes.
- **A hold that ends early.** Its sleep stays armed, so the task can be woken
  once more at the old deadline and find nothing to do. This is deliberate
  (#6038). The next hold moves the deadline later, which tokio does in place
  without the timer driver. Disarming the sleep when a hold ends would make
  every next hold move it earlier instead, a timer-wheel update per hold. Only
  a pause between holds longer than the rest of the wait costs the spurious
  wake.
- **Chunks larger than the window (unmeasured).** Before this patch, a ready
  chunk went to h2 whole and h2 framed the rest itself as WINDOW_UPDATEs
  arrived. Now the pipe hands h2 only the assigned capacity, so each
  WINDOW_UPDATE that reopens a window-limited stream wakes the pipe to hand
  over the next piece: one extra hop from the connection task to the pipe
  and back per update. This is the cost #6038 asked to measure with a 64 KiB
  stream window, and it has not been measured. Reasoning only: an h2 peer
  (hyper, tonic, the benchmark client and backend) sends a WINDOW_UPDATE once
  its unclaimed capacity reaches half of its remaining window, so against a
  64 KiB window each update opens about a third of it, roughly 21 KiB. That
  is far above 256 bytes, so no hold happens: the pipe wakes, compares,
  splits the `Bytes` without copying and returns. The count is about one
  extra wake per 21 KiB sent, around 50,000 per second for each GB/s on a
  window-limited stream, each paying a task wake and a `send_data` call.
  With the benchmark's 8 MiB stream windows a chunk rarely exceeds its
  capacity, so the default protocol matrix should show no change. The peer
  windows are fixed in `proto_bench` and `proto_backend`
  (`tests/performance/multi_protocol/`), so no hosted benchmark workflow can
  run the 64 KiB case yet; measuring it needs a window option there first.

### Not covered

The patch merges window increments, not body chunks. If the source body yields
tiny chunks, for example a client streaming small gRPC messages, each chunk
still leaves as its own frame. Merging chunks would add latency to streamed
messages.

**HTTP/2 CONNECT tunnels** (#6038). WebSocket over HTTP/2 (RFC 8441) on the
frontend and inbound HBONE write through hyper's upgraded send task
(`src/proto/h2/upgrade.rs`), not through `PipeToSendStream`. That task hands
each write to h2 as soon as it arrives, so h2 still cuts one DATA frame from
each small window increment on a tunnel. The task also never waits for the
peer's window before it takes the next write: hyper does not apply flow-control
backpressure to a tunnel writer. A bounded hold therefore cannot be added
without changing more than framing:

- If the task stopped taking writes while it held bytes, every tunnel writer
  would gain window backpressure, and `poll_shutdown` would wait for the peer
  to open its window instead of returning once END_STREAM is queued. The H2
  WebSocket and HBONE relays would need review for both.
- Keeping today's write semantics needs the task to queue writes itself and
  split them by capacity, a rewrite of that task rather than this patch's
  hold.

Either needs its own change and tunnel-specific regressions.

## Regression coverage

`proto::h2::ferrum_h2_small_window_coalescing_tests` runs a raw-frame peer
over an in-memory transport on a paused clock, so frame sizes do not depend
on machine speed:

- `without_a_timer_each_increment_is_its_own_frame` is the control that
  reproduces the run of small frames.
- `small_window_increments_coalesce_into_useful_frames` checks that no
  non-final DATA frame under 256 bytes follows the initial window.
- `a_window_below_a_useful_frame_progresses_after_the_bounded_wait` holds each
  increment for at least the bound and less than four times it. It also checks
  that the final piece of the body is not held.

CI runs the module in the vendored-hyper step's `--lib ferrum_` pass on the
vendored h2:

```bash
cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_h2_small_window_coalescing \
  --config 'patch.crates-io.h2.path="vendor/h2-0.4.19-ferrum-patched"'
```

`test_grpc_h2c_upload_coalesces_small_connection_window_increments` in
`tests/integration/http2_pool_tests.rs` drives the same peer behaviour through
Ferrum's gRPC connection pool over TCP, in real time. It checks that increments
coalesce, and that a lockstep window completes after the bounded wait. On a
real clock frame sizes depend on scheduling, so its load-independent proof is
a lower bound: every lockstep round but the last takes at least the 2 ms wait,
which only a client built with a timer does. The small-frame count only has to
stay under half the increments, where the no-timer control lands (#6038).

`tests/unit/gateway_core/frontend_h2_response_coalescing_tests.rs` covers the
response direction through the production accept loop: a raw-frame client
trickles and then locksteps its connection window against a large response,
over h2c (`handle_connection`) and over TLS with ALPN `h2`
(`handle_tls_connection`). The same lower bound proves that both frontend
HTTP/2 builders set a timer.

## Retirement plan

Patch 005 rewrites the pending-body loop that patches 002 and 004 introduced,
so it belongs to their `hyper-h2-body-progress-and-timeout` co-retirement
group. Retire it with them, or earlier if hyper or h2 adopts sender-side
coalescing of small window increments that keeps every positive window live.
Before retirement, hosted tests must show that the replacement avoids runs of
sub-256-byte DATA frames against a trickling window and still completes
against a window that never reaches 256 bytes.
