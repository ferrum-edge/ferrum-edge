# hyper: wait for useful send capacity before handing an HTTP/2 chunk to h2

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.9.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Filed upstream on 2026-09-30: issue
[hyperium/hyper#4211](https://github.com/hyperium/hyper/issues/4211) and PR
[hyperium/hyper#4212](https://github.com/hyperium/hyper/pull/4212), against
hyper `master`. [`issue.md`](issue.md) and
[`pr-description.md`](pr-description.md) keep the texts as filed. Until a
release carries the change, the vendored copy stays a deliberate fork,
governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. This patch fixes part of Ferrum issue
[#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588).

## The problem

hyper's HTTP/2 body pipe (`PipeToSendStream`, `src/proto/h2/mod.rs`) drives
every request body on a client connection and every response body on a server
connection. In 1.9.0 it reserves one byte of stream capacity, waits until that
byte is assigned, polls the body, and hands the chunk to `send_data`. h2 cuts
DATA frames from whatever capacity the stream holds when the frame is written.
On a connection whose window is nearly spent, that one byte is often all the
stream has, so a 10 KB chunk leaves as a 1-byte DATA frame, followed by more
slivers as capacity trickles in.

h2 0.4.16 and later bound this on the receiving side: every non-final DATA
frame under 256 bytes is charged to a small per-connection budget
(`DEFAULT_DATA_FRAME_OVERHEAD_THRESHOLD`, at least 25600), and exhausting it
sends `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")`, failing every
stream on the connection. Ferrum's pooled HTTP/2 and gRPC backend connections
hit it against a hyper backend with `adaptive_window(true)`: adaptive windows
start at 65535, so a busy pooled connection keeps its window nearly spent. A
local trace counted about 2,900 frames of `sz=10240, available=1` per four
seconds, and the backend GOAWAY'd the pooled connection every few seconds,
failing up to 200 in-flight requests each time.

hyper `master` (1.11.1) moves the 1-byte claim to after the chunk is polled
(hyperium/hyper#4003) but still sends as soon as any capacity is assigned, so
it has the same behaviour.

## Patch

The base is the vendored hyper 1.9.0 with patch 001 applied. Only
`src/proto/h2/mod.rs` changes; the unified diff is
[`hyper-min-data-frame-capacity.patch`](hyper-min-data-frame-capacity.patch).

- `PipeToSendStream` stashes a polled chunk (`pending_data`) instead of handing
  it to h2 at once, and raises its claim to `min(len, MIN_DATA_FRAME_CAPACITY)`
  (1 KiB).
- The top of the poll loop sends the stashed chunk only once that much capacity
  is assigned. The chunk survives `Poll::Pending` in the stash.
- An empty END_STREAM chunk needs no capacity. Chunks shorter than 1 KiB wait
  only for their own length.

The claim stays small, so hyper#4003's point (an idle stream must not pin
connection capacity) still holds, and 1 KiB is far below any stream window a
real peer advertises, so a chunk cannot be held back indefinitely. The upstream
PR applies the same rule to `master`'s restructured loop.

## Regression coverage

`proto::h2::ferrum_min_data_frame_capacity_tests::chunk_waits_for_useful_capacity_instead_of_sliver_frames`
runs a real h2 client and server over an in-memory pipe. Stream A leaves one
byte of connection window; stream B pipes a 10 KB body through
`PipeToSendStream` against it; the server then releases stream A's capacity and
records the size of stream B's first DATA frame. It is 1 byte without the patch
and at least 1 KiB with it. The `Vendored Patch Regressions` CI job runs it with

```bash
cargo test --manifest-path vendor/hyper-1.9.0-ferrum-patched/Cargo.toml --features full --lib ferrum_min_data_frame_capacity
```

End to end, the gateway protocol benchmark's HTTP/2 and gRPC cells against the
adaptive-window benchmark backend are the load-level check.

## Retirement plan

Retire when a hyper release containing hyperium/hyper#4212 (or another fix that
stops cutting a chunk into sub-1 KiB frames from a sliver of capacity) is
adopted. Retire it together with patch 001 when both have shipped; if only
this one has, drop its hunk from the vendored copy, the inventory row, the
lifecycle entry and the CI command, then regenerate
`vendor/VENDOR_INTEGRITY.sha256`.
