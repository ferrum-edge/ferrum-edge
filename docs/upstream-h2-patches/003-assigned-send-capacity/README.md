# h2: report a stream's assigned send window apart from the send buffer

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/h2-0.4.19-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. It exists for
[Hyper patch 005](../../upstream-hyper-patches/005-h2-small-window-coalescing/README.md)
and retires with it.

## Problem

`SendStream::capacity()` reports `min(assigned window, max_send_buffer_size)`
minus the bytes already buffered. A caller therefore cannot tell whether a
small value means the peer's flow-control window is short, or only that h2's
per-stream send buffer is full.

Hyper patch 005 needs exactly that distinction. It splits a body chunk at the
assigned capacity so h2 never buffers bytes it would later cut into small DATA
frames as the peer opens its window a few bytes at a time. That is only a risk
when the *window* is short. When the stream already holds window for the whole
chunk and only the send buffer is full, h2 frames the chunk at its maximum
frame size from window it already has. Splitting it there makes the body pipe
wait for the connection to drain the buffer before it can hand over the rest,
once per buffer-full of every large chunk.

Ferrum's backend pool advertises a 1 MiB maximum frame size by default, so a
backend's response body arrives in chunks of up to 1 MiB, against Hyper's
400 KiB default server send buffer on the frontend leg. Before this patch, every such
chunk was split and the frontend response pipe stalled mid-chunk.

## Patch

[`h2-assigned-send-capacity.patch`](h2-assigned-send-capacity.patch) applies
after Ferrum's h2 patches 001 and 002. It adds one read-only accessor and
changes no state:

- `SendStream::capacity_and_assigned()` (`src/share.rs`) returns
  `capacity()` together with the window already assigned to the stream that
  buffered data has not yet claimed, which ignores the send-buffer limit. Both
  come from one acquisition of the streams lock, so the pair is a consistent
  snapshot and a caller that needs both pays one lock, not two. It goes
  through `StreamRef::capacity_and_assigned` (`src/proto/streams/streams.rs`)
  and `Send::capacity_and_assigned` (`src/proto/streams/send.rs`), which
  evaluate the existing `Stream::capacity` with and without the buffer
  limit.

`capacity()`, `reserve_capacity()`, `poll_capacity()`, flow control and
framing are unchanged.

## Regression coverage

`share::ferrum_assigned_capacity_tests` opens a client stream with a 1 KiB send
buffer against a server whose windows cover a 100,000-byte reservation, and
proves that the capped value stops at the 1 KiB buffer while the assigned
value reports the full assignment, and that both drop by the amount buffered
by `send_data` before the connection writes it. It waits for the server to
accept the request and for the assignment to land, bounded by a deadline,
rather than polling a fixed number of times.

```bash
cargo test --manifest-path vendor/h2-0.4.19-ferrum-patched/Cargo.toml --lib ferrum_assigned_capacity
```

Hyper patch 005's
`a_chunk_within_the_assigned_window_is_not_split_at_the_send_buffer` and
`a_response_chunk_within_the_assigned_window_is_not_split_at_the_send_buffer`
regressions prove the caller's behaviour on the vendored combination, and
Ferrum's
`tests/unit/gateway_core/frontend_h2_response_coalescing_tests.rs::vendored_h2_exposes_the_send_capacity_accessor_hyper_patch_005_reads`
binds the accessor's exact signature, so dropping or changing it breaks the
gateway's test build instead of silently disabling Hyper patch 005's
window-aware path.

## Retirement

Retire together with Hyper patch 005, or earlier when an h2 release exposes the
assigned send window (or Hyper stops splitting chunks at send capacity). Then
remove this lifecycle entry and patch document and regenerate
`vendor/VENDOR_INTEGRITY.sha256`. Against stock h2, Hyper patch 005 falls back
to `capacity()` and splits as it did before this patch, so retiring this patch
alone costs throughput, not correctness.
