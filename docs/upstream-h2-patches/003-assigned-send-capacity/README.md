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
400 KiB default send buffer on the frontend leg. Before this patch, every such
chunk was split and the frontend response pipe stalled mid-chunk.

## Patch

[`h2-assigned-send-capacity.patch`](h2-assigned-send-capacity.patch) applies
after Ferrum's h2 patches 001 and 002. It adds one read-only accessor and
changes no state:

- `SendStream::assigned_capacity()` (`src/share.rs`) returns the window already
  assigned to the stream that buffered data has not yet claimed, ignoring the
  send-buffer limit. It goes through `StreamRef::assigned_capacity`
  (`src/proto/streams/streams.rs`) and `Send::assigned_capacity`
  (`src/proto/streams/send.rs`), which evaluate the existing
  `Stream::capacity` with no buffer limit, under the same lock `capacity()`
  takes.

`capacity()`, `reserve_capacity()`, `poll_capacity()`, flow control and
framing are unchanged.

## Regression coverage

`share::ferrum_assigned_capacity_tests` opens a client stream with a 1 KiB send
buffer against a server whose windows cover a 100,000-byte reservation, and
proves that `capacity()` stops at the 1 KiB buffer while
`assigned_capacity()` reports the full assignment, and that both drop by the
amount buffered by `send_data` before the connection writes it.

```bash
cargo test --manifest-path vendor/h2-0.4.19-ferrum-patched/Cargo.toml --lib ferrum_assigned_capacity
```

Hyper patch 005's
`a_chunk_within_the_assigned_window_is_not_split_at_the_send_buffer`
regression proves the caller's behaviour on the vendored combination.

## Retirement

Retire together with Hyper patch 005, or earlier when an h2 release exposes the
assigned send window (or Hyper stops splitting chunks at send capacity). Then
remove this lifecycle entry and patch document and regenerate
`vendor/VENDOR_INTEGRITY.sha256`. Against stock h2, Hyper patch 005 falls back
to `capacity()` and splits as it did before this patch, so retiring this patch
alone costs throughput, not correctness.
