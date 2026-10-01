# h2: coalesce DATA frames into one write

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/h2-0.4.19-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. Part of Ferrum issue
[#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588). Drafts for
filing are in [`issue.md`](issue.md) and [`pr-description.md`](pr-description.md).

## The problem

h2's `FramedWrite` keeps one write buffer for frame headers and small frames,
plus a single `next` slot for one chained DATA payload. A DATA payload of
256 bytes or more (1 KiB without vectored I/O) is chained into that slot
rather than copied, and while the slot is full `has_capacity()` is false. So
`Prioritize::buffer_pending` can stage only one sizeable DATA frame before the
codec must flush, and every such frame leaves in its own write:

- one `writev` per DATA frame, however many streams have data ready;
- over TLS, a 16 KiB payload plus its 9-byte frame header is 16,393 bytes,
  which does not fit one TLS record, so every frame also costs a 9-byte
  record of its own (an extra AEAD seal on the sender and open on the peer);
- one receiver wakeup per frame on the peer.

Ferrum relays HTTP/2 and gRPC through h2 on both legs. On the protocol
benchmark (Ferrum vs Envoy on one 4-vCPU runner, 200 streams, TLS on both
legs), Ferrum's HTTP/2 backend peer context-switched two to two and a half times as often per
request as behind Envoy, which writes all of a connection's pending frames per
event-loop pass.

## Patch

The unified diff is
[`h2-coalesce-data-frame-writes.patch`](h2-coalesce-data-frame-writes.patch),
against h2 0.4.19. All changes are in `src/codec/framed_write.rs`.

- `Encoder::buffer` copies a DATA payload into the write buffer, with its
  frame header, while the buffer stays within `COALESCE_LIMIT` (64 KiB). The
  copied frame is complete once buffered, so it is recorded in
  `last_data_frame` exactly as a sub-threshold frame already was, and
  `Prioritize` reclaims it before staging the next frame. A payload that
  would push the buffer past the limit is chained as before, behind the
  copied frames, so with vectored I/O it still leaves in the same write.
- `Encoder::has_capacity` counts room under `COALESCE_LIMIT` as capacity, so
  `buffer_pending` keeps staging frames from every ready stream until the
  limit, then flushes them in one write.
- When coalescing needs more room, the buffer grows once, straight to the
  limit, instead of doubling through several reallocations.
- `Encoder::unset_frame` replaces a buffer that grew past its initial 16 KiB
  with a fresh 16 KiB one once everything is written, so an idle connection
  does not keep the larger allocation.

Frame boundaries, frame sizes, flow control and the order of frames are
unchanged; only how many frames share one write changes. The cost is one
`memcpy` of each coalesced payload. Over TLS that copy is already made once
more by rustls; over cleartext it replaces a zero-copy `writev` segment.

## Measured effect

Same-runner A/B against the unpatched build of the same commit, Envoy 1.39.1
as the anchor (run
[36923833476](https://github.com/ferrum-edge/ferrum-edge/actions/runs/36923833476),
30 s, 200 streams, two iterations):

| Protocol | 10 KiB | 70 KiB | 512 KiB | 1 MiB | 5 MiB |
|---|---|---|---|---|---|
| HTTP/2, patched vs unpatched | +5.5% | +8.7% | +16.1% | +10.6% | +6.0% |
| HTTP/2 vs Envoy, unpatched → patched | 0.99 → 1.04 | 1.02 → 1.11 | 0.90 → 1.05 | 0.94 → 1.04 | 0.91 → 0.97 |
| gRPC, patched vs unpatched | +3.6% | +4.1% | +1.9% | +1.2% | +0.5% |

## Regression tests

`codec::framed_write::ferrum_coalesce_data_frame_writes_tests` in the vendored
crate, run with:

```bash
cargo test --manifest-path vendor/h2-0.4.19-ferrum-patched/Cargo.toml --lib ferrum_coalesce_data_frame_writes
```

They check that DATA frames within the limit leave in one write (vectored and
not) with byte-exact framing, that a frame past the limit is chained behind
the copied ones, that a frame larger than the limit is chained whole without
growing the buffer, that the buffer returns to its initial size after a
coalesced write, and that a copied frame is handed back fully consumed. The
rest of h2's library suite also passes, apart from the HPACK fixture tests,
which read data files the published crate does not ship.

## Retirement

Retire when an h2 release batches DATA frames into one write (this patch or an
equivalent), or when Ferrum stops using h2. Remove the `h2` line from
`[patch.crates-io]` in `Cargo.toml` and `tests/performance/mesh/Cargo.toml`,
drop `vendor/h2-0.4.19-ferrum-patched/`, update both lockfiles, remove the
inventory row and `docs/vendored-patch-lifecycle.json` entry, and regenerate
the drift manifest.
