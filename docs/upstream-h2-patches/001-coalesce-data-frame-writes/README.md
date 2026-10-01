# h2: coalesce DATA frames into one write

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/h2-0.4.19-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Owner: Ferrum Edge maintainers. Part of Ferrum issue
[#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588).

Upstream already tracks the problem:

- **[hyperium/h2#902](https://github.com/hyperium/h2/issues/902)** (issue): "Sending and receiving data frames introduces significant overhead".
- **[hyperium/h2#903](https://github.com/hyperium/h2/pull/903)** (PR): "perf: allow multiple DATA frames per write".

Both were opened by a third party on 2026-05-05; the PR is open and awaiting review. The weekly lifecycle poll watches #903.

#903 replaces the encoder's single `next` slot with a queue of frames written by one vectored call, adds per-stream partial-send state in `Prioritize`, and reclaims written frames in bulk (+318/−159 across five files, with merge conflicts against current h2). We carry a smaller, encoder-only patch until #903 or an equivalent ships, because:

- it touches one file, so it is easy to review and to drop;
- it changes no stream state machinery;
- over TLS the copy it adds is one rustls makes anyway.

Do not file a separate upstream issue or PR; add Ferrum's measurements to #902 if useful.

## The problem

h2's `FramedWrite` keeps one write buffer for frame headers and small frames,
plus a single `next` slot for one chained DATA payload. A DATA payload of
256 bytes or more (1 KiB without vectored I/O) is chained into that slot
rather than copied, and while the slot is full `has_capacity()` is false. So
`Prioritize::buffer_pending` can stage only one sizeable DATA frame before the
codec must flush, and every such frame leaves in its own write:

- One `writev` per DATA frame, however many streams have data ready.
- Over TLS, a 16 KiB payload plus its 9-byte frame header is 16,393 bytes, 9 bytes too long for one TLS record. So every maximum-size frame also costs a second, 9-byte record: an extra AEAD seal on the sender and an extra open on the peer.
- One receiver wakeup per frame on the peer.

Ferrum relays HTTP/2 and gRPC through h2 on both legs. On the protocol benchmark (Ferrum vs Envoy on one 4-vCPU runner, 200 streams, TLS on both legs), Ferrum's HTTP/2 backend peer context-switched two to two and a half times as often per request as it did behind Envoy, which writes all of a connection's pending frames per event-loop pass.

## Patch

The unified diff is
[`h2-coalesce-data-frame-writes.patch`](h2-coalesce-data-frame-writes.patch),
against h2 0.4.19. The change is in `src/codec/framed_write.rs`, plus a one-line idle hook in `src/proto/streams/streams.rs` (with its `Codec` delegate in `src/codec/mod.rs`) and test-only accessors in `src/proto/connection.rs` and `src/client.rs`.

- `Encoder::buffer` copies a DATA payload into the write buffer, with its frame header, while the buffer stays within `COALESCE_LIMIT` (64 KiB, inclusive).
  - A copied frame is complete once buffered, so it is recorded in `last_data_frame` exactly as a sub-threshold frame already was, and `Prioritize` reclaims it before staging the next frame.
  - A payload that would push the buffer past the limit is chained as before, behind the copied frames, so with vectored I/O it still leaves in the same write.
  - The limit is approximate for the buffer as a whole: control frames encoded after copied DATA (HEADERS, RST_STREAM, PING, WINDOW_UPDATE, SETTINGS, GOAWAY) can take it past 64 KiB by at most one frame (`max_frame_size` + 9 bytes for HEADERS).
- `Encoder::has_capacity` counts room under `COALESCE_LIMIT` as capacity, so `buffer_pending` keeps staging frames from every ready stream until the limit, then flushes them in one write.
- When coalescing needs more room, the buffer grows once, straight to the limit, instead of doubling through several reallocations.
- A grown buffer is kept across writes and dropped when the connection goes idle. `Streams::poll_complete`, at the point where everything staged has been flushed and nothing else is pending, calls `Codec::shrink_write_buf_if_idle`, which replaces an empty buffer larger than 16 KiB with a fresh 16 KiB one. A busy connection therefore reuses one grown buffer across writes, and an idle connection never keeps more than the initial 16 KiB. The frontend sets no HTTP/2 keepalive, so an idle connection may never write again, and shrinking on a later write would not be enough.

Frame boundaries, frame sizes, flow control and the order of frames are unchanged; only how many frames share one write changes. The cost is one `memcpy` of each coalesced payload. Over TLS, rustls copies the payload once more anyway; over cleartext, the copy replaces a zero-copy `writev` segment.

### Behaviour difference: data staged before a local reset

A copied frame counts as written. If a stream is reset locally after some of its DATA was staged but before the buffer reached the socket, that DATA still goes out, ahead of the `RST_STREAM`. That can be up to about 64 KiB, all of it already charged against flow control. Stock h2 can stage at most one chained DATA frame plus up to 16 KiB of small (sub-256-byte) frames in its write buffer, and sends those in that case.

RFC 9113 permits this: frames sent before `RST_STREAM` are valid, and a peer ignores DATA on a stream it has reset (section 5.4.2), still counting it against the connection window. The same ordering applies when the peer's `RST_STREAM` arrives while DATA for that stream is staged. Stock h2 has that race for one frame; here it covers the staged batch.

This is the one result that differs in h2's own integration suite (`tests/h2-tests` at tag v0.4.19, revision `d57d1b8`):

- With this patch, 214 of 215 tests pass.
- `stream_states::send_err_with_buffered_data` expects exactly one 16 KiB DATA frame before the client's `RST_STREAM(CANCEL)` and receives the second staged frame instead.
- Stock h2 passes all 215.

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

The regression tests are `codec::framed_write::ferrum_coalesce_data_frame_writes_tests` in the vendored crate. Run them with:

```bash
cargo test --manifest-path vendor/h2-0.4.19-ferrum-patched/Cargo.toml --lib ferrum_coalesce_data_frame_writes
```

They check that:

- DATA frames within the limit leave in one write, with byte-exact framing, with and without vectored I/O.
- The limit is inclusive: a frame that fills it exactly is copied, and one byte more is chained.
- A frame past the limit is chained behind the copied ones.
- A frame larger than the limit is chained whole without growing the buffer, with and without vectored I/O.
- Partial writes and `Pending` neither lose, duplicate nor reorder bytes.
- Control frames (HEADERS, RST_STREAM, PING, WINDOW_UPDATE) interleaved with copied DATA keep their order, and END_STREAM survives the copy.
- A grown buffer is kept across writes, is never dropped while unwritten bytes remain, and is dropped once idle. End to end, a client connection that uploaded 512 KiB (and so grew its buffer) holds only the initial 16 KiB once idle; without the idle hook this test fails with a 65,536-byte buffer.
- A copied frame is handed back fully consumed.

h2's library suite also passes, apart from the HPACK fixture tests, which read data files the published crate does not ship.

CI also runs every Ferrum hyper regression (`ferrum_*`, including patch 002's DATA-frame capacity test) against this h2 (the `Vendored Patch Regressions` job), and the H2 guard observation lane builds its observed h2 from the verified archive plus this patch.

## Retirement

Retire when an h2 release containing hyperium/h2#903 (or another change that batches DATA frames into one write) is adopted, or when Ferrum stops using h2. To retire:

1. Remove the `h2` line from `[patch.crates-io]` in `Cargo.toml`, `tests/performance/mesh/Cargo.toml` and `fuzz/Cargo.toml`.
2. Drop `vendor/h2-0.4.19-ferrum-patched/` and update the three lockfiles.
3. Point the H2 guard lane (`tests/performance/multi_protocol/h2_guard/prepare.py`) back at the registry h2.
4. Remove the inventory row and the `docs/vendored-patch-lifecycle.json` entry.
5. Regenerate the drift manifest.
