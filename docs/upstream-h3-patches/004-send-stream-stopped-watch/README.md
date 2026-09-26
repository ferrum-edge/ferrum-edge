# Patch 004 - h3 `SendStreamStopped` watch

## Status

| Field | Value |
|---|---|
| Patch ID | 004-send-stream-stopped-watch |
| Target crate | `h3` |
| Target version | 0.0.8 |
| State | **Applied via vendored crate at `vendor/h3-0.0.8-ferrum-patched`** |
| Upstream issue | _Deliberate fork — unfiled upstream (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Upstream PR | _Deliberate fork — unfiled upstream; no published fork ref yet (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Tracks | Ferrum Edge H3 destination-permit release on per-stream cancel (#3775) |

## Why this directory exists

After an H3 request body is complete (or while a streaming upload is still
being polled on the receive half), the gateway may block on backend response
headers. A client can `STOP_SENDING` the gateway's response direction without
closing the multiplexed QUIC connection. Stock `h3` 0.0.8 exposes no way to
observe that signal without taking `&mut` on the send stream, which would
conflict with a concurrent receive-half poll on an unsplit bidi stream.

This patch adds `quic::SendStreamStopped`: a `&self` method that returns a
`'static` future via stable return-position `impl Future` (RPITIT). Quinn's
`SendStream::stopped` already has that shape; h3 needs the trait so
`server::RequestStream` can forward it through `FrameStream` / `BufRecvStream`
without exclusive send-stream access or a per-call boxed trait object. An
associated-type `impl Trait` (`type Stopped = impl Future`) is intentionally
avoided: that requires unstable `impl_trait_in_assoc_type`.

## Files

| File | Purpose |
|---|---|
| `issue.md` | API-gap report for hyperium/h3. |
| `pr-description.md` | PR description for the API addition. |
| `h3-send-stream-stopped-watch.patch` | Unified diff for the vendored h3 source change. |

## Hand-off - how to file upstream

1. Open an upstream issue in `hyperium/h3` using `issue.md`.
2. Replace the `Fixes #NNN` placeholder in `pr-description.md`.
3. Apply `h3-send-stream-stopped-watch.patch` to an h3 checkout and run `cargo test -p h3`.
4. Push a fork branch, for example `feat/send-stream-stopped-watch`.
5. Open the PR with `pr-description.md` and update this README with the issue and PR numbers.

## Retirement

Once `hyperium/h3` releases a version with equivalent API:

1. Bump the workspace `h3` dependency to that release.
2. Keep the vendored h3 crate until patches 001, 002, 003, and 005 are also retired (co-retirement group `h3-all`).
3. When all active h3 patches are available upstream, remove the h3 `[patch.crates-io]` entry (root and `tests/performance/mesh/Cargo.toml`) and delete `vendor/h3-0.0.8-ferrum-patched`.
4. Move this directory under `docs/upstream-h3-patches/_retired/004-send-stream-stopped-watch/` with a `STATUS.md` noting the upstream merge and release.
5. Keep Ferrum's destination-permit cancellation tests; they should continue to pass against the registry crate.
