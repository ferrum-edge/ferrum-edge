# Patch 002 - h3-quinn `SendStream::stopped` watch

## Status

| Field | Value |
|---|---|
| Patch ID | 002-send-stream-stopped-watch |
| Target crate | `h3-quinn` |
| Target version | 0.0.10 (latest published as of 2026-08-06) |
| State | **Applied via vendored crate at `vendor/h3-quinn-0.0.10-ferrum-patched`** |
| Upstream issue | _Deliberate fork — unfiled upstream (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Upstream PR | _Deliberate fork — unfiled_ |
| Tracks | Ferrum Edge H3 destination-permit release on per-stream cancel (#3775) |

## Why this directory exists

Quinn's `SendStream::stopped` is `&self` and returns a `'static` future. Stock
`h3-quinn` 0.0.10 does not implement h3's `SendStreamStopped` trait (added in
the sibling h3 patch 004), so a server cannot observe peer `STOP_SENDING` on
the response direction without exclusive send-stream access.

This patch implements `h3::quic::SendStreamStopped` for `SendStream` and
`BidiStream` by forwarding to `quinn::SendStream::stopped` as a statically
dispatched return-position `impl Future`. Associated-type `impl Trait` is
avoided so the crate stays on stable Rust.

## Files

| File | Purpose |
|---|---|
| `issue.md` | Bug/API gap report for hyperium/h3. |
| `pr-description.md` | PR description for the API addition. |
| `h3-quinn-send-stream-stopped-watch.patch` | Unified diff for the vendored h3-quinn source change. |

## Hand-off - how to file upstream

1. Open an upstream issue in `hyperium/h3` using `issue.md` (h3-quinn lives in the same repo).
2. Replace the `Fixes #NNN` placeholder in `pr-description.md`.
3. Apply `h3-quinn-send-stream-stopped-watch.patch` to an h3-quinn checkout together with h3 patch 004.
4. Push a fork branch and open the PR with `pr-description.md`.

## Retirement

Once `h3-quinn` ships a release whose `SendStream`/`BidiStream` expose an
equivalent `&self` + `'static` `stopped` watch:

1. Bump the workspace `h3-quinn` dependency to that release.
2. Keep the vendored crate until patch 001 is also retired (they share one vendor directory).
3. When both active h3-quinn patches are available upstream, remove the
   `h3-quinn` `[patch.crates-io]` entry (root and
   `tests/performance/mesh/Cargo.toml`) and delete
   `vendor/h3-quinn-0.0.10-ferrum-patched`.
4. Move this directory under
   `docs/upstream-h3-quinn-patches/_retired/002-send-stream-stopped-watch/`
   with a `STATUS.md` noting the upstream merge and release.
5. Keep Ferrum's destination-permit cancellation tests; drop the vendored-shape
   contract test, which retires with the vendor copy.
