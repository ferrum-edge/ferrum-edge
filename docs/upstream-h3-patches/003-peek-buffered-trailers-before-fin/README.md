# Patch 003 - h3 buffered trailers before FIN

## Status

| Field | Value |
|---|---|
| Patch ID | 003-peek-buffered-trailers-before-fin |
| Target crate | `h3` |
| Target version | 0.0.8 |
| State | **Applied via vendored crate at `vendor/h3-0.0.8-ferrum-patched`** |
| Upstream issue | _Deliberate fork — unfiled upstream (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Upstream PR | _Deliberate fork — unfiled; target branch `feat/peek-buffered-trailers-before-fin` on `jeremyjpj0916/h3`_ |
| Tracks | Ferrum Edge delayed-FIN backend trailer preservation (#1948) |

## Why this directory exists

`RequestStream::poll_recv_trailers` currently waits for the terminal QUIC stream
FIN after it has received trailer HEADERS. That preserves h3's validation rule:
after trailers, another known frame is a protocol error. However, applications
that bound their post-body trailer wait with a timeout cannot recover trailers
that h3 has already buffered internally when the backend delays FIN past that
timeout.

Ferrum Edge needs that recovery for complete H3 backend responses whose trailer
HEADERS arrive on time but whose FIN is delayed. Without an API to inspect the
already-buffered trailer block, the gateway must either keep waiting beyond
`backend_read_timeout_ms` or finish the response without trailers.

This patch adds `peek_recv_trailers()` on client and server request streams. It
decodes a clone of the internally buffered trailer block, does not consume it,
and does not alter normal `poll_recv_trailers` validation for callers that keep
polling until FIN.

## Files

| File | Purpose |
|---|---|
| `issue.md` | Bug/API gap report for hyperium/h3. |
| `pr-description.md` | PR description for the API addition. |
| `h3-peek-buffered-trailers.patch` | Unified diff for the vendored h3 source change. |

## Hand-off - how to file upstream

1. Open an upstream issue in `hyperium/h3` using `issue.md`.
2. Replace the `Fixes #NNN` placeholder in `pr-description.md`.
3. Apply `h3-peek-buffered-trailers.patch` to an h3 checkout and run `cargo test -p h3`.
4. Push a fork branch, for example `feat/peek-buffered-trailers-before-fin`.
5. Open the PR with `pr-description.md` and update this README with the issue and PR numbers.

## Retirement

Once `hyperium/h3` releases a version with equivalent API:

1. Bump the workspace `h3` dependency to that release.
2. Keep the vendored h3 crate until patches 001 and 002 are also retired.
3. When all active h3 patches are available upstream, remove the h3 `[patch.crates-io]` entry and delete `vendor/h3-0.0.8-ferrum-patched`.
4. Move this directory under `docs/upstream-h3-patches/_retired/003-peek-buffered-trailers-before-fin/` with a `STATUS.md` noting the upstream merge and release.
5. Keep Ferrum's delayed-FIN trailer regression tests; they should continue to pass against the registry crate.
