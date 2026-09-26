# Patch 005 - h3 receive-side buffered non-`DATA` frame ceiling

## Status

| Field | Value |
|---|---|
| Patch ID | 005-max-buffered-frame-len |
| Target crate | `h3` |
| Target version | 0.0.8 |
| State | **Applied via vendored crate at `vendor/h3-0.0.8-ferrum-patched`** |
| Upstream issue | _Deliberate fork — unfiled upstream (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Upstream PR | _Deliberate fork — unfiled upstream; no published fork ref yet (see hand-off below + [policy](../../dependency-policy.md#deliberate-fork-policy-and-sla))_ |
| Tracks | Ferrum Edge HTTP/3 unauthenticated declared-frame-length OOM (#4261) |

## Why this directory exists

Stock `h3` 0.0.8 never bounds the **declared** payload length of a non-`DATA`
frame. `Frame::decode` returns `FrameError::Incomplete(2 + len)` for any frame
whose payload has not fully arrived, `FrameDecoder` stores that as its
`expected` accumulation target, and `FrameStream::poll_next` then keeps pulling
QUIC chunks into an unbounded `BufList` until `remaining() >= expected`.

QUIC flow control does not bound that accumulation. `stream_receive_window` and
`receive_window` cap the bytes *in flight*; every poll here **consumes** from
the stream, which re-grants credit. So an unauthenticated peer can complete the
handshake, open one request stream, write frame type `0x01` (HEADERS) followed
by a varint length of `0x3FFF_FFFF_FFFF_FFFF`, and stream arbitrary bytes.
`accept()` never returns and memory grows linearly with the attacker's
bandwidth until the process is OOM-killed. `max_idle_timeout` does not help:
the peer is active, not idle.

The same shape works with:

- any **unknown** frame type — the `buf.advance(len)` skip arm is only reached
  *after* the whole frame is buffered, so "ignore it" still means "buffer it";
- the peer's **unidirectional control stream**, where SETTINGS and GOAWAY are
  decoded by an identically unbounded `FrameDecoder`.

## What the patch changes

- `proto/frame.rs` gains `Frame::decode_bounded(buf, max_buffered_frame_len)`
  and a `FrameError::ExceedsMaxBufferedLen { ty, len, max }` variant.
  `Frame::decode` delegates to it with `u64::MAX`, so the change is additive and
  stock behaviour is preserved for callers that do not opt in.
- The ceiling is compared against the **raw `u64` QUIC varint**, before any
  `usize` conversion, so a `2^32 + n` declaration cannot truncate into a short
  frame on a 32-bit target and slip under the cap. A length the platform cannot
  address is refused the same way whatever the configured ceiling, and the
  accumulation target uses `saturating_add`.
- `DATA` is exempt by construction: its payload is handed to the caller as a
  streaming length and is never accumulated by the decoder. Bounding it would
  break request bodies larger than the header ceiling.
- `frame.rs`: `FrameDecoder` carries `max_buffered_frame_len` (defaulting to
  `FrameDecoder::UNBOUNDED_FRAME_LEN`), decodes through `decode_bounded`, and
  maps the refusal to `FrameProtocolError::ExceedsMaxBufferedFrameLen` **without
  arming `expected`** — so not one payload byte is retained.
- `error/internal_error.rs` maps that to a connection error of type
  `H3_EXCESSIVE_LOAD` (RFC 9114 §8.1), which is what an over-declared length
  is: a resource-exhaustion attempt, not a malformed frame.
- `config.rs` / `server/builder.rs` / `client/builder.rs` expose
  `max_buffered_frame_len(value)`, and the ceiling is threaded to every decoder
  the connection owns: accepted request streams (`server/connection.rs`),
  and CONTROL and PUSH unidirectional streams (`connection.rs`, `stream.rs`).
  `FrameStream::split` propagates it to both halves.

## Files

| File | Purpose |
|---|---|
| `issue.md` | Vulnerability report draft for hyperium/h3. |
| `pr-description.md` | PR description for the API addition and the bound. |
| `h3-max-buffered-frame-len.patch` | Unified diff for the vendored h3 source change. |

## Hand-off - how to file upstream

1. Open an upstream issue in `hyperium/h3` using `issue.md`. Coordinate
   disclosure first: this is a remotely triggerable memory-exhaustion bug in a
   published crate, so prefer the repository's private advisory channel over a
   public issue.
2. Replace the `Fixes #NNN` placeholder in `pr-description.md`.
3. Apply `h3-max-buffered-frame-len.patch` to an h3 checkout and run
   `cargo test -p h3`.
4. Push a fork branch, for example `feat/max-buffered-frame-len`.
5. Open the PR with `pr-description.md` and update this README with the issue
   and PR numbers.

## Retirement

Retirement criteria: `hyperium/h3` ships a release that bounds the declared
payload length of a buffered non-`DATA` frame on the receive side, exposes it
through the server (and ideally client) builder, and refuses an over-declared
frame **before** buffering its payload. A release that only bounds the decoded
field-section size does **not** satisfy this — the OOM happens before QPACK
decoding.

Once such a release exists:

1. Bump the workspace `h3` dependency to that release.
2. Keep the vendored h3 crate until patches 001, 002, 003, and 004 are also
   retired (co-retirement group `h3-all`).
3. When all active h3 patches are available upstream, remove the h3
   `[patch.crates-io]` entry (root and `tests/performance/mesh/Cargo.toml`)
   and delete `vendor/h3-0.0.8-ferrum-patched`.
4. Move this directory under
   `docs/upstream-h3-patches/_retired/005-max-buffered-frame-len/` with a
   `STATUS.md` noting the upstream merge and release.
5. **Behaviour that must survive retirement.** Re-point the frontend builder
   calls in `src/http3/server.rs` and the backend frame-ceiling builder calls in
   `src/http3/client.rs` at the upstream setters and keep these tests green:
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::h3_listener_builder_binds_frame_bounds_to_the_header_policy`
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::h3_backend_client_builder_binds_frame_ceiling_without_response_policy_drift`
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::h3_vendored_frame_decoder_refuses_oversized_declared_non_data_length`
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::h3_vendored_frame_ceiling_maps_to_excessive_load_on_every_decoder`
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::h3_vendored_frame_ceiling_behavioural_regressions_are_present`
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::h3_advertised_field_section_size_tracks_configured_header_policy`
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::h3_buffered_frame_ceiling_leaves_the_graceful_431_reachable`
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::h3_field_section_limits_refuse_an_unrepresentable_header_policy`
   - `tests/unit/gateway_core/http3_server_dispatch_tests.rs::env_config_validation_screens_h3_field_section_limits`

   The three `h3_vendored_*` contracts are vendor-shape assertions and are
   retired with the vendor directory; the rest are Ferrum-owned and must be
   kept. The vendored `--lib frame` behavioural tests
   (`oversized_declared_headers_frame_is_refused_without_buffering` and
   siblings, run by the `Vendored Patch Regressions` CI job) are replaced by
   whatever upstream ships; re-verify the equivalent behaviour against the
   registry crate before deleting them.
