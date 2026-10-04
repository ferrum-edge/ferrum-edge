# hyper: preserve HTTP/2 body progress at every positive window

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.9.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Filed upstream on 2026-09-30 as
[hyperium/hyper#4211](https://github.com/hyperium/hyper/issues/4211) and
[hyperium/hyper#4212](https://github.com/hyperium/hyper/pull/4212). The first
revision waited for at least 1 KiB of assigned send capacity. Review identified
that a peer can legally advertise a smaller stream window, so that revision was
unsafe. On 2026-10-04 the PR and Ferrum patch were revised to preserve progress
for every positive amount of capacity instead.

[`issue.md`](issue.md) is the historical issue text.
[`pr-description.md`](pr-description.md) is the current upstream PR
description. Owner: Ferrum Edge maintainers. This work originated in Ferrum
issue [#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588).

## What was true

Hyper can hand h2 a buffered request-body chunk while only a small amount of
connection capacity is assigned. h2 then emits a DATA frame no larger than that
capacity. A long run of frames under 256 bytes is charged against h2's
connection-level DATA-frame budget; exhausting the budget closes the connection
with `GOAWAY(ENHANCE_YOUR_CALM, "too_many_data_frames")`.

The original 1 KiB Hyper workaround was still incorrect. HTTP/2 permits a peer
to advertise a 512-byte stream window, or to leave only one byte of connection
capacity available. Waiting for a fixed minimum in either case prevents all
body progress and can wait forever because the peer cannot release bytes it has
never received.

This was reproduced with the released Ferrum Edge 0.9.10 macOS arm64 binary and
a standards-compliant h2 backend advertising a 512-byte initial stream window.
The backend received request headers, then zero body bytes before the request
timed out. The permanent gateway regression is
`grpc_upload_progresses_with_512_byte_backend_stream_window` in
`tests/functional/scripted_backend_h2_tests.rs`.

The upstream review's receiver-side diagnosis was also correct: h2's automatic
small-frame budget must follow runtime target-window changes made by adaptive
flow control. Ferrum carries that correction separately as
[h2 patch 002](../../upstream-h2-patches/002-runtime-data-frame-budget/README.md),
filed upstream as [hyperium/h2#965](https://github.com/hyperium/h2/pull/965).

## Patch

Ferrum's body-write-timeout extension can poll and retain a body chunk while
send capacity is zero. The corrected Hyper patch keeps that pending chunk but
sends it as soon as any positive capacity is assigned. It does not impose a
minimum DATA-frame size:

- an empty end-of-stream chunk requires no capacity;
- a non-empty chunk waits only while assigned capacity is zero;
- the existing one-byte reservation is retained, allowing a legal small peer
  window and the last byte of connection capacity to make progress;
- h2 expands the reservation for the remaining buffered data after
  `send_data`.

[`hyper-min-data-frame-capacity.patch`](hyper-min-data-frame-capacity.patch)
records the correction from the former fixed-minimum implementation to the
current progress-preserving implementation.

## Regression coverage

`proto::h2::ferrum_h2_flow_control_progress_tests` runs real h2 peers over an
in-memory transport. It verifies both a complete 2 KiB upload through a
512-byte peer stream window and a second stream making progress with the final
byte of connection capacity. Run it with:

```bash
cargo test --manifest-path vendor/hyper-1.9.0-ferrum-patched/Cargo.toml --features full --lib ferrum_h2_flow_control_progress
```

The ignored functional test exercises the same 512-byte window through the
actual Ferrum Edge gateway:

```bash
FERRUM_EDGE_TEST_BIN=target/debug/ferrum-edge \
  cargo test --test functional_tests \
  functional::scripted_backend_h2_tests::grpc_upload_progresses_with_512_byte_backend_stream_window \
  -- --ignored --exact
```

## Retirement plan

Retire this logical patch when a Hyper release containing PR #4212's regression
coverage is adopted and the pending-body implementation is either upstream or
retired with the body-write-timeout extension. The fixed 1 KiB behavior must
not be restored. Retire h2 patch 002 independently when an h2 release containing
PR #965 is adopted.
