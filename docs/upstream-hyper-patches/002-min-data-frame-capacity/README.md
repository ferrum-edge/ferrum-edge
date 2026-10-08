# hyper: preserve HTTP/2 body progress at every positive window

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.10.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

The original workaround was filed on 2026-09-30 as
[hyperium/hyper#4211](https://github.com/hyperium/hyper/issues/4211) and
[hyperium/hyper#4212](https://github.com/hyperium/hyper/pull/4212). Its fixed
1 KiB send-capacity threshold was unsafe for smaller legal peer windows.
The PR was revised to test positive-capacity progress, then **closed unmerged
on 2026-10-04 at 08:45:54 UTC**. It did not deliver an upstream implementation
for adoption, and a release containing that PR is not a retirement trigger.

The current pending-body implementation is a **deliberate fork**, governed by
the [deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
It is required by [Hyper patch 004](../004-h2-body-write-timeout/README.md).
Owner: Ferrum Edge maintainers; dependency-governance owner:
`@jeremyjpj0916`. No dated owner reaffirmation is recorded. Before the first
stable release checkpoint, the owner must file a current equivalent upstream
proposal or record a dated deliberate-fork reaffirmation in this README and
the lifecycle inventory. The closed proposal is historical context, not
upstream acceptance of the current fork.

[`issue.md`](issue.md) and [`pr-description.md`](pr-description.md) archive the
upstream issue and final PR description. This work originated in Ferrum issue
[#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588).

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
flow control. Ferrum carried that correction separately as h2 patch 002 until
it shipped upstream as [hyperium/h2#965](https://github.com/hyperium/h2/pull/965)
in h2 0.4.20, which Ferrum now vendors.

## Patch

Ferrum's body-write-timeout extension can poll and retain a body chunk while
send capacity is zero. The corrected Hyper patch keeps that pending chunk but
sends it as soon as any positive capacity is assigned. It does not impose a
minimum DATA-frame size:

- an empty end-of-stream chunk requires no capacity;
- a non-empty chunk waits only while assigned capacity is zero;
- Hyper 1.10's body-first polling and reservation for the real chunk length
  are retained, so an idle body cannot pin a byte of connection window;
- every positive assigned capacity still allows a legal small peer window
  and the last byte of connection capacity to make progress;
- h2 expands the reservation for the remaining buffered data after
  `send_data`.

[`hyper-min-data-frame-capacity.patch`](hyper-min-data-frame-capacity.patch)
is the complete patch against the published Hyper 1.10.0 crate with patch 001
applied. It introduces the pending-body foundation and progress regressions;
it does not require the former patch 002 or patch 004 as a preimage. Apply
[the complete ordered stack](../README.md) to reconstruct the current vendor
source, including patch 004's timeout integration.

## Regression coverage

`proto::h2::ferrum_h2_flow_control_progress_tests` runs real h2 peers over an
in-memory transport. It verifies both a complete 2 KiB upload through a
512-byte peer stream window and a second stream making progress with the final
byte of connection capacity. Run it with:

```bash
cargo test --manifest-path vendor/hyper-1.10.0-ferrum-patched/Cargo.toml --features full --lib ferrum_h2_flow_control_progress
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

Retire patches 002 and 004 together when Ferrum adopts an equivalent upstream
HTTP/2 request-body write-stall bound that preserves progress for every positive
assigned capacity, or when Ferrum's HTTP/2 client moves off Hyper. Both entries
belong to the `hyper-h2-body-progress-and-timeout` co-retirement group, with
[patch 005](../005-h2-small-window-coalescing/README.md), which rewrites the
same pending-body loop to coalesce small window increments. Upstream already
permits positive-capacity progress in its ordinary body pipe; merely adopting
that behavior does not replace Ferrum's pending-body timeout path.

Before retirement, hosted tests must verify the 512-byte stream window, final
connection byte, empty end-of-stream handling and write-stall timeout behavior
against the proposed replacement, plus patch 005's trickling-window and
lockstep-window regressions. Keep the gateway behavioral regressions and
regenerate any remaining patch stack. No compatible replacement release has
been selected or tested. The fixed 1 KiB behavior must not be restored.

h2 patch 002 (the runtime budget update) already retired independently: h2
0.4.20 ships hyperium/h2#965, and its accounting regressions still run in CI.
