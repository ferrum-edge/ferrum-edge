# h2: report whether a stream's reset was local or the peer's

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/h2-0.4.20-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. It exists for
[Hyper patch 006](../../upstream-hyper-patches/006-h2-stream-termination-origin/README.md)
and retires with it.

## Problem

`SendResponse::poll_reset` yields the `Reason` of a reset, but not who sent it.
h2 records the initiator internally (`Initiator::{User, Library, Remote}` on the
stream's closed cause), and `ensure_reason` reports library-generated resets,
such as a `PROTOCOL_ERROR` for a `content-length` overrun, through the same
call as a peer's `RST_STREAM`. A server therefore cannot tell a client that
cancelled from a client that broke the protocol.

## Patch

[`h2-reset-origin.patch`](h2-reset-origin.patch) applies after Ferrum's h2
patches 001 and 003, against h2 0.4.20. It adds one read-only accessor and
changes no state:

- `server::SendResponse::reset_is_local()` returns `Some(false)` when the peer
  sent the `RST_STREAM` or `GOAWAY` that closed the stream, `Some(true)` when
  this endpoint did (h2 itself or the user, including a scheduled library
  reset), and `None` while the stream is open, after a clean close, and after
  an I/O error. It goes through `StreamRef::reset_is_local`
  (`src/proto/streams/streams.rs`) to `State::reset_is_local`
  (`src/proto/streams/state.rs`) under one acquisition of the streams lock.

`poll_reset`, flow control and framing are unchanged.

## Regression coverage

Ferrum's
`tests/unit/gateway_core/client_abort_accounting_tests.rs::h2_local_protocol_reset_is_a_protocol_error_not_a_client_abort`
proves a library `PROTOCOL_ERROR` reset reaches the gateway as a local reset,
and the `RST_STREAM(CANCEL)` cases in the same file prove a peer reset reaches
it as the peer's, through Hyper patch 006.

## Retirement

Retire together with Hyper patch 006, or earlier when an h2 release exposes the
reset initiator on `SendResponse`. Then remove this lifecycle entry and patch
document and regenerate `vendor/VENDOR_INTEGRITY.sha256`.
