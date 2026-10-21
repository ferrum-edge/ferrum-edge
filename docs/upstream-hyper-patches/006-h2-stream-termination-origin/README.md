# hyper: report why an HTTP/2 server stream ended before its response

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.10.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. Part of Ferrum issue
[#6768](https://github.com/ferrum-edge/ferrum-edge/issues/6768). It needs
[h2 patch 004](../../upstream-h2-patches/004-reset-origin/README.md) and
retires with it.

## The problem

When an HTTP/2 stream is reset while the service future is still pending,
hyper's `H2Stream::poll2` (`src/proto/h2/server.rs`) returns an error and the
service future is dropped. The future's drop glue is the only code that runs
for the request, and it cannot tell why: the peer's `RST_STREAM` or `GOAWAY`,
a lost transport, and a reset hyper's own HTTP/2 stack sent because the peer
violated the protocol (a `content-length` mismatch, for example) all look the
same. h2 reports all of them through `SendResponse::poll_reset`.

Ferrum records exactly one terminal for every admitted request, including one
dropped this way, and must only call it a client cancellation (`499`) on
positive evidence that the peer cancelled. A local protocol rejection is a
`400`-class terminal instead.

## Patch

[`hyper-h2-stream-termination-origin.patch`](hyper-h2-stream-termination-origin.patch)
applies after patches 001–005.

- `src/ext/h2_stream_termination.rs` (new) defines
  `hyper::ext::H2StreamTermination` (`PeerReset { reason }`,
  `TransportLost`, `LocalReset { reason }`; non-exhaustive) and
  `hyper::ext::take_h2_stream_termination()`. A thread-local slot carries one
  pending cause.
- `H2Stream::poll2` publishes the cause just before it returns the reset
  error that ends the stream: a reset whose `SendResponse::reset_is_local()`
  (h2 patch 004) is `Some(true)` is `LocalReset`, any other reset is
  `PeerReset`; an I/O error is `TransportLost`; an error carrying a reason is
  classified by `h2::Error::is_remote()`.
- `H2Stream` gains a last field, `ClearH2StreamTermination`, which drops after
  the service future and clears the slot. Tokio drops a completed task's
  future synchronously in the poll that completed it, so the cause is visible
  exactly while the service future is dropped and never afterwards.

No allocation is added and nothing changes for a stream that completes
normally beyond one thread-local store when it is dropped.

## Regression coverage

Ferrum's
`tests/unit/gateway_core/client_abort_accounting_tests.rs` drives the patched
server:

- `h2_reset_while_waiting_for_response_headers_records_one_client_abort` and
  `h2_reset_during_buffered_upload_records_one_client_abort`: a peer
  `RST_STREAM(CANCEL)` is recorded as `499`.
- `h2_local_protocol_reset_is_a_protocol_error_not_a_client_abort`: a
  `content-length` overrun that h2 resets with `PROTOCOL_ERROR` while the
  service is pending is recorded as `400`, never `499`.
- `unattributed_http2_drop_is_never_a_client_abort`: a drop with no published
  cause is never labelled a client cancellation.

## Retirement

Retire with h2 patch 004 when hyper exposes why a server stream ended (or the
reset origin) to the service, or when Ferrum stops serving HTTP/2 through
hyper. Then remove this entry from `series`, the verifier's `SERIES`, the
lifecycle inventory, and regenerate `vendor/VENDOR_INTEGRITY.sha256`. Without
it, Ferrum records every HTTP/2 drop as unattributed (`444`), never as a
client cancellation.
