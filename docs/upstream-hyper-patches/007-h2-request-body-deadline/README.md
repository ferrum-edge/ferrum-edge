# hyper: absolute HTTP/2 client request-body deadline

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.10.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. Part of Ferrum PR
[#6870](https://github.com/ferrum-edge/ferrum-edge/pull/6870) (`grpc_deadline`
streaming RPC deadline enforcement).

## The problem

A gRPC client deadline (`grpc-timeout`, or a `grpc_deadline` policy budget)
bounds the whole RPC, including a client- or bidirectional-streaming upload
that is still open after the response headers arrived. hyper's HTTP/2 client
sends the request body from its own pipe task (`PipeMap` /
`PipeToSendStream` in `src/proto/h2/client.rs`), which outlives the response
future. Once the response is in, nothing the gateway owns can end that upload:

- dropping the response body does not reset the stream, because h2 sends
  `RST_STREAM` only once every stream reference is gone and the pipe still
  holds the `SendStream`;
- a deadline inside the request body only fires while the pipe polls the
  body, and a pipe holding a chunk the backend granted no window for parks in
  `poll_capacity` and polls nothing else;
- patch 004's `Http2BodyWriteTimeout` bounds a write *stall* relative to when
  it began, not an absolute instant, and is only installed when
  `backend_write_timeout_ms` is configured.

So a backend that ignores the forwarded `grpc-timeout` and stops granting
upload window could keep both halves of the exchange — its stream, the pooled
connection's concurrency slot, and the frontend upload hyper's pipe owns — past
the client's deadline.

## Patch

[`hyper-h2-request-body-deadline.patch`](hyper-h2-request-body-deadline.patch)
applies after patches 001–006.

- `src/ext/h2_body_deadline.rs` (new) defines the request extension
  `hyper::ext::Http2BodyDeadline` (`new(std::time::Instant)`, `deadline()`).
- `ClientTask` removes it from the request alongside patch 004's extension. On
  a connection built without a `Timer` there is nothing to arm it with, and it
  is ignored (patch 004 instead fails the request; a deadline that cannot be
  armed must not turn every deadline-bearing request into an error).
- When the body pipe is spawned (the eager first poll did not finish the
  body), `PipeMap` arms one sleep from the connection's timer for the
  remaining time. `PipeMap::poll` checks it ahead of the pipe on every wake;
  when it fires, the stream is reset with `CANCEL` and the pipe ends, whatever
  it was parked on.

A body sent in full by the eager poll allocates nothing. No allocation or timer
is added to a request without the extension.

## Regression coverage

Ferrum's `tests/integration/h2_request_body_deadline_tests.rs` drives a real
in-process HTTP/2 client and server:

- `body_deadline_resets_an_upload_parked_on_backend_flow_control`: the backend
  answers at once and stops reading, the client pipe parks on flow control,
  and the backend observes the reset after the deadline.
- `without_a_body_deadline_the_parked_upload_is_not_reset`: the negative
  control.

The gateway attaches the extension in `grpc_proxy::attach_grpc_upload_deadline`
on the native gRPC streaming, sidecar mesh-mTLS / Unix H2c, and direct-H2
dispatches.

## Retirement

Retire when hyper exposes a way to reset an HTTP/2 client stream (or bound its
request body by an absolute instant) from outside the body pipe, or when
Ferrum's HTTP/2 client moves off hyper. Then remove this entry from `series`,
the verifier's `SERIES`, the lifecycle inventory, and regenerate
`vendor/VENDOR_INTEGRITY.sha256`.
