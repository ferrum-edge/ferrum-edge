# hyper: bound how long an HTTP/2 request body may wait to be written

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-1.9.0-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream filing yet, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
Owner: Ferrum Edge maintainers. Part of Ferrum issue
[#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588).

## The problem

`backend_write_timeout_ms` bounds how long the backend may stop taking a
request body. For an HTTP/2 backend, the stall happens inside hyper's body pipe
(`PipeToSendStream`, `src/proto/h2/mod.rs`). When the backend stops granting
flow-control window, the pipe parks in `SendStream::poll_capacity`, and it
waits for capacity before it polls the request body. So nothing the gateway
puts in the body can observe the stall, because a parked pipe polls nothing.

Ferrum therefore moved every bounded HTTP/2 upload into a gateway-owned "upload
pump": a separate future that owns the client body, relays it to hyper through
a one-frame channel, and runs the timer on its own side of the channel. It
works, but every frame crosses a task boundary and a channel. On the native
gRPC path that cost about 3.5% of gateway CPU per request at 10 KiB, plus a
cross-task wakeup per frame. The direct-HTTP/2 passthrough arm (no
request-size limit) skipped the pump to avoid that cost, so it enforced no
write timeout at all.

nginx enforces the same bound (`grpc_send_timeout`, "between two successive
write operations") as a timer on the upstream write event, armed only while a
write is blocked, including when the request body is blocked by HTTP/2 flow
control (`request_body_blocked` in `ngx_http_upstream.c`). Envoy has no
request-body write timeout. It relies on its stream idle timeout (5 minutes by
default).

## Patch

The unified diff is
[`hyper-h2-body-write-timeout.patch`](hyper-h2-body-write-timeout.patch),
against hyper 1.9.0 with patches 001–003 applied.

- **`hyper::ext::Http2BodyWriteTimeout`** (new, `src/ext/h2_body_write_timeout.rs`)
  is a request extension. It holds a duration and a shared `expired` flag that
  every clone reads. The HTTP/2 client removes it from the request before
  sending.
- **`ClientTask`** (`src/proto/h2/client.rs`) keeps the connection's
  `Timer`, which it previously used only for keep-alive pings, and attaches the
  extension's bound to that request's body pipe. A request that carries the
  extension on a connection built without a timer fails with a body-write
  error instead of running unbounded.
- **`PipeToSendStream`** (`src/proto/h2/mod.rs`) runs the timer only while it
  holds a polled chunk that it cannot yet hand to h2. That happens when the
  stream or connection window is exhausted, or when h2's send buffer is full
  (h2 assigns no capacity past it). Every chunk handed to `send_data` disarms
  the timer. The sleep is allocated on the first stall and re-armed in place
  afterwards. When the timer fires, the pipe sets the flag, sends
  `RST_STREAM(CANCEL)` and fails the body. Dropping the pipe releases the
  request body.
- **With a bound configured, the pipe polls the body before waiting for
  capacity**, so time spent waiting for the client to send more is never
  counted as a write stall. It holds at most one chunk, as stock hyper already
  does when a 1-byte claim admits a whole chunk. Without the extension the pipe
  behaves exactly as before.

Ferrum attaches the extension instead of installing the pump on two paths:

- the fully streamed native gRPC upload, when the request has no authorization
  lifetime (`UploadSource::for_streaming_grpc_upload`);
- the direct-HTTP/2 passthrough arm.

On both, an expiry before response headers maps to the existing write-timeout
terminal: grpc-status 4 / `read_write_timeout` for gRPC, and 504 /
`backend_timeout` / `read_write_timeout` for HTTP/2. An upload with an
authorization lifetime keeps the pump, whose absolute deadline must release
the client body even while the pipe is parked.

### What the bound cannot see

h2 accepts a whole chunk into its send buffer once the pipe hands it over, and
exposes no count of buffered-but-unsent bytes. A stall is therefore detected on
the next chunk the pipe cannot hand over, so at most one chunk (one inbound
client DATA frame) is not observed. After the last chunk there is nothing left
to bound, and the response wait is bounded by `backend_read_timeout_ms`. The
pump had the same limits: it measured how long hyper took to accept the
previous frame, and its post-end-of-stream drain check needs a socket that
multiplexed HTTP/2 connections never publish.

## Regression tests

The `proto::h2::ferrum_body_write_timeout_tests` in the vendored crate run a
real `hyper::client::conn::http2` connection against an in-process h2 server.
Run them with:

```bash
cargo test --manifest-path vendor/hyper-1.9.0-ferrum-patched/Cargo.toml --features full --lib ferrum_body_write_timeout
```

They cover four cases:

- a backend that stops reading gets `RST_STREAM(CANCEL)`, and the flag reports
  it;
- a slow client body never trips the bound, however long it pauses;
- a backend that keeps opening the window, each time sooner than the bound,
  completes a transfer that takes longer than the bound overall;
- a request that carries the extension on a connection without a timer fails.

Gateway coverage, run with `--ignored`:

- `grpc_streaming_backend_write_timeout_maps_to_deadline_exceeded` and
  `h2_direct_passthrough_backend_write_timeout_maps_to_504`, in
  `tests/functional/scripted_backend_h2_tests.rs`;
- the source guards in `tests/unit/gateway_core/stream_auth_lifetime_tests.rs`
  and `tests/unit/gateway_core/proxy_tests.rs`.

## Retirement

Retire when hyper offers an equivalent per-request bound on HTTP/2 body write
stalls, or when Ferrum's HTTP/2 client moves off hyper. Until then the
extension is Ferrum-only API, so it should be filed upstream (hyper or h2)
before the deliberate-fork deadline.
