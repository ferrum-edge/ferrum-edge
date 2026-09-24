# Legacy client: an HTTP/1 request can hang forever when the connection closes while the request is being queued

<!-- Draft for hyperium/hyper-util. Cross-reference it from hyperium/hyper,
     because the stranding happens in hyper's HTTP/1 dispatcher. File it, then
     record the issue number in the Ferrum README, the dependency-policy
     inventory, and docs/vendored-patch-lifecycle.json. -->

## Summary

`hyper_util::client::legacy::Client` can leave an HTTP/1 request future pending
forever. This happens when the pooled connection's dispatcher closes (the peer
sends RST, or a FIN on an idle keep-alive connection) at the moment the request
is being enqueued. No error is returned and the request is not retried. The
caller sees a hang that ends only when its own timeout fires.

Versions: hyper 1.9.0, hyper-util 0.1.20, tokio 1.52.3. hyper and hyper-util
`master` have the same code.

## Mechanism

1. `Client::try_send_request` checks out an HTTP/1 `Pooled<PoolClient>` and
   calls `pooled.try_send_request(req).await`. It holds `pooled` across the
   await.
2. `hyper::client::dispatch::Sender::try_send` calls tokio's
   `UnboundedSender::send`, which works in two steps:
   `inc_num_messages()` checks the closed bit and reserves a slot, then
   `chan.send()` publishes the value.
3. Suppose the requester is preempted between those two steps while the
   connection task sees the peer's reset. `proto::h1::dispatch::Client::recv_msg(Err)`
   finds no callback. It calls `rx.close()`, and then `rx.try_recv()`. tokio's
   `recv` returns `Pending` while a send is in progress (the semaphore is not
   idle), and `try_recv` uses `now_or_never`, so it returns `None`. The
   dispatcher returns `Err`, and hyper-util logs
   `client connection error: ... ConnectionReset`. On a graceful FIN, the
   dispatcher finishes `Ok` instead and drops its receiver.
4. Dropping `UnboundedReceiver` drains only published values.
5. The requester resumes and publishes into a channel nobody will read.
   `Envelope::drop` would fail the callback with `Canceled` and give back the
   request. But it runs only when the channel is dropped, and the channel
   stays alive while `pooled` holds its only sender. `pooled` is held until the
   response arrives, and the response never arrives.

tokio documents that a value can be sent after the receiver is dropped
(tokio-rs/tokio#7714, tokio-rs/tokio#8278).

## Evidence

In CI, a server that accepts a connection and immediately resets it
(`SO_LINGER=0`) produces this trace:

```
hyper_util::client::legacy::client: connection is ready
hyper_util::client::legacy::pool: checkout dropped
<server accepts, resets>
hyper_util::client::legacy::client: client connection error: hyper::Error(Io, Os { code: 104, kind: ConnectionReset, message: "Connection reset by peer" })
hyper_util::client::legacy::client: sending connection error to error channel
<nothing until the caller's 5 s timeout>
```

The `client connection error` line appears only when the dispatcher had no
callback and `try_recv` found nothing. Every other ordering fails the request
in microseconds. The hang needs a preemption inside a window of a few
instructions, so it shows up only on loaded, many-threaded runners. We saw it
five times in eight days of CI across nine variants of that test, and never in
local repetition.

## Proposed fix (hyper-util)

Do not keep holding the only HTTP/1 sender after its dispatcher has closed.
While awaiting the response, `try_send_request` also polls
`PoolClient::poll_ready` for HTTP/1 connections:

- `Err` (the `want` taker was canceled, which happens on `rx.close()` and on
  receiver drop): capture `is_reused()` and `conn_info`, then drop `pooled`.
  That drops the last sender. The channel destructor then drops any stranded
  envelope, and hyper fails the callback with `Canceled` plus the request. The
  existing `Retryable` path then retries a reused connection or returns
  `Canceled` for a fresh one, which is exactly what happens when the dispatcher
  does see the queued request.
- `Ok` (the dispatcher asked for more work after the request was published):
  it saw the request, so stop watching.

The response future is polled first on every wake, so a delivered response or
error always wins. The change does not allocate and changes no API.
The patch we carry is attached:
`hyper-util-release-h1-sender-on-dispatch-close.patch`.

An alternative fix in hyper: after `rx.close()`, keep the dispatcher polling
`rx` until it returns `Ready(None)`, and cancel anything that arrives. Do the
same before dropping the receiver on a graceful shutdown. That fixes every
`SendRequest` user, including code that drives `client::conn::http1` directly
and holds its sender while waiting. But it keeps the connection task alive
after close until the preempted sender runs again.
