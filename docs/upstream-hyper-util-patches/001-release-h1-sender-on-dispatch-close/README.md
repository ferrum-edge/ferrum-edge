# hyper-util: release an HTTP/1 sender once its dispatcher stops reading

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-util-0.1.21-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork with no upstream PR, governed by the
[deliberate fork policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).
The bug is reported upstream as
[hyperium/hyper#4202](https://github.com/hyperium/hyper/issues/4202)
(`hyperium/hyper-util` has issues disabled, and the stranding happens in
hyper's HTTP/1 dispatcher). Owner: Ferrum Edge maintainers. This patch fixes
Ferrum issue [#5714](https://github.com/ferrum-edge/ferrum-edge/issues/5714)
(first seen as the #5575 flake). The filed issue text is kept in
[`issue.md`](issue.md).

## The bug

Ferrum sends every plain-`http` HTTP/1.1 backend request through reqwest, which
uses hyper-util's legacy `Client`. For an HTTP/1 connection, the client hands
the request to hyper's connection task over a tokio unbounded channel
(`hyper::client::dispatch::Sender::try_send` → `UnboundedSender::send`). In
tokio 1.52.3, `UnboundedSender::send` works in two steps:

1. `inc_num_messages()` checks the channel's closed bit and reserves a slot
   (`tokio/src/sync/mpsc/unbounded.rs:547-585`).
2. `chan.send()` publishes the message into the block list.

If the backend resets or closes an idle connection between those two steps,
hyper's dispatcher (hyper 1.9.0 `proto/h1/dispatch.rs:658-681`,
`Client::recv_msg(Err)`) finds no in-flight callback. It calls `rx.close()`,
and `try_recv()` returns nothing because the slot is reserved but not yet
published: tokio's `recv` returns `Pending` while a send is in progress, and
hyper's `try_recv` uses `now_or_never`. The dispatcher returns the error, which
hyper-util logs as `client connection error`, and the task ends. Dropping the
receiver drains only published messages (`tokio/src/sync/mpsc/chan.rs:487-524`).
A graceful FIN ends the dispatcher without an error, and its receiver drop has
the same gap.

The requester then publishes into a channel nobody reads. Its `Envelope` is
dropped, which fails the callback with a canceled error carrying the unsent
request (hyper `client/dispatch.rs:217-228`), only when the channel itself is
dropped (`chan.rs:555-567`). hyper-util's `try_send_request`
(`client/legacy/client.rs:324`) holds the pooled connection, which owns the
channel's only sender, across `pooled.try_send_request(req).await`. So the
future never resolves. In Ferrum, the response-header deadline ends it after
`backend_read_timeout_ms` as a 504 `ReadWriteTimeout`, when it should fail at
once as an unsent request.

Every hosted failure of `backend_accepts_then_rst_returns_502__*` logs
hyper-util's `client connection error` within about 500 µs of
`checkout dropped`, then nothing until the watermark fires. That is this
interleaving: the error line appears only when the dispatcher had no callback
and `try_recv` found nothing.

## Patch

The base is the crates.io `hyper-util` 0.1.21 source (package checksum
`ddc03d96684f9226b8a787cdb71488417b53ab5ea8fdb1dac946cb9431cc8bff`, upstream
commit `23a868965964c1d6bb1b94f30ba4c420a4bebe7c`). Only
`src/client/legacy/client.rs` differs; the unified diff is
[`hyper-util-release-h1-sender-on-dispatch-close.patch`](hyper-util-release-h1-sender-on-dispatch-close.patch).
The crate's `.github/`, `Cargo.lock`, `Cargo.toml.orig`, `.gitignore` and
`.cargo_vcs_info.json` are not vendored. `examples/` and `tests/` are kept
because the published manifest names them as explicit targets.

The patch was first carried on 0.1.20 (PR #5719). 0.1.21 still holds the only
HTTP/1 sender across the response wait, so the patch was rebased onto it with
the same behavior and tests. 0.1.21 moves the crate to edition 2024, where
`PoolClient::try_send_request`'s return-position `impl Future` would capture
its `&mut self` borrow and stop `try_send_request` from moving the pooled
connection into `await_pooled_response` while the send is pending. The patch
therefore adds `+ use<B>` to that signature; hyper's send future owns
everything it needs. The regression module also drops the `Future` imports
that the edition 2024 prelude now provides.

`try_send_request` now hands the queued request's response future and the
pooled connection to `await_pooled_response`, which waits through
`await_response_or_release` and maps the outcome back to `try_send_request`'s
result. On every wake `await_response_or_release` polls the response first.
Then, through `poll_h1_dispatch_open`, it polls an HTTP/1 connection's pooled
sender's `poll_ready` (hyper's `want::Giver::poll_want`):

- `Ready(Err)`: the dispatcher closed its queue or is gone. The helper records
  `is_reused()` and `conn_info` (`release_pool_conn`), then drops the pooled
  connection. That drop
  releases the last sender, so tokio drops the stranded envelope and hyper
  fails the callback with `Canceled` plus the unsent request. The pool does not
  reinsert it, because a closed sender is not `is_open()`. The helper then
  polls the response again.
- `Ready(Ok)`: the dispatcher asked for more work after this request was
  published. So it had not closed when the request arrived, and it will serve
  or cancel it itself. The watch ends.
- `Pending`: the waker is parked in the `want` slot, and the next `want()` or
  `cancel()` wakes the task.

The request is always published before the first poll, because `try_send` is
synchronous. Once closure is observed, dropping the sender always resolves the
callback: through the channel destructor if the request was stranded, through
the receiver drain if it was queued in time, or through the dispatcher's own
error or `dispatch_gone` if it had been dequeued. A response delivered before
the close is polled first, so it always wins. HTTP/2 senders are pool-shared
clones and are not watched. A response that arrives after a release comes back
without a connection handle, so `try_send_request` returns it without the step
that hands the connection back to the pool.

The outcome matches what hyper already produces when the dispatcher does see a
request queued behind a connection error:

- **Reused connection:** `TrySendError::Retryable { connection_reused: true }`.
  hyper-util retries on a new connection (`retry_canceled_requests` defaults to
  on). This is safe for every method, because not one byte of the request
  reached the old connection.
- **Fresh connection:** a `Canceled` error. Ferrum classifies hyper
  `is_canceled()` as `ConnectionPoolError`, which is a pre-wire 502 that
  `retry_on_connect_failure` may redial.

Hot path cost: one extra `poll_want` per poll of the response future (an
atomic load; on the first park, a try-lock, a compare-and-swap and a waker
clone, which is a reference-count increment for tokio). There is no
allocation. `conn_info` is cloned only on the release path. The watch also
leaves the task's waker in the connection's `want` slot, so a kept-alive HTTP/1
response whose connection is not yet ready can cost one extra wake when the
dispatcher next asks for work.

## Why not a Ferrum-side workaround

reqwest owns hyper-util's `Client`, and hyper-util owns the pooled sender.
Nothing Ferrum can reach observes the dispatcher's closure for a specific
request, and nothing it can reach drops the sender that keeps the stranded
envelope alive. A shorter response-header deadline would only shorten the
stall, and it would also cut legitimate slow backends. A fix in hyper instead
would mean keeping every dispatcher alive after it closes until in-progress
sends publish. That is a larger change to a much larger crate, and it would
still need a similar change for the receiver drop on a graceful close.

## Regression coverage

`#[cfg(test)] mod ferrum_release_on_close_tests` at the bottom of
`src/client/legacy/client.rs`. The race sits between two instructions inside
tokio's `send`, and no public API can schedule it. So the tests build the
state it leaves behind: a request whose callback fires only when the last
sender drops, on a connection whose dispatcher stops reading.

- `stranded_request_without_release_never_resolves`: the bug. After the close,
  the request stays pending until the sender drops.
- `stranded_request_resolves_when_dispatcher_closes`: the close wakes the
  waiting task, which releases the connection and resolves with the canceled
  error.
- `stranded_request_on_already_closed_connection_resolves_on_first_poll`
- `response_delivered_before_close_wins_and_keeps_connection`
- `in_flight_request_keeps_connection_until_response`
- `wanting_dispatcher_ends_the_watch`
- `release_happens_once`
- `hyper_http1_sender_reports_closed_with_request_queued`: against a real
  hyper HTTP/1 connection, checks the premise that `poll_ready` reports
  closure once the dispatcher is gone with a request queued, and that the
  request comes back unsent.

The `pooled_http1` tests run `await_pooled_response`, the step
`try_send_request` takes after queuing a request, on a real pooled HTTP/1
`PoolClient`:

- `watch_reports_when_the_http1_dispatcher_is_gone`: `poll_h1_dispatch_open`
  ends the watch while the dispatcher waits for work and reports closure once
  it is dropped.
- `release_records_reuse_and_conn_info`: `release_pool_conn` keeps the reuse
  flag and the connection info of fresh and reused connections.
- `unsent_request_on_released_connection_is_retryable_as_reused`: a request
  that fails unsent only after the release maps to
  `TrySendError::Retryable` with the reuse flag recorded before the release.
- `response_on_released_connection_is_not_handed_back_for_the_pool`: a
  response after a release keeps the connection's extras and comes back
  without a handle.
- `request_queued_when_reused_connection_closes_is_retryable`: with no
  simulated state, a request queued on a reused connection whose dispatcher is
  dropped comes back retryable.

The `Vendored Patch Regressions` CI job runs them with

```bash
cargo test --manifest-path vendor/hyper-util-0.1.21-ferrum-patched/Cargo.toml --features full --lib ferrum_release_on_close_tests
cargo test --manifest-path vendor/hyper-util-0.1.21-ferrum-patched/Cargo.toml --features full --test legacy_client
```

The second command runs hyper-util's own legacy-client suite. It covers
keep-alive, reuse, drop and close behavior through the patched send path.

End to end, the `backend_accepts_then_rst_returns_502__*` functional matrix
exercises the reset-at-dispatch shape. PR #5712 makes those cells reset only
after the request head arrives, so they no longer depend on this interleaving.

## Ferrum's own HTTP/1 pools

Ferrum's own HTTP/1 pools that drive `hyper::client::conn::http1::SendRequest`
directly (the HBONE inner HTTP/1 path and the Unix-socket backend pool) hold
their sender across the response wait in the same way. They are outside
hyper-util and get the same release in Ferrum code:
`src/proxy/h1_send_release.rs` (#5720).

## Retirement plan

Retire when a hyper-util release stops holding the only HTTP/1 sender across
the response wait after its dispatcher closes, or when a hyper release stops
stranding a racing send (for example, the dispatcher drains the channel until
in-progress sends publish). Then:

1. Remove the `hyper-util` line from `[patch.crates-io]` in `Cargo.toml` and
   `tests/performance/mesh/Cargo.toml`.
2. `git rm -r vendor/hyper-util-0.1.21-ferrum-patched/`, and restore the
   registry `source`/`checksum` lines in `Cargo.lock` and
   `tests/performance/mesh/Cargo.lock` with a normal lockfile update.
3. Remove the inventory row and the lifecycle entry, drop the CI step, and
   regenerate `vendor/VENDOR_INTEGRITY.sha256`.
