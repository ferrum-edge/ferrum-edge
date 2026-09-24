# hyper-util: release an HTTP/1 sender once its dispatcher stops reading

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/hyper-util-0.1.20-ferrum-patched/` must regenerate the
> drift manifest (`scripts/update_vendor_integrity.sh`).

## Status

Deliberate fork, unfiled upstream. Owner: Ferrum Edge maintainers. This patch
fixes Ferrum issue [#5714](https://github.com/ferrum-edge/ferrum-edge/issues/5714)
(first seen as the #5575 flake). The upstream issue draft is in
[`issue.md`](issue.md). It is ready to file against `hyperium/hyper-util`, and
it cross-references `hyperium/hyper`. Once it is filed, record the number here,
in the inventory table, and in `docs/vendored-patch-lifecycle.json`.

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

The base is the crates.io `hyper-util` 0.1.20 source (package checksum
`96547c2556ec9d12fb1578c4eaf448b04993e7fb79cbaad930a656880a6bdfa0`, upstream
commit `b23a13e2b7ee73e15ba008cd9b19dcd2d3861957`). Only
`src/client/legacy/client.rs` differs; the unified diff is
[`hyper-util-release-h1-sender-on-dispatch-close.patch`](hyper-util-release-h1-sender-on-dispatch-close.patch).
The crate's `.github/`, `Cargo.lock`, `Cargo.toml.orig`, `.gitignore` and
`.cargo_vcs_info.json` are not vendored. `examples/` and `tests/` are kept
because the published manifest names them as explicit targets.

`try_send_request` now awaits the response through
`await_response_or_release`. On every wake that helper polls the response
first. For an HTTP/1 connection it then polls the pooled sender's
`poll_ready` (hyper's `want::Giver::poll_want`):

- `Ready(Err)`: the dispatcher closed its queue or is gone. The helper records
  `is_reused()` and `conn_info`, then drops the pooled connection. That drop
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
clones and are not watched.

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
allocation. `conn_info` is cloned only on the release path.

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

The `Vendored Patch Regressions` CI job runs them with

```bash
cargo test --manifest-path vendor/hyper-util-0.1.20-ferrum-patched/Cargo.toml --features full --lib ferrum_release_on_close_tests
cargo test --manifest-path vendor/hyper-util-0.1.20-ferrum-patched/Cargo.toml --features full --test legacy_client
```

The second command runs hyper-util's own legacy-client suite. It covers
keep-alive, reuse, drop and close behavior through the patched send path.

End to end, the `backend_accepts_then_rst_returns_502__*` functional matrix
exercises the reset-at-dispatch shape. PR #5712 makes those cells reset only
after the request head arrives, so they no longer depend on this interleaving.

## Not covered

Ferrum's own HTTP/1 pools that drive `hyper::client::conn::http1::SendRequest`
directly (the HBONE inner HTTP/1 path and the Unix-socket backend pool in
`src/proxy/mod.rs` and `src/proxy/unix_backend_pool.rs`) hold their sender
across the response wait in the same way, so the same interleaving can stall
them. They are outside hyper-util, and they need the same release in Ferrum
code.

## Retirement plan

Retire when a hyper-util release stops holding the only HTTP/1 sender across
the response wait after its dispatcher closes, or when a hyper release stops
stranding a racing send (for example, the dispatcher drains the channel until
in-progress sends publish). Then:

1. Remove the `hyper-util` line from `[patch.crates-io]` in `Cargo.toml` and
   `tests/performance/mesh/Cargo.toml`.
2. `git rm -r vendor/hyper-util-0.1.20-ferrum-patched/`, and restore the
   registry `source`/`checksum` lines in `Cargo.lock` and
   `tests/performance/mesh/Cargo.lock` with a normal lockfile update.
3. Remove the inventory row and the lifecycle entry, drop the CI step, and
   regenerate `vendor/VENDOR_INTEGRITY.sha256`.
