# h2: close a client connection whose last handle drops mid-poll

> Governance: tracked in [docs/dependency-policy.md](../../dependency-policy.md).
> Any change to `vendor/h2-0.4.19-ferrum-patched/` must regenerate the drift
> manifest (`scripts/update_vendor_integrity.sh`).

## Status

**Deliberate fork**: not filed upstream yet. Filing needs owner approval; the
draft issue text is [below](#draft-upstream-issue-hyperiumh2). Owner: Ferrum
Edge maintainers. Ferrum issue
[#6052](https://github.com/ferrum-edge/ferrum-edge/issues/6052).

The bug is in published h2 0.4.19 and in h2's `master` at the time of writing.

## Problem

`impl Future for client::Connection` (`src/client.rs`) read whether any stream
or handle (`SendRequest`, `SendStream`, `ResponseFuture`, ...) is still held
twice per poll, each time under its own lock:

```rust
self.inner.maybe_close_connection_if_no_streams();               // read 1
let had_streams_or_refs = self.inner.has_streams_or_other_references(); // read 2
let result = self.inner.poll(cx).map_err(Into::into);
if result.is_pending()
    && had_streams_or_refs
    && !self.inner.has_streams_or_other_references()             // read 3
{
    cx.waker().wake_by_ref();
}
```

- Read 1 closes the connection (`GOAWAY(NO_ERROR)`) if nothing is held.
- Read 3 wakes the task once more if read 2 saw something held and nothing is
  held now.
- Dropping the last handle wakes the connection task only through the waker
  that `Streams::poll_complete` parks in `actions.task` (`Drop for Streams`,
  `drop_stream_ref`). The wake that started the current poll has already taken
  that waker, and `poll_complete` parks a new one only later in `inner.poll`.

If the last handle drops between read 1 and read 2:

1. read 1 sees it held and does not close;
2. the drop finds no parked waker and wakes nothing;
3. read 2 sees nothing held, so `had_streams_or_refs` is false;
4. `inner.poll` parks a new waker and returns `Pending`;
5. read 3 does not wake, because read 2 saw nothing held.

Nothing holds a handle any more, so nothing can wake the task through
`actions.task` again. The task now waits for socket I/O. An idle peer never
writes, so the client never sends its `GOAWAY` or closes the socket. It stays
open until the peer closes it, the peer's idle timeout fires, or a keepalive
`PING` happens to be configured.

### Reachability through hyper

hyper's HTTP/2 client (`proto/h2/client.rs`) works around a related h2 bug
with an mpsc channel: when the dispatch task (`ClientTask`) ends, dropping
`conn_drop_ref` wakes the connection task (`ConnTask`) so that it polls the h2
`Connection` again. `ClientTask` declares `conn_drop_ref` before `h2_tx` (the
h2 `SendRequest`), so the wake is sent just before the last `SendRequest`
drops. On a multi-threaded runtime `ConnTask` can therefore poll the h2
`Connection` at the same time as that drop, which is the interleaving above.
hyper's own channels register their wakers atomically and have no separate
race; the fix belongs in h2.

### Observed in Ferrum

`functional_h1_h2_auth_lifetime_test.rs` hung intermittently for 20 s
(`bounded frontend cleanup: Elapsed`), twice, including on release PR #6050.
PR #6051 root-caused it and worked around it in the test client by sending a
`PING` after dropping every handle.

### Product impact (low, pre-existing)

An h2 client connection whose last handle drops while its task is mid-poll can
stay open until the peer closes it. Without HTTP/2 keepalive (for example the
HBONE pool in `src/proxy/hbone_pool.rs`, and hyper-driven backend HTTP/2
connections), the connection and its pool slot stay alive until the peer's
idle timeout. Requests are not affected; this is neither a correctness nor a
security issue for requests.

## Patch

[`h2-client-close-wakeup.patch`](h2-client-close-wakeup.patch) applies after
Ferrum's h2 patches 001 and 002:

- `proto::Connection::maybe_close_connection_if_no_streams` returns the value
  it read: whether streams or handles were held.
- `client::Connection::poll` uses that one value both to decide the close and
  as `had_streams_or_refs` for the post-poll recheck. The separate second read
  is gone, so there is no window between the two decisions.
- A `#[cfg(test)]` hook, compiled only into the crate's own unit tests, runs
  right after the close decision so the regression test can drop the last
  handle at exactly that point.

Every interleaving of the last drop with one poll is now handled:

| Last handle drops | Result |
|---|---|
| Before the read | The read sees nothing held and closes. |
| After the read, before `poll_complete` parks a waker | The read saw it held; the recheck after `inner.poll` sees nothing held and wakes the task. The next poll closes. |
| After `poll_complete` parks a waker | The drop wakes the parked waker. The next poll closes. |

### Why the recheck cannot spin

The recheck wakes only when this poll's read saw something held. Once nothing
is held, nothing can become held again: every handle is gone, and the
`Connection` does not create one. The next poll therefore reads nothing held,
calls `go_away_now(NO_ERROR)` (which sets `close_now`), and its own recheck
does not wake. From then on `inner.poll` either completes or returns `Pending`
only for socket I/O (flushing the `GOAWAY` or `shutdown`), which registers its
own waker. So the patch adds at most one extra wake per connection, the same
bound as the unpatched recheck.

An alternative was considered: keep both reads and, after `inner.poll`, close
and wake whenever nothing is held and `close_now` is not yet set. That also
terminates, but it adds a new state check and a second close path. With one
read, the race cannot happen in the first place.

### Server side

`server::Connection` has no close-when-unreferenced logic. Its users drive it
with `poll_accept` / `poll_closed` and close it with `graceful_shutdown`,
`abrupt_shutdown`, or the peer's close, and it never reads
`has_streams_or_other_references`. The race does not exist there.

## Regression test

`client::ferrum_client_close_wakeup_tests::last_handle_dropped_mid_poll_still_closes_the_connection`
in the vendored crate. Run it with:

```bash
cargo test --manifest-path vendor/h2-0.4.19-ferrum-patched/Cargo.toml --lib ferrum_client_close_wakeup
```

The test drives a real h2 client against an in-process, idle h2 server over a
`tokio::io::duplex` pipe. It polls the client `Connection` by hand with a waker
that counts its wakes, so the steps run in a fixed order:

1. Poll until the `SETTINGS` exchange settles: a poll followed by no wakeup,
   which leaves the waker parked by `poll_complete`.
2. Arm the hook to drop the only `SendRequest`.
3. Call `set_target_window_size`, which takes and wakes the parked waker, as a
   production wake does. The test asserts exactly one wake.
4. Poll once. The hook drops the last handle right after the close decision,
   while no waker is parked. The test asserts that this poll woke the task
   again. With upstream's two reads, the hook runs between them, both reads
   see nothing held, and the wake count stays unchanged.
5. Poll again, and assert that the connection completes with `Ok(())`.

The race spans two adjacent lock acquisitions inside `Connection::poll` with no
caller code between them. A test outside the crate can only make it likely,
not certain: for example, by dropping the handle from another thread in a loop.
So the deterministic regression is an in-crate unit test with a
`#[cfg(test)]` hook, following h2 patch 001's in-crate test accessors. The
gateway's end-to-end coverage is the functional test that first exposed the
hang (`functional_h1_h2_auth_lifetime_test.rs`).

## Retirement

Retire this patch when an h2 release reads the close decision and the
post-poll recheck from one snapshot, or otherwise wakes a client connection
whose last handle drops mid-poll. Remove the inventory row, the
`docs/vendored-patch-lifecycle.json` entry, this directory, and its entry in
`tests/performance/multi_protocol/h2_guard/prepare.py`. Keep a behavioural
regression for the released dependency if one can be written outside the
crate, and regenerate `vendor/VENDOR_INTEGRITY.sha256`. Patches 001 and 002
must also retire before the vendored crate is dropped; see
[patch 001's retirement steps](../001-coalesce-data-frame-writes/README.md#retirement).

## Draft upstream issue (hyperium/h2)

Not filed. File only with owner approval.

> **Title:** Client `Connection` can miss its close wakeup when the last
> `SendRequest` drops during `poll`
>
> **Version:** h2 0.4.19 (and `master`)
>
> `impl Future for client::Connection` checks whether any streams or
> references remain twice before polling the inner connection:
>
> ```rust
> self.inner.maybe_close_connection_if_no_streams();
> let had_streams_or_refs = self.inner.has_streams_or_other_references();
> let result = self.inner.poll(cx).map_err(Into::into);
> if result.is_pending()
>     && had_streams_or_refs
>     && !self.inner.has_streams_or_other_references()
> {
>     cx.waker().wake_by_ref();
> }
> ```
>
> Each check takes the streams lock separately. Dropping the last handle
> (`Drop for Streams` / `drop_stream_ref`) wakes the connection task only
> through `actions.task`, the waker parked by `Streams::poll_complete`. The
> wake that started the current poll has already taken that waker.
>
> If another thread drops the last `SendRequest` between the first check and
> the second:
>
> 1. `maybe_close_connection_if_no_streams` sees a reference and does not
>    close;
> 2. the drop finds `actions.task == None` and wakes nothing;
> 3. `had_streams_or_refs` is `false`;
> 4. `inner.poll` parks a new waker and returns `Pending`;
> 5. the recheck does not fire, because `had_streams_or_refs` is `false`.
>
> No handle remains to wake the task, so it waits for socket I/O. Against an
> idle peer, the client never sends `GOAWAY` or closes the socket, so the
> connection stays open until the peer closes it or a keepalive `PING` fires.
>
> hyper's HTTP/2 client makes this reachable. `ClientTask` drops
> `conn_drop_ref` (waking `ConnTask` through an mpsc channel) just before it
> drops its h2 `SendRequest`, so on a multi-threaded runtime `ConnTask` can
> poll the `Connection` at the moment the last `SendRequest` drops.
>
> **Suggested fix:** take one snapshot per poll and use it for both decisions:
>
> ```rust
> // proto::Connection
> pub fn maybe_close_connection_if_no_streams(&mut self) -> bool {
>     let has_streams_or_refs = self.inner.streams.has_streams_or_other_references();
>     if !has_streams_or_refs {
>         self.inner.as_dyn().go_away_now(Reason::NO_ERROR);
>     }
>     has_streams_or_refs
> }
>
> // client::Connection::poll
> let had_streams_or_refs = self.inner.maybe_close_connection_if_no_streams();
> let result = self.inner.poll(cx).map_err(Into::into);
> // ...unchanged recheck...
> ```
>
> A drop after the snapshot is then caught by the existing recheck, or, once
> `poll_complete` has parked a waker, wakes the task directly. The recheck
> still fires at most once: the next poll sees nothing held and closes.
>
> We carry this fix as a downstream patch, with a deterministic unit test that
> drops the last `SendRequest` right after the close decision through a
> `cfg(test)` hook, and can open a PR.
