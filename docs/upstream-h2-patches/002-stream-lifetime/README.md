# h2: retain a client-stream owner until transport completion

Owner: Ferrum Edge maintainers. Part of [#5991](https://github.com/ferrum-edge/ferrum-edge/pull/5991)
and [#5588](https://github.com/ferrum-edge/ferrum-edge/issues/5588).
Deliberate fork, unfiled upstream, governed by the
[dependency policy](../../dependency-policy.md#deliberate-fork-policy-and-sla).

## Ownership boundary

Hyper's source-body pipe queues an entire final DATA buffer after acquiring any
positive flow-control capacity, then drops the source. A 16 KiB final chunk
against a 1 KiB backend window leaves 15 KiB owned by h2. An early terminal
response can therefore complete while the backend stream still occupies h2's
concurrent-stream budget. Source Drop cannot release Ferrum's affinity count.
Buffered native/retry bodies, DATA plus trailers, and pumped gRPC-Web bodies
have the same independent transport ownership.

No existing public h2 API reports this lifetime. `poll_capacity` returns `None`
as soon as sending closes, even with DATA queued; `poll_reset` only reports
reset, not clean completion. A gateway source observer or frame-buffer wrapper
cannot observe pending trailer HEADERS and all reset/connection cleanup paths.

The additive `h2::ext::StreamLifetime` request extension owns a supplied Arc.
`Streams::send_request` removes it before clearing other extensions and moves
it into the internal stream. `Counts::transition_after` drops it at the same
boundary that releases the concurrent-stream count: the stream state is closed,
its pending frame queue is empty, no buffered DATA remains, and no scheduled
reset still owns DATA. A reset clears/discards queued data before that boundary.
Connection teardown also releases owners when the stream store is dropped.
Errors before stream admission drop the extension normally.

This observes h2 transport ownership, not peer acknowledgment or kernel send
queue drainage. h2 considers frames accepted by its codec written, including
coalesced DATA under patch 001. That is also when h2 frees its stream slot.
It does not change frame ordering, windows, source polling, write timers,
authorization timers, source observers, or byte/probe accounting.

Ferrum attaches the extension at the shared gRPC dispatch seam. The frontend
response and every backend retry share one Arc owner; its last Drop decrements
one affinity count exactly once. A call without an H2 frontend scope allocates
nothing. A scoped gRPC call adds one small Arc allocation shared across attempts,
no background task or new lock. h2 adds one optional Arc field per stream and
one completion check inside its existing state lock. The owner's destructor
must be cheap, non-blocking, and never re-enter h2 or contain h2 handles; Ferrum's
owner only decrements an atomic counter and drops its frontend connection Arc.

## Reproduction and integrity

Apply `001-coalesce-data-frame-writes/h2-coalesce-data-frame-writes.patch` first,
then `002-runtime-data-frame-budget/h2-runtime-data-frame-budget.patch`,
then [`h2-stream-lifetime.patch`](h2-stream-lifetime.patch), to the published
h2 0.4.19 archive (SHA-256
`ef8e5e5a340588f4452631496976cf8636d4a7ecf600239fdc27615d2530bc16`,
upstream revision `d57d1b852fec9dda6d42d3454502006d52104da8`).
All reconstructed `src/` files must match the shipped crate and
`vendor/VENDOR_INTEGRITY.sha256`. The merged manifest entries were
updated using ordinary SHA-256 reads; no project tooling ran locally.

The hosted H2 guard preparation applies all three patches before its diagnostic
observer. Its patch and source pre/postimage hashes were refreshed without
changing the observer or the shipping Admin API.

## Regressions

`tests/integration/http2_pool_tests.rs` uses a real Hyper client and h2 backend
with a 1 KiB upload window. It requires the final 16 KiB source to Drop and the
early terminal response to finish while the transport owner remains live, then
asserts exactly-once release after credit/drain, backend reset, or connection
teardown (`test_hyper_h2_stream_lifetime_*`).

`tests/functional/scripted_backend_h2_tests.rs` retains 40 blocked uploads on
one H2 frontend, consumes every early terminal response, requires the first
32 calls to use the preferred connection and later calls to spill, then drains
even uploads and resets odd uploads. Every upload reports one termination;
16 subsequent probes must regain the original preferred shard. The cases cover
streaming final DATA, retry-buffered native gRPC with a proven actual retry,
translated gRPC-Web DATA/trailers with no pump, and the pumped representation.
The backend verifies the complete native DATA and translated request trailers.

`tests/unit/gateway_core/frontend_affinity_tests.rs` covers concurrent drops,
handler cancellation, both completion orders, and multiple attempt owners.
Hosted CI is the execution/format/lint gate; these tests were not run locally.

## Retirement

Retire when h2 offers an equivalent owned stream-completion hook, or Ferrum
stops using this backend transport. Remove this patch and move the dispatcher
to the upstream hook. Retain the lifetime regressions. The coalescing and
runtime-budget patches must also be retired before removing the vendored
crate; a coalescing release alone is not enough. Upstream filing is still required under the deliberate-fork policy.
