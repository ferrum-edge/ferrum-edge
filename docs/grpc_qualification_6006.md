# gRPC qualification failures in issue #6006

The release qualification run [37217985798](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37217985798)
tested release PR #6005 at `5bab92a367c69ececaaa81e535fca45ba4436f38`.
Its production source, tests, vendor copies, and workflows matched main
`66f25f5f89f1dbd4f7d523f3c57e2ace7f59d017`; release metadata differed.
These failures require fixture repairs and fresh hosted qualification, not a
blind rerun or reliance on older green heads. No production behavior changes
are made by this repair.

## Authorization expiry during sender acquisition

[Protocol job 111484006668](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37217985798/job/111484006668)
returned HTTP 200 / `grpc-status: 4` in the streamed acquisition case after
4.851783558 seconds. The gateway logged a **5000ms** protocol-establishment
budget exhaustion, although `stalled_grpc_proxy_yaml` configured **60000ms**.
The adjacent buffered case passed; that does not prove a streamed-dispatch
defect or a harmless infrastructure flake.

The original fixture minted an integer `exp` six seconds ahead. `jwt_auth`
uses zero leeway by default and publishes the accepted monotonic deadline
through `credential_deadline_from_claims`; its remaining interval is computed
from whole Unix seconds at authentication, then captured once. The fixture
used binary mode with pool warmup off. File-mode startup still runs an initial
capability refresh. `build_backend_capability_probe_proxy` caps that probe's
connect budget at 5000ms, and `probe_h2c` uses the same `GrpcConnectionPool`.
Connect timeout is request policy, excluded from the connection key.

`GenericPool::create_or_get_existing_owned_with_recovery` joins an existing
creation for the same shard and broadcasts a creator's completed error. A
request joining the startup probe can therefore observe its shorter connect
timeout. Whether it joins depends on shard selection and scheduling; probe
cancellation instead allows a waiter to become the next creator. The logged
5000ms creator budget, together with these call sites, identifies the probe
race as the cause of this hosted result. A failure before the captured
authorization instant keeps its timeout terminal. The log does not show an
expired credential being admitted or an authorization winner being changed
to a timeout. Both dispatch shapes already use `GrpcDispatchBounds` for
acquisition and the synchronous handoff gate.

Both acquisition regressions now use the cold in-process harness, whose
`skip_initial_capability_refresh` removes that unrelated creator. They mint
the short JWT after frontend H2 readiness. The first backend connection reads
the actual client preface and withholds peer SETTINGS until the gateway closes
the socket. No timer releases that fixture gate. The tests require:

- HTTP 200 / `grpc-status: 16`, before the 60-second connect watchdog;
- backend EOF/reset, with only connection-control frames and no RPC HEADERS,
  DATA, or CONTINUATION on the cancelled socket;
- one acquisition, no expired RPC at the backend, and exactly one uncached
  credential-expiry count;
- a fresh valid RPC on the same frontend connection, with exactly one new
  backend connection and one healthy request, through a threshold-one breaker;
- no expired request or additional expiry count after that completed recovery.

The fixture owns its accept task and a `JoinSet` of recovery connections.
Timeouts only bound failed observations; sleeps no longer stand in for
acquisition cancellation or absence of a late request. Counter assertions
read the in-process lifetime counters directly, avoiding the runtime snapshot
cache. Hosted nextest gives each functional test its own process, as required
for these process-lifetime counters.

## Attempt spans and physical connection reuse

[Application job 111484006738](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37217985798/job/111484006738)
reached the second live RPC's reuse assertion with `Some(false)` instead of
`Some(true)`. Earlier setup timing, parentage, and refused-target retry checks
had succeeded.

The old `send_grpc` helper connected and handshook a new frontend H2 socket
for **every** RPC, then dropped its sender. The spawned connection driver
could still be tearing down the previous frontend when the next RPC arrived.
Since #5991, a frontend H2 connection owns its gRPC shard. A missing preferred
shard is created even if a sibling is ready, deliberately widening the pool.
Opening a second frontend therefore does not guarantee backend reuse. The
script was copied to each accepted backend connection, so two successful
RPCs alone did not establish that they shared a socket. This is a fixture
lifetime/affinity mismatch; reporting a fresh setup as `false` is correct.

The repaired test keeps one frontend sender alive for the refused-target
call and both live RPCs. Each response body and its trailers complete before
the next call. `ScriptedGrpcBackend` has two unary steps on that connection
and a final `AwaitTestSignal`, so its normal 100ms end-of-script teardown
cannot race span inspection. The test independently requires exactly one
backend TCP accept and H2 handshake. Each RPC's CLIENT span is found using
the backend's received `traceparent`, preserving arrival attribution even
when exports are reordered. It still requires a cold first RPC with measured
setup/DNS/TCP phases, a genuinely reused second RPC with **no** setup timing
attributes, distinct RPC traces/attempt IDs, correct SERVER parentage, and
exactly three CLIENT spans for the refused target's first attempt plus retries.

The shared production siblings are unchanged: buffered and streamed native
gRPC retain the same acquisition/handoff bounds, the H3 gRPC bridge consumes
that dispatch contract, and direct H2 keeps its documented round-robin pool
policy. Existing real-pool affinity regressions cover new frontend shard
creation separately; this OTEL case specifically proves same-frontend reuse.

## Validation and integration

Local validation is static source/diff inspection and `git diff --check`
only. No formatter, compiler, tests, repository script, or other project
tooling was executed locally. Formatting, lint, compilation, ordinary/FIPS
tests, and both functional shards remain **pending for the exact pushed head**.
No workflows, dependencies, public API, configuration, or published Edge
contracts change. Root owns fresh hosted gates, independent review, and later
integration into the still-draft release PR #6005 before release/tagging.
