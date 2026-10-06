# gRPC qualification failures in issue #6006

The release qualification run [37217985798](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37217985798)
tested release PR #6005 at `5bab92a367c69ececaaa81e535fca45ba4436f38`.
Its production source, tests, vendor copies, and workflows matched main
`66f25f5f89f1dbd4f7d523f3c57e2ace7f59d017`; release metadata differed.
These historical failures required fixture repairs and fresh hosted
qualification. The repairs qualified at final fixture head
`9965ec52b2f8b9b96e62dfd080614dffd0c2d7e2` and merged through PR #6007
as `3ce21ad101f164f70cb7f7f77fb033db828b9518`; issue #6006 is closed.
The failed release and main runs remain causal evidence, not rerunnable green
qualification for a new candidate. No production behavior changes were made
by this repair. The final v0.9.11 head
`ff0a9d5152dc3cf2fd240158cbdf5551f511212e` subsequently qualified through review
and hosted CI. Release merge `c764084b3b51c3f7ffde268c039688d35e49c553`
published as v0.9.11 at 2026-10-04T21:26:11Z; see the
[completed release record](releases/v0.9.11.md). [v0.9.12](releases/v0.9.12.md)
was qualified with its own exact-head, main-push and release evidence.

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
The frontend driver is also owned by a `JoinSet`, with bounded readiness and
cleanup. One watchdog covers the expired RPC's send, preface observation,
response body, and trailers; recovery readiness, send, body, and trailers share
the existing termination-grace watchdog. Even a trailers-only status is accepted
only after the body ends. The shared terminal parser's buffered-response sibling
also bounds body/trailer completion. Previously these cases timed out only the
response head, so a missing terminal could strand the remaining assertions.
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

Independent review identified an unbounded wait in response collection: a
missing response terminal could keep `send_grpc` pending forever, preventing
the test from reaching `release_test_signal`. Functional nextest supplies no
termination timeout for this case. The repaired helper uses one 20-second
watchdog for sender readiness, send, complete body collection, and trailers,
including the refused-target RPC. Frontend connection/readiness and normal
driver cleanup each have a five-second bound. An owned `JoinSet` retains the
driver through all reuse/span assertions and aborts it on timeout or assertion
unwind. Normal cleanup releases the backend gate, drops the sender, and joins
the driver. No timeout releases the gate during successful inspection.

`ScriptedGrpcBackend::shutdown`, including its drop path, now explicitly
releases the test signal before aborting its accept and connection-script
tasks. Their control senders are then dropped; the existing H2 driver exits
on control-channel closure with a 200ms flush bound. This covers failures
before the explicit release without relying on reaching the final assertion.
Abort-on-drop schedules task cancellation; failed assertions do not perform
asynchronous joins. The gated acquisition backend separately aborts its accept
task, whose owned recovery `JoinSet` aborts those connections when dropped.

The shared production siblings are unchanged: buffered and streamed native
gRPC retain the same acquisition/handoff bounds, the H3 gRPC bridge consumes
that dispatch contract, and direct H2 keeps its documented round-robin pool
policy. Existing real-pool affinity regressions cover new frontend shard
creation separately; this OTEL case specifically proves same-frontend reuse.

## Exact-main sequential gRPC reuse

[Protocol job 111483212924](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37217711050/job/111483212924)
tested main `66f25f5f89f1dbd4f7d523f3c57e2ace7f59d017` and failed
`h2_direct_pool_reuses_connection_across_requests` at line 2489: the second
response contained `[b"one"]` instead of the required second script's
`[b"two"]`. [Issue comment 5982508001](https://github.com/ferrum-edge/ferrum-edge/issues/6006#issuecomment-5982508001)
groups this third failure with the release qualification repairs.

This test already used the cold in-process harness, so the binary startup
probe is not its cause. Despite its name, it sends `application/grpc` and
uses the native `GrpcConnectionPool`, not the plain direct-H2 pool.
`GrpcClient::h2c` stores only the target and transport. Every `unary` call
reaches `request_with_headers`, opens a new TCP socket, and handshakes H2 in
`send_over_io`. Its `AbortOnDrop` driver is aborted after response collection;
that does not await the gateway releasing the old frontend's affinity slot.

`LazyConnectionAffinity` belongs to the accepted frontend service, and its
slot remains owned until that connection and its retained streams end.
If the old slot is still live when the second frontend arrives, the new
frontend takes another least-loaded slot. `GrpcConnectionPool::get_sender`
creates that preferred shard when missing, even with a ready sibling. The
scripted backend clones the entire ordered script for each TCP accept, so
the first RPC on the new shard receives `"one"` again. These source paths
explain the logged message, independently of the OTEL helper's teardown.
This is a fixture lifetime/affinity mismatch, not proof of broken pool reuse.

The repair keeps one raw H2 frontend sender and an owned `JoinSet` driver
through both RPCs and all backend assertions. Each RPC must complete within
a bounded watchdog, with HTTP 200, the exact length-prefixed `"one"` or
`"two"` body, and an actual `grpc-status: 0` trailer before the next starts.
Their frontend stream IDs must differ. The backend's existing
`AwaitTestSignal` holds its connection open through inspection, which requires
exactly two recorded RPC streams, one TCP accept, one completed H2 handshake,
and no matcher or script errors. `ReceivedStream` exposes no backend stream
ID; the accept/handshake counts independently establish the physical socket.

The old 100ms counter-settlement sleep is removed: accept and handshake
counters and each stream's record are published before its scripted response,
so receipt of both complete bodies and trailers proves those events occurred.
Cleanup releases the backend barrier, drops the frontend sender, and joins
the owned driver under a five-second bound; dropping the `JoinSet` also aborts
the driver on a failed assertion or timeout. The backend retains its existing
drop shutdown. No shard-count override, affinity bypass, reconnection-as-reuse,
weaker message assertion, or production change is introduced.

Inspection confirmed that this sequential-reuse fixture already bounds its
entire RPC and owns its frontend driver. Its RPC behavior needs no further
change for the completion finding; it receives the shared backend's signal
release on shutdown. The four exact formatter hunks from
[CI Plan job 111489249137](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37220349894/job/111489249137)
were applied by hand. The later head `5f66db02d` also exposed one formatter
hunk in its distinct-stream assertion in
[CI Plan job 111490626071](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37220824175/job/111490626071);
that exact hunk is applied too. Neither deterministic formatting failure was
rerun.

## Validation and integration

Local validation is static source/diff inspection and `git diff --check`
only. No formatter, compiler, tests, repository script, or other project
tooling was executed locally. At initial authoring, fixture formatting, lint,
compilation, ordinary/FIPS tests, and the functional shards were pending.
That authored-pending state is superseded by the completed qualification below.
No production source, workflows, dependencies, public API, configuration, or
published Edge contracts changed.

Root reviewed the complete final 1,122-line diff at
`9965ec52b2f8b9b96e62dfd080614dffd0c2d7e2` and all fix deltas. Fresh
independent whole/focused review2 returned **NO FINDINGS** after the accepted
response-completion finding was fixed. All 12 head-associated hosted workflows
succeeded. All 80 reported check runs completed: 49 successful and 31
nonapplicable PR skips. All nine protected Actions `15368` contexts passed,
including [Tests](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37221404613/job/111497123584),
[FIPS Build & Test](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37221404632/job/111497115431),
and [Trusted Cross Build Policy](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37221402537/job/111492323617).
The [protocol functional shard](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37221404613/job/111494299218)
qualified both strict acquisition-expiry shapes, healthy recovery, and direct
sequential physical reuse; the
[application functional shard](https://github.com/ferrum-edge/ferrum-edge/actions/runs/37221404613/job/111494299059)
qualified same-frontend OTEL physical reuse and strict attempt telemetry.
Zero review threads and no further thread pagination were verified before
landing.

[PR #6007](https://github.com/ferrum-edge/ferrum-edge/pull/6007) was
squash-merged at 2026-10-04 18:08:04 UTC into
`3ce21ad101f164f70cb7f7f77fb033db828b9518`.
[Issue #6006](https://github.com/ferrum-edge/ferrum-edge/issues/6006) closed
at 18:08:06 UTC. Release PR #6005 normally integrated that main commit,
preserving the qualified fixture source bytes. See the
[complete workflow evidence](releases/v0.9.11.md#grpc-fixture-source-integration-evidence).

The final #6005 head `ff0a9d5152dc3cf2fd240158cbdf5551f511212e` subsequently
qualified through complete root and fresh independent review and hosted CI.
Root verified release merge `c764084b3b51c3f7ffde268c039688d35e49c553` with
that exact second parent, all 14 pre-tag main-push workflows and all 20 release
jobs successful. v0.9.11 published at 2026-10-04T21:26:11Z and its distribution
was verified; see the [actual release record](releases/v0.9.11.md) for artifact
identities and GHCR/revision-label limits. Canonical `contracts-edge-0.9.11`
subsequently published at `390edbd5b2485af0988e02f7827fde778d76ae0a`.
Neither historical failed head was used as qualification. These results do not
qualify [v0.9.12](releases/v0.9.12.md), which carries its own evidence, nor
downstream adoption or advisory closure.
