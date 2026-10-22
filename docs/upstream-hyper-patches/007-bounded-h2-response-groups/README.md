# Bounded autonomous HTTP/2 response waiter groups

Experimental unfiled fork, owned by Ferrum Edge maintainers. No performance gain
has been established. This candidate is based on commit
`4a7be250e45a367314e3dec872ecbd512220558e` and deliberately excludes the independent
lazy-cancellation-channel candidate and diagnostic instrumentation. No public
Hyper 1.10.0 API controls this private task handoff; a gateway workaround would
need to replace the client or change response ownership.

The ordered [patch](hyper-bounded-h2-response-groups.patch) applies after patches
001–006. Only two runtime files change: `src/client/dispatch.rs` and
`src/proto/h2/client.rs`. Tests are in the separate test-only
`src/proto/h2/client/ferrum_send_batch_tests.rs` module. No dependencies, public
API bounds, protocol options, request/response metadata, pools, or timers change.
The original unconditional upload cancellation channel remains in place.

## Mechanism

`poll_pipe` constructs the same `SendWhen` and still eagerly polls/spawns the
same upload pipe. A local `SmallVec<[SendWhen; 1]>` accumulates only response
waiters from requests already dequeued during the current dispatcher poll.
The second waiter reserves space for eight in one allocation. Eight flushes
immediately. The outer `Future::poll` calls `poll_dispatch`, then always calls
`flush_sends` before returning its result. Every `ready!`, `?`, shutdown, error,
and explicit return is confined to `poll_dispatch`; no partial group survives
a normal driver poll return. There is no timer, fill threshold wait, or
persistent driver-owned response collection. Unwinding is not a normal result.

A singleton goes through the original `H2ClientFuture::Send` task variant. A
group of 2–8 transfers the already-spilled vector into one new `Batch` task.
There are no per-child boxes and no change to an upload task. The batch polls
each live `SendWhen` once per poll and immediately drops completed/canceled
children with `Vec::retain_mut`. Its shared waker may repoll up to eight blocked
children; this bounded extra work is a measurement tradeoff. A slow child does
not prevent later children from being polled, and no ready child waits for the
whole group to complete. The cap is fixed at eight before measurement.

| Already-dequeued heads in a group | Old head tasks | Candidate head tasks | Added collection allocation |
|---|---:|---:|---:|
| 1 | 1 | 1, same variant | 0 |
| 2–8 | N | 1 | 1 vector |

Counts exclude the unchanged callback oneshot/envelope, upload task, connection
driver, and CONNECT upgrade task. Real grouping frequency depends on dispatch
queue occupancy. The controlled 17-request test is not production occupancy
evidence, nor a claim about CPU, allocator bytes, or the Ferrum/Envoy gap.
Ranking builds must have no test/counter instrumentation. Separately measured
actual occupancy and inclusive profiles are required before attributing gains.

## Lifecycle proof and rejected requester ownership

The individual `SendWhen::poll` and `ResponseFutMap::poll` bodies are unchanged:

- A ready response wins over a closed callback. A successful early response
  drops the upload cancellation sender normally; it never explicitly CANCELs
  the remaining upload. Failed callback delivery drops the completed response
  through the existing oneshot path.
- A pending response with a canceled callback calls `cancel()` and drops the
  waiter in that poll. `PipeMap` resets the stream with CANCEL, drops its guards,
  and releases flow-control capacity. EOS requests retain h2 handle-drop reset.
- Post-wire errors have no retryable request. Queued, never-accepted envelopes
  retain request ownership through the unchanged dispatch drop path.
- Response and upload owners remain detached from `ClientTask`; every partial
  group is submitted before a driver shutdown/error returns. Body deadlines,
  coalescing, trailers and connection error propagation remain in their current
  code. CONNECT still invokes the same executor-specific upgrade path.
- Each head independently records header activity and transitions its ping
  recorder into the response body. Completed children are dropped even while
  another child in the same group stays pending. Dormant callers do not stall
  response processing or retain otherwise-completed ping activity.

A plain requester-owned head envelope was rejected on concrete lifecycle
behavior. At the exact base, `client/dispatch.rs:347–385` polls the head before
checking callback cancellation; `proto/h2/client.rs:628–678` records header
activity, maps completed bodies and executes CONNECT upgrades independently of
the requester. `proto/h2/ping.rs:227–258` updates activity and disables a recorder
for an EOS receive stream, while `ping.rs:326–328` derives idle state from its
Arc strong count. Moving the head to a dormant requester would delay those
transitions and could CANCEL an upload after a successful head had already
arrived. `SendRequest<B>` also omits executor `E` (`client/conn/http2.rs:24`),
whereas `ResponseFutMap<B,E>` owns `E` for CONNECT: returning it directly would
leak executor generics or require boxed type erasure/new executor bounds.
Separating ordinary/CONNECT heads avoids that type problem but not the dormant
caller/liveness change. Faithful background ownership repairs are wider than
this experiment. The bounded grouping keeps that ownership intact.

No new `Send`, `Sync`, or `Unpin` bound is added. `SendWhen`'s pinned fields are
h2 handles and an oneshot sender; the executor is not pinned. Safe `Pin::new`
and existing structural pin projection suffice. Remote compilation must retain
all five existing `client::conn::http2::tests` executor-contract tests, including
non-Send/non-Sync executors; their ignored bodies are still type checked.

## Remote correctness and paired controls

Sixteen focused tests cover DATA/trailers, eager body error, grouped CONNECT,
EOS/upload cancellation, normal and parked early response, 64 pending heads,
grouped transport loss/reset, unchanged singleton task counts, 17 queued heads
with expected groups 8/8/1, canceled-child release before sibling completion,
closed-dispatch partial flush, unsent retry ownership, and parked-caller
keepalive idle behavior. The cancellation/head-ready race gates only head
execution, observes actual HEADERS writes, then waits for a subsequent PING ACK
before dropping the caller and resuming the head task. It does not infer wire
ordering from task scheduling. The keepalive test counts client PING frames
with paused time and observes positive activity before asserting idle suppression.

Run only on authorized remote CI. Copy Hyper and h2 outside the root Cargo
workspace, leaving their manifests unchanged. Capture source revisions, copies,
commands, Cargo.lock files, dependency trees, exit status and unfiltered logs.
Use two dependency graphs:

```sh
# Graph 1: stock registry h2, exactly 0.4.20 (isolated Hyper copy).
cargo update --manifest-path "$HYPER/Cargo.toml" -p h2 --precise 0.4.20
RUSTFLAGS='--cap-lints=warn --check-cfg=cfg(ferrum_h2_batch_control)' cargo test --manifest-path "$HYPER/Cargo.toml" --features full --lib ferrum_send_batch_tests -- --nocapture
# Graph 2: the exact base/candidate vendored h2, supplied as an absolute path.
RUSTFLAGS='--cap-lints=warn --check-cfg=cfg(ferrum_h2_batch_control)' cargo test --manifest-path "$HYPER/Cargo.toml" --features full --lib ferrum_ --config "patch.crates-io.h2.path=\"$H2\"" -- --nocapture
# Compile (ignored runtime bodies) all existing executor-contract tests too.
RUSTFLAGS='--cap-lints=warn --check-cfg=cfg(ferrum_h2_batch_control)' cargo test --manifest-path "$HYPER/Cargo.toml" --features full --lib client::conn::http2::tests --config "patch.crates-io.h2.path=\"$H2\""
```

For each graph, repeat the focused suite against an isolated copy of unchanged
base Hyper plus only the same test module. The [control preparer](prepare_test_control.py)
checks SHA-256 of both relevant base runtime files before writing the test-only
module declaration and copying its exact test bytes. Invoke it from this
candidate checkout with `python3 .../prepare_test_control.py "$CONTROL_HYPER"`.
Add `--cfg ferrum_h2_batch_control` to that control test's RUSTFLAGS. This cfg only
excludes the nonexistent Batch match arm and sets expected task counts to one
per request; it changes no runtime source. Preserve the preparer's receipt.
Never apply this overlay to a ranking/build source. Dependency trees must prove
stock h2 0.4.20 versus the exact expected path before accepting either graph.
The cap-lints allowance is confined to standalone vendored tests, as in existing
vendor CI; ordinary root compilation/lints retain normal policy.

The full `ferrum_` graph also covers write-stall timeout, slow-client/progress,
positive flow control, small-window coalescing and CONNECT reset. Root remote
gates include normal formatting/clippy, `integration_tests vendor_integrity`,
`http2_pool_tests`, `mesh_hbone_tests`, `mesh_grpc_transport_tests`,
`mesh_retry_rotation_tests`, and `gateway_mesh_trust_retirement_tests` as selected
by the production harness. Preserve all failures, including drain-time failures.

## Retained preflight failure

Remote vendor preflight [39707376772](https://github.com/ferrum-edge/ferrum-edge/actions/runs/39707376772)
checked candidate `f65d0801ae340f1745eda2847b49d88174e5e1ed` with harness
`1fc903bb82776360a25c7396998ff729aa6c64a0` and exited 101 before generating
any manifest change. Hyper's `deny(missing_debug_implementations)` rejected the
new `SendBatch` type. The retained checks artifact is `12395741084`, with ZIP
SHA-256 `1bb96ed8b946c24fba941d54b1d980d7d2219dfc76fee7e04c871a40d4a1c699`.
The repair adds a manual `Debug` implementation reporting only the waiter count;
it adds no `B`/`E` trait bounds and changes no polling, ownership, or scheduling.
The failed source and evidence remain preserved.

Generated-manifest preflight [39708299251](https://github.com/ferrum-edge/ferrum-edge/actions/runs/39708299251)
subsequently passed seven vendor tests; its generated manifest was committed as
`ad8439007dbdf128e8b42cf728ab9108500eb999`. This was generation preflight only.
Exact-head comparison [39713142704](https://github.com/ferrum-edge/ferrum-edge/actions/runs/39713142704)
then failed while compiling the shared stock-H2 baseline tests: the free
`h2::server::handshake` accepts one type parameter and already returns a Bytes
connection. The shared fixture and ordered patch now use `handshake(server_io)`.
Zero lifecycle tests executed in that failed run; release builds and performance
sampling were skipped. This test-only correction changes no runtime source and
still requires remote manifest generation followed by all exact-head gates.

## Integrity and retirement

The initial source preparation is not ready to merge: the approved remote
`scripts/update_vendor_integrity.sh` must generate the manifest, followed by
lifecycle checks and full checksum-pinned archive reconstruction through
`.github/scripts/verify_hyper_patch_stack.py`. Do not hand-edit the manifest.
No Rust build, test, runtime or benchmark was executed locally.

Remove this patch on any lifecycle regression or if balanced uninstrumented
controls reject it. If retained, propose bounded autonomous response task sharing
upstream and retire on a compatible release or retirement of this Hyper client.
Keep tests covering cancellation, early response, dormant callers, singleton
allocation, and flush on shutdown when adopting any replacement. Do not tune the
eight-child cap after looking at performance outcomes of this fixed candidate.
