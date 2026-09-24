# Temporary H2 receive-guard observation

This hosted-only diagnostic follows the failures recorded in
[`docs/benchmark_h2_grpc_2026_09_18.md`](../../../../docs/benchmark_h2_grpc_2026_09_18.md)
for issue #5588. It distinguishes the two DATA guards and the other local
reason-11 reset guards on the actual reqwest/native Hyper dependency paths.
It is observation work; no production repair or throughput improvement is
established by this change.

The source-backed findings from run `35414728772` and the remaining identity
and history gaps are recorded in
[`docs/benchmark_h2_guard_transitions_2026_09_19.md`](../../../../docs/benchmark_h2_guard_transitions_2026_09_19.md).
The merged #5613 lane identified one adaptive HTTP/2 framing-credit failure;
it did not capture live successful backend histories or establish a repair.

The ordinary Cargo manifests, lockfiles, vendored inventory and published
images continue to use the existing dependency graph. `prepare.py` requires a
GitHub-hosted Linux runner, copies the checkout into a new temporary directory,
verifies the immutable h2 0.4.19 archive/revision and every modified preimage,
applies the reviewed patch without fuzz, verifies postimages and injected
assets, and selects the result only in that copy. The generated Dockerfile
retains the ordinary stages/features and adds `--locked` to its Cargo builds.
The manual job loads its image locally and does not publish it or export its
cache. Graph verification requires both transport paths to select the patched
crate. `source.json` is the exact source, patch and asset identity record.

All existing guards, budgets, thresholds, return values, receive ordering and
credit-return operations remain intact. The patch adds bounded numeric
observations only when the narrow `ferrum_h2_guard=debug` target is enabled.
It never logs payloads, headers, peers or arbitrary dependency error strings.
The existing `ferrum_h2_observe=debug` target remains enabled in both arms.

The branch codes are:

| Code | Existing guard |
|---|---|
| 1 | Nonempty, nonfinal DATA framing-credit exhaustion |
| 2 | Empty, nonfinal DATA lifetime count |
| 3 | Local error-reset count in the send path |
| 4 | Local error-reset count in the receive-error path |
| 5 | Remotely reset pending-accept streams |

IDs are local to one gateway process. `last_stream`, `last_len`, `last_flow`
and `last_end` describe the last observed DATA frame; `trigger_stream` names
the stream involved in a guard event, which can differ for reset guards.
There is no claimed cross-hop, request, reqwest-pool or native-gRPC mapping.
Window fields describe local state and API updates, not independently observed
peer negotiation. Constructor records precede later window updates. Lifetime
counters include earlier payloads. A dump's phase is its emission time; the
ordered tail has connection-local transition numbers and receive-poll epochs,
not individual wall-clock timestamps. Cross-process clock skew is unmeasured.

## Transition and snapshot contract (V2)

Each admitted connection keeps 512 numeric transitions. DATA records retain
stream ID, payload/flow lengths, END_STREAM, actual receive disposition,
guard operation outcome (0 bypass, 1 success, 2 rejection), before/after credit
and absolute credit change. Large DATA replenishment uses the same entry.
Poll/clear entries retain the actual capped refund and budgeted-event flag
(`consume=1` means budgeted there); flow length is unavailable after dequeue
and explicitly zero in those entries. Final events remain exempt. Pending
counts include **all** queued nonfinal DATA events, including large events and
the queued triggering frame whose debit failed. They exclude ignored frames.
High-water pending and lifetime minimum credit do not reset at snapshots.

Transition kinds are DATA=1, successful DATA dequeue=2, clear=3, target-window
setter=4, local stream-window SETTINGS=5, receive-poll epoch=6, application, clear or
automatic byte-capacity release=7, and buffered wire-window progress=8. An epoch
starts at the existing `clear_expired_reset_streams` entry, once per real
`Connection::poll2`, not once per codec frame. Empty/Pending consumer polls do
not refund credit or produce dequeue entries. Byte state is connection-level;
SETTINGS' stream-window field is not every stream's remaining byte window.

There is no per-frame tracing, clock read, allocation or additional lock:
transitions overwrite a preallocated ring under the existing Inner mutex.
Failure emission dumps that ring immediately after the actual rejected debit,
before later consumer refunds can replace its history. This bounded failure
dump still adds synchronous formatting work under Inner. Live snapshots copy
one ring under `try_lock`, then format/emit after releasing Inner. Initial and
terminal events carry summaries only, to avoid duplicating every lifetime tail.
Counter overflow/underflow, overwritten entries and wrap count are explicit.

The generated diagnostic context alone adds a hidden h2 snapshot function and
a trigger to the **already authorized** `/metrics` path. The exact fixed header
`x-ferrum-h2-guard-snapshot: 1` requests one pass; regular scrapes do not trigger
it. `source.json` binds the generated admin pre/postimages and hook asset.
The shipping admin source, OpenAPI, graph and images do not gain this API.
When the tracing target is disabled, no observer, ring, registry entry or
snapshot is created. There is no background thread, task, timer or socket.

The weak registry never owns a connection. Registration and snapshot admission
use `try_lock`; a busy/poisoned lock produces explicit loss/partial status.
Snapshot order is snapshot-serialization lock, registry-copy lock, release
registry, then one Inner try-lock at a time. Connection paths never take the
snapshot lock; retirement only increments an atomic and releases its memory
permit. This prevents registry/Inner inversion. A temporary strong reference
and copied ring live for one bounded iteration. This is a sequential census
interval, not a simultaneous stop-the-world state: registry changes, missed
locks and lifecycle IDs missing from a generation reject completeness.

Every process permits at most 16 explicit generations. The collector requests
one startup smoke and before/after each whole sample (including setup/warmup,
measurement and drain; these are **not** measurement-barrier snapshots). It
uses one trigger request, the existing 200 ms metrics request bound, and at
most six sink observations over a one-second drain-observation budget, with
no trigger retries. The smoke checks its HTTP ack against the log fence before
offered work. Failure retains evidence and leaves missing samples invalid.
No workload timeout, retry policy, concurrency or campaign duration changes.

Schema-2 samples must identify the manifest's host and their canonical
pair/gateway/protocol/payload cell, with 200 requested/effective workers and
15 seconds of offered measurement. Setup, warmup, measurement and drain
timings are required, finite, typed and ordered. HTTP/2 also requires its
existing transport-close interval; gRPC has no graceful-close timestamp and
none is inferred. Request errors and transport-close timeouts remain diagnostic
evidence, never permission for a performance claim. Samples that never reach
measurement remain retained but cannot establish bounded capture completeness.

The harness writes a separate `*_invocation.json` immediately before launching
the existing client command and immediately after it returns, retaining its
exit code. This records the whole invocation, including output/teardown after
measurement and drain. Before/after snapshots and the invocation carry the
same host/pair/gateway/protocol/payload identity; the process's shared smoke
uses payload zero. Each boundary requires schema 2 and finite ordered start,
sink-observation and end times. The before capture must finish before launch,
the after capture must start after return, and the reported client phase
interval must fit inside that envelope. These are harness wall-clock bounds,
not precise DATA timestamps or new connection/cross-hop identities. Clock
reversal or inconsistent phase timing rejects completeness.

The HTTP response returns the generation's final-issued sequence separately
from the tracing sink. The collector requires matching fence delivery, every
sequence through it, each promised tail in order, every enumerated live summary,
and successful client-role DATA progress between boundaries. It checks both
log sinks' drops, health, queued records/bytes/reservations, write/flush failures,
shutdown timeouts and incomplete shutdown records. No missing counter means
zero. Counters must be nonnegative JSON integers, excluding booleans, fractions
and nonfinite numbers. The index recomputes annotations from retained raw files
and hashes them, including the manifest and invocation envelopes. It always
writes the full expected 12-cell HTTP/2 or 24-cell gRPC matrix before reporting
validation failure. Missing/unparseable/nonobject samples retain placeholders,
available input hashes, and per-row causes; a corrupt first row or raw artifact
does not prevent reconciliation of later rows and remaining raw inputs. JSON
decoder recursion failures become malformed-record causes at the line boundary,
preserving surrounding valid records. A separate row boundary retains escaped
recursion failures and continues indexing all later cells and raw hashes.

`bounded_capture_complete` certifies only that enumerated boundary evidence.
`full_transition_history_complete` is false on wrap or omitted terminal history.
`process_capture_closed` is always false: `closed=0` explicitly reports no
process shutdown/flush fence, and events after the last boundary remain outside
that acknowledgment. Missing HTTP/log acknowledgment makes the bounded capture
partial too. None of these fields grants a cross-hop or pool-family join.

## Explicit budgets and perturbation

* 4,096 lifetime IDs remain the admission ceiling. At most 64 simultaneous
  ring owners reserve 128 KiB each (8 MiB global admission budget); 512 entries
  at 136 bytes plus observation/registry metadata fit each slot on the hosted
  64-bit target. One serialized snapshot clone has a separate 128 KiB allowance.
  Reconstructing initialized-minus-terminal IDs in the prior captured prefixes
  peaks at 56 (fixed HTTP/2 pair 1: 21 server-role and 35 client-role IDs).
  Sixty-four covers that observed peak; it is not a future concurrency guarantee.
  At quota exhaustion the connection is unobserved and the global memory-loss
  counter prevents a complete-capture claim. Each owner frees its ring before
  releasing its shared permit; the last owning snapshot clone keeps that permit
  live until its own ring is freed. Only then can another connection reuse it.
* Ordinary emission reserves 128 MiB per process in 4,096-byte record units;
  actual failures have a separate 8 MiB reserve (2,048 units). Each failure
  atomically reserves its summary plus its complete retained tail before any
  emission. The reserve admits three full 513-record dumps even when a fourth
  full failure competes concurrently. An unreservable dump emits no fragment,
  consumes no units, and increments the explicit suppressed-failure-dump count;
  the remaining 509 units can still admit a smaller complete dump. No global
  emission lock is introduced. Ordinary live dumps still use per-record units.
  These are diagnostic serialized-byte budgets, **not** larger h2 credits.
  Ordinary capacity accommodates three full sets of 16 backend tails across
  the two gRPC payloads (~24,576 entries), plus summaries/smoke; it does not
  promise every possible 64-connection/16-generation sequence will fit.
* At most 192 power-of-two suppression notices and 16 fences are additional
  fixed records (<1 MiB at the same conservative size). Their counters are
  lower bounds until a later HTTP fence returns current suppression totals.
  The parser admits at most 35,024 records and 144 MiB of input, retaining an
  explicit bound error. The ordinary bounded logging sink is unchanged; it
  does **not** gain reserved failure capacity, so sink saturation can still
  make a reserved observer dump partial.

Memory traffic for each ring update and occasional copies/dumps can change
scheduling and fragmentation. Every instrumented sample, including direct
controls and zero-error fixed samples, remains calibrated-performance-ineligible.
Partial capture can establish a positive guard observation but cannot certify
absence, complete histories, or the cause of every client error.

## Hosted validation and dispatch

Pull requests touching the assets run `H2 pinned guard regressions`, and so
does every push to `main` that touches the assets or a pinned repository file
(`src/admin/mod.rs`, `Cargo.toml`, `Cargo.lock`, `Dockerfile`), so pin drift
fails on the commit that causes it. The job
verifies/prepares the source, formats the generated dependency on the runner,
compiles/lints it, exercises its real receive/poll/clear paths and existing
budget tests, checks both dependency chains, and runs the harness tests.
It also type-checks the generated admin hook and exports a real receive/poll/
clear producer transcript in an isolated test invocation. Python consumes that
transcript and mutates it to reject missing live snapshots, lost final fences,
missing/ordered tails, malformed fields/generations, overflow and sink loss.
An isolated producer regression fills four real rings and releases their tracing
callbacks one record per producer per round, requiring three complete failure
tails (including each failed debit) and explicit suppression of the fourth.
This schedule exposes per-record quota interleaving; the invocation starts with
a fresh process-wide reserve. A test-only ring destructor probe checks admission
while the original and then its last snapshot clone are being freed. It adds no
allocation, lock or field to non-test builds. Parser regressions use recursive
stdlib JSON decoding/encoding with a controlled stack bound, independently of
the host's C decoder, and require all 12/24 cells, every raw hash, surrounding
valid records and later good reconciliation after recursion failure.
Synthetic fixture ordering is boundary coverage, never a campaign replay.
Artifacts retain the input archive, patch/assets, generated source, selection
diff, compiler identities and logs. No local project execution is required.

Clippy runs on both an unmodified copy of the checksum-verified archive and the
instrumented copy with the same toolchain and flags. Existing upstream warnings
are retained in both JSON logs. Both Clippy invocations use `--cap-lints warn`
because upstream's test build declares `deny(warnings)`; no diagnostic is
suppressed, and the comparison is the gate. Every new or changed diagnostic
fails, as does every compiler error, missing completion record or non-Clippy warning. Matching
uses the lint code, message, file, primary source text and multiplicity, so moving
line numbers cannot hide a new warning. This avoids changing upstream behavior
just to address style warnings in newer Clippy. Ordinary repository lint gates
are unchanged.

After the workflow is registered on the default branch, root can dispatch
`h2-guard-observation.yml` at the reviewed ref with `run_campaign=true`.
The default `false` runs checks only. The campaign uses the explicitly selected
`h2_guard/experiment.json`; ordinary `experiment.json` remains disabled.
HTTP/2 has 12 canonical samples (70 KiB); gRPC has 24 (10/70 KiB): four
counterbalanced pairs of direct/adaptive/fixed arms, 15 seconds and 200 offered
workers. Existing CA/name, exact status/body/protobuf, phase, failed-sample,
hardware and configuration checks remain in force. The original guard build
is shared between both arms; only the declared window policy differs.
`guard-evidence-index.json` retains every expected sample and reports missing
or incomplete observations. Request errors are evidence and are never retried
away or silently discarded. Results require root inspection of raw artifacts.

## Ownership and retirement

Owner: Ferrum Edge maintainers, tracked by issue #5588. This is an unshipped,
temporary diagnostic patch rather than a new entry in the production vendored
crate inventory. No upstream repair has been proposed by this change.
Reassess at each campaign and remove the workflow, patch and selection/parser
seams once the observed guard mechanism has a recorded disposition and any
necessary correction has its own regression and normal review/CI path.
An h2 version change fails preparation until its source and observations are
reviewed anew. Promoting a dependency repair to a shipping graph requires the
normal dependency lifecycle inventory, retirement plan and behavioral gates;
this diagnostic lane does not authorize that promotion.
