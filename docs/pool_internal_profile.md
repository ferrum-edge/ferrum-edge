# Hosted H2/native-gRPC acquisition profiling (#5588)

This is diagnostic plumbing, **not an optimization or measured performance
result**. `bench-pool-profile` is default off. It enables the existing
`bench-h1-profile` allocator foundation, without modifying its source, 206-counter
schema, four allocation scopes, exporter or H1 report. There is one global
allocator: the existing Jemalloc forwarding wrapper. No new dependency, cache,
pool ownership scheme, retry, wait, readiness poll or production policy is added.

The existing FIPS optional-feature inventory includes `fips,bench-pool-profile`,
which transitively enables the H1 observer. Its resolved dependency graph and
compilation receive the same hosted gates; this is functional coverage, not
a separate cryptographic certification claim.

The branch starts at PR5614's `3cd9296c2fea0a21d385c723999142d34b89f006`, itself
based on PR5602. Those parents remain root-owned. PR5602 recorded adaptive
70 KiB H2 and gRPC correctness failures; PR5613 owns guard diagnosis. This lane
fixes adaptive windows **false**, and does not imply those failures are resolved.
Root must decide correctness before accepting affected performance rates.

## Source coverage and interpretation

`Http2ConnectionPool::get_sender` and
`GrpcConnectionPool::get_sender_with_purpose` wrap the original acquisition
future. The H2 capability-probe call site uses a purpose-specific entry point
delegating to the same acquisition body, matching gRPC's existing distinction.
Fixed family/purpose combinations are H2/gRPC × request/capability; no pool key,
address, shard number, request identity, generation or credential is exported.
Keys, TLS/SAN/SVID generations, DNS/subsets/caps, ownership and locks are retained.

Every first-polled acquisition increments its denominator. Each OS thread selects
its first and every 64th acquisition independently per family/purpose. The
selection travels with the future across migration. Only sampled acquisitions
produce phase/event observations; **do not multiply these into exact totals**.
This systematic sample can alias periodic traffic and overrepresents cold starts
on new threads. Compare cold setup separately from steady state; retain phase
boundaries and inspect misses/owners, not just aggregate per-request averages.

| Boundary | Observation | Limitation |
| --- | --- | --- |
| Entire acquisition | sampled/completed/error/cancel counts, wall ns, probes/acquisition buckets | first poll to completion/drop; never-polled futures are excluded |
| Each acquisition poll | execution ns and allocator-request deltas; Ready/Pending | elapsed execution can include preemption; not CPU samples |
| Phase 1 | key preparation plus complete synchronous shard sweep | includes nested RR/probe/readiness; no isolated key-only estimate |
| RR group | map lookup/Arc clone or cold seed plus increment | no claim that atomic contention is material |
| Each shard probe | `GenericPool::cached` elapsed/allocations; probe count | aggregate across shards; no shard/key label |
| Cached lookup | missing entry, unhealthy invalidation, exact connection clones | clone count is not an allocation estimate; includes fallback cache checks and creation insertion/recheck clones |
| Readiness | one original `now_or_never(sender.ready())`, Ready/Pending/Error | adds no awaited readiness or repoll |
| Sweep outcome | warm hit, miss fallback (no Pending), busy fallback (at least one Pending), fallback entry | miss fallback can include unhealthy/error shards; not necessarily first-ever connection |
| Recovery | error-recovery entry and alternative cached success | recovery preserves the existing no-readiness-check behavior |
| Slow fallback polls | execution/allocator deltas around the original pool fallback future | includes semaphore/cache/recheck bookkeeping and nested creation/wait phases; not wall wait |
| Generic pending/create path | creation ownership, coalesced wait entries, actual create success/error, individual create/wait poll work | re-election can produce multiple entries; owner recheck can avoid actual creation |
| Empty synchronous bracket | timer/snapshot baseline per sampled poll | useful observer calibration, not a subtractable constant |

Phase snapshots are inclusive and overlap. Their times/allocations must not be
summed. Whole-poll allocation deltas include synchronous nested observer work;
detached Hyper/rustls/Tokio drivers, native allocations bypassing Rust's allocator,
kernel buffers and allocator internals are outside the acquisition scope.
Returned-sender destruction and cancellation destructors outside polling are not
scoped allocation observations. Creation includes handshake execution in that
future, but not detached driver work. No per-datagram shared counter is added.

Each synchronous measurement reads only the existing thread's first ten H1
process allocator counters before and after the operation. H1 indexes and
meanings are unchanged. Fields distinguish alloc/zeroed/realloc/dealloc requests,
attempted/successful requested bytes, failures and realloc old/new/dealloc bytes.
These are neither RSS nor copy volume. Scopes install/restore a private non-Send
TLS context **inside each poll only**, including Pending and nested polls. No TLS
guard survives await; a migrated future snapshots its new polling thread.

Acquisition wall time includes scheduling and asynchronous setup/coalescing waits.
Subtracting poll ns from wall ns does not isolate CPU or readiness waiting.
Phase 2 may return a healthy but busy sender; later send/admission/response waits
and downstream stream credit remain **opaque**. This branch collects no CPU
stacks, hardware-cache events or lock-contention samples. Those are explicit
residuals before attributing a material bottleneck or justifying a cache.

## Publication, completeness and observer cost

The separate pool store follows H1's bounded publication algorithm: 128
cache-aligned, never-reused lifetime thread slots; fixed TLS integer arrays;
checked/saturating counts; atomic SeqCst payload and version publication; at most
three reader attempts. No new allocator callback or unsafe memory access exists.
Each 1024 local observer updates publishes a slot. The scraper publishes its own
thread only. Idle/exited threads can retain unpublished tails, explicitly reported
even after exit. An event tail does not bound its byte residual. No forced flush,
wakeup, destructor registration or cross-thread wait is introduced.

`/metrics` retains its existing JWT/token/CIDR authorization. The new schema is
the fixed list in `tests/performance/multi_protocol/pool_profile_schema.json`.
Metadata includes schema, PID, sample_every, allocator installation, registration
and capacity, missing slots, unpublished events, lost updates and overflow.
The collector also requires the underlying H1 allocator's loss/overflow metadata;
successful zero snapshots cannot conceal allocator slot exhaustion. Unsampled
denominators, sampled phase totals and snapshot gauges have distinct meanings.

`observer_ns` brackets timestamp and allocator-snapshot overhead around each
operation. It excludes the final pool-counter aggregation/publication itself;
nested observer costs remain in outer elapsed measurements. Empty-bracket
observations expose the clock/snapshot floor, including occasional H1 publication.
`Instant` resolution is platform-dependent and **not measured** by this lane.
Zero elapsed values can be below clock resolution. The same-revision calibration
captures whole-observer effects, including TLS, counter aggregation, publication
and scraping. No guessed observer overhead is subtracted.

The collector retains raw fixed-prefix metrics even on schema rejection, every
failed observation, sample IDs, wall/monotonic timestamps, capture/sampler CPU
cost, process PID/start ticks, start/end snapshots and boundary slack. The process
sampler atomically checkpoints partial timelines and lifetime sampler CPU during
pool captures; interrupted captures remain
incomplete. Missing fields, changed identities, resets, duplicate samples, loss,
overflow and unpublished tails reject completeness. Boundary acquisitions still
in flight also reject completeness: an exact closed cohort is not claimed.
Partial published deltas remain useful diagnostics, with their limitations.

Traffic validity is assessed independently using the parent's useful-work
validator plus pool-specific H2 evidence validation. Every arm, including direct
and observer-off controls, requires explicit integer transport-error and
suppressed-event counts, boolean phase/transport-close timeout status, a capture
error list and an integer backend-error count. Missing, null or incorrectly typed
required fields fail closed; nonzero errors/suppression, timeouts and capture
errors reject traffic even when `h2_observation` is empty or absent. The existing
producer emits `backend_log_limit_reached` only when the limit is reached: absence
is normal, while a present value must be boolean and true rejects the sample.

Non-direct arms also require `gauges_available=true` and a nonempty list of usable
gateway gauge snapshots inside the measurement window. Each snapshot requires
finite nonnegative wall/monotonic timestamps and capture duration, both resident
H2/gRPC pool-entry gauges, and the active-connection gauge. Gauge values must be
finite nonnegative numbers, never booleans or substituted configured pool widths.
Direct controls have no gateway scrape (`gauges_available=null`, `gauge_samples=[]`);
observer-off controls still require these ordinary H2 gauges, but no pool profile.
The shared historical validator and H1 evidence contracts are unchanged.

Reports enumerate every expected arm/pair/size, including absent or malformed
samples, and retain raw capture failures and specific traffic rejection reasons.
The report command exits nonzero when any traffic row fails. Reports
verify same revision/config/environment, and same image for profile repetitions.
`fully_measured_comparison_eligible` stays false pending root's external correctness
disposition. No failed repetition is silently removed from a favorable average.

## Hosted checks and bounded manual campaign

No project code, formatter, lint, compiler, test, benchmark or container was run
locally. Only static inspection, data/text edits and `git diff --check` are local
validation. `.github/workflows/pool-internal-profile.yml` runs on PRs that edit the pool
profiler itself and daily on the `main` tip
(see `docs/ci_cd.md` -> "Optional PR lanes and post-merge validation"),
with pinned external actions, the shared Rust build setup and native prerequisites
including `libcurl4-openssl-dev`. It registers feature-on formatting/lint/binary
build, bounded publication tests, migrated/nested poll allocation and cancellation
tests, real generic-pool coalescing/error tests, a live H2/gRPC purpose/hit/miss
test, existing key/lifecycle contracts with observers on/off, and collector tests.
These are **unexecuted registrations**, not passing-check claims.
The existing hosted collector-test discovery also covers the actual report and
CLI exit status with producer-generated H2 annotations: complete H2/gRPC matrices
in both modes, direct/observer-off controls, absent/empty/malformed diagnostics,
unusable gauges, typed error/suppression status and independent phase failures.
Negative cases require the full matrix and unchanged failed samples to be retained.

Root alone may dispatch `pool-internal-profile.yml` at the reviewed branch. The
worker neither dispatches nor waits for CI. The manual matrix is explicit:

| Protocol | Payload bytes | Offered workers | Per-cell campaign |
| --- | --- | --- | --- |
| native H2 and gRPC TLS | 10240, 71680, 512000 | 200 | calibration + profile, four pairs each |
| native H2 and gRPC TLS | 1048576 | 100 | larger-size recheck, same pairs |
| native H2 and gRPC TLS | 5242880 | 50 | larger-size recheck, same pairs |

Ten cells, maximum two concurrent VMs, 240 minutes per cell including builds;
each campaign declares 3600 seconds, 15-second measurements, no adaptive extension.
Each cell runs both arms and repeated direct controls on one host. Order is the
parent harness's counterbalanced order; setup/warmup/measurement/drain, errors,
timeouts and offered work are unchanged. Windows are fixed 8/32 MiB, width 16,
caps 1000, frame size 1 MiB, keepalive 30/45 seconds, CA verification and route
retry/timeout configuration unchanged and archived. A native request sample must
appear in the relevant pool family or profiling is incomplete.

Calibration builds symbolized feature twins at one revision: H1 foundation only
versus H1 plus pool observer. This isolates incremental pool observation cost;
it is **not total H1+pool cost against production**. The parent's H1 calibration
remains necessary for that. Profile repeats use the exact same observer-on image
for both arms; there is no cache/ownership candidate. Default crypto-ring,
Jemalloc, release optimization/LTO/codegen/panic policy are shared; both twins
retain matching debug info without changing production Cargo profiles or forcing
frame pointers. Literal Cargo/Docker commands remain visible in the workflow.
Source/lock/config/compiler/binary/build-ID/image/hardware/kernel/boot records and
debug artifacts accompany the raw paired samples.

`--pool-profile calibration|profile` selects the new manifest/schema explicitly.
The ordinary disabled `experiment.json`, H1 reports, frozen benchmark workflow
and immutable policy files are untouched. Shared harness edits are gated by that
selector. Root must review parent integration overlaps in `process_usage.py`,
the runner and pool/proxy files, validate hosted results, and retain CPU/stream
credit/streaming and issue #5588 obligations independently. Nothing here closes
#5588 or asserts measured cost, materiality or throughput gain.
