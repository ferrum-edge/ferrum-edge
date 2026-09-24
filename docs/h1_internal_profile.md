# Hosted H1 internal profiling foundation (#5588)

`bench-h1-profile` is a **default-off diagnostic feature**, accompanied by
hosted regression fixtures. It does not change coalescing, Content-Length, body limits,
timeouts, retries, offered load, TLS verification, release optimization settings,
or forwarding policy. #5600's client frame/chunk/TLS observations and `/proc/io`
remain distinct sources. Historically this branch started at #5602 development
head `5e32b808af5631978cedc525d0dff7a29aedbb4c`. #5602 landed at reviewed head
`3ba46fcd73d22304dca4ddd20b14c8ecadd6c814`, merge
`61c68cb0e73504f389a2fdf065bf5297d6baf3ba`; it is no longer an outstanding
dependency. Preserve its error campaign. There are no new performance results here. The prior
cutoff campaign demonstrated no gain; its failed 5 MiB observations remain valid
failure evidence and are not replaced by this foundation.

The feature introduces no dependency or crypto-provider edge. `fips,bench-h1-profile`
is explicitly included in the FIPS optional-profile inventory, so the existing
hosted resolved-graph audit and compile matrix cover that combination. This is
functional build coverage, not a separate cryptographic certification claim.

## Allocator safety and publication contract

`src/main.rs` wraps the existing `tikv_jemallocator::Jemalloc` on non-Windows
platforms only when the feature is enabled. The default allocator declaration is
otherwise unchanged. Windows does not install this observer and exports
`allocator_installed=0`; the hosted collector rejects that as missing coverage.
The library alone does not replace an embedding application's allocator and
exports `allocator_installed=0`, including on non-Windows. Only a binary that
declares the forwarding global allocator explicitly calls
`register_global_allocator()` at entry. The hosted library test never mutates
this registration; the separate cadence child checks `1` with the feature and
absence of the metric without it, avoiding process-global test resets/races.

`src/h1_profile/allocator.rs::ForwardingAllocator` forwards alloc, alloc_zeroed,
realloc and dealloc exactly once with unchanged pointer/layout/size. The return
pointer is unchanged. A failed realloc leaves ownership of the old allocation
with its caller. Requested bytes include attempted allocations/zeroed allocations
and **new requested sizes** for realloc. Successful requested bytes exclude null
returns. Realloc old/new sizes and deallocation bytes are separate fields.
Deallocation is attributed where it executes, not to its original allocation.
These counters are neither live memory nor RSS, and realloc sizes are not copy
volume. Jemalloc internals, native-library allocations bypassing Rust's allocator,
kernel storage and hidden memcpy/memmove are outside coverage.

Callbacks use fixed arrays, const non-destructible TLS, `RefCell::try_borrow_mut`,
checked arithmetic and atomics only. They do not allocate, acquire locks, log,
format, dereference caller storage, or panic. Non-destructible TLS avoids lazy
destructor registration inside callbacks. `try_with` failure, reentrant borrow
failure, exhausted registration and publication version exhaustion increment
`lost_events` on the exceptional path. Saturation is sticky; counter overflow is
exported and invalidates completeness. Internal array indices are constants or
bounded enum/registration results. This contract depends on the backing
allocator's `GlobalAlloc` contract and Rust's const TLS implementation; root
should review these unsafe/concurrency seams explicitly.

There are 128 cache-aligned, never-reused thread slots, each with 206 fixed
counters. Registration uses bounded atomic compare-exchange over static storage.
Normal accounting mutates only the calling thread's TLS and stores an event
watermark into its own slot; there is no shared process-total atomic increment
per allocation. Every 1024 observer events (allocator calls, body/write events
and scope transitions) publish that thread's entire cumulative snapshot.
Frontend observer drop and the scraper's own thread also publish explicitly.
There is no hot-path clock or stack capture.

Publication has one writer per slot. The writer makes a sequence odd, stores
atomic counter fields and the published event watermark, then makes it even.
All these operations are SeqCst. Readers accept only an unchanged even version,
with at most three attempts. Payloads are atomic: **no plain-memory seqlock data
race**. Busy slots increment `missing_slots`; they are not silently accepted as
zero. Version exhaustion freezes that slot and reports loss. Cross-thread sums
are not a simultaneous stop-the-world snapshot.

This is intentionally a bounded minimum: idle/exited threads can retain an
unpublished tail. No TLS destructor flush is promised. Their event watermarks
remain in unrecycled static slots, so `unpublished_events` stays visible even
after thread exit. A tail may contain an arbitrarily large requested allocation;
its byte residual cannot be bounded from its event count. Abrupt termination
also loses unsampled data. The collector keeps published deltas but sets
`complete=false` when a tail, missing slot, overflow, reset, or loss exists.
Do not present these partial sums as exact process totals. Thread churn beyond
128 lifetime registrations requires a separately reviewed extension.

The process view covers all observed Rust allocator calls, including runtime,
administration and metrics export. Four **synchronous execution** scopes cover
`ProxyBody::poll_kind`, the two reqwest input polls, plaintext write/flush/shutdown
polls and ciphertext write/flush/shutdown polls. A closure installs/restores TLS
on every poll, including Pending and error. A private non-Send guard never escapes
the closure and never survives await. Nested inclusive scope counters count once
per active scope; exclusive attribution goes only to the innermost scope.
Inclusive views overlap and must not be summed. Detached tasks, TLS reads,
handshake orchestration, header construction, dispatch, and background Hyper
drivers are not exhaustively scoped. Scope calls are not request IDs or sampled
CPU time. Unscoped process traffic can be derived only from a complete snapshot.

## Source coverage inventory

| Source site | Exact observation | Boundary / limitation |
| --- | --- | --- |
| `body.rs::direct_streaming_body` reqwest byte stream | input DATA/frame bytes, poll/Pending/error/EOF, disjoint size buckets | response input only; reqwest has already adapted wire framing |
| `body.rs::coalescing_body` reqwest byte stream | same, separate counters | input before aggregation; no direct-H2/H3/upload coverage claimed |
| `body.rs::ProxyBody::poll_frame` | output DATA/non-DATA, bytes, poll/Pending/error/EOF, size buckets | shared output across protocols, not H1-only; known EOF may let Hyper skip a final poll |
| `CoalesceBuffer::push`, Single promotion, both `extend_from_slice` calls | `first.len()` plus `data.len()` copied, after each executed call | exact explicit source copies, all coalescer users |
| `CoalesceBuffer::push`, Merged `extend_from_slice` | appended `data.len()` copied | reserve/growth may additionally move old storage; not counted as payload copy |
| CoalesceBuffer/Coalescing | single holds, spare reuse, new region, capacity growth, large bypass, nonempty flush | aggregate flush count only, not a complete flush-reason classification |
| `handle_connection` above TCP | cleartext AsyncWrite observations | H1/h2c mixed; upgrades can outlive HTTP |
| `handle_tls_connection`, above TLS | plaintext AsyncWrite observations, non-h2 ALPN versus ALPN h2 | non-h2 includes absent ALPN (not proof of negotiated H1); accepted bytes can still be buffered in rustls |
| `handle_tls_connection`, below TLS before accept | ciphertext AsyncWrite observations and TLS framing | mixed ALPN/handshake/control traffic; ALPN unknown during handshake |

Size buckets are disjoint: 0, 1–1024, 1025–16384, 16385–131072,
131073–1048576 and larger bytes. `Bytes` clones, Single ownership transfer,
large-frame bypass, split/freeze, and retained spare ownership count **zero payload
copies** at those sites. The five-byte TLS parser's own header copy is observer
work, not a response-payload copy counter.

The AsyncWrite adapter forwards exactly one inner call with the original buffer
or slice vector, preserving vector order/empty entries, `is_write_vectored`,
partial success, zero success, Pending, errors, flush and shutdown. Reads are
delegated unchanged. Requested byte totals count repeated poll offers and must
not be used as successfully transferred bytes. It adds no retry, await or flush.
Only the accepted ciphertext prefix enters the incremental parser, including
partial vectored writes. It retains five header bytes, never payload. Complete
TLS records and wire bytes include encrypted control records; parser faults and
incomplete terminal records are separate counters. At mid-stream sample
boundaries, client receive counts and gateway accepted counts can disagree.

No new listener or endpoint exists. Export appends fixed `ferrum_h1_profile_*`
fields to the existing authenticated `/metrics` response. There are no request
labels, paths, addresses, headers, credentials or body contents. Admin/sampler
connections are outside the frontend write wrappers but their allocations remain
in process totals. This build should run an isolated H1 workload; shared body,
coalescer and mixed-wire counters must not be relabeled H1 under mixed traffic.

## Hosted checks and exact root dispatch

No repository code, build, formatter, lint, test, benchmark, container or server
was executed locally for this implementation. Static inspection and
`git diff --check` are the only local validation. The new
`.github/workflows/h1-internal-profile.yml` registers a hosted lane (PRs that
edit the H1 profiler itself, a daily run on the `main` tip, and
manual dispatch; see `docs/ci_cd.md` -> "Optional PR lanes and post-merge
validation") for
feature-enabled clippy/binary compilation, registered external observer tests,
private publication-seam tests located under `tests/unit/gateway_core/`, existing
coalescer contracts with observers on/off, existing live functional streaming
contracts, the explicit H1 cadence/safety matrix below, supported-protocol
trailer gates, and H1 schema/completeness tests. The independent Benchmark Harness
Tests discovery also runs the new Python tests. These are registrations, not
claims of passing execution.

Root dispatches after reviewing this branch (#5602 is already landed; worker
does not dispatch). Once the workflow is available to GitHub Actions:

```sh
gh workflow run h1-internal-profile.yml \
  --ref codex/20260919-5588-h1-kernel-profile -f payloads=all -f diagnostic_only=true
```

`diagnostic_only=true` is the default: it runs the bounded slice below, then
stops. Root must pin and verify the dispatched head against the pushed branch
before interpreting artifacts; the command selects a ref, not an immutable SHA.
For full profiles after reviewing the slice, root uses the same command with
`-f diagnostic_only=false`. That dispatch includes its own diagnostic slice;
there is no automatic rerun. `payloads` is `all` (default), `10240`, `71680`,
`512000`, `1048576`, or `5242880` and applies only to full profiles. Root can
budget separate size dispatches; all five remain required. Each comparison's two arms and repeated direct controls share one VM.
No worker dispatch, PR, review, merge or issue write is part of this task.

The manual job builds observer-off/on binaries at the **same checked-out SHA**,
default `crypto-ring` features, Linux Jemalloc, release opt-level 3, fat LTO,
one codegen unit and abort panic. Both diagnostic twins add debug info and retain
symbols using job-local profile overrides; production Cargo profiles are
unchanged. No forced frame pointers. The ordinary release binary is not a third
arm, so calibration applies to these diagnostic twins, not historical release
rates. Source-tree/lock/config hashes, compiler/build flags, image IDs, binary
hashes/build IDs, matching debug artifacts, kernel/hardware/boot identity and
effective safe runtime settings are retained. The shared harness retains raw
traffic samples, startup logs, phase boundaries, process CPU/RSS and concurrency.

Calibration first measures on/off at cutoff 0; cutoff then compares 0/1 with
identical observers. Both use four counterbalanced pairs, repeated direct
controls, 15-second measurement, five sizes and 200/200/200/100/50 offered workers.
Existing warmup, drain, error, timeout, retry and TLS policy are preserved. The
new H1 selector bypasses but never edits `experiment.json` or `experiment_arms.py`.
Shared runner/sampler edits are isolated behind `--h1-profile`; root should
coordinate those two file overlaps with #5602. The frozen benchmark job and its
policy verifier are untouched.

`h1_internal_profile.py` requires schema-2 traffic samples bound to the expected
pair, gateway, payload and nonempty campaign host ID. The runner manifest records
the H1 mode, `http1-tls` selection, 15-second duration and base 200 workers; each
sample must carry the producer's `HTTP/1.1+TLS` protocol, 15-second measurement
phase and both worker fields matching the committed 200/200/200/100/50 size table.
Legacy samples, copied rows, aggregate samples, wrong-host samples and substituted
workloads remain failed observations. Invalid/missing manifest selections retain
the full expected matrix; valid budgeted payload subsets retain every selected
pair/arm/size and do not satisfy the separate all-five-size campaign obligation.

Every gateway arm also requires a versioned runtime record with embedded
pair/arm/host/mode identity, including calibration's observer-off control. The
runner records its full checked-out revision in the campaign manifest and
captures the two fixed revision/observer labels from both `docker inspect` and
`docker image inspect` of the container's immutable `sha256:` image ID. Image
inspection has a 10-second bound. Both label sets must identify the manifest's
full 40-hex revision and the expected `ferrum.h1-profile=off` or `on` build.
Missing labels, overridden container labels, mutable tags, malformed metadata,
missing runtimes and stale cross-pair records fail validation. Calibration may
use distinct off/on images, but each arm's image ID must stay fixed across all
four pairs. Cutoff 0/1 must use exactly one observer-on image ID across all pairs.

The collector verifies the running container's command (`/app/ferrum-edge run`
without config overrides), working directory, and the read-only bind from the
hashed source file to `/etc/ferrum/config.yaml`. The report recomputes SHA-256
from **each retained config file**, then requires identical config hashes across
all gateway arms and pairs. The current runner selects cutoff in the environment,
so **no config-file difference is permitted**, even if its new hash is valid.
Each launch now supplies the cutoff setting exactly once; ambiguous duplicate
environment entries fail capture. The exact safe `FERRUM_*` settings from the
release image and runner must be present with valid values, including fixed
file/metrics bindings and the arm's declared cutoff. Unknown settings and secret
provider overrides fail capture without recording their names or values. Every
other safe setting must agree across arms/pairs; only cutoff 0 versus 1 differs
in the cutoff campaign. Other environment values and other mounts are retained
as canonical hashes and must also agree. Only Docker's generated short-ID
`HOSTNAME`, if present, is normalized; arbitrary hostname overrides fail.

For observer-off controls, the raw process timeline must continuously bracket
measurement with the runtime's owned host PID/start ticks, and its retained
`h1_gateway` and embedded measurement PID must agree. Missing observer counters
in that build are expected; missing runtime/process ownership is not. The same
capture timing validator runs for OFF and ON: it requires interior capture,
consecutive integer IDs, finite increasing clocks, nonoverlapping captures,
one-second maximum sampling gaps and process-to-scrape lag, two-second total
process/capture boundary slack, and 50 ms wall/monotonic agreement. The OFF
metrics parse failure does not waive before/after listener ownership or timing.
Sparse or excessively wide brackets retain their partial CPU observations but
cannot calibrate observer overhead. Runtime
failures appear in each affected observation's `runtime_issues` and make
`runtime_complete`, `traffic_complete`, `profiles_complete`, and comparison
eligibility false. Available profile deltas and the entire declared matrix are
still retained. These checks validate retained Docker evidence, not signed
binary provenance, and do not retroactively certify older artifacts.

Profile brackets have a **two-second total boundary-slack limit**, including the
last scrape's duration, and a **one-second maximum start-to-start sampling gap**
for the fixed 500 ms sampler / 200 ms HTTP timeout. They require an observation
inside measurement, nonnegative integer sample IDs increasing consecutively,
strictly increasing finite wall/monotonic timestamps, nonoverlapping captures,
and wall/monotonic elapsed agreement within **50 ms of the first bracket sample**.
Process observations must precede their scrape by at most one second. These are
fixed acceptance limits, not bounds enlarged to rescue scheduling stalls. Excess
slack, skipped samples and discontinuities retain available published deltas as
partial evidence. Each accepted row needs present, finite, nonnegative numeric
sampler CPU (booleans excluded); invalid overhead remains null with an issue,
never silently zero. A measured zero CPU value is valid.

The runner retains the owned container's full ID, host init PID/start ticks,
host-network mode and fixed `http://127.0.0.1:9000/metrics` endpoint. The sampler
checks that record against the selected container ID. Before **and** after each
scrape it rereads `/proc` start ticks and `NSpid`, requires exactly one observed
gateway, and joins the unique IPv4 loopback port-9000 LISTEN inode to that
process's fd table. The stored namespace PID must equal the exported metrics PID
at every accepted row; before/after and successive bindings must agree with the
retained runtime. This distinguishes unrelated containers exporting PID 1.
Missing permissions/ownership records, reuse, restarts, stale mappings and
ambiguous listeners produce partial profiles. This is bounded listener ownership
evidence, not a new syscall/connection tracing facility or a cryptographic artifact
attestation. Older captures without the binding cannot become complete retroactively.

The fixed export remains **206 counters + eight metadata fields (214 total)**.
The consumer requires positive metrics PID, capacity 128, and 1–128 registered
slots that never decrease. Successful traffic requires positive advancement of
`body_proxy_output_all_data_bytes`, the guaranteed response DATA boundary for
this H1 workload. It does not require optional coalescing, copy, vectored-write
or EOF counters to advance, nor equate bracket bytes with measured client bytes.
Missing/malformed/decreasing counters, missing slots, loss and overflow remain
failures. Idle-thread tails explicitly prevent complete allocation coverage.
Useful traffic validity is separate from profile completeness. Every expected
arm/pair/size is retained, including missing samples and failed 5 MiB observations.
The hosted H1 Python suite exercises complete producer-shaped campaigns and
negative campaign, timing, identity, metadata/work and CPU cases, including
written full-matrix reports and the capture-to-sampler ownership path. Runtime
fixtures pass Docker-shaped inputs through the actual collector with only Docker
inspection and `/proc` reads mocked. Hosted regressions cover missing/malformed
image/container labels, revisions, environment/command/mount evidence, retained
config tampering, image/config/environment drift in later pairs, and observer-off
process ownership. The pool collector is a sibling with its own review/fix; this
change is confined to H1 collection/reporting. No local execution was performed.
No surviving-worker average, guessed observer
overhead subtraction, or gain claim is produced. Raw on/off measurements are the
overhead calibration; shared-host process CPU is not isolated proxy cost, and RSS
is not allocation traffic. Scrape overhead is included in the gateway process and
sampler timings, not analytically subtracted.

## Bounded H1 request-drain diagnostic

The retained three 5 MiB drain failures and slow 1 MiB tails still have **no
proven cause or repair**. Process write accounting near 79 kB/s does not identify
socket throughput, TCP pacing, a TLS flush, or an HTTP body boundary. This mode
adds evidence at the client boundary; a clean run alone cannot resolve those
failures. No production `src/`, allocator, body/counter, H3 observer or global
clock implementation is changed by this diagnostic addition. Backend upload EOF,
upstream identity joins, syscall and CPU traces remain later observations; no
cross-hop request identity is inferred from the client IDs.

`proto_bench http1 --h1-diagnostic` is default off. It wraps the existing
`ObservedBody` admission and response `collect()` with last-state observations;
the first transport body poll still admits work, and the existing status/exact
bytes/content check still determines useful completion. It adds no warmup,
retry, request deadline, flush or measurement extension. The existing `Phases`
coordinator (the harness phase coordinator) supplies the narrow phase/snapshot
hooks; the real connection still owns the existing `ConnectionGuard`.

The parent-owned registry survives cancelled worker futures. Each registered
worker has a numeric worker ID and one latest request record, with globally
increasing numeric request and connection IDs within that diagnostic session.
Connection records retain numeric local/peer socket tuples when available;
missing tuples are null, never fabricated. Request-body first poll, accepted
body bytes, last progress and body end; response status/version, parsed
Content-Length and framing flags; response DATA bytes, last progress, end/error
class and validation completion are separate observations. No paths, arbitrary
header values, payloads or credentials enter this registry. Header flags are
meaningful only when the headers timestamp is present. Null completion/end/error
means unobserved, not success. Errors use bounded classes, not arbitrary error
strings. Lifetime offered/admitted/completion/error counters survive cancellation;
they do not reconstruct the lost worker's measured histogram or silently replace
useful-work totals. A stale body cannot update a newer request's record: that
update is counted as capture loss.

Every timestamp carries session microseconds plus phase name and phase-relative
microseconds in `client_process_diagnostic_session_instant_microseconds`, from
one client `std::time::Instant` epoch. Snapshots and the final report name that
clock domain and client PID explicitly. This is **not host CLOCK_MONOTONIC** and
cannot be directly compared with backend, BPF, perf or another process's times.
Measurement/drain classification follows the existing fixed deadline. Session
origin is diagnostic creation, not the generic harness monotonic origin; existing
wall timestamps remain approximate cross-process context only. Generic clocks
are left for root and the separate H3 repair.

At warmup +10 seconds, if workers have not reached the barrier, the coordinator
captures one `delayed_warmup` snapshot without extending its existing preflight
bound. It snapshots immediately before preflight/drain worker abortion, then
after request collection and after separate driver retirement. Last await and
stage-entry time remain intact on worker drop; lifecycle becomes
`dropped_without_return`, which deliberately does not guess cancellation versus
panic. Snapshot copying briefly serializes diagnostic updates, so this mode is
intrusive and is excluded from the full off/on performance comparison.

Bounds per client invocation: 256 worker records, 512 connection records, four
snapshots, fixed-size fields and no per-packet/request history. Omitted records,
stale/unrecordable updates, snapshot overflow and poisoned locks are explicit
loss counters; any loss makes diagnostic completeness fail. Numeric socket
addresses and static enums bound strings. Compact serialized diagnostic state is bounded below 4 MiB at these capacities;
the hosted capacity regression checks the compact report. Budget up to 16 MiB
for the pretty-printed diagnostic report in stdout and 4 MiB for the four compact
stderr snapshots per invocation; the single slice has three client invocations. Existing process/startup logs and build/debug artifacts retain their
existing bounds and are not covered by that diagnostic byte budget. Snapshots
are emitted immediately as `H1_DIAGNOSTIC` JSON lines, then included in
`phases.h1_diagnostic`, so an outer timeout need not erase pre-abort evidence.

Only when enabled, driver handles are owned in a bounded `JoinSet`, finished
handles are reaped during connection registration, and remaining handles are
reaped **after all request workers join**. At most 512 live/unreaped driver
handles are accepted; capacity rejection is an explicit failed worker and a
retirement error, never a silent detach or a valid workload sample. Connection
metadata overflow alone does not stop admission. The declared 50-worker slice
fits both capacities; the bounds are diagnostic resource guards, not tuning.
Retirement allows 5 seconds, then requests abort and allows 1 second to reap;
any remaining handles are counted `unreaped_after_abort` and dropped with abort
requested. Normal completion, Hyper error, cancellation, panic, pending/aborted
and unreaped counts are distinct. `completed_ok` means the Hyper driver returned
`Ok`, not peer FIN, TLS close_notify or successful request completion. In
[Hyper 1.8.1's dispatcher](https://github.com/hyperium/hyper/blob/v1.8.1/src/proto/h1/dispatch.rs#L306),
a response parse error delivered to `SendRequest` can be followed by driver
`Ok`; the malformed-header regression asserts both observations separately. The old
H1 `transport_close_secs=0`/false defaults are still **unobserved** when this mode
is off. They must never be interpreted as successful transport closure. The
new retirement report is authoritative only when present; driver retirement
never increments useful request completions or replaces request-drain timing.

The existing manual workflow builds its same-revision twins and common harness,
then runs exactly one direct/cutoff-0/cutoff-1 pass using the observer-off gateway
image and diagnostic-on client. Each arm uses 5 MiB, 50 workers (the unchanged
200-base scaling), one full-payload warmup, 30-second measurement, 30-second
request drain, and unchanged timeout/guard/TLS policies. Preflight remains
70 seconds and the runner's existing outer bound remains 190 seconds per arm;
the complete campaign budget is **900 seconds**, enforced by the independent
`h1_diagnostic_campaign.py` supervisor, including startup, Docker operations,
passive readers, between-arm cleanup and final cleanup/reporting. Builds remain
separate workflow prerequisites. Its monotonic deadline starts before campaign
artifact initialization. At most **870 seconds** are available for the entire
runner; **30 seconds are reserved within the 900**, not added afterwards. The
cleanup helper gets at most 20 seconds (less if less time remains), and reporting
gets the remaining time minus a two-second final bookkeeping reserve. An early
runner exit enters cleanup immediately. Smaller explicit budgets scale the
reserve down; budgets above 900 are refused in diagnostic mode.

The runner owns a new Linux session. Cleanup checks PID/start-tick/session
identity and sends TERM then KILL to its remaining processes, including nested
timeout process groups, without an unbounded wait. The privileged passive reader
also has its own TERM/KILL deadline before the work limit, so it cannot rely on
the blocked runner to stop it. Container names are unique per campaign and are
known before creation. Bounded cleanup captures remaining container logs,
removes only those names and checks their absence. Helper commands each receive
a fraction of the remaining cleanup time, including force-kill grace. The
diagnostic path does not use the general runner's port-wide cleanup. No request
timeout, request-drain allowance, concurrency, retry or measurement duration
changes; exhausting the campaign budget fails the slice.

`diagnostic_termination.json` distinguishes runner exit, exhausted budget,
interruption, supervisor failure and incomplete cleanup. It records observed
exit/reap codes, survivors, cleanup/report outcome and elapsed time. Missing
permissions, an unavailable Docker daemon, an unkillable process or unsuccessful
reaping cannot become successful cleanup. This is a hosted userspace deadline,
not a guarantee against kernel uninterruptible I/O, host suspension or loss of
the runner/filesystem. Such failures remain incomplete and need root attention;
no successful termination is inferred from missing evidence.

Before starting the child, the supervisor atomically retains a failed report
with all three rows. Raw client stdout and backend output go directly into the
artifact directory from process launch. Partial client output survives a kill
during the invocation or reader join; an absent client exit file is unobserved,
not a fabricated timeout return. Final reporting is a separately bounded process;
a failed/killed report leaves the seed, and the existing workflow `always()`
step can regenerate it from retained evidence. Existing output directories are
not overwritten by a second campaign. The existing unconditional artifact upload
and job timeout are unchanged.

No optional 1 MiB control, automatic
retry or adaptive extension is added. Failed diagnostics block full profiles on
that dispatch. The runner retains original/partial client stdout as
`diagnostics/<arm>_5242880_client.raw.json` and exit status before writing any
error placeholder or metadata; stderr, each sample, runtime config, process
usage, image identity, gateway/backend logs, and the diagnostic report are all
retained in `h1-profile-evidence/diagnostic/`. Upload remains unconditional,
14 days, in `h1-internal-profile-<sha>-<payloads>`. The three-arm report includes
missing/failed arms and always sets `comparison_eligible=false`.

Admission requires the schema-2 manifest and each sample's exact 30-second,
5 MiB, 50-worker, host, pair, arm and order identity. Legacy/aggregate samples
and copied arms fail. Both gateway arms must carry the same immutable
**observer-OFF** image and revision, equal retained config/environment hashes
apart from the declared cutoff, distinct owned container/process lifetimes and
complete process capture. Client diagnostic PID, self-measured resource PID and
passive-reader lifetime must agree. The versioned Rust diagnostic schema is
checked field by field, including all five loss counters, unique worker/request/
connection IDs, typed request state/timestamps, final worker lifecycles,
connection ownership, ordered snapshots ending in `driver_retirement_finished`,
and complete driver retirement accounting. No missing field is supplied a
successful default. These joins validate retained evidence, not cryptographic
provenance. All three rows and available partial evidence survive rejection.

The review repairs add producer-to-consumer hosted regressions: real Rust plain
and TLS H1 reports cross the Python typed validator (clean and failed responses),
the actual runtime capture and sample-stamping paths feed diagnostic reports,
and the real supervisor terminates TERM-resistant child sessions with nested
process groups under short test deadlines. Docker/expensive campaign dispatches
are substituted in those supervisor tests; they do not validate live Docker
cleanup or the 5 MiB workload. The existing discovery gates select these tests
without workflow dispatch or command-policy changes. All new Python process
calls use literal executable/script argument lists; variable paths, deadlines
and owned identities are data in the environment. The immutable-base CI policy
checker remains the hosted authority and was not executed or weakened locally.

Manual run **35419342312** is pinned to old head
`ac7ff645f766597b9e4f38aa9e18272c0b3c249d`. It remains raw prior-revision evidence
and does not validate these repairs. New hosted formatting, lint, compilation,
regressions and any root-owned manual slice must use the repair revision. No
passing result, 5 MiB stall repair, performance gain or issue closure is asserted.

Hosted registration: `metrics_tests::h1_diagnostic_tests` exercises actual plain
and rustls H1 worker paths, opt-in/off useful-work parity, clean responses,
length/chunk truncation, malformed headers, the unchanged delayed warmup and
30-second pre-abort hooks, cancellation-preserved counters, capacity/stale-update
loss and separately timed driver cancellation. It is selected explicitly in the
existing H1 checks job and included by the existing Benchmark Harness Tests
`metrics_tests` target. Python selection/report/registration regressions run in
both existing Python discovery gates. All cadence and supported-trailer gates
remain registered unchanged. These are registrations only: no repository code,
formatter, linter, test, build or benchmark was executed locally.

## Live cadence and safety gate

`tests/functional/h1_cadence_tests.rs` is registered in the functional binary on
Linux and explicitly selected by the dedicated `cadence` job. The existing
`functional_streaming` filter does not select it. Each observer-off/on matrix
job compiles and lints the functional target, builds and copies its external
binary, pins `FERRUM_EDGE_TEST_BIN`, and retains the revision, binary SHA-256,
test output and failures in `h1-cadence-{off,on}-<sha>` artifacts. No implicit
harness rebuild is allowed. Measurement now depends on both cadence jobs as
well as the existing checks. PR events run these gates without measurements;
manual dispatch uses the inputs and command above. Full calibration/measurement
requires `diagnostic_only=false` and a successful diagnostic slice. These are hosted registrations;
no passing execution is claimed by this implementation.

Each of five tests runs cutoffs **0 and 1**, with cleartext H1 on both hops and
with **verified TLS on both hops**. The TLS backend uses the existing `TestCa`
and scripted `TlsConfig` with H1-only ALPN; the client trusts only that CA.
Leased sockets and `TestGateway` supply listener ownership, child-authenticated
readiness and cleanup. The existing scripted steps have no release barrier, so
this module owns a small channel-driven script without changing shared runners.

| Contract | Observable assertion |
| --- | --- |
| Tiny/delayed ordinary DATA and mixed tiny/256 KiB/tiny body | Exact ordered bytes for every released marker before the next release; first DATA and complete-marker arrival recorded |
| One tiny frame followed by idle | Complete DATA arrives with backend EOF still withheld; no extra bytes or terminal event during the idle gate |
| Declared-length and chunked truncation | After observed prefix, clean transport shutdown with incomplete HTTP framing causes a body error; clean EOF and client timeout cannot pass |
| Cancellation after observed DATA | Active request count is first 1; dropping the response yields backend peer EOF/reset and a joined task within 10 seconds, followed by accounting returning to 0 within 10 seconds |
| Delayed allowed-prefix/blocked policy window | Exact allowed SSE prefix arrives first; the later lexical leakage window yields only the exact policy error event and its `[DONE]` marker, clean downstream EOF, backend cessation and accounting release |

There are 24 scenarios per observer build (truncation has two framing cases).
All release/readiness/terminal waits are bounded. A sequence-numbered backend
notification follows each flushed write, and only client-observed exact bytes
authorize the next release or EOF. A **5-second** release-to-client scheduling
tolerance covers both the write acknowledgement and complete marker; explicit
elapsed checks complement async timeouts. The **200 ms** idle dwell starts only
after readiness or observed DATA. The backend read timeout is **60 seconds**,
so it cannot satisfy the cancellation bound. These are progress guards, not
latency benchmarks. HTTP-decoded bytes may split or combine arbitrarily across
TCP reads, TLS records and DATA callbacks.

The lane checks the child executable through `/proc/<pid>/exe`, safe selected
environment values, the exact file config, the authenticated effective route,
and presence/absence of observer schema metrics (including child PID when on).
An empty settings file and cleared child environment prevent inherited config
from selecting another path. Size limiting and latency tracking are disabled.
The fixture uses one gateway runtime worker so the existing metrics publication
seam exposes positive direct/coalesced input evidence after completion; the
opposite branch must stay unused. This proves branch selection, not complete
profile accounting or coverage of multithreaded scheduling. Observer-off uses
the same pinned source/config and direct/coalescing selection predicates.

The policy case exercises `inspected_streaming_body`, which intentionally
bypasses coalescing. It reuses the existing semantic-firewall lexical leakage
policy and `on_error: warn` with a leased unavailable embedding provider for
the allowed prefix; it does not establish successful embedding-provider
inspection or ordinary-body policy semantics. The configured lexical violation
must still block the later window. No production behavior is changed.

H1 trailer preservation remains **unproven and unsupported by this adapter**:
`body.rs::{direct_streaming_body,coalescing_body}` map reqwest `bytes_stream()`
items to `Frame::data`; they cannot forward trailer frames. No H1 trailer pass
is claimed. The lane explicitly retains the existing H2/gRPC hop-by-hop trailer
filter, H2-frontend/H3-backend streaming trailer policy, and delayed-FIN trailer
forwarding cases with both builds. These supported-protocol gates remain
necessary for future shared-coalescer work; root must disposition the H1
adapter limitation separately.

## Open obligations before any optimization

With the default `trace_mode=none`, actual syscall collection is **not enabled**. AsyncWrite polls, TLS records,
logical body frames and `/proc/io` accounting are four different quantities.
Without an external trace, syscall availability and loss remain unknown. The
opt-in follow-up below registers a separately budgeted intrusive pass to establish
capabilities/permissions, PID/TID and socket/FD lifetime attribution, successful
write/writev/send* returns, lost events and measured tracing overhead. No inference
from a zero field or missing trace closes that obligation. Sampled CPU stacks and
native/hidden copy completeness also remain open.

The live cadence/safety gates above must pass on the exact reviewed head before
any later aggregation/adapter optimization. They cover only their declared
contracts, not H1 trailers, all policy modes, full native memory/copy coverage,
syscalls, sampled CPU, backpressure saturation or performance. Syscall/CPU
tracing uses the merged H3 foundation in the opt-in follow-up below; hosted
results and measurement interpretation remain outstanding.
Review allocator safety/publication, the nondefault feature's hosted results,
calibration, partial-profile residuals, all-size traffic failures and source
coverage before interpreting measurements. #5588 is not closed by instrumentation.

## Hosted syscall and CPU follow-up (issue #5588)

The authoritative historical dependency record is
`h1_profile_manifest.json` → `external_trace.dependency_provenance`; generated
capabilities and trace manifests read that same record. These are three distinct
historical checkpoints, **not** three competing definitions of the current head:

| Role | H1 | H3 |
| --- | --- | --- |
| Initial bases | `a798c0bac68151fbe860e3cb48843cbd434c0f84` | `d19abaa3c4fbb40af6136cb577a1ed7e82bf8529` |
| Integration checkpoints | `2491d44b1149bf33dece351595244351d2dbc322` | `e00f0a91cb5ae2b0686392f504471283e6f52b4c` |
| Reviewed checkpoints | `ac7ff645f766597b9e4f38aa9e18272c0b3c249d` | `45dbde8ccc9575b225890afb450579213d62cb21` |

Subsequent normal integrations are described by Git ancestry. Each capture's
runner revision and exact source/object/tool hashes identify its actual code;
the historical pairs do not claim to enumerate all integrated parents. This
follow-up adds no production
forwarding change, Cargo dependency, tuning, competitor arm, pool/UDP profiling,
frame-pointer rebuild or measurement claim. The H3 probes, fixture commands,
calibration and campaign remain separate. The H1 cadence and fixed 5 MiB drain
slice above remain required and unchanged.

Manual input `trace_mode=none|syscalls|cpu` defaults to `none`.
The campaign manifest records that selection as `h1_trace_mode`. External
calibration requires the internal observer **ON in both arms** and one immutable
image across every pair; ordinary observer calibration and observer-off drain
diagnostics retain their separate build rules.

The retained report validates every selected external capture against its own
arm/pair/payload/mode, runtime PID generation/container, binding and client
completion hashes, release ELF and required artifact hashes. It validates typed
readiness/termination/clock evidence, recomputes syscall completeness from raw
records, and reconciles CPU decoder/attribute receipts and sample counts.
Original absolute producer paths are checked for the selected pair, while reads
use the caller's retained artifact tree, allowing relocation. Missing evidence
or substitution leaves `validation_complete=false` and `capture_complete=false`;
the original failed claim remains under `producer_claim`. Live supervisor stdout
and stderr remain raw artifacts but are explicitly excluded from final hashes
because the process still writes them during handoff. `external_traces_complete`
and `trace_comparison_eligible` are separate from internal counters and from the
always-false full measurement eligibility. The report command fails when a
selected capture cannot validate. Hashes establish retained-file association,
not a signed attestation or a performance result.

`diagnostic_only=true` still stops after the existing drain slice even if a trace
mode was supplied. An intrusive campaign requires `diagnostic_only=false`, a
successful slice and explicit `syscalls` or `cpu`, plus **one payload selection**.
Run separate root-selected shards for 10240, 71680, 512000, 1048576 and 5242880;
all five are still required, with 200/200/200/100/50 workers. No worker dispatch is
authorized by this implementation. The workflow keeps internal observer off/on
calibration and cutoff comparisons, then runs external off/on calibration with
exactly the same observer-on image/config/cutoff, then a separate externally
observed cutoff 0/1 matrix. Each matrix has four counterbalanced pairs, repeated
direct controls, 15-second measurement, and unchanged warmup/drain/TLS/status,
body, timeout and retry rules. Syscalls and CPU occupy separate repetitions.
Raw overhead is retained without subtraction or historical throughput borrowing.

The `trace-fixtures` job compiles the shared C/BPF observer with warnings as
errors, compiles the optimized omitted-frame-pointer/unwind-table fixture,
checks shell/Python syntax and consumer regressions, and actually runs the
fixtures on GitHub-hosted Ubuntu. The same preflight runs again on the measurement
VM. `H3 Proof Preflight` also runs on changes to the shared observer. These are
registered gates, **not locally executed or passing results**. No trusted policy
verifier/exemption or frozen gateway benchmark workflow was edited. All commands
used by the supervisor have literal execution sites in `h1_trace_commands.sh`.
Ubuntu package versions/origins and actual tool hashes are retained; no unpinned
downloads are introduced. The installed distro perf ELF is retained separately
from the running kernel version; a mismatched/unusable tool is reported, not
assumed capable because its wrapper exists.

### Syscall contract

The shared observer's isolated `h1` mode enables only `h_*` programs/maps; H3
modes do not allocate the H1 maps. Native amd64 `raw_tp/sys_enter/sys_exit` read
actual register arguments and signed returns, admitting long-mode user CS 0x33
and rejecting compat/x32/out-of-range calls. Runtime BTF and exact ftrace function
visibility must establish `tcp_sendmsg(sock, msghdr, size_t)` and
`tcp_recvmsg(sock, msghdr, size_t, int, int*)`, both returning int. Failure is a
separate discovered/load/attach/unsupported record with errno and retained bounded
verifier diagnostics. No guessed offsets, fallback FD lookup or JIT inspection.
The ABI reference is the Linux
[TCP implementation](https://github.com/torvalds/linux/blob/v6.17/net/ipv4/tcp.c);
actual running BTF remains authoritative.

All ten read/readv/recvfrom/recvmsg/recvmmsg/write/writev/sendto/sendmsg/sendmmsg
paths keep entry attempts separate from signed outer exits. Counters separate
positive, zero, errno and kernel restart results; known offered bytes, successful
accepted bytes, shorts, TCP EOF and syscall elapsed time are distinct. A zero
read counts EOF only after actual TCP context and a known nonzero request.
`mmsg` positive returns count **messages**, with accepted bytes read only from
the returned prefix's `msg_len`. Inner TCP calls/accepted bytes/errors remain
separate: outer EFAULT can follow an inner transfer, and batch success can hide
a later failure. Accepted bytes are not peer delivery; syscall elapsed time is
not CPU time. The syscall census names sendfile/splice/vmsplice/tee/io_uring and
pread/pwrite variants without claiming their bytes.

Only length metadata is read: at most 16 iovecs per message and 16 messages per
batch. Oversize, overflow and metadata read failures remain unknown. No payload,
TLS buffer, control/credential data or raw kernel pointer is exported. Outer
flags and effective inner flags/lengths are separate. Aggregate totals are atomic;
min/max and first/last timestamps are explicitly approximate during concurrent
updates. Counter overflow/reset, pending calls, unmatched entry/exit, abandoned
calls, map exhaustion and unknown cookies remain explicit. The first 4096
syscall witnesses are diagnostic examples, not an event-complete stream.
The shared `read_failed` counter includes whole-call ownership/register failures,
so any nonzero count invalidates aggregate, measurement, offered-length and
accepted-byte completeness; surviving partial counters remain retained. Loss
counter resets also invalidate the capture. Lifecycle/witness certification
requires exactly one typed requested, bound termination, all three omission/
failure fields present and zero, matching PID generation/cgroup/netns, and no
loss capable of suppressing lifecycle records. Witness-cap exhaustion alone
still does not invalidate otherwise complete aggregate totals.

The supervisor exists before `start_ferrum`. Before any collector attach or
binding, it requires the live PID/start ticks to match the retained Docker runtime
and the full container ID to be an exact Docker cgroup path component. The same
ELF alone cannot establish ownership. It rechecks this identity immediately
before attachment, before BPF target binding, and after acknowledgement. The
loader attaches initially unbound only after that first admission, then receives
the verified PID/start ticks/cgroup/netns. The process remains ordinary
UID with zero effective/permitted/ambient capabilities. All existing threads
are inventoried, new threads use actual task generation, exec invalidates the
binding, and fork/exit events are retained. Health-check child processes, client,
backend and sampler cannot pass the TGID/generation/cgroup filter. Boot identity,
namespace inodes, selected safe runtime settings, exact config hash, image and
matching retained release ELF bind the evidence. No arbitrary environment is
copied. Startup before binding is an explicit coverage gap.

TCP INET_DIAG runs in the admitted target network namespace before tracing and refreshes
during capture; it primes the kernel cookie through the existing diag ABI/parser.
Each syscall socket join comes from its actual `tcp_sendmsg/tcp_recvmsg` context.
A zero cookie or socket created/closed between dumps stays unknown forever.
IPv4 local port 8443 and IPv4 loopback peer port 3447 define the four
frontend/upstream send/receive roles only after the exact runtime config is
verified. Other target sockets are excluded. IPv6 role attribution is not claimed.
The initial FD/inode/diag table is bracketed evidence, never an authoritative
exit-time association. Lifecycle syscall records retain dup/reuse/close intervals;
shared file tables, inherited FDs, SCM_RIGHTS, pidfd_getfd, close errors and races
leave exact alias/lifetime joins unproven. Shutdown is not destruction. TLS
handshake/control and HTTP overhead remain transport bytes, with no per-request
or exact cross-hop request join. Startup probe traffic cannot be separated into
requests by syscall metadata and is outside the measured phase.

The actual fixture exercises scalar/vector/batch APIs, partial nonblocking sends,
EAGAIN, zero reads/EOF, bad FDs, oversize/faulting metadata, partial batches and
read-only `msg_len` copyout, signal-interrupted calls, sibling threads, dup/FD
reuse, four socket roles and an excluded same-namespace process. Its receipts
are reconciled with real observed signed returns and lengths. Deliberate map
capacity, stale-generation binding, missing BTF/symbol and unprivileged attachment
cases are separate. Actual PID-number recycling, compat/IPv6, shared-file-table
and nondeterministic close-in-flight fixtures remain explicitly unexercised.
A passing fixture cannot imply all gateway APIs were observed. If attachment is
unavailable, this implementation retains an unavailable syscall capture; a stock
perf syscall fallback is not enabled or spliced onto a different repetition.

### CPU capture and bounds

The CPU lane records actual `cpu-clock:uS` software samples (`S` retains sample-read enabled/running time) at fixed 99 Hz with
`--clockid mono --call-graph dwarf,8192`, bounded mmap pages, target PID/all threads
and inherited future tasks. It requires an actual perf enable/control receipt
before client setup. Hardware cycles and kernel stacks are not selected.
Raw perf.data, build IDs, header attributes, task/MMAP records, decoder exit
status, loss/throttle records, per-TID samples, depth distribution, unresolved
samples and folded/decoded call chains are retained. Matching mapped ELF/DSOs
come from the target mount namespace while alive, never substituted host libc.
The gateway's retained ELF must match exactly one symbolized release twin.
Only this disposable synthetic benchmark process's user stack memory may enter
perf.data. Matching DSO packages are retained under `builds/<twin>/symfs`, with
a separate 512 MiB ceiling that includes existing partial files and metadata
reservations; repeat artifacts reference that package. Acquisition pins the
admitted target's root directory, walks every subsequent source component without
following symlinks, and requires a regular file with the `/proc/<pid>/maps`
device/inode. One pinned readable descriptor supplies ELF magic, bounded copy,
and SHA-256. Destination traversal also uses pinned directories and refuses
symlinks, hard-linked files and nonregular files. Reuse compares bounded bytes
against the pinned source; readelf receives the retained descriptor itself. Each
repeat keeps a distinct metadata output/receipt, including failed decoders.

The byte budget and 30-second deadline are checked throughout acquisition,
including between reads/writes; a growing source is rejected before its newly
read bytes are written, and no read extends beyond its admitted initial size.
Existing partial files remain charged to the package. Replaced, changed,
symlinked, deleted, anonymous or otherwise unsupported mappings retain explicit
errors and any safe partial ELF diagnostics. No host-library substitution or
broader file access is enabled. Decoder output has the existing combined output
cap checked again after every reap, including already-exited children, and a
matching per-file child limit. Partial CPU capture remains distinct from full
symbol/CFI coverage and complete unwinding.

Attribute verification reads the retained, hash-matched `perf evlist -v` output
within the existing 2 MiB metadata cap (at most 32 lines, 16 KiB per line).
It binds fields to exactly one `cpu-clock:uS` event; the separate `dummy:u`
metadata event or any unrelated event cannot supply missing requirements.
The actual `{ sample_period, sample_freq }: 99` union is interpreted as 99 Hz
only with `freq: 1`. Numeric software type 1/config 0, inheritance, kernel
exclusion, `use_clockid: 1`/monotonic clock ID 1, an 8192-byte user stack dump,
nonzero user register mask, and exact sample/read-format bits are verified on
that same event. Missing, malformed, duplicate, ambiguous or wrong-valued fields
fail with specific reasons in `attribute_validation` and the CPU issues list.
The original attributes and command status remain retained on failure. The
consumer fixture retains the verbatim two-event output from hosted run
`35422193763` (artifact `10577439767`); regressions mutate it to exercise missing
fields, wrong events, period mode, wrong values and cross-event borrowing.
Attribute verification alone establishes neither successful capture nor complete
unwinding; all sample, ownership, loss, symbol/CFI and nested-chain checks remain.

The optimized CPU fixture contains noinline nested functions, sibling threads,
a post-attach child and a separate busy control. The gate requires actual samples,
thread/child coverage and **one admitted leaf-to-caller callchain containing
`fixture_leaf`, then `fixture_middle`, then `fixture_outer`**. The preflight and
consumer regressions call the same nested-proof helper. Three unrelated flat
samples or a reversed chain fail; compiler clone/offset suffixes and intervening
inline/unknown frames are allowed. Whole matching chains, PID/TID, sample times
and matched frame indices remain in `nested_proof.witnesses`; unknown frames and
unresolved sample counts are not erased by a successful nested witness. Symbol
names pooled across samples or a PMU count alone cannot pass. Corrupt perf data
and an actual 64 KiB negative capture cap test decoder/capture failure.
Kernel/permission/tool failures retain
explicit unsupported status. Optimized-away/tail/inlined/async frames, incomplete
CFI, unresolved symbols and an 8192-byte stack truncation fraction that cannot be
proved stay unknown. Useful multi-frame hotspots do not establish complete stacks,
full native allocation/copy coverage or a fully profiled comparison.

Each preflight case prints at most 4 KiB of verdict/error details and bounded,
address-scrubbed stderr tails; `preflight.json` and each case's raw reports remain
the complete evidence. Failed capability collection also writes a failed report.
After collectors are reaped, their owned perf control/ack FIFOs are removed.
Producer exit and an always-run workflow fallback hand only the declared trace
trees to the ordinary sudo caller for upload, adding owner read/traversal access
without widening group/other permissions. Regular raw data, including failed or
capped `perf.data` and regular control receipts, is preserved byte for byte;
verifier stderr retains its existing address redaction. The handoff does not
follow symlinks or alter hard-linked files and fails on unexpected file types.
Upload still runs after a failed fixture or handoff; no retention step changes
the fixture verdict, capture limits, or measurement eligibility.

One capture lasts at most 300 seconds through client setup/warmup/measurement,
request drain and gateway removal, with 64 map/metadata snapshots. The existing
32 MiB observer admission includes an 8 MiB conservative H1 map reservation plus
observer RSS (CPU uses the same total RSS ceiling); per-repeat peak CPU/RSS and
sample failures are retained. H1 capacities are 8192 aggregate rows, 512 pending
calls, 512 process-total slots, 1024 census slots, a 512 KiB ring, 4096 syscall
witnesses and 8192 userspace lifecycle/witness rows. Fixed non-LRU maps never
silently evict evidence. Ring loss/witness omission and aggregate loss are separate.
Raw perf has a hard 64 MiB RLIMIT_FSIZE per repeat, and total trace artifacts have
128 MiB job-wide admission including previous failed repeats and preflight,
excluding retained build/debug/DSO packages. A 32 MiB reservation covers bounded
decoding/final records. Exhaustion can leave later matrix entries missing; no
full campaign is claimed or automatically retried at a lower sampling rate. Deadline/cap exits
stop/reap owned children and mark capture incomplete. Parent-death signals close
observer/perf children; bounded decoder teardown does not extend measured work.
No gateway runs privileged and no host perf/security sysctl is changed.

### Workload completion and collector teardown

The runner retains raw client stdout/exit and stamps the sample before requesting
teardown, after the synchronous client has returned. H1 emits its phase report
only after `Phases::finish` has joined all request workers. The supervisor rejects
nonzero exit, absent/malformed/changed results, incomplete or timed-out drain,
stalled workers, stale capture/session/binding/target evidence, and a measurement
that is not inside this capture's host clock bracket. Error-free useful work is
still assessed independently; a teardown receipt cannot turn failed requests
into useful throughput. Request drain is not a claim that every idle gateway
socket or transport has closed.

The supervisor rechecks the live target generation and live collectors **before**
publishing `teardown-ready.json`. The receipt retains the request, result hashes,
binding hash, identity, host clocks and collector observations. The runner waits
for that receipt before its existing owned `docker rm -f`, then signals `stop`.
The acknowledgement wait uses the existing 30-second readiness budget capped by
the original 300-second capture deadline. Failed startup/abort cleanup has no
verified transition and remains incomplete. Client work, request timeouts, drain,
retries, sample cadence and measured RPS are unchanged; this wait is postwork.

This ordering addresses perf's normal target-exit behavior. Linux
[`is_event_hup`/`perf_poll`](https://github.com/torvalds/linux/blob/v6.8/kernel/events/core.c#L5297)
reports hangup after an event has exited and its inherited child events are gone.
The [`perf record` drain loop](https://github.com/torvalds/linux/blob/v6.8/tools/perf/builtin-record.c#L2535)
drains and ends after its event descriptors disappear. The previous runner
removed the gateway before touching `stop`, while the 50 ms supervisor loop
rejected any intervening collector exit. Thus a normal target teardown could be
misclassified as premature loss. These upstream sources explain the race; actual
hosted kernel/tool versions and fixture results remain authoritative.

Capture stays enabled through removal where possible. Only perf's zero exit
after an acknowledged transition and observed target exit is permitted; exit
while the target is still live, pre-acknowledgement loss, early target death,
nonzero/forced exit, syscall observer exit, missing/partial decoder output,
loss/attribute failures and failed evidence reads remain incomplete. A stop
marker alone cannot authorize closure. Final client evidence is checked again.
Collector last-live/first-exited host clock bounds and reap clocks are retained
separately from supervisor/decoder end. Coverage uses the conservative last-live
bound. Exact exit time and full gateway-removal coverage are **not** certified;
post-target-exit samples are not promised, and unwind gaps remain separate.

The hosted CPU fixture now joins its worker threads/child, emits and retains a
`workload_done` receipt, and waits for the same live transition helper before
exiting. The supervisor observes real perf autoexit without first signaling it,
under a bounded fixture deadline. This proves only synthetic fixture behavior,
not gateway drain or RPS. Mocked consumer regressions exercise the real runner
request and supervisor acknowledgement, stale/missing/partial evidence, bad event
ordering, and the target-exit/resource-read race. These new checks have not been
executed locally; hosted results must be inspected before calling the repair
verified.

H1 teardown and trace event placement admit explicit `clock_receipt` records
from readiness, the runner and the supervisor. Each carries the producer's boot
ID, time namespace and paired realtime/CLOCK_MONOTONIC reads. Admission requires
the owned target's boot/namespace, bounded read uncertainty, monotonic ordering,
actual measurement start/end brackets, and realtime agreement with the client
phase report (1 ms read uncertainty plus 1000 ppm slew). These receipts certify
clock bounds only: the H3 passive resource consumer still requires whole read
intervals and rejects clock-only rows. `process_usage.py` also retains paired
realtime/monotonic brackets. No client process-local Instant epoch is compared
with kernel ktime. Capture
starts before client invocation and remains enabled during gateway removal;
measurement coverage requires actual bracketing observations and the conservative
collector end bound. Exact absolute warmup/drain boundaries
are an explicit gap in the existing phase report; cumulative snapshots are not
instantaneous phase counts. A capture cap can never imply full measurement.

Each `pairs/pair_NNN/traces/<arm>_<payload>/` directory retains capabilities,
identity, initial/periodic TCP inventories, readiness/termination, raw syscall
snapshots/lifetimes or raw perf/decoded stacks, build mapping inventory and
`trace-manifest.json`. Failed raw client stdout/exit, including 5 MiB failures,
remain alongside it. The report separates useful-work, internal-profile, syscall,
socket/lifetime, CPU-sample and unwind validity. `internal_comparison_eligible`
requires valid traffic, complete internal profiles and complete runtime pairing;
`fully_measured_comparison_eligible` remains false with missing dimensions. Root must review actual hosted compiler,
fixture and capture evidence before any interpretation; #5588 remains open.
