# Hosted unit compilation diagnostics

The CI Unit Tests job retains `unit-compile-diagnostics-RUN_ID-ATTEMPT` for seven
days, including on failure when the runner can still upload artifacts. A lost
runner may prevent both upload and final log delivery. No local execution is
needed to inspect these files.

Each default and ACME precompile produces a Cargo `--timings` HTML report and a
five-second procfs sample stream. Cargo reports individual compilation units,
their dependencies, concurrency, and code-generation time where available; it
does not expose every internal rustc or linker phase. See [Cargo's timing
reference](https://doc.rust-lang.org/cargo/reference/timings.html).

The JSONL samples include recognized compiler, linker, Cargo, and sccache
processes across the hosted runner, including rustc children reparented to an
sccache server. A process is identified by PID and start ticks, with a validated
crate name and test-harness flag for rustc. Command lines, environment values,
and filesystem paths are not recorded by the sampler.

Interpret the measurements carefully:

- RSS and swap totals are simultaneous samples across recognized processes.
  Shared pages can be counted more than once. A five-second interval can miss
  short-lived processes and peaks, so these are sampled observations rather
  than a complete physical-memory accounting.
- Per-process minor/major faults and CPU ticks are cumulative for that process.
  Compare successive samples with the same PID and start ticks. Processes lost
  between procfs reads are counted separately; they are not reported as zero
  activity. Tick frequency and page size accompany the observations.
- `runner_pswpin_pages` and `runner_pswpout_pages` are runner-wide cumulative
  paging counters. Their change over a phase measures runner paging, not just
  one compiler. Available memory and free swap are also runner-wide.
- GNU time supplies wall time, maximum child RSS, and child major/minor faults
  for each of the seven required phases. Maximum child RSS is distinct from
  simultaneous RSS. The timed Cargo interval excludes sampler cleanup/upload.
- The sampler exits on its shell's termination or after two hours, and ordinary
  successful compilation explicitly stops and joins it. Cargo and log-pipeline
  failures remain fatal; telemetry does not turn a failed compile green.

Compare default and ACME target costs with the setup-rust-ci restore log, cache
key, commit, runner type, and full job duration recorded. Warm cache is not the
same as an unchanged workspace target. Preserve test counts and named optional
feature/live proofs when evaluating a scheduling or harness-layout experiment.
The instrumentation itself leaves compiler concurrency, debug/codegen profiles,
production profiles, and test selections unchanged. Issue #4704 remains open
until measured changes reduce the footprint and complete hosted validation.

The application shard can also report bounded diagnostics for an unexpected
HTTP/2 preface in a scripted backend (issue #4720). The observer forwards the
existing I/O operations, stores at most 24 prefix bytes, and reports only a
protocol category, byte count, loopback peer, backend port, and connection index
on protocol-handshake errors. It never logs those bytes or relaxes the fixture's
error assertion. This captures evidence for an unresolved intermittent fixture
failure; it is not a claim that the sending path has been repaired.


## Scheduling comparison

Dispatch **Resources Scale Benchmark** with `benchmark=unit-compile` to compare
one and three Cargo jobs on the same source revision. Each standard Ubuntu
runner starts with empty Cargo target and local sccache directories after setup;
downloaded dependency sources may be reused. The normal unit suite's default,
hardening, kTLS and ACME selections and log verifiers run before readiness is
recorded. Production profiles and ordinary CI scheduling remain unchanged.

Each matrix lane then repeats default and ACME precompilation with its existing
workspace artifacts. This measures same-workspace reuse after feature switching,
not a restored Actions cache on another runner. Both cold and warm Cargo reports,
procfs samples, GNU time logs, test proofs, source/toolchain provenance and readiness
start/end timestamps are retained for seven days. Full job duration adds setup,
artifact transfer and cleanup costs. The two runner instances can differ in noise;
one observation is descriptive and does not establish a robust performance bound.
The matrix remains fail-fast disabled so either result survives the other failure.
Do not adopt a lower job count solely from maximum-child RSS: compare concurrent
samples, paging, cold readiness, warm reuse and total standard-runner minutes.
