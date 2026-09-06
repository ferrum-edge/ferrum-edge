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

## First hosted scheduling result

Run [34054416834](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34054416834)
used source `8fdabdaeca9764a9e0ffc2e76b98c01521654c77` and empty compiled-artifact
state. Both lanes passed all 18,240 external unit tests and the same required
inline, hardening, kTLS and ACME proofs. Later workflow edits only make the
sccache stop command explicit for policy inspection; this run's provenance is
retained separately from final-head validation.

| Measurement | 3 Cargo jobs | 1 Cargo job |
| --- | ---: | ---: |
| Cold default compile | 1,183.75s | 1,636.15s |
| Cold ACME compile | 760.92s | 1,011.06s |
| Required readiness after setup | 2,477s | 3,189s |
| Full experiment job | 42m10s | 54m09s |
| Same-workspace default repeat | 0.49s | 0.51s |
| Same-workspace ACME repeat | 0.43s | 0.47s |
| Default maximum-child RSS, KiB | 10,785,872 | 14,939,960 |
| ACME maximum-child RSS, KiB | 12,899,912 | 14,739,016 |
| Default sampled concurrent RSS, KiB | 15,492,060 | 14,882,768 |
| ACME sampled concurrent RSS, KiB | 15,461,896 | 14,545,976 |
| Default sampled concurrent swap, KiB | 9,160,224 | 793,584 |
| ACME sampled concurrent swap, KiB | 8,089,288 | 928,508 |
| Default major faults | 3,048,042 | 61,470 |
| ACME major faults | 1,187,567 | 71,798 |
| Default runner swap in/out, GiB | 26.10 / 28.40 | 0.33 / 1.26 |
| ACME runner swap in/out, GiB | 11.98 / 15.59 | 0.37 / 1.04 |

One job sharply reduced paging but delayed required readiness by 712 seconds
(28.7%). Full standard-runner consumption was 42.17 versus 54.15 runner-minutes,
including setup, the extra reuse measurements, upload and cleanup. This is not
an estimate of recurring billing. Higher individual resident peaks in the
one-job lane do not imply more total allocation: competing compiler pages can
be swapped out in the three-job lane. Keep three jobs in ordinary CI. The next
footprint investigation should examine compilation-unit boundaries while
preserving the complete test inventory; execution-only sharding would retain
the expensive compilation. Issue #4704 remains open.

## Reuse the library in the gateway executable

Cargo builds the gateway binary when compiling integration targets. The initial
three-job measurement spent 533.04s in that binary target after separately
compiling the normal library and library test harness; the binary finished
last. Its module declarations duplicated the library's gateway source tree.

The executable now retains the same non-Windows jemalloc declaration and calls
`ferrum_edge::run_gateway_cli()` under its explicit unsafe process-start contract.
The caller must enter once before concurrent environment access or application
thread startup, preserving the original environment-mutation precondition.
Startup bodies live in `src/gateway_entry.rs`,
included at the library root to preserve existing crate-relative paths and
implicit tracing targets. The version constant remains the library's existing
Cargo-derived constant. No startup ordering, error handling, secret resolution,
crypto initialization, runtime sizing, shutdown logic or test selections change.
CI relevance rules and source-contract assertions follow the startup file.

Hosted cold/warm default and ACME timings, memory/paging and complete test
readiness must be measured before claiming a reduction. Production optimization
profiles are unchanged; binary layout and link work can change when the same
implementation is linked through its library, so image/runtime checks remain
required.
