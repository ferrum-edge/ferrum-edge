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

## Reuse the library in the gateway executable

Cargo builds the gateway binary when compiling integration targets. The initial
three-job measurement spent 533.04s in that binary target after separately
compiling the normal library and library test harness; the binary finished
last. Its module declarations duplicated the library's gateway source tree.

The executable now retains the same non-Windows jemalloc declaration and calls
`ferrum_edge::run_gateway_cli()` under its explicit unsafe process-start contract.
The caller must enter once before concurrent environment access or application
thread startup, preserving the original environment-mutation precondition. Startup bodies live in `src/gateway_entry.rs`,
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
