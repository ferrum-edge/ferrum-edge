# Hosted unit compilation diagnostics

Each CI Unit Tests shard retains `unit-compile-diagnostics-SHARD-RUN_ID-ATTEMPT`,
and the ACME Feature Tests job retains `acme-compile-diagnostics-RUN_ID-ATTEMPT`.
Both are kept for seven days and are uploaded on failure too, as long as the
runner can still upload artifacts. A lost runner may prevent both upload and
final log delivery. No local execution is needed to inspect these files.

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
  for each of the eight required phases. Maximum child RSS is distinct from
  simultaneous RSS. The timed Cargo interval excludes sampler cleanup/upload.
- The sampler exits on its shell's termination or after two hours, and ordinary
  successful compilation explicitly stops and joins it. Cargo and log-pipeline
  failures remain fatal; telemetry does not turn a failed compile green.

Compare default and ACME target costs with the setup-rust-ci restore log, cache
key, commit, runner type, and full job duration recorded. Warm cache is not the
same as an unchanged workspace target. Preserve test counts and named optional
feature/live proofs when evaluating a scheduling or harness-layout experiment.
The instrumentation itself leaves compiler concurrency, debug/codegen profiles,
production profiles, and test selections unchanged. Issue #4704 was closed on
2026-09-06.

The application shard can also report bounded diagnostics for an unexpected
HTTP/2 preface in a scripted backend (issue #4720). The observer forwards the
existing I/O operations, stores at most 24 prefix bytes, and reports only a
protocol category, byte count, loopback peer, backend port, and connection index
on protocol-handshake errors. It never logs those bytes or relaxes the fixture's
error assertion. This captures evidence for an intermittent fixture failure
(issue #4720, closed on 2026-09-09); it is not a claim that the sending path has
been repaired.

## Reuse the library in the gateway executable

Cargo builds the gateway binary when compiling integration targets. The initial
three-job measurement spent 533.04s in that binary target after separately
compiling the normal library and library test harness; the binary finished
last. Its module declarations duplicated the library's gateway source tree.

The executable retains the same non-Windows jemalloc declaration and imports
its gateway modules from the library with `use ferrum_edge::*`. Startup bodies
remain in `src/gateway_entry.rs`, included at the binary root; they are not
included by the library. This keeps the shared gateway modules compiled once
per profile/feature set while library consumers, including the isolated fuzz
workspace, do not compile the executable's CLI/runtime/mode-dispatch pipeline.
There is no fuzz-only configuration branch and no change to fuzz targets,
features, instrumentation or execution bounds.

The initial extraction in #4727 also put startup in the library. Its hidden
`ferrum_edge::run_gateway_cli()` entry has been replaced by the binary's private
entry function, retaining the same unsafe process-start contract. Startup still
runs once before concurrent environment access or application thread startup.
Two narrow hidden startup adapters retain the private configuration seams:
`startup::publish_gateway_stream_settings(&EnvConfig)` publishes the accepted
stream settings, and `startup::initialize_gateway_buffer_budgets(&EnvConfig)`
publishes the three process-buffer budgets. Both retain the same accepted
fields, ordering and startup positions, before listeners or request processing
begin. Configuration parsing and validation stay pure. The buffer budgets keep
their existing first-initialization-wins and restart-to-change semantics.

Both crate roots have the `ferrum_edge` tracing target, and crate-relative paths
in startup resolve to the imported library modules. The version remains the
library's Cargo-derived constant. Startup ordering, error handling, secret
resolution, crypto initialization, runtime sizing, shutdown logic and test
selections are unchanged. CI relevance rules and source-contract assertions
continue to follow `src/gateway_entry.rs`. All fuzz targets still
exercise the same library APIs. Their previous successful cold measurements
predate the initial startup extraction and are not a controlled comparison with
the enlarged library; new hosted evidence is required for this separation.

Hosted cold/warm default and ACME timings, memory/paging and complete test
readiness must be measured before claiming a reduction. Production optimization
profiles are unchanged; binary layout and link work can change when the same
implementation is linked through its library, so image/runtime checks remain
required.
