# HTTP/2 and gRPC CPU profiles

The manual **H2 and gRPC CPU Profile** workflow investigates #6147 and #6148 on a
GitHub-hosted Linux x86-64 runner. Select `http2` or `grpcs`, and 10 KiB or 70 KiB.
Each dispatch builds the selected revision with the production release optimizer,
DWARF symbols and no stripping. It retains the source, compiler, executable hash,
build ID, image identity, kernel and CPU model.

The campaign runs four separately retained passes on one VM:

1. An unprofiled control.
2. All-thread scheduler counters, without external CPU sampling.
3. Scheduler counters and user-space CPU stacks.
4. Another unprofiled control.

Every pass uses two counterbalanced pairs of direct, Ferrum and Envoy arms, with
15-second measurement windows, concurrency 200 and fresh backends. Windows,
connection counts and protocol fixtures retain the ordinary benchmark defaults.
All campaign containers use UID/GID 65532 and drop every capability, including in
the controls. No production proxy setting or normal benchmark arm changes.

The CPU pass shares the H1 collector's container/PID-generation admission,
99 Hz software `cpu-clock:uS` event, 8 KiB DWARF stack capture, measurement clock
bracketing, client-drain handshake, collector lifetime checks, raw artifact caps
and actual mapped-ELF retention. Only the fixed H2/gRPC workload admission is new.
Ferrum must match the retained symbolized binary. Envoy's actual mapped ELF and
build IDs are retained; stripped or unresolved frames stay explicit in coverage.
The collector does not sample the whole host or collect kernel stacks.

`process_usage.measurement` adds `user_cpu_seconds` and `system_cpu_seconds` from
Linux `/proc/PID/stat`. With scheduler sampling enabled, gateway/backend
`context_switches` contains `voluntary_ctxt_switches` and
`nonvoluntary_ctxt_switches`, summed across **all process threads**. The client
records these counters and the user/kernel split with its existing `getrusage`
measurement-boundary snapshots. A missing thread sample, generation change,
thread-set change or decreasing counter makes the scheduler delta unavailable.
The sampler never substitutes zero for an incomplete observation. Raw thread
snapshots remain in the retained process timeline.

The workflow writes `h2-cpu-report.json`, per-pair raw JSON, process timelines,
trace manifests, `cpu-coverage.json`, `stacks.txt`, `stacks.folded`, bounded
`perf.data`, ELF/build-ID evidence and the preflight results. Failures and
unsupported collectors are uploaded too. The report checks all 24 observations
and reports profile overhead relative to the bracketing controls. A control RPS
drift over 5% marks that comparison unsuitable. Two pairs on shared hardware are
diagnostic evidence; they do not establish a throughput improvement.

Every pass is explicitly marked `h2_cpu_profile.diagnostic_only`, and ordinary
scoreboards reject these samples. CPU capture completeness and stack-resolution
coverage are separate: optimized-away/async frames and partial unwinds cannot be
called complete profiles. User/kernel CPU and context-switch deltas can indicate
where to investigate parked workers or kernel overhead; stack samples alone do
not prove the cause of an idle interval.

All execution and validation run in hosted CI. The workflow is manual and has no
publication credentials, repository write permission, or scheduled measurement.
