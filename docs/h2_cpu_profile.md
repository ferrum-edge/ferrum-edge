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

Envoy's release image ships a stripped executable, so almost none of its own
frames have function names. After capture, the job symbolizes each Envoy CPU capture
offline. It fetches one layer of `envoyproxy/envoy:debug-v1.39.1` by
its pinned content digest. That layer holds `/usr/local/bin/envoy` with
`.symtab` and the **same GNU build ID** as the measured `v1.39.1` binary.

The profiler checks:

- the layer member's pinned SHA-256, size and build ID;
- the capture's recorded build ID;
- the retained release ELF and every retained DSO hash;
- that `perf.data`, `stacks.txt`, `perf-buildids.txt` and
  `build-mappings.json` match their trace-manifest receipts.

It then re-decodes a copy of the unchanged `perf.data` through the same bounded
decoder. Only the `perf script` call gets wider offline bounds (600 seconds,
64 MiB); the other decoder calls keep their 30-second bounds. In the overlay
`--symfs`, only the executable is swapped for its debug twin.

The re-decode must reproduce every sample and every unwound PC of the original
decode, so only names may change. A capture is reported as unmatched if:

- the twin's extra sections changed unwinding;
- the original decode was incomplete;
- the measurement window has no Envoy executable leaves;
- some Envoy executable leaves were unresolved and the twin resolved no more of
  them.

The same overlay then decodes each sample's sampled PC with `perf script -G`,
which skips DWARF unwinding. That names the leaf of samples whose unwind kept
no frame. This flat decode has the same 600-second, 64 MiB bounds. It must
reproduce every original sample (PID, TID and time), with exactly one PC each.
Where the original decode unwound a sample, that sample's PC must equal its
unwound leaf, and a leaf the symbolized decode named must stay named.
Otherwise the capture is unmatched and gets no flat summary. A flat leaf is
self time only; it has no callers.

Each capture that reaches the publish step gains `envoy-symbols/`; every other
capture appears only in `envoy-symbols.json`. The directory holds folded stacks,
decoder coverage, the flat decode (`flat.txt`), the stack and flat decoders'
stderr and status, and a summary. It is published whole and never overwritten. The summary
gives measurement-window leaf coverage before and after symbols, and the top
leaf functions with their DSOs. `flat` gives the same summary for every sampled
PC; `flat_no_unwound_frame` restricts it to samples whose unwind kept no frame.
The run also writes `envoy-symbols.json` after every capture, which
`h2-cpu-report.json` includes. Only the closing write, with a row for every
capture, can be complete. A decoder that outlives its post-kill reap bound
stops the pass.

The 881 MB debug executable is never added to the artifact. A missing or
mismatched symbol twin fails that step but leaves the capture evidence and
calibration unchanged.

Symbols do not fix Envoy's unwinding. In retained run 40999505084, matching
symbols named the existing Envoy leaves but did not repair the missing unwinds
([dated counts](benchmark_h2_cpu_profile_envoy_unwind_2026_10_30.md)). Comparing
functions for those samples requires their sampled PCs even when DWARF
unwinding fails, which the flat decode above now supplies.

The flat decode closes that gap. In hosted run 41136450150 (HTTP/2, 10 KiB), both
Envoy captures passed the flat checks of that revision, and their retained data
also satisfy the later named-leaf check. Flat leaves named 91.8% and 92.0% of
window samples, against 2.9% and 19.8% from the symbolized stacks. Of the
1,861 and 1,596 window samples that kept no unwound frame, 1,838 and 1,570 had
their sampled PC in the Envoy executable; the other 23 and 26 were in
`[vdso]`. Those executable PCs spread across Envoy's functions much like all of
its samples do, so the unwind failure is not confined to a few functions. The
remaining unnamed leaves are libc and `[vdso]` addresses. Envoy's self time is broad: no function exceeds 4% of
window samples, and AES-GCM, tcmalloc and nghttp2 lead.

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
