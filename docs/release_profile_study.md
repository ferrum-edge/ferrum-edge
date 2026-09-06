# Release profile study

Issue #4674 remains open. No shipping profile or publication path changes in
this experiment. Dispatch **Release Profile Study** with all protocols and three iterations to compare
fat LTO / one codegen unit with thin LTO / sixteen codegen units on the same
source revision. Each uses a standard Linux runner, an empty Cargo target,
disabled compiler caching, the release profile's other settings and the
`cloud-secrets` feature. Downloaded dependency sources may be reused.

Both builds finish before their protocol measurements. Benchmark tools use the
same unmodified release profile in both lanes. Results retain gateway Cargo
timings, wall time, maximum-child RSS, page faults, runner-wide vmstat samples,
source/toolchain/CPU provenance, executable size/hash/version and raw protocol
results for seven days. The first vmstat row covers time since boot; subsequent
rows cover five-second intervals. Cargo timings attribute compilation units,
not every rustc frontend, LLVM and linker subphase. Separate runner instances
can differ in noise; comparisons are descriptive and need confirmation before
adopting a tradeoff.

This native Linux study is not the pinned GNU sysroot release producer and
cannot establish the shipping ABI floor. Its binaries are used only inside the
benchmark job, are not uploaded as release binaries, and are not published as
images or release assets. Artifact names distinguish both lanes. A successful
workflow is evidence collection, not approval to change optimization settings.

Before adoption, agree an explicit tolerated p99/throughput regression budget,
confirm useful protocol results with no missing/error-only samples, and extend
measurements to the affected macOS, Windows and protected ARM64/sysroot
producers. Existing exact-SHA publication gates, Cross isolation, FIPS boundaries
and install/image/ABI checks remain prerequisites for any shipping change.

## Initial hosted measurements

Run [34055184720](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34055184720)
used `d5a92bb1df1dc292b82fed46f414959486d9a716` and Rust 1.98.1. Both workflow
lanes completed. These measurements predate the separate workflow layout but
use the same compilation settings and protocol harness.

| Measurement | Fat LTO / 1 codegen unit | Thin LTO / 16 codegen units |
| --- | ---: | ---: |
| CPU | Xeon Platinum 8370C | Xeon Platinum 8573C |
| Exposed vCPUs | 4 | 4 |
| Empty-target gateway compilation | 2,600.20s | 1,265.21s |
| Maximum-child RSS | 13,768,744 KiB | 12,932,248 KiB |
| Major faults | 8,374 | 7,965 |
| Executable size | 92,918,592 bytes | 112,983,168 bytes |

All three iterations in each lane produced 20 positive-throughput records,
covering gateway and direct controls for ten protocols. Thin had no reported
errors. Fat's second direct-backend TCP+TLS sample reported 14 errors; its
remaining samples, including the gateway samples, reported none. A green job
alone therefore does not establish an error-free benchmark.

The CPU-model mismatch confounds both compilation and protocol comparisons;
raw throughput differences cannot be attributed to LTO/codegen settings. The
observed thin executable is 21.6% larger. These are preliminary measurements,
not evidence for shipping adoption. A follow-up must compare both produced
binaries on the same host with interleaved repetitions, require complete valid
samples, and retain the previously listed platform/ABI and agreed-budget gates.
