# Release profile study

Issue #4674 remains open. Dispatch **Release Profile Study** to build fat LTO /
one codegen unit and thin LTO / sixteen codegen units on one standard Linux
runner. Both use the same revision, toolchain, native dependencies, other
release settings and `cloud-secrets` feature. Each compilation starts with an
empty Cargo target and disabled compiler caching. Downloaded crate sources and
OS file caches can benefit the second build: the fixed fat-then-thin compile
order is recorded, and compile-time differences remain descriptive.

Both binaries finish before benchmarking. Common benchmark tools use the
unmodified release profile. The existing full ten-protocol harness runs three
pairs in fat/thin, thin/fat, fat/thin order, at five seconds, 100 connections and
10,240 payload bytes (the harness uses 2,048 for UDP). Binaries stay on that
runner and are selected by copying to the harness's expected path. Each run's
binary hash must match its compiled profile. No binaries are uploaded or
published as release assets or images.

The data-only verifier requires all 120 ordered gateway/direct samples, exact
protocol/control identities, positive finite throughput and p99, the fixed
workload and zero errors. Missing, duplicate, malformed or error-bearing
samples fail the study. Raw logs remain available on failure. Hosted self-tests
exercise rejection cases on changes to the workflow or verifier. Summaries
report median paired percentage changes, not confidence bounds or equivalence.

Seven-day artifacts retain both Cargo timing reports, compile logs/wall time,
maximum-child RSS, page faults, runner-wide vmstat, source/toolchain/CPU
provenance, executable sizes/hashes/versions and raw/validated protocol results.
Cargo timings do not isolate every frontend, LLVM and linker subphase. The
first vmstat row covers time since boot; subsequent rows cover its interval.

A successful study does not authorize shipping changes. Agree a tolerated
p99/throughput regression budget and extend measurements to affected macOS,
Windows and protected ARM64/sysroot producers before adoption. This native
Linux experiment does not establish the shipping GNU ABI floor. Exact-SHA
publication gates, Cross isolation, FIPS boundaries and install/image/ABI
checks remain prerequisites. Production profiles and publication paths are
unchanged.

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
not evidence for shipping adoption. The paired workflow above addresses the host mismatch and validates complete
samples. Its measurements are pending; the platform/ABI and agreed-budget
gates still apply.
