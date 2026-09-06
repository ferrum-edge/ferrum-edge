# Release profile study

Issue #4674 remains open. No shipping profile or publication path changes in
this experiment. Dispatch **Multi Protocol Performance Benchmark** with
`build_profile=release-study`, all protocols, and three iterations to compare
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
