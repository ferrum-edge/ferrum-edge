# Nonpublishing platform release-build study

Issue #4674 includes macOS and Windows release builds that previously exceeded
80–95 minutes. The manual **Release Platform Build Study** measures the current
shipping profile on the three matching release-runner/target pairs: macOS
x86_64 and ARM64 on macos-latest, and Windows x86_64 on windows-latest. The
macOS x86_64 target may cross-compile on an ARM64 host; recorded host and target
identities must be used when interpreting it.

The study installs and explicitly selects Rust 1.98.1 with RUSTUP_TOOLCHAIN,
then checks the active rustc/Cargo versions and installed target before building.
This prevents rust-toolchain.toml from selecting an older cached stable toolchain.
It uses cloud-secrets and the existing fat-LTO/one-unit
release profile, preserves Apple deployment floors and the canonical fast
linker setup, and copies the checksum-pinned Windows protoc/NASM setup from
the release producer. Each run starts with an empty target directory and
compiler wrappers disabled. It does not restore or publish build caches.
The workflow and profiler spell each platform command explicitly so the trusted
policy can inspect every executable and target without interpreting dynamic argv
or expanded process options. Windows termination passes only the owned numeric
PID as data to a fixed process-tree termination command.
A changed shipping-profile value or release-profile environment override fails
the study rather than silently measuring different settings.

A 150-minute compile deadline leaves room within the 165-minute measurement
step and 180-minute job for cleanup and evidence upload. This provides margin
above the observed 84-minute Windows and at-least-95-minute macOS runs while
avoiding an implicit six-hour experiment. The production release workflow's
budgets and publishing behavior are unchanged.

Seven-day artifacts contain source/toolchain/host/profile provenance, Cargo
logs and timing HTML, decoded per-unit timing data including frontend/codegen
sections where Cargo supplies them, ten-second process-tree RSS observations,
host memory/swap counters, final status and executable size/hash. The script
waits for Cargo independently of the sampler, so sampling delay does not inflate
the recorded build wall time. Samples can miss short-lived processes and RSS
counts can include shared pages repeatedly; sampled peaks are not exact peak
physical-memory measurements. Sampling itself has overhead. Cargo units overlap,
codegen does not isolate LLVM optimization from linking, and build-script time
is not exclusively native compilation. Keep those distinctions in any report.

A successful build must execute the gateway's version command on the runner.
macOS also records Mach-O load commands. This is a host smoke check, not proof
of the oldest supported OS, complete ABI compatibility, installation behavior,
or a full protocol/performance matrix. ARM64 Cross and GNU sysroot profiling
remain separate required work; this workflow cannot replace their protected
producers or their ABI gates.

Only data/log/report extensions from study-results are uploaded. Executables
remain in the runner's temporary target directory; no image, release asset or
version tag is published. PR/main events execute only telemetry contracts;
expensive platform compilation requires manual dispatch. Process sampling is
limited to the Cargo process and descendants and excludes command arguments.
Existing Cargo timing reports are copied even when compilation fails, before
parsing validation. Logs and samples are flushed during compilation and retained by the always-run
upload step when possible; an abrupt runner loss can still prevent upload.

Before adopting a shipping-profile change, require an agreed runtime-regression
budget and the affected-platform runtime/ABI/install/image evidence. This study
changes no shipping profile and makes no adoption decision.
