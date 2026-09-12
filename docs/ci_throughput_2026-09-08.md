# Hosted CI throughput follow-up, September 8, 2026

This audit uses GitHub Actions run/job metadata, retained primary job logs and
the cache inventory read around 00:42 UTC. It follows issues
[#4643](https://github.com/ferrum-edge/ferrum-edge/issues/4643),
[#4672](https://github.com/ferrum-edge/ferrum-edge/issues/4672),
[#4694](https://github.com/ferrum-edge/ferrum-edge/issues/4694) and
[#4674](https://github.com/ferrum-edge/ferrum-edge/issues/4674). None is treated
as fully resolved by this change. No workflow was dispatched for this audit.

## Repair: require completed shared-cache producers

The fixed sccache wrapper path and cache-lane consolidation are already on
main. The earlier `fix/issue-4643-cache-lane-diet` branch / PR #4665 was
integrated separately; repeating it would duplicate existing work. However,
the current Unit core shard, Lint and coverage lib-unit producer explicitly
opted back into `cache-on-failure: "true"`.

At the pinned rust-cache revision, the
[post condition](https://github.com/Swatinem/rust-cache/blob/6323deb102c322ba6fcbdcafc7e3dddab59af2b6/action.yml)
allows saving after failures when this input is true. Its
[save implementation](https://github.com/Swatinem/rust-cache/blob/6323deb102c322ba6fcbdcafc7e3dddab59af2b6/src/save.ts)
returns immediately for an up-to-date cache. Neither checks whether the job
completed compilation. The earlier verified fetch-only publication in
[job 101571089089](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34064592905/job/101571089089)
reserved an immutable key with only 168,625,963 bytes; later successful
exact-hit consumers could not enrich it. Protecting running main workflows
from supersession does not prevent setup, fetch, compilation or runner failures.

All three shared producers now explicitly disable failure saves. Hosted
runtime-cache policy checks exercise each real caller and reject true,
computed, missing, duplicate or commented-out failure-save inputs, plus a
missing setup step. The composite, designated writer expressions, key inputs,
restore eligibility and separate FIPS contract remain unchanged. A failed test
after a complete compile now also forgoes its cache save; that is the deliberate
cost of requiring a completed producer without inferring compilation success.
No existing cache is deleted or renamed, so this does not repair any already
incomplete immutable entry. Diagnose such an entry from its producer log before
proposing retirement; small size alone is insufficient evidence.

## Current cache and compile evidence

The [retained inventory](ci_throughput_2026-09-08_cache.json) contained seven
entries, totaling **5,785,469,165 bytes**.
The configured allowance remains 10 GB. All seven had later access timestamps.
The following IDs were still present after main push `a21ead6e3d` at 00:31:56 UTC:

| Family | Cache ID | Compressed bytes | Created September 7 UTC |
| --- | ---: | ---: | --- |
| ci-debug | 7411848327 | 883,476,251 | 10:44:31 |
| ci-lint | 7411340788 | 542,721,628 | 10:29:17 |
| fuzz-smoke | 7412846220 | 2,475,701,225 | 11:14:42 |
| ci-coverage | 7428219550 | 900,592,755 | 19:09:15 |
| FIPS contract | 7410260875 | 926,258,182 | 09:58:17 |
| eBPF programs | 7418593947 | 19,780,291 | 13:53:23 |
| Kubernetes tools | 7409369539 | 36,938,833 | 09:32:59 |

In successful PR [run 34171096527](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34171096527),
Unit core and Build Test Artifacts both logged an exact restore of
`v0-rust-ci-debug-Linux-x64-364cb90d-ae313cd2`; Lint restored
`v0-rust-ci-lint-Linux-x64-08f74bf7-ae313cd2`. Log byte counts match the table.

| Job | Measured step | Duration |
| --- | --- | ---: |
| [Unit core](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34171096527/job/101891529873) | Precompile inline and hardening test binaries | 9m52s |
| [Lint](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34171096527/job/101891529845) | Run clippy | 5m25s |
| [Build Test Artifacts](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34171096527/job/101891529837) | Build gateway binary | 5m11s |

The main run at `a21ead6e3d` was still running at collection time. These are
actual retained entries and successful PR restores, but one snapshot cannot
establish survival through every later write of that main run. The unit suite
has also been split since the original issue's 19–25 minute precompile baseline;
the new core-shard duration is not a controlled same-workload speedup.

## Sanitizer critical path remains measurable

The latest completed main CI run at collection, [34165057380](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34165057380),
passed. Its [Fuzz Smoke job](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34165057380/job/101875708843)
restored the exact 2,475,701,225-byte fuzz cache. The property step took 5m39s
and all 12 tests passed. The sanitizer step reported **1,780 seconds (29m40s)**;
all seven targets completed **512 iterations each**, including the 64 KiB
`datagram_client_address` bound. Final compiler telemetry reported **0 hits and
16 Rust misses**, versus eight misses before sanitizer compilation.

The current frozen lane retains targets but no longer archives the sccache
directory. Earlier #4694 target-only experiments already showed that losing
compiler-store reuse could substantially lengthen a warm sanitizer stage.
This latest observation warrants a same-input compiler-store comparison, not
another optimization-profile guess. The prior dev-profile experiments lost
iterations or failed to show repeatable benefit. The GHCR transfer foundation
from #4750/#4815 proves transport, not compiler reuse or a production migration.
Keep AddressSanitizer, target inventory, input limits, runtime bounds and useful
stack traces intact. Root must verify both actual compiler hits and subsequent
main cache retention before adopting a storage change.

## Cancellation and release follow-through

The paginated CI-workflow cohort from September 7 00:00 through September 8
00:42 UTC contains 185 runs: 129 PR, 49 push and seven manual runs. PR outcomes
are 45 success / 25 failure / 58 cancelled / one active; pushes are 16 success /
seven failure / 25 cancelled / one active. There are no merge-group runs.
These are latest run conclusions, not per-attempt runner-minute accounting.
Pending coalescing, explicit cancellation and runner loss must not be inferred
from a cancelled conclusion alone. This mixed, partial post-change cohort
does not replace the week-long baseline recorded on #4672.

For acceptance, collect a complete post-change week with the same exact-SHA,
event-matched required-context joins, all retained attempts, queue/dispatch
intervals, job execution and incomplete-head denominator. Report p50/p95
readiness, minutes in cancelled runs, and runner-minutes per landed change
across all required workflows; separate successful-only survivorship bias.
Main no longer automatically publishes production releases, so measure main
validation freshness separately from explicit release freshness. No change to
concurrency, required gates, test eligibility, artifact producer/head matching,
merge-base policy or repository settings is proposed here.

The release studies already exist in #4725, #4732 and #4739. The same-host
thin-LTO experiment reduced compilation but lost gateway throughput; the
single native Intel macOS comparison was 11.56% slower than its ARM-host
counterpart. Repeating those configurations without a new hypothesis adds
cost without satisfying #4674. Shipping profiles and runners remain unchanged.
An agreed runtime-regression budget, protected Cross phase measurements and
affected-platform runtime/ABI/install/image results are still required.

## Validation and handoff

Local validation is static review and `git diff --check` only. The existing
hosted required-policy path invokes `verify_ci_runtime_cache.py` and its
self-tests; their result on the new PR head is pending. Root owns fresh hosted
CI, exact-head review and merge. Subsequent snapshots must retain the same
cache IDs across completed main writes and PR readers before asserting durable
retention. None of the four issue acceptance sets is closed by configuration
alone, and no closing directives are attached to this partial repair.
