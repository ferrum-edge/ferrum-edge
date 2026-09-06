# Coverage

Ferrum Edge uses `cargo-llvm-cov` for Rust line coverage. The measured local
and CI scope is `--lib`, `--test unit_tests`, and `--test integration_tests`.
Functional tests, conformance tests, custom plugins, vendored crates, and
performance workspaces are outside the default baseline because they either
spawn subprocesses, use separate coverage reporters, or are not actionable for
the core proxy codebase. Build inputs such as `build.rs`, `proto/**`, and
`ebpf/**` remain report-ignored for the default baseline, but they are coverage
trigger surfaces in CI: changing them runs the full coverage matrix instead of
the plugin-only or no-op PR path.

## Running Locally

Install the tool once:

```bash
cargo install cargo-llvm-cov --locked
rustup component add llvm-tools-preview
```

Run the deterministic local coverage suite:

```bash
scripts/coverage.sh
```

The script prints a terminal summary and writes:

- HTML: `target/llvm-cov/html/index.html`
- LCOV: `target/llvm-cov/lcov.info`
- JSON summary: `target/llvm-cov/coverage.json`

Use a filter for targeted investigation:

```bash
scripts/coverage.sh -- plugins::cors
```

Run the heavier top-gap functional coverage pass when investigating the proxy,
HTTP/3, TCP/UDP, admin, and mode-level gaps:

```bash
scripts/coverage.sh --functional
```

This opt-in path builds Cargo's instrumented `ferrum-edge` binary and exports
its path through `FERRUM_EDGE_TEST_BIN` so subprocess-based functional tests
contribute to the same coverage report. MongoDB functional tests are included
in the filter list and skip gracefully when local MongoDB is not available.

## Database/File Mode Regression Notes

The DB/file-mode regression matrix is split by what can run deterministically in
the in-process coverage suite versus what needs backend services or subprocess
orchestration:

- SQL runtime config loading is covered through SQLite-backed integration tests
  for the shared `DatabaseStore` implementation. These tests pin full-load
  keyset pagination, durable `config_changes` incremental create/update/delete
  delivery, retained-history cursor expiry, saturated-batch full-reload
  fallback, proxy/plugin association fail-closed behavior, and the invariant
  that normal incremental polling does not discover raw runtime rows without
  change-log records.
- Database-mode poll-loop unit tests cover rejected-delta backoff, escalation to
  authoritative full reload, bounded metrics, recovery clearing, and preserving
  the accepted sequence cursor when a full-load or incremental candidate is
  rejected. Unchanged valid database configs commit the sequence cursor and keep
  the gateway available.
- MongoDB standalone behavior is covered by functional CI against the default
  `mongo:7` service and intentionally forces database-mode pollers to full
  reloads instead of accepting non-transactional incremental cursors. MongoDB
  replica-set transaction/incremental behavior requires a replica-set topology
  and is tracked here as a backend-specific coverage boundary for remote CI
  environments that provide one.
- File-mode lifecycle parity is covered by in-process `file::serve` unit tests
  for fallible listener draining, bounded background-task shutdown, reserved
  port calculation with pre-bound listeners, and HTTP/3 bind-address parity.
  Subprocess functional tests cover YAML startup and SIGHUP reload behavior.

## CI Baseline And Gates

The `Coverage` workflow runs on pull requests, merge-queue `merge_group`
events, pushes to `main`, manual dispatch, and Sundays at 06:00 UTC. It
publishes an HTML report, LCOV file, JSON
summary, and terminal summary as a 30-day GitHub Actions artifact named
`coverage-report` whenever coverage is collected. It also writes the overall
coverage percentage and lowest/highest-covered files to the workflow step
summary. The Coverage workflow's `Merge Coverage` job is a branch-protection
required check in its own right; the main `CI` workflow no longer waits on it
with a mirror job, so a PR or merge-queue group merges only once coverage has
completed for the same SHA via the required check.

The full default-branch gate is based on the latest completed `main` coverage
artifact available when the gate was introduced on 2026-06-20:

| Scope | Remote baseline | Gate |
| --- | ---: | ---: |
| Overall line coverage | `210900/269397` lines, **78.29%** | **78.28%** |
| `src/plugins/` line coverage | `54957/64665` lines, **84.99%** | **84.98%** |
| Changed coverable `src/plugins/` lines on plugin PRs | same plugin baseline | **84.98%** |

The thresholds are intentionally rounded down from the measured remote values
so presentation precision does not fail a run, while any real coverage drop in
overall or plugin coverage still fails the full default-branch gate.

PR coverage is mode-aware:

- Pull requests that touch only plugin coverage-relevant files keep the
  plugin-specific mode: they run the `lib-unit` shard (`--lib` and
  `--test unit_tests`) and the merge job reuses that shard's profraw/artifacts
  instead of re-collecting coverage. The changed-line plugin gate still applies
  to coverable `src/plugins/` lines. This mode is used only when all
  coverage-relevant changes are plugin-scoped; mixed plugin and core changes
  select the affected core shards and still enforce the plugin changed-line
  gate when plugin files are in the diff.
- Pull requests that touch classifiable core coverage-relevant files run an
  explicit shard-scoped plan: `lib-unit` plus only the integration shards that
  own the changed tree. Isolated trees stay narrow: `src/admin/**` selects the
  admin-bearing shards, `src/modes/mesh/**` selects the mesh shards, and
  protocol trees such as `src/http3/**` select the protocol data-plane shard.
  Shared runtime trees select every integration family they feed rather than an
  optimistic single shard: `src/config/**`, `src/config_delta.rs`,
  `src/proxy/**`, `src/dns/**`, `src/grpc/**`, `src/identity/**`, `src/pool/**`,
  `src/connection_pool.rs`, `src/xds/**`, and `src/modes/control_plane.rs`
  select the full matrix. `src/tls/**` selects mesh plus protocol shards;
  file, database, and data-plane mode files select admin plus protocol shards;
  `src/config_sources/**` selects admin-config plus both mesh shards. The
  required `Merge Coverage` check verifies that every
  planned shard succeeded, that exactly those shard artifacts are present, and
  that reports are still published. Partial shard reports do not enforce the
  overall or `src/plugins/` floors because those floors are only meaningful on
  the complete matrix.
- Pull requests that touch neither plugin nor core coverage-relevant files keep
  the required `Merge Coverage` check as a fast no-op.
- Push to `main`, `schedule`, `workflow_dispatch`, empty or unavailable diffs,
  coverage-controller edits, dependency/build-graph inputs (`Cargo.toml`,
  `Cargo.lock`, `build.rs`, `proto/**`, `ebpf/**`, `.cargo/**`,
  `rust-toolchain.toml`), unknown coverage-relevant paths, and malformed or
  hostile changed-path transport fail closed to the full six-shard matrix and
  still enforce the overall and `src/plugins/` thresholds. Classifiable paths
  use the conservative repository-relative `[A-Za-z0-9._+@~ /-]` alphabet, so
  Markdown controls cannot alter the Coverage Plan summary. A skipped planned
  shard cannot green the merge aggregate.
- Pushes to `main`, manual dispatches, and scheduled runs therefore keep
  published main coverage complete and semantically unchanged.

Plugin coverage-relevant paths are `src/plugins/**`, `src/plugin_cache.rs`,
`tests/unit/plugins/**`,
and `tests/functional/functional_redis_rate_limiting_test.rs`.
The authoritative planner lives in `.github/scripts/coverage_plan.py` so the
workflow and examples use one path decision table. The coverage workflow
verifier in `.github/scripts/verify_coverage_workflow.py` mechanically checks
the matrix/aggregate contract, including exact planned shard outcomes, artifact
presence, and required reporting. On pull requests and
merge-queue groups, the `Coverage Plan` job collects changed files with
`git diff --name-only --no-renames` so a rename's source and destination are
both classified and a move into an irrelevant path cannot suppress a required
gate. Generated, ignored, or
otherwise non-coverable changed lines are ignored consistently with the LCOV
report. The report ignore regex excludes `vendor/`, `tests/`, `build.rs`,
`target/`, `custom_plugins/`, `ebpf/`, and `proto/`; those exclusions do not
hide `build.rs`, `proto/**`, or `ebpf/**` from CI trigger decisions.

To inspect the same remote results without running coverage locally:

```bash
gh run list --repo ferrum-edge/ferrum-edge --workflow Coverage --branch main
gh run download <run-id> --repo ferrum-edge/ferrum-edge --name coverage-report --dir /tmp/ferrum-coverage
python3 scripts/check_coverage_thresholds.py \
  --coverage-json /tmp/ferrum-coverage/coverage.json \
  --lcov /tmp/ferrum-coverage/lcov.info \
  --min-overall-line 78.28 \
  --min-plugins-line 84.98
```

For PR changed-line investigation, compare against the PR base SHA:

```bash
python3 scripts/check_coverage_thresholds.py \
  --coverage-json /tmp/ferrum-coverage/coverage.json \
  --lcov /tmp/ferrum-coverage/lcov.info \
  --changed-base <base-sha> \
  --min-changed-plugins-line 84.98
```

The normal full-mode PR `CI` workflow also includes required plugin hardening
regressions:

- The `Unit Tests` job runs the cache byte-accounting and last-known-good plugin
  reload regressions explicitly before the complete unit suite. Keeping both
  invocations in one job reuses the compiled `unit_tests` binary.
- `Plugin Hardening Redis Regression`: multi-instance Redis request
  deduplication with `FERRUM_REDIS_REQUIRED=1`, so Redis startup failures cannot
  silently skip the regression. Covers cross-gateway lock/completed-value
  sharing for one `plugin_config_id`, same-proxy sibling instances under the
  shared default `{FERRUM_NAMESPACE}:dedup` prefix, and distinct-header
  instances with unique Redis prefixes that each complete and token-release
  independently.

Latest opt-in functional benchmark: **81.68% line coverage**
(`148,432/181,717` lines), captured locally on 2026-05-25 with
`rustc 1.95.0 (59807616e 2026-04-14)`. This is not the scheduled CI baseline
because functional coverage is heavier and depends on subprocess-based
fixtures, but it is the current top-gap benchmark for tracking progress toward
90%.

The 81.68% profile used:

- `scripts/coverage.sh --functional`
- `scripts/coverage.sh --functional-filter functional_cp_dp`
- `scripts/coverage.sh --functional-filter functional_cp_dp_resilience`
- `scripts/coverage.sh --functional-filter functional_grpc`
- `scripts/coverage.sh --functional-filter functional_load_balancer`

The default `--functional` filters include coverage-aware TCP/UDP/Mongo and
common-harness subprocess paths. Broad filters such as `h3`, and additional
legacy functional filters, can still select tests that under-report
child-process coverage until their local `kill()` cleanup paths are migrated to
the shared coverage-aware shutdown helper.

## Artifact fan-in transport and measurements (#4670)

Shard uploads retain the same Actions ZIP containing one
`coverage-<shard>.tar`, the same packaging `find` exclusions, raw profiles,
object files, executable permissions, retention, and default ZIP compression.
The merge job downloads the compressed ZIP through the Actions artifact API
and streams its single tar member through `unzip -p` into `tar -xpf -`.
This avoids writing and rereading the intermediate uncompressed tar. It stages
only one compressed archive at a time and preserves the planner's sequential
extraction/overwrite order, including all shared paths. No objects are stripped,
deduplicated, renamed, or selected differently; no profiles are pre-merged.

Artifact IDs come only from the current workflow run's paginated artifact list.
Each planned name must resolve uniquely to a non-expired artifact, and its ZIP
must contain exactly the expected tar member. Download failures retain the
two-attempt retry; failed downloads, invalid ZIPs, CRC errors, tar failures, and
missing profiles fail the step. The pipeline drains tar end padding so ZIP CRC
verification finishes, and `pipefail` preserves both processes' failures.
The required `Merge Coverage` check, shard-success checks, report commands,
ignore regex, full/changed-line gates, and exact-SHA publication evidence remain
unchanged. The operative workflow floors remain **77.50% overall**, **84.50%
plugins**, and **84.98% changed plugin lines**; the earlier baseline table above
records the historical introduction values.

Before-change observations from the two successful main runs on 2026-09-06:

| Measurement | [34008463617](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34008463617) | [34018271783](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34018271783) |
| --- | ---: | ---: |
| Source SHA | `5d586f5e013ec4ea7d0ed573c604bb2ddade4e2f` | `aa251c3326c8d237e46bf8b7346861cec6c7aaf4` |
| Lib/unit job | 28m02s | 33m39s |
| Integration job range | 13m07s–14m31s | 17m21s–18m10s |
| Sum of six shard job durations | 96m12s | 121m55s |
| Merge Coverage job | 9m58s | 12m10s |
| Download/extract step | 5m58s | 7m11s |
| Report generation | 2m22s | 2m53s |
| Total uploaded shard ZIP bytes | 7,492,574,957 | 7,531,180,534 |

The job-duration sum measures elapsed runner time, excluding queueing, rather
than billing-rounded minutes. API artifact sizes are exact; the expanded tar
sizes below are only the rounded `ls -lh` values in the packaging logs, not
exact extracted-file byte counts.

| Shard | Historical ZIP bytes | Historical tar | Latest ZIP bytes | Latest tar |
| --- | ---: | ---: | ---: | ---: |
| lib-unit | 872,186,168 | 4.0 GiB | 878,861,708 | 4.1 GiB |
| admin-api | 1,205,668,583 | 4.8 GiB | 1,212,123,854 | 4.8 GiB |
| admin-config | 1,340,759,632 | 5.2 GiB | 1,347,138,224 | 5.3 GiB |
| mesh-routing | 1,307,752,897 | 5.1 GiB | 1,314,158,779 | 5.2 GiB |
| mesh-platform | 1,338,184,871 | 5.2 GiB | 1,344,557,956 | 5.3 GiB |
| protocols-data-plane | 1,428,022,806 | 5.5 GiB | 1,434,340,013 | 5.6 GiB |

Log timestamps put download-to-extract intervals at approximately 3m15s and
4m43s in total, with the remaining approximately 2m43s and 2m28s spent in
extraction, cleanup, and other step overhead. The old download interval itself
includes ZIP decompression and writing the expanded tar, so these are not pure
network measurements. Streaming removes about 30 GiB of intermediate tar writes
and rereads per full run; its net wall-time benefit remains unmeasured until
hosted CI runs this change. ZIP size, upload cost, and report-generation cost
are not expected to improve. These different-SHA runs are timing evidence, not
a same-source coverage-equivalence comparison. Identical cross-run object
content and the cost of duplicate workspace metadata have not been established.
The latest lib/unit log reports 21m07s compilation and about 9m26s running its
two suites; this change does not add shards or address compilation latency.

Hosted workflow regression tests exercise the actual transport shell using
small ZIP/tar fixtures: forced ZIP64 headers, pagination, unplanned artifacts,
retried partial downloads, exhausted retries, missing/expired/duplicate planned
artifacts, wrong/extra ZIP members, CRC errors, invalid tars, missing
profiles, profile bytes, executable modes, and sequential shared-object
overwrites. Actual coverage artifacts retain their format and objects; ZIP CRC
checks validate the stream on every hosted merge. The step summary now records
exact ZIP/tar bytes, download/extraction seconds per shard, and fan-in wall time
for comparison with subsequent exact-head CI. No local test or benchmark result
is claimed for this optimization.

Cancellation remains a separate limitation: GitHub re-evaluates job and step
conditions, and an `always()` job can continue after cancellation
([workflow cancellation reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation)).
Both sampled runs succeeded, so they do not measure a cancellation delay.
The required aggregate's existing `always()` and failure semantics are retained;
changing cancellation behavior needs a dedicated failing/cancelled-run check.

## Lowest-Covered Modules (historical snapshot)

> **Historical.** The table and percentages below are a dated local baseline
> snapshot retained for archaeology. They are **not** a current coverage claim
> and must not drive "next priority" planning without regenerating from a fresh
> `scripts/coverage.sh` / CI coverage artifact. Prefer timeless guidance: raise
> coverage where new code lands; do not treat this table as the live gap list.

Measured from a prior local baseline run. Percentages are line coverage.

| Module | Coverage | Assessment |
| --- | ---: | --- |
| `src/main.rs` | 0.00% | Binary startup and process-exit paths are not exercised by lib/unit/integration coverage; keep most testing in CLI/startup helpers and functional smoke tests. |
| `src/http3/` | 23.69% | Protocol integration candidate; the server, WebSocket, and cross-protocol fallback paths need QUIC/H3 stream fixtures. |
| `src/bin/ferrum-cni.rs` | 49.64% | CLI-style binary path; targeted command parsing and error-path tests should be cheap. |
| `src/cli.rs` | 54.68% | Easy win; parser, path resolution, and health/version/reload branches are deterministic. |
| `src/runtime_metrics_tracing_layer.rs` | 58.33% | Easy win; small classification layer with bounded pure functions plus one untested event-recording path. |
| `src/health_check.rs` | 60.95% | Mixed candidate; passive health is unit-friendly, while active HTTP/gRPC probes need mocked backends. |
| `src/identity/` | 63.03% | Integration-test candidate; rotation and Workload API paths involve async CA/SPIFFE flows and long-running tasks. |
| `src/proxy/` | 64.81% | High-value integration candidate; hot-path protocol behavior needs focused fixtures rather than broad unit mocks. |
| `src/tls_offload.rs` | 75.71% | Targeted-test candidate for policy and offload edge cases. |
| `src/grpc/` | 77.34% | Protocol integration candidate; CP/DP and mesh gRPC failure paths are the likely remaining gaps. |

## Next Test Priorities (historical planning notes)

> **Historical.** The H3-fixture / health-check / identity / CLI / UDP items
> below were written against the snapshot table above. Substantial H3 fixtures,
> health-check, identity, CLI, and UDP coverage have landed since; do not treat
> this list as the current backlog. Regenerate priorities from the latest
> coverage artifact when prioritizing new tests.

1. `src/http3/`: add a small H3 fixture layer for handshake, request body,
   WebSocket, and cross-protocol fallback error cases. This was the largest
   measured gap in core protocol code at snapshot time.
2. `src/health_check.rs`: cover passive-state transitions and active-probe
   formatting/error branches with mocked HTTP/gRPC backends.
3. `src/identity/`: add fake-CA and fake-Workload-API tests for SVID rotation,
   failed issuance, revision bumps, and trust-bundle refresh behavior.
4. `src/cli.rs` and `src/bin/ferrum-cni.rs`: add parser/error-path tests for
   command surfaces.
5. `src/proxy/udp_proxy.rs` and `src/proxy/udp_batch.rs`: add narrow UDP
   fixture tests for batching, disconnect, and timeout/error accounting.
