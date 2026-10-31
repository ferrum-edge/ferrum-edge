# Coverage

Ferrum Edge uses `cargo-llvm-cov` for Rust line coverage. The default local
and CI scope is `--lib`, the four unit targets (`--test unit_tests`,
`--test unit_plugins_a_tests`, `--test unit_plugins_b_tests`,
`--test unit_gateway_core_tests`), and `--test integration_tests`. CI full
plans also run the subprocess `functional_tests` suite against the
instrumented `ferrum-edge` binary in dedicated shards (see
[Functional coverage shards](#functional-coverage-shards)); the default local
`scripts/coverage.sh` run omits it, and `--functional` adds a curated subset.
Conformance tests, custom plugins, vendored crates, and performance
workspaces stay outside the baseline because they use separate coverage
reporters or are not actionable for the core proxy codebase. Build inputs such
as `build.rs`, `proto/**`, and `ebpf/**` are report-ignored for the default
baseline. Pull requests normally skip instrumented coverage; see
[CI Baseline And Gates](#ci-baseline-and-gates).

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

The default path collects `--lib`, the four unit targets, and
`--test integration_tests` through `run_coverage_target`, matching the CI
baseline documented above.

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
contribute to the same coverage report. Every functional gateway spawner
resolves the binary through `gateway_binary_path()` / `locate_binary()` in
`tests/common/gateway_harness.rs`, which prefers `FERRUM_EDGE_TEST_BIN` over a
`target/debug` or `target/release` build. The selected instrumented binary is
therefore launched even when a stale ordinary debug build exists, and is found
when it is the only build. A structural parity test in
`tests/unit/gateway_core/shared_invariant_parity_tests.rs` rejects a fixed
gateway path anywhere else under `tests/functional/` or `tests/common/`
(#6379). MongoDB functional tests are included
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
- MongoDB standalone behavior is covered by functional CI against the
  `mongo:4.4.29` standalone fixture (the supported floor; the Coverage
  workflow's standalone fixture is `mongo:9`) and intentionally forces database-mode pollers to full
  reloads instead of accepting non-transactional incremental cursors. MongoDB
  replica-set transaction/incremental behavior requires a replica-set topology
  and is tracked here as a backend-specific coverage boundary for remote CI
  environments that provide one.
- File-mode lifecycle parity is covered by in-process `file::serve` unit tests
  for fallible listener draining, bounded background-task shutdown, reserved
  port calculation with pre-bound listeners, and HTTP/3 bind-address parity.
  Subprocess functional tests cover YAML startup and SIGHUP reload behavior.

## Admin TLS Inventory Regression Notes

The in-process admin TLS inventory regressions in
`tests/integration/admin_metrics_tls_inventory_snapshot_tests.rs` cover cached,
I/O-free scrapes, single-flight refresh, TTL expiry, config invalidation,
serving-cycle generation fencing, and invalidation during collection. Two active
admin fixtures own separate caches, collectors, and metrics registries, including
while one collector is blocked and the other fixture reloads. They use channel
barriers and refresh-task completion rather than sleeps or scrape retries, so
`cargo test --test integration_tests admin` keeps working with parallel test
threads (#5544). Hosted CI runs integration tests under nextest, one process per
test, so that single-process property holds by construction rather than by a
CI gate.

## CI Baseline And Gates

The `Coverage` workflow runs on pull requests, merge-queue `merge_group`
events, pushes to `main`, manual dispatch, and Sundays at 06:00 UTC. It
publishes an HTML report, LCOV file, JSON summary, and terminal summary as a
30-day GitHub Actions artifact named `coverage-report` whenever coverage is
collected. It also writes the overall coverage percentage and
lowest/highest-covered files to the workflow step summary. The Coverage
workflow's `Merge Coverage` job is a branch-protection required check in its
own right (the main `CI` workflow does not mirror it), so a PR or merge-queue
group merges only once coverage has completed for the same SHA.

The current floors are set in the `env` block of `.github/workflows/coverage.yml`:

| Scope | Gate | Applies to |
| --- | ---: | --- |
| Overall line coverage | **81.00%** (`MIN_OVERALL_LINE_COVERAGE`) | Full matrix only |
| `src/plugins/` line coverage | **89.00%** (`MIN_PLUGINS_LINE_COVERAGE`) | Full matrix only |
| Changed coverable `src/plugins/` lines | **84.98%** (`MIN_CHANGED_PLUGIN_LINE_COVERAGE`) | Plugin and shard-scoped PR plans only (not selected by the active planner; see below) |

Floors are deliberately below measured main coverage to allow run-to-run
variance; raise them deliberately after coverage improves, rather than pinning
them to a measured peak (measured provenance is in the `coverage.yml` comments).

The active planner, `select_plan` in `.github/scripts/coverage_plan.py`,
treats coverage as a main-branch backstop:

- Pull requests and merge groups skip every instrumented shard, and the
  required `Merge Coverage` check reports as a fast no-op.
- A pull request or merge group that edits a coverage controller
  (`coverage.yml`, `coverage_plan.py`, `verify_coverage_workflow.py`,
  `scripts/check_coverage_thresholds.py`, `scripts/coverage.sh`) runs the full
  matrix so the tooling change is exercised before it lands.
- Push to `main`, `schedule`, `workflow_dispatch`, empty or unavailable diffs,
  and malformed or hostile changed-path transport fail closed to the full
  matrix (lib-unit, the five scoped integration shards, the two
  integration-remainder shards, and the three functional shards), which
  enforces the overall and `src/plugins/` floors. Classifiable
  paths use the conservative repository-relative `[A-Za-z0-9._+@~ /-]`
  alphabet, so Markdown controls cannot alter the Coverage Plan summary. A
  skipped planned shard cannot green the merge aggregate.
- Because pushes to `main`, manual dispatches, and scheduled runs always use
  the full matrix, published main coverage stays complete. A commit that trips
  a floor turns `main` red and is not releasable.

`select_scoped_plan` keeps a path-scoped classification for diagnostics and a
possible future opt-in; the workflow does not currently use it. When selected,
it works as follows:

- Plugin-only diffs use the plugin mode: they run the `lib-unit` shard
  (`--lib` and the four unit targets) and the merge job reuses that shard's
  profraw/artifacts instead of re-collecting coverage. Only this mode and the
  shard-scoped mode enforce the changed-line plugin gate
  (`MIN_CHANGED_PLUGIN_LINE_COVERAGE`) on coverable `src/plugins/` lines; mixed
  plugin and core changes select the affected core shards and keep that gate.
- Classifiable core diffs run a shard-scoped plan: `lib-unit` plus only the
  integration shards that own the changed tree. `src/admin/**` selects the
  admin shards, `src/modes/mesh/**` the mesh shards, and protocol trees such as
  `src/http3/**` the protocol data-plane shard. Shared runtime trees
  (`src/config/**`, `src/config_delta.rs`, `src/proxy/**`, `src/dns/**`,
  `src/grpc/**`, `src/identity/**`, `src/pool/**`, `src/connection_pool.rs`,
  `src/xds/**`, `src/modes/control_plane.rs`) select the full matrix.
  `src/tls/**` selects mesh plus protocol shards; file, database, and
  data-plane mode files select admin plus protocol shards;
  `src/config_sources/**` selects admin-config plus both mesh shards. Partial
  shard reports do not enforce the overall or `src/plugins/` floors, which are
  only meaningful on the complete matrix.
- Dependency/build-graph inputs (`Cargo.toml`, `Cargo.lock`, `build.rs`,
  `proto/**`, `ebpf/**`, `.cargo/**`, `rust-toolchain.toml`) and unknown
  coverage-relevant paths fail closed to the full matrix; diffs with no
  coverage-relevant files skip.

In every mode, the required `Merge Coverage` check verifies that every planned
shard succeeded, that exactly those shard artifacts are present, and that
reports are still published.

For the scoped classification, plugin coverage-relevant paths are
`src/plugins/**`, `src/plugin_cache.rs`, `tests/unit/plugins/**`, and
`tests/functional/functional_redis_rate_limiting_test.rs`. The authoritative
planner is `.github/scripts/coverage_plan.py`, so the workflow and examples use
one path decision table. `.github/scripts/verify_coverage_workflow.py`
mechanically checks the matrix/aggregate contract, including exact planned
shard outcomes, artifact presence, and required reporting. On pull requests and
merge-queue groups, the `Coverage Plan` job collects changed files with
`git diff --name-only --no-renames` so a rename's source and destination are
both classified and a move into an irrelevant path cannot suppress a required
gate. Generated, ignored, or otherwise non-coverable changed lines are
ignored consistently with the LCOV report. The report ignore regex excludes
`vendor/`, `tests/`, `build.rs`, `target/`, `custom_plugins/`, `ebpf/`, and
`proto/`; those exclusions do not hide `build.rs`, `proto/**`, or `ebpf/**`
from the scoped planner's trigger decisions.

To inspect the same remote results without running coverage locally:

```bash
gh run list --repo ferrum-edge/ferrum-edge --workflow Coverage --branch main
gh run download <run-id> --repo ferrum-edge/ferrum-edge --name coverage-report --dir /tmp/ferrum-coverage
python3 scripts/check_coverage_thresholds.py \
  --coverage-json /tmp/ferrum-coverage/coverage.json \
  --lcov /tmp/ferrum-coverage/lcov.info \
  --min-overall-line 81.00 \
  --min-plugins-line 89.00
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

- The `Unit Tests (plugins-b)` shard runs the cache byte-accounting and
  last-known-good plugin reload regressions explicitly (`--exact`) before its
  complete unit target. Keeping both invocations in one job reuses the compiled
  `unit_plugins_b_tests` binary.
- `Plugin Hardening Redis Regression`: multi-instance Redis request
  deduplication with `FERRUM_REDIS_REQUIRED=1`, so Redis startup failures cannot
  silently skip the regression. Covers cross-gateway lock/completed-value
  sharing for one `plugin_config_id`, same-proxy sibling instances under the
  shared default `{FERRUM_NAMESPACE}:dedup` prefix, and distinct-header
  instances with unique Redis prefixes that each complete and token-release
  independently.

The default `--functional` filters include coverage-aware TCP/UDP/Mongo and
common-harness subprocess paths. Broad filters such as `h3`, and additional
legacy functional filters, can still select tests that under-report
child-process coverage until their local `kill()` cleanup paths are migrated to
the shared coverage-aware shutdown helper.

## Integration remainder shards

The five scoped integration shards (`admin-api`, `admin-config`,
`mesh-routing`, `mesh-platform`, `protocols-data-plane`) select modules with
positional nextest filters, so path-scoped plans can run only the owning
family. Every full plan also adds `integration-remainder-1` and
`integration-remainder-2`, which carry no positional filters. Their shared
filterset, `INTEGRATION_REMAINDER_FILTERSET` in
`.github/scripts/coverage_plan.py`, is `not test(/integration::(...)/)` over
every scoped filter, split with `nextest --partition hash:N/2`. A positional
filter and the unanchored regex both match a substring of the test name, so
the remainder is exactly the complement of the scoped shards. Every registered
module therefore runs in full coverage, and a new module needs no filter edit
(#6377). The remainder runs non-ignored tests only, like every integration
coverage shard, so ignored live-store regressions stay outside coverage.

`verify_coverage_workflow.py` parses `tests/integration/mod.rs` and requires
every declared module to reach exactly one of a scoped filter or the
remainder. It also rejects a scoped filter that matches no registered module.
Path-scoped plans never select the remainder shards.

## Functional coverage shards

Most of the code the in-process suites miss (the HTTP/3 server and
cross-protocol bridge, `src/proxy/mod.rs`, the TCP/UDP proxies, the
database/file/CP/DP mode runtimes, and the MongoDB store) is exercised only by
the functional suite, which drives a real `ferrum-edge` process. Every full plan
therefore adds three functional shards after the integration shards:

- `functional-1` and `functional-2` split every functional module except the
  service-backed ones with `nextest --partition hash:N/2`. New functional
  modules join them automatically; no filter list needs updating.
- `functional-data` runs the service-backed modules (the `data-plane` and
  `data-plane-runtime` modules of `ci.yml`'s Functional Tests) serially against
  plaintext Redis, MongoDB (standalone and replica set), PostgreSQL, and MySQL
  containers. The list lives in `FUNCTIONAL_DATA_MODULES` in
  `.github/scripts/coverage_plan.py`; a module that moves into ci.yml's
  data-plane shards should be added there too, or it runs in a partition shard
  without its services. The database TLS fixtures are not started, so those
  cells skip.

Path-scoped plans never select the functional shards; a scoped plan that
selects every integration shard is promoted to the full matrix, which includes
them.

Each functional shard first builds `functional_tests` under
`cargo llvm-cov nextest` with a filter that selects no test, which also builds
the instrumented `ferrum-edge` binary into `target/llvm-cov-target/debug/`. The
step exports it as `FERRUM_EDGE_TEST_BIN`, which every functional spawner
resolves first, and hard-links it to the fixed `target/debug/ferrum-edge`
fallback path so no resolution path can launch an uninstrumented build. It is a
hard link, not a symlink, because `functional_cli_test` hard-links the resolved
binary into temp directories, and a relative symlink copied that way dangles. The test run
reuses that binary: `--no-report` implies cargo-llvm-cov's `--no-clean` (the two
flags conflict), so it does not run `cargo clean -p ferrum-edge` and rebuild the
linked binary. The step sets `FERRUM_SKIP_GATEWAY_BUILD=1` so no test process
rebuilds an uninstrumented binary. The spawned gateways inherit
`LLVM_PROFILE_FILE` and write their profiles next to the test binaries'
profiles when they exit. The step sets
`LLVM_PROFILE_FILE_NAME=ferrum-edge-functional-%4m.profraw`: the default
cargo-llvm-cov name carries `%p`, which would write one multi-megabyte profile
per test and gateway process, so every process of one binary instead merges
online into a pool of at most four files. A gateway stopped with SIGTERM flushes its profile; one stopped with SIGKILL (a
bare `Child::kill()`) does not, so moving legacy `kill()` teardown to the shared
graceful-shutdown helper raises measured coverage without new tests.

`ci.yml`'s Functional Tests shards are the correctness gate for this suite. A
functional coverage shard therefore only warns on test failures (it runs with
`--retries 1`), because instrumented debug binaries are slower and a
timing-sensitive failure must not fail the coverage floor. It still fails when
the instrumented binary was not built or the run wrote no profiles.

## Artifact fan-in transport and measurements (#4670)

Shard uploads retain the same Actions ZIP containing one
`coverage-<shard>.tar`, the same packaging `find` exclusions, raw profiles,
object files, executable permissions, retention, and default ZIP compression.
The merge job downloads the compressed ZIP through the Actions artifact API
and streams its single tar member through `unzip -p` into `tar -xpf -`.
This avoids writing and rereading the intermediate uncompressed tar. It stages
only one compressed archive at a time and preserves the planner's sequential
extraction/overwrite order for objects and other shared paths. No objects are
stripped, deduplicated, renamed, or selected differently; no profiles are
pre-merged.

Raw profiles are the exception to shared-path overwriting (#6378). Their
target-relative names can coincide across runners. cargo-llvm-cov's default
`<package>-%p-%Nm.profraw` name repeats when two runners reuse a pid for the
same binary signature. The functional shards' pooled
`ferrum-edge-functional-%4m.profraw` name carries only the binary signature.
Right after each shard's tar is extracted, every `*.profraw` it produced is
renamed in place to `<name>.fanin-<shard>.profraw`, before the next shard is
extracted. An existing destination fails the step. `cargo llvm-cov report`
merges every top-level `*.profraw` in `target/llvm-cov-target/` whatever its
name, so every shard's counters reach the report.

Artifact IDs come only from the current workflow run's paginated artifact list.
Each planned name must resolve uniquely to a non-expired artifact, and its ZIP
must contain exactly the expected tar member. Download failures retain the
two-attempt retry; failed downloads, invalid ZIPs, CRC errors, tar failures, and
missing profiles fail the step. The pipeline drains tar end padding so ZIP CRC
verification finishes, and `pipefail` preserves both processes' failures.
The required `Merge Coverage` check, shard-success checks, report commands,
ignore regex, full/changed-line gates, and exact-SHA publication evidence are
unaffected by this transport (floors: see
[CI Baseline And Gates](#ci-baseline-and-gates)).

Pre-streaming timing measurements were taken from successful main runs
[34008463617](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34008463617)
and [34018271783](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34018271783)
on 2026-09-06 (issue #4670). Streaming removes the intermediate tar writes and
rereads (its net wall-time benefit was not measured); ZIP size, upload cost,
report generation, and compilation latency are not expected to improve.

Hosted workflow regression tests exercise the actual transport shell using
small ZIP/tar fixtures: forced ZIP64 headers, pagination, unplanned artifacts,
retried partial downloads, exhausted retries, missing/expired/duplicate planned
artifacts, wrong/extra ZIP members, CRC errors, invalid tars, missing
profiles, profile bytes, executable modes, sequential shared-object
overwrites, and two shard artifacts carrying the same raw-profile path, which
must both survive as shard-tagged top-level profiles. Actual coverage artifacts retain their format and objects; ZIP CRC
checks validate the stream on every hosted merge. The step summary now records
exact ZIP/tar bytes, download/extraction seconds per shard, and fan-in wall time
for comparison with subsequent exact-head CI.

Cancellation remains a separate limitation: GitHub re-evaluates job and step
conditions, and an `always()` job can continue after cancellation
([workflow cancellation reference](https://docs.github.com/en/actions/reference/workflows-and-actions/workflow-cancellation)).
Both sampled runs succeeded, so they do not measure a cancellation delay.
The required aggregate's existing `always()` and failure semantics are retained;
changing cancellation behavior needs a dedicated failing/cancelled-run check.
