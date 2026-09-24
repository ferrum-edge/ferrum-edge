# PR validation review, September 24, 2026

This review asks three questions: does each pull request run only the
validation its diff can affect, which validations can move from the PR path to
post-merge `main`, and what that saves. Two measurements back it:

- **Scheduling:** a replay of merged pull requests through the baseline and
  candidate gate code (`.github/scripts/ci_gate_replay.py`).
- **Cost:** hosted job durations from the GitHub Actions API.

No workflow was dispatched for this review. Branch protection, the nine
required checks, and the release publication gate are unchanged.

## Summary

| Change | Effect per 30 days (646 merged PRs) |
|---|---|
| Profile lanes: PR trigger limited to profiler paths; daily run on `main` | 610 fewer PR runs; about **30,100 runner-minutes** net of the daily runs |
| `ci.yml` edits no longer start the Kind live suites | 248 fewer Kind jobs; about **5,100 runner-minutes** |
| `tests/performance/**` benchmark workspaces no longer start the Rust lane | 17 fewer full Rust lanes; about **2,100 runner-minutes** and about 35 minutes of wall time on each of those PRs |
| Data-plane functional shard split in two | Estimated median full-mode PR wall time from about 34.6 to about 32 minutes (not yet measured); costs about 1,200 extra runner-minutes |
| Superseded PR runs cancelled in 16 side workflows | Unmeasured; each saves up to the full job length per extra push |
| Replay tool plus its self-test in `Tests` | Future gate changes can be measured before merge |

- **Net:** at least **36,000 runner-minutes (about 600 runner-hours) per 30
  days**, with no change to the required set.
- **Why that is a floor:** every figure counts one PR run per merged PR. Real
  PRs get several pushes, and the replay counts only the merged diff.

## Method

- **Replay:** the 646 pull requests merged to `main` from 2026-08-24 to
  2026-09-23. Each sample's changed-file list is the first-parent diff of its
  merge commit. Command:
  `python3 .github/scripts/ci_gate_replay.py --since 2026-08-24`. The baseline
  is `origin/main` at `471126f`; the candidate is this change.
- **Durations:** median hosted job durations (`completed_at - started_at`),
  from `list_workflow_jobs` on recent non-cancelled runs:
  - `ci.yml`: 12 full-mode PR runs, 2026-09-20 to 2026-09-24.
  - Profile workflows: 7 to 8 PR runs each.
  - Live suites: 5 to 7 runs each, from either PRs or `main` pushes.
- **Merge queue:** the last `merge_group` CI run was on 2026-09-05. The queue
  is currently unused, so every figure is pull-request cost.

## Current PR critical path (`ci.yml`, full mode)

The median wall time from run creation to `Tests` is 34.6 minutes (p90 35.6).

| Phase | Median minutes after run creation |
|---|---:|
| `CI Plan` done (`CI Policy` runs in parallel, 3.1 min) | 1.4 |
| Unit shards done (lib 8.0, gateway-core 8.5, core 11.4, plugins-a 11.4, plugins-b 13.6); Lint done (10.8) | 9.3–14.7 |
| `Build Test Artifacts` done (16.5 min job) | 17.8 |
| Functional shards done: application 7.1, protocols 13.7, **data-plane 16.3** | 25.0 / 31.4 / **34.2** |

`Functional Tests (data-plane)` was the last job to finish in 12 of 12 sampled
runs. Its 16.3 minutes are about 48 s of database container startup plus 915 s
of tests run serially (`nextest_jobs: 1`). The busiest modules in that 915 s
(job 107510432828):

| Module | Seconds |
|---|---:|
| `functional_admin_crud_resources_test` (`test_admin_mongodb_runtime_resource_crud_matrix` alone: 244) | 301 |
| `functional_mesh_mode_test` | 136 |
| `functional_redis_rate_limiting_test` | 83 |
| `functional_database_parity_test` | 73 |
| `functional_mongodb_test` | 71 |
| `functional_db_outage_test` | 67 |
| Everything else | 184 |

## Changes kept

### 1. Optional profiling lanes ran on almost half of all pull requests

`pool-internal-profile.yml`, `h1-internal-profile.yml` and
`udp-internal-profile.yml` compile the gateway with observer features and run
contract suites. None is a required check or a release gate. Their
`pull_request.paths` included shared, high-traffic paths:

- `src/proxy/**`, `src/lib.rs`, `src/main.rs`
- `Cargo.toml` and `Cargo.lock`
- `tests/unit/gateway_core/**` and `tests/scaffolding/**`

**Change:**
- **PR trigger:** now only each profiler's own sources, tests, harness scripts,
  doc, and workflow.
- **Broader coverage:** the shared surfaces are re-validated by a daily
  scheduled run on the `main` tip. A red daily run points at that day's
  merges for revert or bisect before a release is cut. Previously these lanes
  never ran on `main` at all.
- **Why daily and not per push:** about 280 merges a month match the pool
  profiler's former paths. One run per merge would give most of the saving back.

| Workflow | Job median (min) | PR runs, baseline → candidate | Runner-minutes removed |
|---|---:|---|---:|
| `pool-internal-profile.yml` | 48.8 | 281 → 1 | 13,660 |
| `h1-internal-profile.yml` | 79.7 (feature checks 37.3 + cadence on 22.1 + cadence off 19.7 + fixtures 0.6) | 203 → 3 | 15,940 |
| `udp-internal-profile.yml` | 43.9 | 131 → 1 | 5,710 |
| Daily runs added back | 172.4 per day | — | −5,170 |
| **Net** | | | **≈30,100** |

### 2. Editing `ci.yml` started four Kind live suites

`live_suite_path_filter.py` listed `.github/workflows/ci.yml` as a trigger for
the Gateway API, multicluster (federation and poller partition), sidecar, and
Ambient Host UDP suites. Those suites are separate workflows that never
execute `ci.yml`; the trigger dates from when their smoke jobs lived there.

**Change:** `ci.yml` is removed from those four pattern lists.
- Each suite's own workflow file is still a trigger.
- Every suite still runs in full on each push to `main`.
- Each suite stays required on PRs whose paths match its scope.

| Live suite (required check) | Job median (min) | PR runs, baseline → candidate | Runner-minutes removed |
|---|---:|---|---:|
| Gateway API Conformance | 15.8 | 145 → 99 | 730 |
| Multicluster Federation Live | 18.2 | 144 → 89 | 1,000 |
| Multicluster Poller Partition Live | 16.1 | 144 → 89 | 890 |
| Mesh E2E Sidecar Live | 21.6 | 151 → 97 | 1,170 |
| Ambient Host UDP Live (live 28.9 + image reader 6.1) | 35.0 | 157 → 119 | 1,330 |
| **Total** | | 248 fewer jobs | **≈5,100** |

### 3. Standalone benchmark workspaces started the full Rust lane

`run_rust` matched `^tests/(?!k8s/)`, which includes `tests/performance/**`.

- **What that tree holds:** separate cargo workspaces (`multi_protocol`, the
  `mesh` Criterion workspace, `payload_size`). The root crate declares no
  target there and no `ci.yml` job builds them.
- **Who owns them:** `benchmark-harness-tests.yml`,
  `performance-regression.yml`, and `rr-build-comparison.yml`.
- **What root-crate tests read:** exactly two files from that tree.

**Change:** `tests/performance/` is excluded from `run_rust` except for
`PERFORMANCE_TREE_WORKSPACE_INPUTS`. The trusted planner self-test scans
`src/**/*.rs` and `tests/**/*.rs`. It fails when root-crate code references any
other `tests/performance/` path, so a newly embedded fixture cannot silently
drop out of the gate.

**Result:** 17 fewer full Rust lanes. Each lane costs a median of 125.6
runner-minutes (all always-run `ci.yml` jobs), so about 2,100 runner-minutes.

### 4. The data-plane functional shard was the PR critical path

**Change:** the shard is split into `data-plane` and `data-plane-runtime`.

- **Balance:** by the measured module times, about 509 s and 406 s of serial
  tests.
  - `data-plane`: admin CRUD matrix, MongoDB, DB parity, DB TLS, database, DB
    upstream, DB failover.
  - `data-plane-runtime`: mesh mode, stock xDS, Redis rate limiting, DB outage,
    trust-bundle HA, namespace, capability registry, plugin quarantine, CP/DP.
- **Containers:** each runner starts its own Redis, MongoDB, PostgreSQL and
  MySQL containers.
- **Unchanged:** serialization within each shard, and every URL, TLS fixture
  and `*_REQUIRED` flag.
- **Gating:** container startup and backend URLs are now keyed on a
  `data_services: true` matrix field instead of the shard name.
  `functional_ci_shard_coverage_test` still proves every module is assigned
  to a shard.

**Expected result:**
- The slowest functional shard becomes `protocols` (13.7 min), so the
  full-mode critical path drops from about 34.2 to about 31.5 minutes after
  run creation.
- That is roughly 2.7 minutes, about 8% faster, on each of the 553 Rust PRs a
  month.
- The cost is one more runner's setup and container start: about 2.1 minutes,
  or about 1,200 runner-minutes a month.
- These are estimates from the per-module times. Confirm them against the
  hosted durations of the first few runs after merge.

### 5. Superseded runs were never cancelled in 16 side workflows

Sixteen path-filtered workflows had no `concurrency:` block, and
`h3-live-comparison` explicitly disabled cancellation:

- `benchmark-harness-lockfile`, `benchmark-harness-tests`
- `ci-latency-report`
- `h1-internal-profile`, `pool-internal-profile`, `udp-internal-profile`
- `h2-guard-observation`
- `mesh-benchmark-lockfile`
- `native-cache-envelope`, `native-compiler-store`
- `release-platform-study`, `release-profile-study`, `release-sbom-smoke`
- `rr-build-comparison`
- `trusted-policy-candidate`

A new push to the same pull request left every older run holding its runner.
Two examples:

- `release-platform-study` fans out across Linux, macOS and Windows.
- The profile checks run for 40–80 minutes.

**Change:** each workflow now uses a pull-request-scoped group that cancels
superseded PR runs. Push, dispatch and schedule runs get a unique group, so
they are never cancelled and never displace each other. This PR's own CI
showed the effect: H1 Internal Profile runs on superseded heads were cancelled.

### 6. Replay tool

`.github/scripts/ci_gate_replay.py` makes future gate changes measurable before
merge.

- **What it compares:** the baseline and candidate revisions of the planner,
  the live-suite filter, and every workflow's `on.pull_request.paths`,
  evaluated against real merged PRs.
- **What it reads:** Git objects only.
- **Self-test:** `--self-test` (glob translation, merge-subject parsing,
  trigger semantics) runs inside `verify_required_ci.py` in the `Tests`
  aggregate.

### 7. Stale pin in an optional lane (found while validating this PR)

This PR's own CI turned `H2 pinned guard regressions`
(`h2-guard-observation.yml`) red.

- **What the pin is for:** the workflow pins the SHA-256 of `src/admin/mod.rs`
  so its diagnostic metrics hook is applied only to a reviewed context.
- **How it went stale:** #5661 changed that file on `main` on 2026-09-23.
  Nothing noticed, because the workflow has no `main` trigger and only ran
  again because this PR edited its YAML.
- **Fix in this PR:** the pin is refreshed. The anchor still occurs once and
  the hook bytes are unchanged.

## Unchanged by design

- **Required set and release gate:**
  - The nine required checks and `.github/required-publication-checks.json`
    are unchanged.
  - Every live suite, FIPS, coverage, and full `ci.yml` still run on each push
    to `main`.
  - `verify_publication_gate.py` still requires all nine to be green at the
    exact release SHA. That post-merge gate is what makes the narrower PR
    scoping safe.
- **Trusted policy:** on this PR's second head (`1ca78e9`), `CI Policy`
  reported `verified=true` and `Trusted Cross Build Policy` ran on the same
  changes. The data-plane shard split edits the frozen `test-functional` job
  in `ci.yml`, so it may need a reviewed policy decision if the trusted
  verifier rejects it.
- **FIPS (`ci_runtime_plan.py` `fips-build`):** already scoped to FIPS logic.
  124 of 646 PRs (19%) run it, driven by `src/http3/server.rs`, `src/tls/`,
  `tests/unit/tls/`, and `Cargo.*`. It is required, so it stays.
- **Production Dockerfile smoke:** already skips ordinary source changes.
  29 of 646 PRs (4%) run it.
- **Unit shards and Lint:** each finishes before `Build Test Artifacts`, so
  none is on the critical path.

## Follow-ups (not in this PR)

- **Faster `Build Test Artifacts`:** the next critical-path lever after the
  shard split (16.5 min). It builds the gateway, the CNI binary, and both
  nextest archives in sequence. Splitting the functional archive build from
  the integration archive, or starting integration shards on a separate
  producer, would shorten the path further.
- **Pinned-hash optional lanes:** give `h2-guard-observation.yml` (and any lane
  that pins a `src/` file hash) a `push: main` trigger on the pinned files.
  Pin drift then surfaces on the commit that caused it, not on an unrelated PR.
- **NodeWaypoint eBPF Live on PRs:** this check isn't required.
  - **Current cost:** it runs on 128 of 646 PRs (20%), about 28.7 min per run,
    triggered by `src/modes/mesh/`, `src/plugins/mesh/`, `charts/ferrum-mesh/`,
    and `src/k8s_controller/`.
  - **Proposal:** narrow it to NodeWaypoint-owned paths and rely on the `main`
    run. That would save roughly 3,000 runner-minutes a month.
  - **Constraint:** `NODE_WAYPOINT_RELEVANCE_CONTRACT` in
    `verify_cross_build_policy.py` freezes its relevance job, so this is a
    direct-to-`main` policy change.
- **Merge-queue cost:** `ci_runtime_plan.py` force-runs FIPS, the production
  images, and NodeWaypoint on `merge_group`. If the merge queue comes back into
  use, give those suites the same path gating `pull_request` gets.
