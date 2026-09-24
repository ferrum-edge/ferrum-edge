# PR validation review, September 24, 2026

This review asks three questions: does each pull request run only the
validation its diff can affect, which validations can move from the PR path to
post-merge `main`, and what that saves. The measurements use a replay of
merged pull requests through the baseline and candidate gate code
(`.github/scripts/ci_gate_replay.py`), plus hosted job durations from the
GitHub Actions API.

No workflow was dispatched for this review. Branch protection, the nine
required checks, and the release publication gate are unchanged.

## Sample

- **Replay:** 646 pull requests merged to `main` between 2026-08-24 and
  2026-09-23. Each sample's changed-file list is the first-parent diff of its
  merge commit.
- **Command:** `python3 .github/scripts/ci_gate_replay.py --since 2026-08-24`.
  The baseline is `origin/main` at `471126f`; the candidate is this change.

## Findings and changes kept

### 1. Optional profiling lanes ran on almost half of all pull requests

`pool-internal-profile.yml`, `h1-internal-profile.yml`, and
`udp-internal-profile.yml` compile the gateway with observer features and run
contract suites. Their `checks` jobs have 90–120 minute budgets. None of them
is a required check or a release gate. Their `pull_request.paths` included
shared, high-traffic paths such as `src/proxy/**`, `src/lib.rs`, `src/main.rs`,
`Cargo.toml`, `Cargo.lock`, `tests/unit/gateway_core/**`, and
`tests/scaffolding/**`. None of them ran on `main`.

**Change:** the PR trigger now covers only each profiler's own sources, tests,
harness scripts, doc, and workflow. The previous broad path list moved to
`push` on `main`. A shared-code change that breaks an observer build now shows
up post-merge, where the commit can be reverted before a release is cut.
Before this change it could only ever show up on a pull request.

| Workflow | PR runs, baseline | PR runs, candidate |
|---|---:|---:|
| `pool-internal-profile.yml` | 281 | 1 |
| `h1-internal-profile.yml` | 203 | 3 |
| `udp-internal-profile.yml` | 131 | 1 |

That is 610 fewer optional workflow runs per 30 days. The runs are replaced by
at most one run per matching `main` push.

### 2. Editing `ci.yml` started four Kind live suites

`live_suite_path_filter.py` listed `.github/workflows/ci.yml` as a trigger for
the Gateway API, multicluster (federation and poller partition), sidecar, and
Ambient Host UDP suites. Those suites are separate workflows that never
execute `ci.yml`. The trigger dates from when their smoke jobs lived in
`ci.yml`.

**Change:** `ci.yml` is removed from those four pattern lists. Each suite's
own workflow file is still a trigger. Every suite still runs in full on each
push to `main`, and it is still required on pull requests whose paths match
its scope.

| Live suite (required check) | PR runs, baseline | PR runs, candidate |
|---|---:|---:|
| `gateway-api` (Gateway API Conformance) | 145 | 99 |
| `mesh-federation` (Multicluster Federation Live **and** Poller Partition Live) | 144 ×2 | 89 ×2 |
| `mesh-e2e-sidecar` (Mesh E2E Sidecar Live) | 151 | 97 |
| `ambient-host-udp` (Ambient Host UDP Live) | 157 | 119 |

That is 248 fewer Kind-cluster jobs per 30 days.

### 3. Standalone benchmark workspaces started the full Rust lane

`run_rust` matched `^tests/(?!k8s/)`, which includes `tests/performance/**`.
That tree holds separate cargo workspaces (`multi_protocol`, the `mesh`
Criterion workspace, `payload_size`). The root crate declares no target there
and no `ci.yml` job builds them. `benchmark-harness-tests.yml`,
`performance-regression.yml`, and `rr-build-comparison.yml` own them. Root-crate
tests embed exactly two files from that tree.

**Change:** `tests/performance/` is excluded from `run_rust` except for
`PERFORMANCE_TREE_WORKSPACE_INPUTS`. The trusted planner self-test scans
`src/**/*.rs` and `tests/**/*.rs`. It fails when root-crate code references any
other `tests/performance/` path, so a new embedded fixture cannot silently drop
out of the gate.

Result: 17 fewer full compile-and-test runs (unit ×5, lint, test artifacts,
integration ×2, functional ×3, Redis regression) per 30 days.

### 4. Superseded runs were never cancelled in 16 side workflows

Sixteen path-filtered workflows had no `concurrency:` block:
`benchmark-harness-{lockfile,tests}`, `ci-latency-report`,
`{h1,pool,udp}-internal-profile`, `h2-guard-observation`,
`mesh-benchmark-lockfile`, `native-{cache-envelope,compiler-store}`,
`release-{platform,profile}-study`, `release-sbom-smoke`,
`rr-build-comparison`, and `trusted-policy-candidate`. `h3-live-comparison`
explicitly disabled cancellation. A new push to the same pull request left
every older run holding its runner. Several of these jobs run for 45–120
minutes, and `release-platform-study` fans out across operating systems.

**Change:** each of these workflows now uses a pull-request-scoped group that
cancels superseded PR runs. Push, dispatch, and schedule runs get a unique
group, so they are never cancelled and never displace each other.

### 5. Replay tool

`.github/scripts/ci_gate_replay.py` makes future gate changes measurable before
merge. It evaluates the baseline and candidate revisions of the planner, the
live-suite filter, and every workflow's `on.pull_request.paths` against real
merged PRs. It reads Git objects only. Its `--self-test` (glob translation,
merge-subject parsing, trigger semantics) runs inside `verify_required_ci.py`
in the `Tests` aggregate.

### 6. Stale pin in an optional lane (found while validating this PR)

This PR's own CI turned `H2 pinned guard regressions` (`h2-guard-observation.yml`)
red. The workflow pins the SHA-256 of `src/admin/mod.rs` so its diagnostic
metrics hook is applied only to a reviewed context. #5661 changed that file on
`main` on 2026-09-23. The pin went stale on `main`, and nothing noticed: the
workflow has no push trigger and ran again only because this PR edited its
YAML. The pin was refreshed here. The anchor still occurs once and the hook
bytes are unchanged.

Optional lanes that pin source hashes need a post-merge trigger on the pinned
file, or they fail on whichever unrelated PR happens to touch them next. See
the follow-ups below.

## Unchanged by design

- **Required set and release gate:** the nine required checks and
  `.github/required-publication-checks.json` are unchanged. Every live suite,
  FIPS, coverage, and full `ci.yml` still run on each push to `main`.
  `verify_publication_gate.py` still requires all nine to be green at the
  exact release SHA. This is the "blocker to a new release cut" safety net
  that allows the narrower PR scoping.
- **FIPS (`ci_runtime_plan.py` `fips-build`):** already scoped to FIPS logic.
  124 of 646 PRs (19%) run it, driven by `src/http3/server.rs`, `src/tls/`,
  `tests/unit/tls/`, and `Cargo.*`. It is required, so it is left unchanged.
- **Production Dockerfile smoke:** already skips ordinary source changes.
  29 of 646 PRs (4%) run it.

## Follow-ups (not in this PR)

- **Pinned-hash optional lanes:** give `h2-guard-observation.yml` (and any
  lane that pins a `src/` file hash) a `push: main` trigger on the pinned
  files. Pin drift then surfaces on the commit that caused it, not on an
  unrelated PR.
- **NodeWaypoint eBPF Live on PRs:** this check isn't required. On pull
  requests it runs for any `src/modes/mesh/`, `src/plugins/mesh/`,
  `charts/ferrum-mesh/`, or `src/k8s_controller/` change: 128 of 646 PRs (20%)
  in the sample. Narrowing it to NodeWaypoint-owned paths and relying on the
  `main` run would drop most of those 120-minute Kind/eBPF jobs. Its relevance
  job is frozen by `NODE_WAYPOINT_RELEVANCE_CONTRACT` in
  `verify_cross_build_policy.py`, so this needs a direct-to-`main` policy
  change.
- **Merge-queue cost:** `ci_runtime_plan.py` force-runs FIPS, the production
  images, and NodeWaypoint on `merge_group`. If the merge queue becomes the
  normal path, give those suites the same path gating `pull_request` gets.
