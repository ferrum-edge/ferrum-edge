# CI/CD Pipeline Documentation

Ferrum Edge includes comprehensive CI/CD pipelines for automated testing, building, and releasing.

## Table of Contents

- [Pipeline Overview](#pipeline-overview)
- [Workflow Inventory](#workflow-inventory)
- [CI Pipeline (ci.yml)](#ci-pipeline-ciyml)
- [CI runtime caching (production images and FIPS)](#ci-runtime-caching-production-images-and-fips)
- [Release Pipeline (release.yml)](#release-pipeline-releaseyml)
- [Process supervision](#process-supervision)
- [How Releases Work](#how-releases-work)
- [Creating a New Release](#creating-a-new-release)
- [Binaries and Downloads](#binaries-and-downloads)
- [Image Signatures, SBOMs, and Provenance](#image-signatures-sboms-and-provenance)
- [GitHub Actions Secrets](#github-actions-secrets)
- [Root Merge Gate Attestation](#root-merge-gate-attestation)

## Pipeline Overview

The publish-critical flows are `ci.yml` and `release.yml`: CI validates PRs,
merge-queue groups, and `main`, then publishes `latest` artifacts from `main`;
Release publishes versioned artifacts from `v*` tags. Additional workflows
provide coverage, scheduled dependency governance, live datapath/conformance
labs, manual benchmark suites, and repository maintenance automation.

| Workflow | Trigger | Purpose |
|----------|---------|---------|
| **CI** (`ci.yml`) | Pull Requests, `merge_group`, push to `main` | Required validation for PRs, merge-queue groups, and `main`; latest binaries and Docker images after `main` validation |
| **Release** (`release.yml`) | Push tag matching `v*` | Validate the tagged SHA, then publish versioned binaries, GitHub release, and Docker tags |

## Workflow Inventory

Workflow files live under `.github/workflows/`. Keep this table in sync when
adding, removing, or materially changing a workflow.

| Workflow file | Display name | Triggers | Role |
|---|---|---|---|
| `ci.yml` | CI | PRs, `merge_group`, push to `main`, manual | Required validation gate plus `latest` prerelease and Docker image publishing from `main`. The `Tests` check runs on PRs and merge-queue groups. |
| `coverage.yml` | Coverage | PRs, `merge_group`, push to `main`, weekly schedule, manual | Coverage planning/reporting and coverage floor enforcement; `Merge Coverage` is directly required on PRs and merge-queue groups. |
| `fips-build.yml` | FIPS Build Policy | PRs, `merge_group`, push to `main`, manual | Required FIPS feature-graph audit plus compile/clippy/handshake gate. Warm PR target <=30 minutes (p95 <=45); see [CI runtime caching](#ci-runtime-caching-production-images-and-fips). |
| `release.yml` | Release | `v*` tag push | Versioned binary, GitHub Release, and Docker publishing after CI/Coverage validation. |
| `gateway-api-conformance.yml` | Gateway API Conformance | PRs, `merge_group`, push to `main`, weekly schedule, manual | Upstream Gateway API conformance lab; `Gateway API Conformance` is directly required on PRs and merge-queue groups. |
| `mesh-e2e-sidecar-live.yml` | Mesh E2E Sidecar Live Datapath | PRs, `merge_group`, push to `main`, manual | Release-blocking sidecar datapath validation; `Mesh E2E Sidecar Live` is directly required on PRs and merge-queue groups. |
| `cross-build-policy.yml` | Cross Build Policy | `pull_request_target` for PRs to `main`, `merge_group` | Read-only trusted-base validation of every PR-controlled ARM64 Cross configuration and invocation surface on PRs; merge-group mode verifies the synthesized combined SHA with `contents: read` only. `Trusted Cross Build Policy` is directly required. |
| `ambient-host-udp-live.yml` | Ambient Host UDP Live Kernel | Every PR, `merge_group`, push to `main`, manual | Privileged live-kernel gate for Ambient host-network UDP capture (`ProxyHostUdpBackend`), plus a production-image contract job that proves the chart-selected `-ebpf-tools` runtime can execute the shell/iptables tool set while `-ebpf` stays distroless; relevance is decided by a trusted-base classifier and `Ambient Host UDP Live` reports on every run. Issue #4302 added the unconditional `push: main` trigger so publication can bind exact-main-SHA evidence. |
| `node-waypoint-ebpf-live.yml` | NodeWaypoint eBPF Live Datapath | Every PR, `merge_group`, push to `main`, manual | Live eBPF datapath validation in kind plus the production-image smoke. Relevance is decided by a trusted-base classifier and `NodeWaypoint eBPF Live` reports on every run; it is **not** a required live-suite check. |
| `istio-status-cas-live.yml` | Istio Status CAS Live | Every PR, `merge_group`, push to `main`, manual | Kind/apiserver competing-writer proof that Ferrum's Istio status CAS preserves foreign and Ferrum-owned conditions. Relevance is decided by a trusted-base classifier and `Istio Status CAS Live` reports on every run; **not** a required live-suite check. |
| `cni-lifecycle-live.yml` | CNI Install Lifecycle Live | Every PR, `merge_group`, push to `main`, manual | Live CNI install/uninstall lifecycle recovery proof in kind. Relevance is decided by a trusted-base classifier and `CNI Lifecycle Live` reports on every run; **not** a required live-suite check. |
| `multicluster-federation-live.yml` | Multicluster Federation Live Datapath | PRs, `merge_group`, push to `main`, manual | Release-blocking multicluster federation datapath validation; `Multicluster Federation Live` is directly required on PRs and merge-queue groups. |
| `multicluster-poller-partition-live.yml` | Multicluster Poller Partition Live | PRs, `merge_group`, push to `main`, manual | Release-blocking two-CP/two-DP trust/discovery partition and bounded last-good-retention validation; `Multicluster Poller Partition Live` is directly required. |
| `dependency-audit.yml` | Dependency Audit | Weekly schedule, manual | Scheduled supply-chain governance beyond the per-PR audit gate. |
| `fuzz.yml` | Fuzz | Weekly schedule, manual | Sanitizer-backed libFuzzer lane for hostile parser targets; see [fuzz.md](fuzz.md). |
| `scaling-regression.yml` | Scheduled Scaling Regression | Weekly schedule, manual | Runs the 30k proxy scale and 10k proxy load-stress tests excluded from PR CI. A follow-on publisher upserts a `severity:high` issue when the matrix is red. Publisher jobs share `scaling-gate-publisher` with `queue: max` and `cancel-in-progress: false` so overlapping weekly/daily work stays queued; GitHub does not guarantee FIFO, so issue mutation is generation-aware and close is compare-and-set against the recorded run id. |
| `scaling-gate-freshness.yml` | Scheduled Scaling Gate Freshness | Daily schedule, manual | Fail-closed freshness check of the latest scaling-regression run on `main`. Only a completed success within eight days may close that issue; a newer failure, cancel, timeout, skip, or in-progress run keeps it open, as does stale or missing history. The publish step runs even when static verification fails so a broken contract cannot stay silent. Shares the generation-aware publisher concurrency group (`queue: max`). |
| `protocol-perf-regression.yml` | Protocol Performance Regression | Weekly schedule, manual | Scheduled multi-protocol throughput/latency regression with churn, soak, resource plateaus, reload-under-load, versioned alert-only budgets, and machine-readable trends. Not a required PR check; see [protocol_perf_regression.md](protocol_perf_regression.md). |
| `mesh-performance-baselines.yml` | Mesh Performance Baselines | Manual (`workflow_dispatch`) and reusable (`workflow_call`) | Provenance-complete collection of mesh Criterion + HBONE/DNS E2E baseline artifacts for [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) on pinned `ubuntu-24.04`. Uploads `mesh-performance-baselines-<sha>`; fails selected-suite acceptance when gates are false (artifacts still upload); does not invent `baseline.md` numbers. |
| `claude-review.yml` | Claude PR Review | `@claude review` issue comment on PRs | Maintainer-triggered AI review comments. |
| `cleanup-pending-reviews.yml` | Cleanup Pending Deployment Reviews | Schedule, manual | Clears stale pending deployment review state. |
| `prune-stale-prs.yml` | Prune Stale PRs and Branches | Schedule, manual | Repository hygiene for stale PRs/branches. |
| `perf-benchmark.yml` | Multi Protocol Performance Benchmark | Manual | Multi-protocol benchmark suite for selected refs. |
| `payload-size-benchmark.yml` | Payload Size Performance Benchmark | Manual | Payload-size benchmark suite for selected refs. |
| `comparison-benchmark.yml` | Gateway Comparison Benchmark | Manual | Cross-gateway comparison benchmarks. |
| `gateways-protocol-benchmark.yml` | Gateways Protocol Benchmark | Manual | Gateway/protocol benchmark harness. |
| `connection-saturation-benchmark.yml` | Connection Saturation Benchmark | Manual | Connection saturation benchmark suite. |
| `scale-benchmark.yml` | Resources Scale Benchmark | Manual | Large resource/config scale benchmark suite. |
| `root-merge-gate-attestation.yml` | Root Merge Gate Attestation | Manual (`workflow_dispatch` on `main` only) | Supplies the single required human-root approval for one exact independently reviewed PR head after hosted checks and review-thread resolution; see [Root Merge Gate Attestation](#root-merge-gate-attestation). |

### CI Pipeline Flow

```
Pull Request / Merge Queue group
    ├─► Trusted Cross Build Policy
            ├─► PR: `pull_request_target`, base code only, PR tree as data
            └─► Merge group: synthesized queue SHA, `contents: read`, no secrets
    ├─► CI plan (event-aware base/head; merge_group uses payload base_sha)
            ├─► Docs/license/agent-only: lightweight Tests aggregate
            └─► Full CI
                    ├─► Format + integration-shard coverage (in CI plan)
                    ├─► Unit+inline-lib / integration-shard / functional-shard tests
                    ├─► Planner-gated Secret Backends / PKCS#11 SoftHSM jobs
                    ├─► Lint, dependency audit, vendored regressions
                    ├─► Fuzz smoke (property budgets on PRs; the seven-target
                    │   libFuzzer budget on push to main / manual)
                    ├─► Per-suite eBPF kernel / netns-capture / two-cluster live checks when planner marks relevant
                    ├─► Planner-gated Helm / eBPF / Secret Backends / PKCS#11 / performance gates
                    └─► Five target release builds
    └─► Dedicated required checks (internally skip unrelated changes)
            ├─► Merge Coverage
            ├─► Gateway API Conformance
            ├─► Mesh E2E Sidecar Live
            ├─► Multicluster Federation Live
            ├─► Multicluster Poller Partition Live
            └─► Ambient Host UDP Live

Push to main
    ├─► Full required validation gate
    └─► Four native release builds + isolated Linux ARM64 Cross build
            └─► Tests aggregate passes
                    ├─► Replace latest GitHub prerelease
                    └─► Push per-arch Docker images to Docker Hub and GHCR
                            └─► Create multi-arch Docker manifest (`latest`, `main-<sha>`)
```

### Required checks and merge queue

Branch protection / repository rulesets for `main` must require these nine
GitHub Actions check names (exact spelling; source app is **GitHub Actions**,
app id `15368`). The same nine are the publish-blocking set: see
[Publish-blocking required checks](#publish-blocking-required-checks).

| Required check name | Owning workflow | Owning job |
|---|---|---|
| `Tests` | `.github/workflows/ci.yml` | `test` |
| `Merge Coverage` | `.github/workflows/coverage.yml` | `coverage-merge` |
| `Gateway API Conformance` | `.github/workflows/gateway-api-conformance.yml` | `gate` |
| `Mesh E2E Sidecar Live` | `.github/workflows/mesh-e2e-sidecar-live.yml` | `gate` |
| `Trusted Cross Build Policy` | `.github/workflows/cross-build-policy.yml` | `verify` |
| `Multicluster Federation Live` | `.github/workflows/multicluster-federation-live.yml` | `gate` |
| `Multicluster Poller Partition Live` | `.github/workflows/multicluster-poller-partition-live.yml` | `gate` |
| `Ambient Host UDP Live` | `.github/workflows/ambient-host-udp-live.yml` | `gate` |
| `FIPS Build & Test` | `.github/workflows/fips-build.yml` | `fips-build` |

The launch-readiness governance lane (`launch-readiness.yml`,
`launch-integrity.yml`, `launch-advisory-trust.yml`, their verifiers, the blocker
policy/exemption data, and `release.yml`'s `validate-launch-readiness` job) was
removed once every tracked blocker had closed. There is no automated go/no-go
launch verdict, and a `v*` tag no longer requires one. `Launch Readiness
Integrity` must also be dropped from the branch ruleset's required contexts, or
pull requests will wait on a check that can never report.

Each owner declares a `merge_group` (`types: [checks_requested]`) trigger in
addition to its existing `pull_request` / `pull_request_target` / `push` /
schedule / manual triggers. Merge queues run required checks on the
`merge_group` event against a synthesized `gh-readonly-queue/main/...` commit.
`github.sha` / `merge_group.head_sha` is the exact code under validation;
`merge_group.base_sha` is the queue base. Workflows must not read
`github.event.pull_request.*` on `merge_group` (those fields are absent) and
must not silently fall back to a base/`main`-only check. Path-sensitive skips
are allowed only when that base/head range is derived successfully; otherwise
the required check fails closed or runs fully.

Concurrency groups include the event name and a PR number or merge-group head
SHA so a merge-group run cannot cancel an unrelated PR (or another group).

Required-check ownership validation accepts one fail-closed workflow layout:
the root jobs mapping is spelled as a literal block `jobs:`, job IDs are plain
mapping keys indented by two spaces, and direct job fields are mapping keys
indented by four spaces. Flow-form root/job mappings, explicit mapping keys,
alternate job indentation, and mapping indirection are rejected across the
complete workflow collection. Quoted, escaped, expression, and block-scalar
values remain supported inside a canonical direct `name` field; alias and tag
values are conservatively treated as possible owners.

**`merge_group` runs execute candidate workflow YAML.** GitHub loads workflow
files for a `merge_group` event from the synthesized queue commit, so unlike
`pull_request_target` there is no trusted-base copy of the workflow itself.
Merge-group runs still read their *executable inputs* from the payload base
(`verify_cross_build_policy.py`, `pr_ci_plan.py`, `live_suite_path_filter.py`
are all extracted from `merge_group.base_sha`), but the surrounding job
definition is candidate-supplied. The protected-file boundary therefore rests
on the queue's entry precondition: a merge queue admits a pull request only
after its required checks have already passed **on the pull request**, and the
PR-side `Trusted Cross Build Policy` run executes the base branch's workflow
under `pull_request_target` and rejects any change to
`.github/workflows/cross-build-policy.yml` or
`.github/scripts/verify_cross_build_policy.py`. Consequences for operators:

- Do **not** follow the common "trigger required checks on `merge_group` only"
  advice for these nine owners. Every owner must keep reporting on the pull
  request as well, and all nine must stay *required* so a failing PR-side check
  blocks queue entry. `verify_required_ci.py` enforces both the `merge_group`
  trigger and an unfiltered `pull_request` / `pull_request_target` trigger for
  each owner.
- `merge_group.base_sha` is the group's parent commit — the base branch tip
  plus any entries already ahead of this one in the queue — not necessarily the
  current `main` tip. Every entry ahead of it cleared the same required checks
  against its own base before being queued, which is what keeps the payload
  base usable as a trusted baseline.

**Live admin / no-bypass posture (root-owned repository settings; re-applied
and re-verified 2026-09-01, issue #4445):** classic branch protection and
ruleset `20208307` both require all nine GitHub Actions checks above, including
`FIPS Build & Test`. Classic protection enforces administrators
(`enforce_admins=true`); it previously did not, and it previously required only
seven contexts. The active ruleset has no bypass actors -- the standing
`OrganizationAdmin` / `bypass_mode: always` actor is removed, not narrowed --
and it blocks force pushes and deletion, requires one approval with stale
approvals dismissed on push, resolves review threads, and validates the combined
result through the merge queue. The pull-request and merge-queue parameters are
unchanged by this settings edit. The owner intentionally disabled GitHub's
"approval of the most recent reviewable push by someone other than the pusher"
rule (`require_last_push_approval=false`), so do not document or re-enable that
distinct restriction without an explicit settings decision.

After any future settings edit, re-query both protection APIs and confirm the
nine exact check names, GitHub Actions app id `15368`, admin enforcement, empty
bypass list, pull-request parameters, and merge-queue parameters. Exercise a
queued PR to prove every required owner reports on the synthesized SHA.

`.github/scripts/verify_required_ci.py` statically enforces merge_group
triggers, unfiltered `pull_request` / `pull_request_target` triggers,
check-name parity, event-aware SHA/base markers, and concurrency markers for
all nine owners.

### Publish-blocking required checks

`.github/required-publication-checks.json` is the ONE canonical,
machine-consumed inventory of publish-blocking required checks. Nothing may
carry an independent hard-coded subset beside it. Every artifact publication --
the mutable `latest` GitHub prerelease, the mutable `latest` / `main-<sha>`
Docker tags, and the immutable `v*` tag artifacts -- fails closed unless every
inventoried context is **successful for the exact product SHA** under trusted
workflow identity.

Each entry declares the required context, the canonical workflow file, path,
and display name, the owning job, how the `main` publishing path carries it
(`main_publication`), and how a run is bound to the SHA (`evidence`).

| Required context | Workflow | `main_publication` | `evidence` |
|---|---|---|---|
| `Tests` | `ci.yml` | `ci_job_dependency` | `check_run` |
| `Merge Coverage` | `coverage.yml` | `ci_main_publish_gate` | `push_main` |
| `Gateway API Conformance` | `gateway-api-conformance.yml` | `ci_main_publish_gate` | `push_main` |
| `Mesh E2E Sidecar Live` | `mesh-e2e-sidecar-live.yml` | `ci_main_publish_gate` | `push_main` |
| `Trusted Cross Build Policy` | `cross-build-policy.yml` | `publication_gate_job` | `pr_head` |
| `Multicluster Federation Live` | `multicluster-federation-live.yml` | `publication_gate_job` | `push_main` |
| `Multicluster Poller Partition Live` | `multicluster-poller-partition-live.yml` | `publication_gate_job` | `push_main` |
| `Ambient Host UDP Live` | `ambient-host-udp-live.yml` | `publication_gate_job` | `push_main` |
| `FIPS Build & Test` | `fips-build.yml` | `publication_gate_job` | `push_main` |

#### Why the `main` path has two halves

`ci.yml`'s `main-publish-gate` job, and the `needs` / `if` of `latest-release`,
`docker`, and `docker-manifest`, are frozen byte-for-byte by
`.github/scripts/verify_cross_build_policy.py`, a protected trusted-policy file
**no pull request may modify**. Its polling array therefore keeps carrying three
contexts, while `Tests` is carried by the publishing jobs' direct in-run
dependency. The remaining five are carried by a second job,
`main-publication-required-checks`, hosted in `gateway-api-conformance.yml` --
a workflow whose *run conclusion* the frozen array already requires to be
successful for the exact SHA before anything publishes. A failure there makes
that run's conclusion `failure`, so `main-publish-gate` refuses and neither
`latest-release` nor `docker` runs.

The two halves are not independent lists. `.github/scripts/verify_publication_gate.py`
parses the frozen array out of `ci.yml` and checks it for exact parity with the
`ci_main_publish_gate` entries, and checks the hosted
`main-publication-required-checks` job **structurally**: the exact main-push
`if`, `ubuntu-latest`, bounded `timeout-minutes`, the least-privilege
permissions mapping `contents: read` + `actions: read` with no extra or write
scopes, a pinned checkout, and the one named proof step that owns
`set -euo pipefail` plus both Python invocations. Comments, unrelated steps,
flow/duplicate/opaque spellings, `continue-on-error`, and extra job controls
do not count. The proof fail-closes over the whole `jobs:` mapping: a quoted,
escaped, or otherwise YAML-equivalent duplicate of either protected job, or
any opaque job-key spelling the dependency-free parser cannot prove distinct,
is rejected rather than leaving a canonical decoy as the inspected body. It
also proves `release.yml`'s `validate-release-sha` the same
way: exact `actions: read` / `checks: read` / `contents: read` mapping, no
failure-weakening fields, and the named tag-target step owning tag resolution,
ancestry proof, SHA export, self-test, and `--enforce release`. A hard-coded wait list is
still rejected. `.github/scripts/verify_required_ci.py` runs those checks, plus
parity between the inventory and `REQUIRED_MERGE_GROUP_WORKFLOWS`, on every pull
request. With those checks unmodified, adding a required context without
publication coverage fails policy CI, and an adversarial fixture exercises that
case.

The enforcement now has two distinct trust tiers:

- **Protected enforcement.** The trusted-base
  `.github/scripts/verify_cross_build_policy.py` comparison freezes
  `.github/scripts/verify_publication_gate.py` and
  `.github/required-publication-checks.json` by whole-file digest. It also
  freezes the complete `main-publication-required-checks` job body in
  `.github/workflows/gateway-api-conformance.yml`, just like the exact
  `main-publish-gate` job contract. A pull request cannot change any of those
  three surfaces. The trusted comparison checks the exact hosted job before
  the generic proposed-workflow scan, and checks the two whole-file digests
  before proposed automation reachability or executable-surface inspection;
  it treats candidate publication code only as data and never executes it.
- **PR-mutable parity checks.** `.github/scripts/verify_required_ci.py` still
  checks inventory, required-context, workflow, and hosted-job parity from the
  proposed tree. Those checks remain useful drift and consistency evidence,
  but they do not authorize a proposed change to the protected tier. The
  publication step's product-SHA `--self-test` is likewise runtime consistency
  evidence, not the trusted admission decision.

Changing either frozen file or the frozen hosted job is a direct-to-`main`
trusted-policy operation. Ordinary pull requests may still edit unrelated
parts of `gateway-api-conformance.yml`; only the complete
`main-publication-required-checks` body is frozen.

#### What counts as evidence

For every inventoried context the gate resolves the workflow through the
canonical `.github/workflows/<file>` endpoint and requires the server-reported
`id`, `path`, `name`, and `state: active` to match. For `push_main` and
`pr_head`, it then requires **every** matching run for the evidence SHA to have
`status: completed` and `conclusion: success`. A single passing duplicate never
masks a failed run of the same workflow. For release-path `check_run` evidence,
each canonical `ci.yml` push run is identified first and its check-suite ID must
own a successful `Tests` check run from the GitHub Actions app (id `15368`). The
CI workflow's aggregate conclusion is deliberately ignored, so an unrelated
Docker or publication-job failure cannot disqualify a successful `Tests` check.

Each polling sweep re-evaluates the complete selected set: a
completed success observed while another required context is still pending is
never cached, because GitHub permits rerunning a completed workflow and its
API record can return to `queued` / `in_progress` and later fail during the
wait. Publication is permitted only when one complete sweep sees every
selected context successful. Workflow identity may be reused while a context
is still pending so the token budget stays bounded; the sweep that would
permit freshly revalidates canonical workflow `id` / `path` / `name` /
`state: active` and PR binding before returning.

Blocking in all cases: missing, `queued`, `in_progress`, `waiting`, `failure`,
`cancelled`, `skipped`, `timed_out`, `stale`, `neutral`, `action_required`,
`startup_failure`, an unknown conclusion, an unrecognized status, a wrong
`head_sha`, a wrong `event`, a wrong `head_branch`, a wrong workflow `path` or
`id`, a run whose `repository` / `head_repository` is missing, malformed, or
not this repository, and a tag or commit that is not `main` or an ancestor of
it. A display name alone is never an identity. The `Tests` context is the one
intentional non-aggregate exception: the gate authenticates its named check run
through the canonical CI workflow's check-suite ID.

`push_main` evidence requires `event: push` on `head_branch: main`.
`pr_head` evidence first reads `/commits/{product_sha}` and
`/commits/{product_sha}/pulls`. The product commit must have a second parent and
exactly one associated pull request; that PR must be merged, target `main` in
this repository, and have a head SHA equal to the second parent. The gate then
requires every canonical `pull_request_target` run at that PR head and branch
to succeed. Zero or multiple associated PRs, an unmerged PR, a wrong base,
parent mismatch, or a non-merge commit all fail closed.

`check_run` evidence is used only by the release path for `Tests`. It lists the
canonical `ci.yml` push runs at the product SHA, binds their check-suite IDs to
the `Tests` check-run listing for that commit, and requires every bound check
run to be a completed GitHub Actions success.

#### Trigger changes and operational consequences

* `ambient-host-udp-live.yml` gained an unconditional `push: main` trigger
  (issue #4302) so `Ambient Host UDP Live` yields exact-main-SHA evidence
  instead of merge-group-only evidence. On a `main` push the frozen
  trusted-base relevance job takes its `--force-run` branch -- the branch it
  uses for every event that is neither `pull_request` nor `merge_group` -- so
  the full suite always executes and the required check is never a
  relevance-skipped green. `merge_group` is **not** force-run; it still
  classifies its own change set, which is exactly why merge-group-only evidence
  was insufficient. The trigger carries no `paths:` filter, because a filtered
  required gate can make publication evidence absent. Its `push` concurrency
  group is keyed by commit and is never cancelled, so a later push cannot wedge
  an earlier SHA's evidence. The cost is deliberate and material: every `main`
  commit now runs the full ~45-minute host-UDP kernel lab, superseded runs are
  not cancelled, and a burst of `main` pushes therefore runs one lab per commit
  concurrently.
* `cross-build-policy.yml` is itself protected and is a PR-admission policy, so
  publication uses `pr_head` evidence rather than treating that check as a
  property of the later `main` merge commit. A commit pushed **directly to
  `main`**, with no associated pull request, has no `pr_head` evidence and does
  not publish `latest`, the Docker tags, or a version tag. This is deliberate
  supply-chain behavior, including for an administrative direct push.
  Publication resumes when a normal merged pull request lands on top.
* Publication never races ahead of checks. The main gate polls once a minute;
  the release gate polls once every three minutes. They fail closed at their
  own deadlines (100 minutes on the `main` path, 160
  minutes on the release path) rather than proceeding on an unproven result.
  A success observed mid-wait is not a publication proof; the final permitting
  sweep must still see the entire selected set successful under freshly
  revalidated workflow identity. Rate-limited `403` / `429` responses and any
  `5xx` keep the sweep pending; `X-RateLimit-Reset` / `Retry-After` is honored
  without sleeping past the gate deadline. Other `4xx` identity errors fail
  immediately.
* On the `main` path the hosted gate's own 100-minute deadline is not the
  binding constraint. `main-publication-required-checks` runs inside the
  `Gateway API Conformance` workflow run, and the frozen `main-publish-gate`
  waits for that **run** to conclude under its own 3600-second budget, which
  starts only after `test` and `build-binaries` finish. The hosted gate must
  therefore conclude inside `main-publish-gate`'s remaining window, not merely
  inside its own. Because the hosted gate waits on the ~45-minute host-UDP lab,
  a `main` push typically leaves the `Gateway API Conformance` run in progress
  for roughly 50 minutes. If the labs are slow or runner-starved beyond that,
  `main-publish-gate` times out and `latest` / the Docker tags are simply not
  republished for that commit; the next `main` commit publishes normally. That
  is a deliberate fail-closed miss, not a wedge.
* A superseded `main` push does not publish and cannot be released.
  `ci.yml`, `coverage.yml`, `gateway-api-conformance.yml`, and
  `mesh-e2e-sidecar-live.yml` key their `push` concurrency by branch with
  `cancel-in-progress`, so a second push to `main` cancels the first commit's
  runs. For the `latest` / Docker path this is self-consistent -- the
  publishing `ci.yml` run is cancelled together with the evidence it was
  waiting on, and the newest commit publishes instead. For the **version-tag**
  path it is a real constraint: a `cancelled` run is blocking evidence, so a
  `v*` tag must target a `main` commit whose push runs actually completed --
  in practice the tip after `main` has been quiet long enough for them to
  finish. Tagging a commit that was superseded mid-run leaves
  `validate-release-sha` waiting until its deadline and then failing closed.
  Re-running the cancelled workflows for that exact SHA, or moving the tag to a
  commit with complete evidence, are the two supported remedies.
* The Ambient Host UDP `push: main` evidence starts with the commit that lands
  this cutover. Earlier `main` commits have no such push run, so a `v*` tag
  targeting a pre-cutover commit cannot satisfy `Ambient Host UDP Live` and
  does not publish.

### Release Pipeline Flow

```
Push tag v* (e.g., v0.2.0)
    └─► Validate tag matches the Cargo.toml package version
            └─► Validate tag target has the complete publish-blocking required-check set for the exact SHA
            └─► Four-target native matrix (linux-x86_64 / macos-x86_64 /
                macos-aarch64 / windows-x86_64) + isolated linux-aarch64 Cross job
                    └─► Push versioned Docker images to Docker Hub and GHCR
                            └─► Create Docker manifest tags
                                    ├─► Sign and attest final manifest digests,
                                    │   then verify signatures, subjects,
                                    │   provenance, and SPDX SBOMs
                                    └─► Create GitHub Release with binaries
                                            └─► Fail-closed publication gate
                                                requires attestation success
                                                (retracts an unverified release)
```

## CI runtime caching (production images and FIPS)

Issue #3888 cuts the production-Dockerfile and FIPS PR gates that were taking
60–83 minutes on cold sequential builds, without dropping distroless, eBPF,
clippy, claimed-feature, or handshake coverage.

**Warm PR target.** Each of `Production Dockerfile eBPF image smoke` and
`FIPS Build & Test` should complete in **<=30 minutes** on a warm cache, with a
documented **p95 <=45 minutes**. Hosted evidence is three consecutive warm
`pull_request` runs after this change lands (same cache keys, no
`force_cold_cache`), plus job summaries that record phase durations, cache
hit/miss, restored bytes, and `github.run_attempt` retry amplification.
A `workflow_dispatch` input `force_cold_cache` skips restore so a hosted
cold-cache run still proves every live contract within the existing job
timeouts.

**Production images.** The ordinary `runtime` and distroless `runtime-ebpf`
targets build in parallel with `docker/build-push-action`. Each job restores a
schema- and architecture-scoped local BuildKit cache (`type=local`) through pinned
`actions/cache/restore`. Cache keys are
`production-dockerfile-smoke-{default,ebpf}-v1-${{ runner.os }}-${{ runner.arch }}-${{ github.sha }}`
with matching `v1-${{ runner.os }}-${{ runner.arch }}-` restore prefixes. The `v1`
component is the BuildKit cache schema; bump it only when the exported layout
changes. The Ambient production-image job uses a separate GHA-backend
restore-only policy documented with that live suite, not this exact-generation
local cache.

`actions/cache/restore` v4 outputs are classified strictly: `cache-hit == 'true'`
is an exact primary-key hit; `cache-hit == 'false'` is a restore-key partial
match (still a hit); empty `cache-hit` plus empty `cache-matched-key` is an
ordinary miss. Exact and partial hits require a nonempty matched key and an
existing restored directory; contradictory tuples fail closed.

Trusted same-repository pull requests and `workflow_dispatch` never export or
save on an exact `${{ github.sha }}` hit: that path builds restore-only with
`cache-from` and no `cache-to`/`actions/cache/save`, so it does not pay for a
`mode=max` export or upload. Only a partial match or miss uses the publishing
BuildKit step, exports a fresh `*-out` directory, and saves the new exact key.
The cache-save preparation step requires that fresh export and fails rather than
relabeling the restored/stale destination. Fork pull requests restore and must
not have a save or cache-publication step. `force_cold_cache` skips restore and
save. Job summaries time cache-restore, image-build/export, and cache-save
separately, and record the restore action's classified hit kind plus the
measured restored directory size; unknown is never rendered as a miss or `0 B`.
The Dockerfile declares `ARG FEATURES` after the shared apt and manifest layers
so those two feature sets reuse toolchain work. A trusted-base copy of
`.github/scripts/ci_runtime_plan.py` reads a NUL-delimited
`git diff --name-only --no-renames -z` listing. Skip only when every decoded
path is safe, none is sensitive, and every remaining path is on the explicit
non-sensitive allowlist; a missing planner, a truncated listing, an empty
listing, an unknown path, or an unsafe path (every C0 control including
tab/newline, DEL, invalid UTF-8, absolute, traversal) fails closed toward
running. In the FIPS workflow, every trusted-tree lookup, proposed-entry check,
materialization target, post-write hash check, and invocation names the literal
`.github/scripts/ci_runtime_plan.py` path. The trusted Cross scanner rejects a
mutable path alias, so the validated base blob cannot be written somewhere else
while PR-controlled planner bytes remain at the executed path. Filenames in the
plan summary are JSON-escaped then HTML-escaped
inside `<code>` so a hostile name cannot break Markdown.

**FIPS.** `FIPS Feature Policy` stays a cheap always-on graph audit.
Compile, claimed-profile `cargo check`, clippy `-D warnings`, and the
policy/key-admission/handshake tests share one cache layer plus an immutable
artifact handoff:

- **Stable rust-cache fallback.** `shared-key` is
  `ci-fips-contract-${{ hashFiles(...) }}` over the manifest/lockfile, Cargo
  config, root build script, FIPS workflow, claimed-profile policy,
  `src/fips/**`, and `vendor/**`. Pinned `Swatinem/rust-cache` uses `shared-key`
  and ignores a sibling `key:` input whenever `shared-key` is set, so the
  contract hash must live in `shared-key` (no ignored `key:` /
  `add-job-id-key` wiring). Automatic toolchain, environment, manifest, and
  lockfile hashing stays enabled. This layer is **not** SHA-scoped, so
  AWS-LC/compiler work stays warm across commits. `fips-compile` may save it
  (`save-if` false for fork PRs); the three ordinal `fips-claimed-checks`
  shards, `fips-clippy`, and `fips-test-build` restore it with `save-if: false`
  and never publish. The test job does not restore build caches.
- **Immutable producer handoff (same-run channel and inter-run warm
  source).** A successful non-cold `fips-compile`
  packages its exact `target/` + `.cache/sccache` producer tree, the
  checkout's Git tree identity, and a `fips-producer-identity` member that
  records source SHA, run id, and run attempt as a zstd tar
  (preserving executable modes that artifact ZIP extraction would normalize)
  and publishes it as the one-day run artifact
  `fips-producer-handoff-${{ github.event.pull_request.head.sha || github.sha }}-${{ github.run_id }}-${{ github.run_attempt }}`.
  Pull-request events use `github.event.pull_request.head.sha` rather than the
  synthetic merge SHA so a manual run of the same branch head can address the
  artifact; other events fall back to `github.sha`.
  This is intentionally not a repository cache: concurrent CI writers
  empirically evicted a 4.15 GB late cache handoff within three minutes, and
  the former run-attempt-scoped `actions/cache` producer key
  (`fips-producer-<sha>-<run_id>-<run_attempt>`) was repeatedly LRU-evicted
  out of the shared 10 GB quota between the producer's save and the five
  consumers' restores, while a `rerun --failed` could never succeed because
  consumers at attempt N asked for a key the skipped producer only saved at
  attempt 1. Run artifacts sit outside that quota, and the artifact name's
  attempt suffix exists only so a full rerun can republish without an
  immutable-name conflict.

  The three claimed-profile shards, clippy, and `fips-test-build` download
  the handoff with the attempt-independent pattern
  `fips-producer-handoff-<sha>-<run_id>-*` and `merge-multiple: false`. The
  pinned download action flattens a single matching artifact's payload
  directly into the channel directory; two or more matches extract each
  artifact into a child directory named after that artifact. Promotion admits
  both layouts, binds the attempt from the `fips-producer-identity` member
  packaged at the front of the tar (never from the consumer's
  `github.run_attempt`), requires child directory names and payload identity
  to agree, and rejects mixed files and directories, extra entries, symlinks,
  and malformed identity. It then promotes the newest matching attempt, so a
  failed-job rerun reuses the artifact the skipped producer published at an
  earlier attempt. They never publish this channel. Each
  claimed shard filters the policy checker's single inventory by ordinal
  modulo three and fails closed if it selects no profile. Those consumers run
  in parallel after the build-only compile producer, so test-binary precompile
  does not sit on the claimed-profile/clippy critical path. Unlike the former
  cache channel (whose saves were fork-gated), the artifact channel is
  fork-usable, so fork pull requests get the same exact compile-to-consumer
  reuse and the same fail-closed promotion.

  GitHub also deletes a workflow run's artifacts when that same run is fully
  rerun, so warm evidence uses separate `workflow_dispatch` runs. Each
  dispatch names
  the exact source run ID and attempt; the pinned download action requests only
  `fips-producer-handoff-${{ github.event.pull_request.head.sha || github.sha }}-<run_id>-<run_attempt>` from that run
  in the current repository. A promoted artifact — same-run or explicitly
  requested — must contain a
  real tar payload that extracts to real `target/` and `.cache/sccache`
  directories or the consuming job fails closed. The archive carries the
  producer
  checkout's Git tree identity; promotion requires an equal, clean current
  checkout, preventing a synthetic PR merge tree from masquerading as the same
  branch head after its base changes. Because checkout gives identical source
  files newer mtimes than archived outputs, the promoting job refreshes
  only regular files under `target/` after validating that tree and a real,
  nonsymlink FIPS executable. Every refreshed file receives one common
  reference timestamp: Cargo compares a unit's outputs with dependency outputs,
  so independently generated `touch` times can themselves make a dependency
  look newer and invalidate its dependents.

  Cargo also includes the resolved `RUSTC_WRAPPER` executable identity in its
  artifact hashes. The checksum-pinned sccache installer intentionally uses a
  fresh runner-private path, which is safe for ordinary compiler caching but
  cannot identify an exact `target/` tree across jobs. Each FIPS Cargo job
  therefore stops that private wrapper and clears both wrapper variables before
  any cache or Cargo operation; the immutable exact-target channel is the FIPS
  compiler cache. These two controls keep Cargo from rebuilding
  content-identical outputs without allowing a partial, fork, cold,
  mismatched-tree, or runner-unique-compiler restore to masquerade as current.
  `force_cold_cache` skips both handoff download and upload. Run artifacts
  cannot populate another ref's shared cache.

`fips-test-build` precompiles the complete FIPS `unit_tests` and
`integration_tests` executables and stages digest-bound copies in an
immutable same-run artifact together with `fips-test-identity`. The test job
downloads the run-scoped, attempt-wildcard pattern
`fips-test-binaries-<run_id>-*` with `merge-multiple: false`. A single
matching artifact flattens `unit_tests`, `integration_tests`, `manifest.json`,
and `fips-test-identity` into the channel directory; multiple matches create
per-artifact child directories. Validation admits both layouts, binds the
attempt from `fips-test-identity` (never from the consumer's
`github.run_attempt`), requires directory names and payload identity to agree,
rejects malformed artifact names and paths, selects the newest attempt, then
rejects unexpected bundle names, symlinks, path escapes, and SHA-256
mismatches before executing the two binaries directly. A failed-job rerun can
therefore reuse the artifact
from the successful `fips-test-build` prerequisite that GitHub skipped in the
new attempt. Fresh-checkout source mtimes cannot make Cargo repeat test-only
compile/link work.
Non-cold consumers fail closed if no producer handoff for their source
SHA/run_id exists. Fork pull requests restore the rust-cache fallback only
and cannot save it; GitHub confines
`pull_request` writes to `refs/pull/.../merge`, not the default branch.

`force_cold_cache` skips every cache restore/save and the producer-handoff
download, packaging, and upload while still executing the
live contracts. The immutable same-run test artifact is transport, not a warm
cache, so forced-cold and fork runs can execute the exact binaries produced by
their own `fips-test-build` job without publishing shared state. rust-cache
`cache-on-failure` remains on the compile producer so
ordinary failing jobs can publish stable dependency work when post-job cleanup
still runs. The producer handoff is packaged and uploaded by main steps after
the locked
profile build and
before rust-cache's post cleanup, which strips workspace crates from `target/`
before saving the stable fallback. Example plugins stay out of the FIPS
artifact (`FERRUM_CUSTOM_PLUGINS` is unset). Job summaries record rust-cache
hit/miss from the action output as **stable fallback**, same-run producer
handoff promotion as an evidence-backed **hit** (a missing handoff fails the
job rather than recording a fabricated miss), and the
explicit inter-run handoff artifact as **hit / miss** (never as a fabricated
hit). Measured restored bytes are the sccache-directory subset for
rust-cache and the on-disk `target/` directory for the promoted producer
handoff; rust-cache Cargo/target archive bytes are not exposed. The
required `FIPS Build & Test`
aggregate depends on `fips-test-build` and fails closed if that test-binary
producer does not succeed.

**Trust boundary.** Untrusted `run:` steps never receive GitHub Actions cache
write credentials. `setup-sccache` installs a checksum-pinned
`mozilla/sccache` GitHub release (Linux/macOS/Windows, the x86_64 and
aarch64 archives actually used by callers) and does **not** invoke
`mozilla-actions/sccache-action`, which exports `ACTIONS_RUNTIME_TOKEN` and
`ACTIONS_RESULTS_URL` into `GITHUB_ENV`. A fail-closed assertion before cargo
refuses to continue if those variables are present in a `run:` environment
(values are never printed). The installer publishes an empty
`FERRUM_SCCACHE_BIN` sentinel first, then sets `RUSTC_WRAPPER` to that
checksum-verified path only; it never puts sccache on `PATH`. The install
root is the fixed, job-private `${RUNNER_TEMP}/ferrum-sccache-bin`, removed
and recreated before the verified copy: rust-cache hashes the wrapper path
into its key, and a randomized root made every lane unrestorable (#4643). It persists
`SCCACHE_GHA_ENABLED` as empty so a later step cannot re-enable the
credential-bearing GHA backend. Install failure clears the rustc wrapper and
continues uncached. Compiler outputs use a 2 GiB local directory persisted by
rust-cache / the FIPS producer archive. Production-image cache restore and save stay inside the
pinned `actions/cache/*` actions; PR-controlled `run:` steps only measure the
restored directory and move the BuildKit local export. Workflows stay
`permissions: contents: read`. Static checks live in
`.github/scripts/verify_ci_runtime_cache.py`. The cache-credential gate is
structural: `fips-build.yml` may invoke only a closed allowlist of pinned
actions and the two local shell-only composites (`setup-sccache`,
`setup-fast-linker`). Extracted `uses` must match that allowlist with exact
occurrence counts, so inserting a duplicate of an already-admitted
checkout, rust-cache, artifact, toolchain, or local action fails. Each
`actions/checkout` step must keep the current-repository / default-ref /
default-root contract: `persist-credentials: false` and no `repository`,
`ref`, or `path` redirection (including equivalent quoted, escaped, or
dynamic spellings). Each checkout has exactly one inspectable `with:` mapping,
so duplicate-key shadowing cannot hide the effective inputs. Those local actions
must remain `using: composite`
with `run:` steps only — no nested `uses:`, so no inline or third-party
JavaScript carrier can reach the Actions toolkit credential environment.
Alternate YAML spellings of `uses` (flow mappings, unbraced flow pairs,
quoted/escaped/multiline keys, explicit keys, anchors, aliases, tags,
merge keys, block scalars, templates, compact-sequence siblings after a
block scalar, and non-comment `#` data in plain flow scalars) are
rejected fail-closed rather than treated as an absence of invocations.
The contiguous
`exportVariable` token deny remains defense in depth; it does not catch
computed property forms such as `core["export" + "Variable"]` on its own.
It is scanned over every slot except the **document-root** `description:`
metadata **scalar**, which GitHub renders and never evaluates:
`setup-sccache/action.yml` is whole-file digest-frozen by the Cross build
policy, so the installer that enforces the credential boundary has to stay free
to document the toolkit call it refuses. The carve-out is that one key at
column zero — its plain or quoted scalar plus its correctly delimited block
body — and nothing else. A root `description:` whose value is a flow mapping,
flow sequence, explicit complex value, or any other non-scalar shape stays
scanned: it is not rendered string prose, and a nested `&anchor` inside a flow
collection is not a leading node property, so blanking it would hide the token
while an alias could still feed it into executable data. Nested `description:`
keys are **not** exempt: an action or
`workflow_dispatch` input description is `core.getInput('description')`, an
`env:`/`with:` entry is `process.env.description`, and any other nested mapping
is data some `run:` body can read, so a carrier parked there could rebuild the
forbidden property (`core[process.env.description]`) with no contiguous token
left on the line. A root `description:` carrying a leading `&anchor`, `*alias`,
or `!tag` is scanned too, because an anchored scalar is reachable by alias from
an executable slot, and only the first root `description:` is exempted because a
second one is a duplicate key rather than more rendered metadata. A
`description:`-shaped line inside a `run:` body is stepped
over as shell, a `- description:` item is a sequence entry rather than the root
mapping, and quoted or suffixed key spellings keep the full scan.

`node-waypoint-ebpf-live.yml` carries **no workflow-level `paths:`** trigger
filter (issue #3908). A `paths:` list lives in the pull request's own checkout,
so the same commit that broke a Docker build input or the NodeWaypoint datapath
could delete its own trigger and the workflow would never start — the trusted
planner cannot force a gate for a run that does not exist. The workflow now
triggers unconditionally on `workflow_dispatch`, `pull_request`, `merge_group`
(`checks_requested`), and `push` to `main`, and the trusted-base planner is the
only relevance authority. `verify_ci_runtime_cache.py`
(`check_governed_live_trigger_shape`) rejects a restored `paths:` /
`paths-ignore` filter and requires all four events.

Required aggregate jobs (`Production Dockerfile eBPF image smoke`, `FIPS Build
& Test`) use an **exact-boolean contract**: skip only on `relevant == 'false'`,
run expensive jobs only on `relevant == 'true'`, and fail closed when planning
succeeds but the output is blank or malformed (neither exact `true` nor exact
`false`).

The same trusted plan job emits a second exact boolean,
`node_waypoint_relevant`, from the `node-waypoint-ebpf-live` planner suite.
That suite is the pre-#3888 NodeWaypoint path scope (eBPF, node-agent,
mesh/HBONE, chart, harness, and specific `src/` files) plus the NodeWaypoint
datapath modules that landed after the historical list was written: every
`src/proxy/node_waypoint_*` module, `src/proxy/stream_listener.rs`,
`src/proxy/udp_proxy.rs`, and `src/proxy/mesh_tcp_inbound.rs`. The
`src/proxy/node_waypoint_` entry is a **prefix**, not a file list, because
that historical set enumerated `src/proxy/` file by file and was already
stale when it was frozen: `node_waypoint_ingress_capture.rs` and the four
`node_waypoint_udp_*.rs` modules were the only gate for the
`node_waypoint.udp.*` and `node_waypoint.dtls.*` live assertions and were
skipping it. A new NodeWaypoint proxy module is now sensitive by
construction. Ordinary `src/**`, `vendor/**`, `.cargo/**`,
`rust-toolchain.toml`, and `custom_plugins/**` changes still start the
workflow for production-image smoke, but skip the 120-minute Kind/eBPF live
job unless they also match that scope. The live job uses `if: always() &&
needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false'`:
GitHub skip-propagation is defeated with `always()`, and a trustworthy exact
`false` is the only skip. A missing trusted planner (adoption PR), planner
failure, unknown path, or blank/malformed NodeWaypoint verdict fails closed
toward running.

`node-waypoint-ebpf-live-gate` (check name `NodeWaypoint eBPF Live`) is the
always-reporting aggregate for that live job. It fails when relevance planning
fails, reports green when the planner proved exact `false`, and otherwise
reports whatever the live job did. It is deliberately **not**
branch-protection-required; `verify_required_ci.py` asserts it stays out of
`REQUIRED_MERGE_GROUP_WORKFLOWS` and `DEDICATED_REQUIRED_CHECKS`. The
production-image contract keeps reporting separately through `Production
Dockerfile eBPF image smoke`, so an image-relevant but live-irrelevant change
is still gated on the images without paying for the Kind/eBPF cluster.

The `node-waypoint-ebpf-live` planner suite also covers
`Dockerfile.ebpf-tools-layer` and the local composite actions the live job
executes (`setup-rust-ci`, and through it `setup-sccache` and
`setup-fast-linker`, plus `setup-bpf-linker`). The retired `paths:` list reached
the workflow for the tools layer but the planner then skipped every job, and it
named none of the toolchain actions at all, so an edit to one could change what
the live datapath compiled without re-running it.

## CI Pipeline (ci.yml)

The CI workflow is triggered by every pull request, every merge-queue
`merge_group` check request, and every push to `main`.
The `CI Plan` job first selects `full` or `light` mode. Pull requests and
merge-group runs whose entire diff is limited to ordinary documentation,
`.agents/**`, `.claude/**`, Markdown outside `vendor/`, or license files use
light mode and preserve a fast `Tests` aggregate without starting the Rust/build
matrix. Documentation that
deliberately triggers a live datapath suite (including the mesh, SPIRE,
configuration, NodeWaypoint, and CI contract/runbook files) remains full mode.
The planner runs `git diff --check` for PR/merge-group diff hygiene and disables
rename detection when classifying paths, so both the source and destination of a
rename are checked. `CI Plan` collects those paths as a NUL-delimited
`git diff --name-only --no-renames -z` stream (no newline `sort`) and parses
bytes fail-closed: a nonempty stream must be complete NUL-terminated UTF-8, and
every path must be a repository-relative `[A-Za-z0-9._+@~ /-]` name with no
absolute/dot/dotdot/empty components, C0/DEL, backslash, backtick, or other
unclassifiable punctuation. Malformed or hostile names select full mode, force
every job gate on, and are omitted from the step summary rather than
interpolated into Markdown. The same `--no-renames` fail-closed classification applies
to `coverage.yml` coverage planning, `gateway-api-conformance.yml` relevance
filtering, and the `performance-regression` path classifier on both
`pull_request` and `merge_group` diffs. Coverage planning is shard-scoped on
classifiable pull-request and merge-group diffs: `lib-unit` always runs with the
affected integration shards, plugin-only diffs keep the plugin gate but reuse
the `lib-unit` profraw/artifacts, and push to `main`, schedule, dispatch, empty
or unavailable diffs, controller edits, dependency/build-graph inputs, unknown
paths, and malformed/hostile path transport fail closed to the full coverage
matrix. The `Merge Coverage` aggregate verifies exact planned shard outcomes and
artifact presence so a skipped shard cannot false-green the required check.
Merge-group planning diffs
`merge_group.base_sha...HEAD` and executes the planner from that base SHA so a
queued planner edit cannot self-classify as light.
Any unrecognized path, an empty/unavailable diff, a mixed code-and-docs change,
a push to `main`, or a manual run fails over to full mode. The decision table
and its executable examples live in `.github/scripts/pr_ci_plan.py`. PR
decisions use the planner from the base branch when available, so a planner-only
edit cannot classify itself as light; edits to the planner therefore receive
the full matrix. The required-CI verifier also checks that documentation paths
used by live-suite filters remain in the planner's full-CI set.

`paths_classifiable` is a trust/transport version handshake between `CI Plan`
and the planner. Pull requests and merge groups execute the trusted-base
planner, so the change that introduces NUL transport still runs the older
newline-only planner that does not emit this flag. That older planner can treat
a NUL-delimited stream as one record and still print syntactically valid
`false` values for pre-existing Helm, mesh, and eBPF gates. Unless
`paths_classifiable` is exactly `true`, the controller force-runs every job
gate before writing `$GITHUB_OUTPUT`, even when those values look like valid
booleans. Narrow `true`/`false` gate values are honored only after the new
planner proves the NUL stream classifiable. Missing or invalid individual
outputs still fail closed to `true`. Unclassifiable and pre-handshake summaries
use the canned reason and never interpolate hostile paths.

The same trusted planner emits fail-closed job outputs for Helm, eBPF program
builds, three separate live suites (`run_ebpf_kernel_live`,
`run_netns_capture_live`, `run_two_cluster_live`), Secret Backends
(`run_secrets_backends`), and PKCS#11 SoftHSM (`run_pkcs11`). Each live job
reads only its own output. Pattern lists are derived from the files those jobs actually
compile and execute: kernel live is the BPF crate plus `src/ebpf/`, the
node-agent ingress-redirect helpers, `src/capture/` (`should_fallback_to_iptables`
via `kernel_probe`), and the loader-adjacent transparent bind
(`src/proxy/mod.rs` `create_proxy_socket` + `src/socket_opts.rs`); netns
capture live is the netns/TPROXY/SO_ORIGINAL_DST/UDP producer surfaces
(`src/proxy/host_udp_capture_live_tests.rs`, `src/proxy/udp_placement_migration.rs`) plus
the HBONE/mesh-runtime/MeshSubscribe/identity/TLS boundaries, backend dispatch,
TCP relay, route selection, and mesh policy the source-capture e2e tests
traverse; two-cluster live is mesh/HBONE/identity/SPIRE/east-west plus
`SO_ORIGINAL_DST`, mesh trust withdrawal, backend dispatch, route selection,
mesh policy, MeshSubscribe JWT helpers, the shared functional harness, and
`two_cluster_spire.sh`. Shared compile inputs
(`Cargo.lock`, `rust-toolchain.toml`, `.cargo/`, `vendor/`, `setup-rust-ci`)
still fire every live gate. The functional harness file schedules netns and
two-cluster only — kernel live tests live in `src/ebpf/loader.rs`, not that
file. CP-side trust serving (`src/grpc/cp_trust.rs`) stays isolated from all
three, while `src/grpc/cp_server.rs` schedules netns and two-cluster because it
owns the default JWT issuer shared by their functional fixture and production
MeshSubscribe client. The deliberate drops from the old `run_ebpf_live` union —
`src/k8s_controller/**`, `src/service_discovery/**` (except `mesh.rs`),
`src/grpc/{mod,cp_trust,cp_trust_health,configsync_lifecycle}.rs`,
`src/modes/control_plane.rs`, and `src/plugins/prometheus_metrics.rs` — are not
exercised by any of the three ci.yml live jobs and stay out of their gates;
they are instead covered by the dedicated live workflows or the always-run
cargo jobs. The shared `tests/k8s/lib/` Kind/SPIRE harness is likewise not a
ci.yml live input: `node-waypoint-ebpf-live.yml` owns it through its
`pull_request.paths` (`tests/k8s/lib/**`) and its scoped planner suite.
Non-PR events, empty or unavailable diffs, and
edits to `GATE_CONTROLLER_PATHS` (`pr_ci_plan.py`, `live_suite_path_filter.py`)
force every gated suite on. Missing/invalid planner outputs fail closed to
`true` in `CI Plan`. Non-mesh-plugin-only, admin-only, Dockerfile, and dedicated
ambient-host-UDP/k8s-live paths do not schedule these three jobs.
Authoritative sidecar and multicluster datapath coverage rides the dedicated
`mesh-e2e-sidecar-live.yml` and `multicluster-federation-live.yml` workflows
(path-filtered on PRs, fail-closed on `merge_group` / every `main` push);
`ci.yml` no longer runs a subset deploy-only smoke of either suite. PRs outside those curated path sets skip the
downstream job before GitHub allocates a runner. Pushes to `main`, manual
`workflow_dispatch` runs (the Secret Backends and PKCS#11 SoftHSM jobs use the
same event guard as the other path-gated Helm/eBPF/secrets/PKCS jobs), empty or
unavailable diffs, unclassifiable/unsafe changed paths, a missing or non-`true`
`paths_classifiable` handshake from an old trusted-base planner, and edits to
the gate-controller scripts force all of these gates on. Shared compile-graph
inputs (`Cargo.toml`/`Cargo.lock`, `vendor/`, `build.rs`, `proto/`,
`rust-toolchain.toml`, `.cargo/`, `.github/workflows/ci.yml`, and the
`setup-rust-ci` / `setup-sccache` / `setup-fast-linker` actions) also schedule
the Secret Backends and PKCS#11 jobs. Rust formatting and the integration-shard
coverage contract also run as named steps in `CI Plan`, avoiding two additional
runner allocations.

The `Helm Chart` job additionally runs the trusted node-agent/ambient chart
runtime lint (`.github/scripts/check_node_agent_chart_runtime.py`, issue #3615)
after proving the working-tree `.github/actions/setup-kubernetes-tools` matches
the trusted revision and installing that pinned Helm binary. The proof runs
before `uses:` can execute the action: the workflow takes a `git archive`
tarball of the action directory at the trusted revision (the pull request base,
the merge-group base, or the checkout itself on `push`/`workflow_dispatch`)
while `PATH` is still the pristine runner one, and
`.github/scripts/verify_trusted_local_action.py` decides regular-file,
no-symlink, mode, byte-content, no-extra-file, and ancestor-directory
constraints entirely from that manifest, spawning no process of its own.
Anything it cannot answer fails closed.

The default comparison is byte-identical. Issue #3904 admits exactly one
additional, controller-frozen generation transition for
`.github/actions/setup-kubernetes-tools`, and only that path. The trusted-base
tree whose sole governed file is non-executable `action.yml` at SHA-256
`6ecb4bde09a0d3d456d6019c03ef1678c3903cbc0275bba31fde3e56f6e6ef08` may move to
the PR #3910 tree whose `action.yml` is SHA-256
`41dd4b9ae1b0ad74e021e2974afbcdac1a1bc0d856a166a57e94046e803d6cd9` with the same
path set and executable bit. Both source and destination generations are bound
inside the extracted checker (complete file set, modes, and content hashes).
Another base generation, a one-byte or mode change, an extra or missing file,
or any other local-action path is still rejected. The candidate cannot supply
a digest, a mutable allowlist, or an unbound proposed manifest.

Once the destination generation is the trusted base, an unchanged working tree
passes by ordinary byte identity, and any further unadmitted drift fails. The
predecessor constants are then inert — the trusted archive is no longer the
source generation — and should be retired in a follow-up so the old tree
cannot remain an admitted source. PR #3943 merged that predecessor onto `main`
before this implementation; it did not contain #3910's action or workflow
changes.

Keeping the proof in Python rather than inline shell also keeps `helm-chart`
free of the opaque-inline-shell and Cross surfaces that `Trusted Cross Build
Policy` freezes per job.

Live labs that compile the same default-feature `cargo build --profile pr-build
--bin ferrum-edge` graph share the Swatinem rust-cache key `ci-live-pr-build`
(`gateway-api-conformance.yml`, `mesh-e2e-sidecar-live.yml`,
`multicluster-federation-live.yml`, and `multicluster-poller-partition-live.yml`).
Lanes whose cache-affecting inputs differ keep private keys: CNI additionally
links `ferrum-cni` (`ci-cni-lifecycle-live`), NodeWaypoint rebuilds with
`--features cloud-secrets,ebpf` plus a nightly bpfel toolchain
(`ci-node-waypoint-ebpf-live`), and Ambient Host UDP compiles the debug-profile
lib/functional test binaries (`ci-ambient-host-udp-live`). Kind, kubectl, and
Helm downloads used by those labs are restored inside
`.github/actions/setup-kubernetes-tools` under an exact key of pinned
versions/checksums, install subset, and runner OS/arch; checksums are verified
after both restore and download. That compile-cache and tool-download sharing
landed in PR #3910. A later #3904 slice retires the redundant `ci.yml`
deploy-only mesh jobs (`mesh-multicluster-federation` /
`mesh-e2e-sidecar` with `FERRUM_*_DEPLOY_ONLY=1`): each dedicated full live
suite already performs the same SPIRE/workload rollout and then continues into
traffic probes and fail-closed live assertions, so the extra kind clusters did
not add unique coverage. Cross-workflow executable-artifact polling is still
out of scope; independent workflows start concurrently, and the shared
`ci-live-pr-build` cache remains the accepted compile reuse.

On pull requests and merge groups the checker is extracted from the base revision when
one exists, then self-tested and executed against the proposed chart tree. That
prevents the step from executing a checker replaced by the same pull request and
prevents a PR-modified local installer from substituting a fake `helm` renderer
for the authoritative scan; the workflow wiring remains a reviewed pull request
surface and the required aggregate checks its expected shape. `FERRUM_TRUSTED_HELM`
pins the scan to the installer output so a later `PATH` prepend cannot swap the
renderer, and the checker rejects a `helm` path that is a symlink, is not a
regular file, or is not executable. A separate, clearly non-authoritative step
then exercises the proposed in-tree checker (self-test + scan) so syntax/render
behavior at the PR head is hosted-validated before merge without becoming the
security authority — without it, a checker change would get no hosted execution
at all on its own pull request. The
checker rejects Docker/containerd/CRI-O socket mounts, a `runtime.sock` host
path, or a true/dynamic `privileged` assignment. The scan walks every regular,
non-symlink chart template, values file, example values file, and chart fragment
rather than trusting a fixed pair of workload filenames. It also invokes Helm
and scans the default, node-agent/ambient-enabled, and example-values rendered
manifests (YAML/YML/JSON, including nested example paths), so helper expansion
or a path assembled by a Helm expression cannot hide dangerous workload output
from the gate.

It lives in `Helm Chart` rather than in `CI Plan` or a new standalone job for
two reasons. First, `Trusted Cross Build Policy` freezes the per-job digest of
every Cross-sensitive `ci.yml` job — `ci-plan` and `test` are both
Cross-sensitive — and compares the `test` aggregate byte for byte, so a pull
request cannot add a step to either. Second, `Helm Chart` is already an enforced
gate: it is a `needs` of the required `Tests` aggregate and is asserted there by
`require_planned_gate "Helm chart"`, which makes the lint blocking today with no
branch-protection change and no new required check. Its `run_helm` path gate
fires on `^charts/`, a strict superset of the `charts/**` tree the checker
scans, so a pull request that skips the job cannot contain a violation for it to
find. The required `Tests` aggregate runs the first-party
Markdown link checker through its CI contract verifier
(`.github/scripts/check_markdown_links.py`), including in light mode, so
docs-only PRs still validate relative file targets and GitHub heading slugs.

Both live-datapath suites validate their emitted `live-assertions.json`, but by
different mechanisms, because the trusted ARM64 Cross build policy freezes each
workflow's existing Cross-sensitive executable/configuration surfaces.

`mesh-e2e-sidecar-live.yml` validates in-workflow inside its live job via
`conformance::live_contract::live_contract_artifact_gate` (a cargo test).

`multicluster-federation-live.yml` cannot do that: adding a cargo step to its
live job, or editing that job at all, changes the per-job digest the trusted
policy compares and is rejected by `Trusted Cross Build Policy`. Its live job is
therefore byte-identical to `main`, and validation happens in the separate
`gate` job — the same job that publishes the required
`Multicluster Federation Live` check. That job carries no toolchain and no
build: it downloads the pinned `multicluster-federation-results` artifact with a
full-SHA-pinned `actions/download-artifact` and runs
`.github/scripts/validate_live_assertions.py` (standard library only), which
fails closed on a missing or non-regular artifact, malformed JSON, a wrong
schema version, suite, `github.sha` commit, or
`kind-spire-multicluster-federation` platform profile, an invalid, future, or
more-than-six-hour-old timestamp, duplicate assertion ids, a missing or extra
required `multicluster.*` id, or any required assertion whose status is not
`pass`. An irrelevant pull request skips the download entirely — the artifact
steps run only after the aggregate step positively establishes that a relevant
live run succeeded.

Three layers therefore have to agree, and hosted CI fails if they drift:

1. The fixture's own fail-closed
   `ferrum_live_assertions_require_all_passed` call over the run.sh-local
   `REQUIRED_LIVE_ASSERTIONS` array.
2. The `gate` job's explicit `--require` id list.
3. The enforced, non-`live_deferred` `multicluster-federation` rows of
   `tests/conformance/ga_contract.yaml`.

`tests/conformance/live_contract.rs` asserts set equality between (1) and (3)
and between (2) and (3); `.github/scripts/verify_required_ci.py` independently
pins the gate's download action, its exactness flags, its `validate`-gated
steps, and the same id set, and runs the validator's own self-tests (which
prove each rejection dimension) in the `Tests` aggregate.

In full mode, the `Tests` aggregate waits for the planner/format checks, test
shards, lint, dependency audit, vendored patch regressions,
planner-gated Secret Backends / PKCS#11 / Helm gates, per-suite eBPF
kernel / netns-capture / two-cluster live gates, performance, and the
cross-platform build matrix. When the planner marks `run_secrets_backends` or
`run_pkcs11` false, the aggregate accepts a skipped Secret Backends or PKCS#11
job; when the planner marks either true, that job must succeed. In light mode
it requires the planner to succeed
and accepts the planned heavy jobs as skipped. Pushes to `main` publish the
`latest` prerelease and Docker images only after the full aggregate and build
matrix pass.

Branch protection must require nine independent PR **and** merge-queue checks:
the unchanged `Tests` aggregate from `ci.yml`, `Merge Coverage` from
`coverage.yml`, `Gateway API Conformance` from `gateway-api-conformance.yml`,
`Mesh E2E Sidecar Live` from `mesh-e2e-sidecar-live.yml`,
`Multicluster Federation Live` from `multicluster-federation-live.yml`,
`Multicluster Poller Partition Live` from
`multicluster-poller-partition-live.yml`,
`Ambient Host UDP Live` from `ambient-host-udp-live.yml`,
`FIPS Build & Test` from `fips-build.yml`, and
`Trusted Cross Build Policy` from `cross-build-policy.yml`. Each dedicated
workflow triggers on every pull request and on `merge_group`, and fails closed
on planning or validation failures. They are required directly rather than
mirrored by runner-holding polling jobs in `ci.yml`. See
[Required checks and merge queue](#required-checks-and-merge-queue) for the
operator contract, queue SHA semantics, and staged enablement procedure.

`cross-build-policy.yml` is bootstrapped by the change that introduces it, so
it cannot emit a `pull_request_target` check until it exists on the default
branch. After that change merges and the first check is visible, a repository
administrator must add `Trusted Cross Build Policy` to the required checks for
`main`. Ordinary pull requests must not modify the trusted verifier or its
workflow; such maintenance requires an explicit branch-protection bypass.
Merge-group mode reuses the same check name while validating the synthesized
queue commit with read-only permissions.

CI uses
`concurrency.group: ci-publish-${{ github.event_name }}-${{ github.event.pull_request.number || github.event.merge_group.head_sha || github.ref }}`
with `cancel-in-progress: true`, so a newer push to the same PR or the same
merge-group head cancels the older run without cancelling unrelated lanes. On
`main`, that can interrupt an in-flight publish job such as Docker manifest
creation. If the cancellation left publishing incomplete, re-run the newest
workflow attempt (the one for the latest `main` SHA) — re-running the older,
canceled run would re-publish stale binaries and images as `latest`.

### Jobs

#### 1. CI Plan Static Checks

**Runs**: `ubuntu-latest`

Checks Rust formatting and integration-shard declarations on full-mode pull
requests and pushes to `main`:

```bash
cargo fmt --all -- --check
# Also diffs tests/integration/*.rs against integration::<module> filters in ci.yml.
```

**Failures**:
- Indicate formatting drift
- Indicate a missing or stale integration shard filter
- Must be fixed before merging

#### 2. Test Jobs

**Runs**: `ubuntu-latest`

Runs the required test matrix in parallel for full-mode pull requests and
pushes to `main`. The commands below are grouped by job, not run as one
sequential shell script:

```bash
# test-unit: compile the inline and external targets together, then run the
# inline lib, unchanged four-test plugin-hardening exact gate, kTLS live-kernel
# proof, and complete external unit suite in the same job. The joint no-run
# step prevents a runner-loss window between two full target compilations.
cargo test --lib --test unit_tests --no-run
cargo test --lib
FERRUM_KTLS_LIVE_REQUIRED=1 cargo test --lib -- --ignored --test-threads=1 \
  proxy::ktls_live_kernel_tests
cargo test --test unit_tests
cargo test --features acme --lib --test unit_tests --no-run
cargo test --features acme --lib tls::acme::client::tests
cargo test --features acme --test unit_tests tls::acme_dns01_hook_tests
cargo test --features acme --lib tls::acme_renewal_resume_tests

# test-pkcs11-softhsm: compile both libtest binaries before either filtered
# invocation, then exercise the signer and certificate-pairing contracts.
cargo test --features pkcs11 --lib --test unit_tests --no-run
cargo test --features pkcs11 --lib \
  tls::pkcs11::tests::signer_loads_configured_token_and_signs -- --ignored
cargo test --features pkcs11 --test unit_tests tls::pkcs11 \
  -- --include-ignored --test-threads=1

# test-integration-{admin-platform,mesh-protocols}
cargo nextest run --archive-file integration-tests-*.tar.zst \
  --workspace-remap . \
  --no-fail-fast \
  <shard filters>

# build-test-artifacts (one job/cache for both archives and both binaries)
cargo build --profile pr-build --bin ferrum-edge
cargo build --config profile.dev.debug=0 --bin ferrum-cni
cargo nextest archive --test integration_tests ...
cargo nextest archive --test functional_tests ...

# test-functional-{application,protocols,data-plane}
cargo nextest run --archive-file functional-tests-*.tar.zst \
  --workspace-remap . \
  --run-ignored=all \
  --no-fail-fast \
  -E 'not test(/test_scale_perf_30k_proxies/) and not test(/test_load_stress_10k_proxies/)'
```

The kTLS step is a **live-kernel** gate, not a unit test: it drives a real
rustls TLS 1.2 ChaCha20-Poly1305 client through `try_ktls_accept`, installs
kernel TLS keys on the runner's own kernel with `setsockopt(SOL_TLS, ...)`,
relays application bytes through `splice(2)`, and asserts the TLS close
handshake (authenticated `close_notify` → clean EOF, bare FIN → truncation,
backend EOF → reciprocal alert, unauthenticated record → attributed failure)
plus the unlimited ChaCha confidentiality posture the handoff hands to the
relay (`u64::MAX`, no guard, no pinned receive window). The same first test
also proves an AES-GCM-only offer is refused with the socket still pristine
before any install. Those assertions are folded into the first test rather
than added as a fourth, because the step's expected pass count of three is
part of the gate. It lives in
`test-unit`
because that job is `require_success "Unit and inline lib"` in the required
`Tests` aggregate, so the live path is blocking today without touching the
byte-frozen aggregate wiring. `FERRUM_KTLS_LIVE_REQUIRED=1` turns an
unavailable ChaCha20-Poly1305 kernel capability into a failure rather than a
skip, and the step additionally fails on any `SKIP:` line or on a pass count
other than three, so a green check cannot mean "the live path did not run". A
capability failure prints every cipher's probe verdict *with its install
`errno`*, because a bare `chacha20=false` cannot distinguish a kernel without
the cipher from a gateway-side `tls12_crypto_info` layout error. See
[tcp_udp_proxy.md](tcp_udp_proxy.md#hosted-live-kernel-coverage).

The excluded 30k scale variants (SQLite, PostgreSQL, and MongoDB) and the 10k
PostgreSQL load-stress test run weekly and on manual dispatch in the
`Scheduled Scaling Regression` workflow. Its matrix jobs have independent
failure signals and a five-hour timeout for the large provisioning and load
phases (raised from three hours by issue #4136, after read-your-write live
apply made every batch pay a synchronous convergence cost). The 30k harness
does not count route-miss 404s from an in-flight config publication as routing
failures: it discards that partial 30-second window, proves end-to-end
convergence again, and permits one full-window restart. A second interrupted
window fails explicitly as convergence instability; non-404 failures and RPS
remain routing measurements. A red matrix, or a latest main
scaling-regression run that is not a completed success within eight days (the
daily `Scheduled Scaling Gate Freshness` workflow), upserts a `severity:high`
issue so the streak cannot stay silent. Weekly and daily publisher jobs
share `concurrency.group: scaling-gate-publisher` with `queue: max` and
`cancel-in-progress: false` so a newer publisher does not replace queued
work; they do not claim FIFO dispatch. The publisher always inspects the
API's newest-first `scaling-regression.yml` run on `main` and treats the
current weekly `SCALING_JOB_RESULT` as authoritative only when
`GITHUB_RUN_ID` is that exact run. An older publisher derives the issue
from that latest run instead, so a stale success cannot close over a
newer red or in-progress run and a stale failure cannot reopen over a
newer fresh success. Close also refuses to mutate when the existing issue
body records a newer run id, or when that id cannot be parsed. Issue
discovery lists `state=all` issues created by `github-actions[bot]`,
sorted by `updated` descending, so ordinary `severity:high` history cannot
exhaust the pagination bound. Missing identity, malformed history, or API
failure keeps the issue open. Public issue reasons are truncated and
stripped of newlines and backticks before they are written.

**What it tests**:
- Unit tests in `tests/unit_tests.rs`
- Inline `#[cfg(test)]` modules in `src/`
- Secret backend tests compile once with Vault/AWS/GCP/Azure enabled and use
  nextest `--no-fail-fast`. The planner schedules this job (`run_secrets_backends`)
  only when secret-provider sources, `tests/secrets_functional/`, secret-resolution
  startup wiring (`src/main.rs`, `src/config/env_config.rs`), the feature-gated
  TLS secret-source resolver, nextest config, or shared compile-graph/controller
  inputs change; plugin-only and admin-only PRs skip it before runner allocation.
  Manual `workflow_dispatch` runs, pushes to
  `main`, and fail-closed planner cases still run it. Service integration
  likewise runs Consul, LDAP, Kafka, MySQL, OIDC, OAuth2 introspection, and
  ClickHouse in one independently reported invocation.
- PKCS#11 SoftHSM smoke (`run_pkcs11`) compiles the `pkcs11` feature graph and
  runs the token signer plus certificate-pairing tests against SoftHSM. The
  planner schedules it for `src/tls/pkcs11.rs`, the TLS load/backend/source/reload
  paths those tests call, the feature-gated config and TLS inventory surfaces,
  `tests/unit/tls` PKCS modules, and the same shared compile-graph inputs;
  sibling ACME/FIPS TLS unit files do not schedule it.
- Integration tests split across two shards (`admin-platform`,
  `mesh-protocols`). Each shard runs the prebuilt `integration_tests` nextest
  archive with a visible list of `integration::<file_module>` positional
  filters that nextest ORs together. Integration tests are in-process (no
  gateway binary, no Redis/Mongo services); each shard has a 30-minute cap.
- The `CI Plan` job diffs `ls tests/integration/*.rs` against the union of
  declared shard filters in `ci.yml`. Adding a new `mod foo_tests` without
  wiring it into a shard fails this silent-skip guard.
- Functional tests split across three shards (`application`, `protocols`,
  `data-plane`). `build-test-artifacts` compiles the gateway, CNI binary, and
  both nextest archives in one job/cache; each functional shard downloads the
  existing OS/architecture-keyed artifacts with
  `FERRUM_SKIP_GATEWAY_BUILD=1`. The data-plane shard remains serialized with
  `nextest_jobs: 1` and is the only shard that starts Redis/MongoDB containers.

**Output**:
- Test pass/fail status
- Failures block PR merges and `main` publishing through the `Tests` aggregate

#### 3. Lint Job

**Runs**: `ubuntu-latest`

Enforces code quality. Clippy omits DWARF (`profile.test.debug=0` and
`profile.dev.debug=0`) so large integration targets stay within hosted-runner
memory while `CARGO_BUILD_JOBS=2` restores modest compile parallelism:

```bash
cargo clippy \
  --config profile.test.debug=0 \
  --config profile.dev.debug=0 \
  --all-targets -- -D warnings
```

**What it checks**:
- Code style and idioms (clippy)

**Failures**:
- Indicate quality issues
- Must be fixed before merging

#### 4. eBPF Build Job

**Runs**: `ubuntu-latest`

The planner schedules this job on PRs only when files under `ebpf/` changed, so
unrelated PRs consume no runner; pushes to `main` and manual runs force it on.
The job installs stable and nightly Rust toolchains plus the repository-pinned,
SHA-256-verified upstream `bpf-linker` static release, uses
nightly to build `ferrum-ebpf`, uses stable to run
`cargo test -p ferrum-ebpf-common`, and uploads the compiled `ebpf-programs`
artifact with 14-day retention. If this job is edited, preserve the intent that
the shared-types test runs on stable Rust.

#### 4b. eBPF / netns / two-cluster live jobs (`ci.yml`)

**Runs**: `ubuntu-latest` (privileged), only when `CI Plan` marks the matching
gate `true`

These three jobs used to share one `run_ebpf_live` allow-list. They now have
separate fail-closed planner outputs and the `Tests` aggregate enforces each
with `require_planned_gate` against that job's own output:

| Job | Planner output | Distinctive surfaces |
|---|---|---|
| `ebpf-live` | `run_ebpf_kernel_live` | `ebpf/`, `src/ebpf/`, `src/capture/`, `src/proxy/mod.rs`, `src/socket_opts.rs`, `src/modes/node_agent.rs`, `setup-bpf-linker` |
| `netns-capture-live` | `run_netns_capture_live` | netns/UDP/TPROXY/SO_ORIGINAL_DST producers, `src/capture/`, HBONE pool/proxy, mesh runtime, MeshSubscribe (`src/grpc/mesh_*`, `auth.rs`, `cp_server.rs`, `dp_client.rs`), backend dispatch/TCP relay, routing/service discovery, mesh policy, identity, TLS, `mesh_trust_registry`, source-capture functional tests |
| `two-cluster-mesh-live` | `run_two_cluster_live` | `src/modes/mesh/`, `src/identity/`, `src/tls/`, MeshSubscribe JWT/gRPC helpers (including `cp_server.rs`), backend dispatch/TCP relay, routing/service discovery, mesh policy, HBONE, east-west, `SO_ORIGINAL_DST`, `mesh_trust_registry`, `two_cluster_spire.sh` |

All three also schedule on shared compile/CI inputs (`Cargo.toml`/`Cargo.lock`,
`rust-toolchain.toml`, `.cargo/`, `vendor/`, `build.rs`, `.github/workflows/ci.yml`,
and the rust-ci/sccache/fast-linker actions). `tests/functional/functional_mesh_mode_test.rs`
schedules netns-capture live and two-cluster live only; kernel live does not
run from that file because `ebpf-live` executes `ebpf::loader::live_kernel_tests`.
Empty diffs, non-PR/`main`/manual events, and planner controller edits force
every gate on. The dedicated `ambient-host-udp-live.yml` and
`node-waypoint-ebpf-live.yml` workflows keep their own path filters; they are
not part of these three `ci.yml` jobs.

#### 5. NodeWaypoint eBPF Live Datapath Workflow

**Runs**: `ubuntu-24.04`

The workflow triggers unconditionally on `workflow_dispatch`, `pull_request`,
`merge_group` (`checks_requested`), and `push` to `main`, with **no
workflow-level `paths:`** filter (issue #3908) — a queue entry is a combined
commit, so relevance has to be re-evaluated there, and a `paths:` list supplied
by the pull request could exclude the very change that broke the datapath.

Relevance is decided entirely by the trusted-base `production-dockerfile-plan`
job. `node-waypoint-ebpf-live` runs on its planner scope: eBPF, node-agent,
NodeWaypoint identity, netns capture, socket option, TCP/HBONE mesh, chart,
live harness files, `Dockerfile.ebpf-tools-layer`, the local composite actions
the job executes, the specific `src/` paths from the pre-#3888 trigger, and the
NodeWaypoint datapath modules added since (the `src/proxy/node_waypoint_`
prefix, `src/proxy/stream_listener.rs`, `src/proxy/udp_proxy.rs`,
`src/proxy/mesh_tcp_inbound.rs`, PR #3953). The expensive Kind/eBPF job is
gated by `node_waypoint_relevant` from that planner:
`if: always() &&
needs.production-dockerfile-plan.outputs.node_waypoint_relevant != 'false'`.
Unrelated production-image-only paths skip the live cluster; planner failure,
a missing trusted copy, an unknown path, or a blank/malformed verdict cannot
skip it. The `NodeWaypoint eBPF Live` aggregate (`if: always()`) reports green
for proven irrelevance and fails closed otherwise, and is **not**
branch-protection-required.
It builds the normal runtime Docker image from the host-built binary, builds the
eBPF userspace binary with `FEATURES=cloud-secrets,ebpf`, builds the
`ferrum-ebpf` BPF ELF with nightly Rust, and packages the `:<tag>-ebpf` runtime
image from those cached host-built artifacts instead of recompiling inside
Docker. A separate production-Dockerfile smoke builds the ordinary `runtime`
target (which must omit `ip`) and the privileged `runtime-ebpf` target (which
must contain `ip`) **in parallel** through BuildKit, restoring a scoped local
BuildKit cache (`type=local`) via pinned `actions/cache/restore` and measuring
restored bytes from the restored directory. Trusted runs save that cache with
pinned `actions/cache/save`; fork pull requests restore-only and do not save.
Each job then checks a normalized
filesystem inventory for shells and package managers. A trusted-base path
planner reads a NUL-delimited `git diff --name-only --no-renames -z` listing and
skips the smoke when the diff cannot change those images; uncertain
classification runs the full gate. It then creates a disposable dual-stack kind cluster with two
workers, mounts bpffs in each kind node, loads both images into the cluster, and
installs the Istio policy CRDs. The runner must provide Docker and a Linux kernel
with cgroup v2 and kernel >= 5.7.

The harness renders the Helm chart to assert enabled eBPF topologies select the
`-ebpf` image, installs NodeWaypoint eBPF mode, checks
`ferrum_node_agent_capture_state`, collects `bpftool` program/link/map evidence,
checks the shared node-agent ↔ ambient pod registry plus per-pod in-netns ready
markers, and verifies every ambient proxy accepted a mesh slice with the live
workloads and policies before traffic starts. It then runs same-node and
cross-node source/destination pod traffic, requiring `src-a` Service ClusterIP
requests to succeed and `src-b` Service ClusterIP plus direct Pod-IP attempts to
be rejected by live `AuthorizationPolicy`. The dual-stack pass verifies IPv6 is
rejected before traffic is admitted until the end-to-end IPv6 NodeWaypoint path
is completed. The harness also emits
`target/node-waypoint-ebpf-live/live-assertions.json`, a machine-readable H2
evidence file using the shared live-assertion schema. These assertion IDs are
observational while NodeWaypoint remains Experimental; they are not part of the
release-blocking sidecar GA contract. The workflow uploads Kubernetes
diagnostics, mesh drift snapshots, pod-registry dumps, live assertions, and
`bpftool` evidence with 14-day retention.

#### 5a. Istio Status CAS Live Workflow

**Runs**: `ubuntu-24.04`

`istio-status-cas-live.yml` is a Kind/apiserver lane for issue #3838. It is
**not** a required live-suite check and is not wired into the `ci.yml` `Tests`
aggregate (that aggregate is Cross-frozen). Since issue #3908 it carries no
workflow-level `paths:` filter: it triggers on `workflow_dispatch`, every
`pull_request`, `merge_group` (`checks_requested`), and `push` to `main`, and a
`changes` job decides relevance from the base branch's copy of
`live_suite_path_filter.py` (`--suite istio-status-cas`). The `Istio Status CAS
Live` aggregate runs with `if: always()`: it fails when change detection fails
or returns a non-boolean verdict, reports green when relevance was proven
`false`, and otherwise reports the live job's result. The workflow uses the same
pinned `.github/actions/setup-kubernetes-tools` Kind/kubectl install as the other
Kind-capable jobs, applies the checked-in AuthorizationPolicy CRD fixture
(`tests/fixtures/k8s/istio_authorizationpolicy_status_crd.yaml`), and runs the
ignored `k8s_istio_status_cas_live` test binary with
`FERRUM_ISTIO_STATUS_CAS_LIVE=1`. That binary drives Ferrum's real
`IstioStatusWriter` plus a kube-rs competing status writer; it must observe a
resourceVersion conflict and keep both the foreign condition and
`FerrumAccepted`. In-process mock coverage remains in
`tests/integration/k8s_controller_istio_status_cas_tests.rs` and is not a
substitute for this lane.

#### 5b. Ambient Host-Network UDP Live-Kernel Workflow

**Runs**: `ubuntu-24.04`

`ambient-host-udp-live` triggers on **every** pull request and merge-group run —
it carries no top-level `paths:` filter, because a required check that can
disappear cannot be relied on. A `changes` job instead decides relevance from
the **base branch's** copy of `.github/scripts/live_suite_path_filter.py`, read
by pinned object id at one immutable trusted commit and executed under an
isolated interpreter, so a pull request can never widen its own suite patterns
to declare itself irrelevant. The live job runs only when that verdict is
`true`, and the `if: always()` final gate `Ambient Host UDP Live` reports on
every run: green when the suite passed or was legitimately irrelevant, red when
a relevant live job failed or was unexpectedly absent. Every checkout, parsing,
or classifier error fails closed.

The `changes` job is frozen byte-for-byte by
`LIVE_SUITE_RELEVANCE_CONTRACTS` in
`.github/scripts/verify_cross_build_policy.py`, together with the live job's
`needs`/`if` binding. The trusted-base verifier therefore rejects any pull
request that rewrites the Ambient gate's relevance logic, points it at
pull-request-supplied classifier code, severs the live job binding, or removes
the required workflow. This is the same fail-closed contract used by the other
required live-datapath gates.

The relevant surfaces are host-UDP capture, mesh UDP serving, capture plan
generators, Ambient mesh serving, the Ambient UDP lifecycle's production entry
points (`src/cli.rs` and `src/main.rs` for the `ambient-udp-preflight`
subcommand, and `src/modes/node_agent.rs` for the node-identity publication
every placement proof binds to), Helm mesh charts, the `Dockerfile` and its
runtime tool staging, the release publication workflow, the live fixture, and
related docs. When relevant, the job builds the lib and functional test binaries
(without running them as the invoking user), preflights `unshare` /
`iptables` / `ip6tables` / TPROXY primitives, then runs
`tests/k8s/ambient_host_udp_live/run.sh` as root inside an explicit hosted
disposable outer network + private mount namespace (`unshare --mount --net`,
#3804) with a fresh read-only sysfs view tied to the owned network namespace and
`FERRUM_LIVE_TESTS_REQUIRED=1`. The runner itself also creates a structurally
proven disposable outer netns for every ordinary root execution so ad-hoc runs
share the same ownership boundary. The fixture exercises the production
`ProxyHostUdpBackend` path: multi-veth dual-stack TPROXY delivery, original
destination recovery, ingress-ifindex attribution, transparent replies,
restart/cleanup ownership, and explicit negative cases. Skips under required
mode are hard failures. Bounded redacted diagnostics are uploaded with 14-day
retention.

A second required-gate job, **Ambient host-UDP production image contract**,
covers the boundary the live-kernel job structurally cannot. That job runs
prebuilt test binaries directly on the hosted runner, so it proves the RUNNER
has `ip`/`iptables`/`ip6tables` — not that the image the mesh chart selects
does. The Ambient UDP lifecycle drives generated `sh -c` iptables/ip6tables
scripts, so a chart that selected a distroless image would render a pod that
could not run the very backend the live gate validates, with CI still green.
The image job therefore:

1. builds `capture-tools-base` first (cheap: apt only), so a broken tool closure
   fails in about a minute instead of after the Rust and nightly eBPF builds;
2. builds the exact production target `runtime-ebpf-tools` — the `-ebpf-tools`
   tag the chart names — and proves inside the container that `/bin/sh`, `ip`,
   `iptables`, `ip6tables`, `iptables-save`, and `ip6tables-save` all execute,
   that `ferrum-edge version` runs, and that the BPF ELF is present (so the
   image really is a superset of `-ebpf`);
3. builds `runtime-ebpf` and proves from its normalized exported filesystem that
   it has **not** gained a shell, package manager, `iptables`, `ip6tables`, or
   `nft`, and has kept its staged `ip`. Without step 3 a later change could
   "satisfy" this contract by weakening the distroless variant instead.

Full containerized TPROXY execution is deliberately out of scope for this job:
the datapath needs privileged host-netns manipulation that the live-kernel job
already performs against the real kernel. The two jobs are complementary — the
live job proves the datapath, the image job proves the shipped runtime can
execute it — and the `Ambient Host UDP Live` gate requires both.

**Cache-budget policy.** GitHub Actions gives each repository a 10 GB cache
quota and evicts the least-recently used entries across every ref when that
budget is exhausted. The Ambient production-image job previously published
`type=gha,mode=max` BuildKit layers on every pull request under
`scope=ambient-host-udp-images`. Those PR-scoped `buildkit-blob-*` entries
cannot be restored by other PRs or by `ci-test`, but they still consume the
shared quota, so ordinary Swatinem rust-cache entries disappear and Unit /
PKCS#11 jobs compile cold. The image job still restores
`cache-from: type=gha,scope=ambient-host-udp-images` on every event, including
fork PRs, so a trusted default-branch cache remains useful. It publishes
`cache-to` only when `github.ref == 'refs/heads/main'`, the event is neither
`pull_request` nor `merge_group`, and the head is not a fork — today that is
`workflow_dispatch` on `main`. The three required image targets
(`capture-tools-base`, `runtime-ebpf-tools`, `runtime-ebpf`) and their
executable/distroless contract checks always run; an empty `cache-to` does not
skip a build. Existing cache entries are left for GitHub's LRU rather than
deleted by this change. The Fuzz Smoke lane's separate main-only save is owned
by PR #3918 and is not changed here. The NodeWaypoint/FIPS exact-generation
local BuildKit design from PR #3889 is also unchanged.

The shared `setup-rust-ci` action applies the same restore-only policy to the
Swatinem rust-cache: `save-if` is true only when the event is neither
`pull_request` nor `merge_group`, `github.ref == 'refs/heads/main'`, and the
head is not a fork — pushes to `main` (and a manual `workflow_dispatch` on
`main`) refresh the per-`shared-key` caches that every pull-request lane then
restores. PR-merge-ref-scoped rust-cache entries were multi-gigabyte per lane
(`v0-rust-ci-test`, `v0-rust-ci-test-secrets`, live-suite keys, and so on) and
evicted the default-branch entries under the shared 10 GB quota, which is what
left Unit Tests / PKCS#11 compiling cold in the first place. The known cost:
re-runs of a pull request's failed jobs no longer restore a same-PR warm
cache and compile from the `main` baseline instead. The FIPS workflow's own
rust-cache producer/consumer sites keep their existing fork-only `save-if`
contract — that workflow's caching architecture is generation-pinned
separately (PR #3889).

**Rust-cache quota diet (#4643, part 2).** The editable direct rust-cache
calls in `ci.yml` (`build-binaries`, `build-ebpf`) and the six on-demand
benchmark workflows now save only on
`github.event_name == 'push' && github.ref == 'refs/heads/main'`. Because the
benchmark workflows only have `workflow_dispatch` triggers, they restore
existing entries but publish no new ones, including on manual `main` runs.
Their existing keys remain isolated; they do not gain a new cache producer.
The binary producer retains separate `release` and `prbuild` keys, so its
PR/merge-group builds cannot restore the release-profile cache and will
compile cold once old `prbuild` entries expire.

Lanes that cache useful Cargo targets stop also archiving the bounded 2 GiB
`.cache/sccache` directory. Comparison, connection-saturation, and
gateways-protocol benchmarks compile their host tools in nested workspaces
and build the gateway in Docker; their default root `target/` archive never
covered those host tools. They now set `cache-targets: "false"`, retaining
only Cargo downloads and the compiler-cache restore path. No new shared
sccache service or credential export is introduced.

| Lane / shared key | Expected archive after the diet (not yet measured) |
|---|---|
| `build-<target>-release` | Cargo downloads + target dependencies; previous archive minus its compressed sccache subset (up to 2 GiB before compression) |
| `build-<target>-prbuild` | 0 new bytes; PR and merge-group saves disabled |
| `ci-ebpf-programs` | Cargo downloads + `ebpf/target`; previous archive minus its compressed sccache subset, when the existing cache step runs |
| `ci-perf-bench`, `ci-payload-bench`, `ci-scale-bench` | 0 new bytes on dispatch; restore paths are Cargo downloads + root target dependencies |
| `ci-comparison-bench`, `ci-connection-saturation`, `ci-gateways-protocol-bench` | 0 new bytes on dispatch; restore paths are Cargo downloads + sccache, without root target |

This is a partial quota reduction, not evidence that the repository fits
under 10 GB. The frozen `setup-rust-ci` action still archives both target and
sccache for Unit Tests (`ci-test`), Lint (`ci-lint`), Build Test Artifacts,
coverage, and its other callers; it exposes neither `cache-targets` nor
`cache-directories` nor `save-if` overrides. Changing that common policy
requires a trusted direct-to-`main` generation. The frozen `fuzz-smoke` lane
(reported at about 4.3 GB) still needs shrinking/splitting through a separate
policy generation. FIPS, release publication, and `ci-perf` (#4090) keep
their existing arrangements. Existing large entries are left to LRU expiry.

To measure, capture this inventory before and after a subsequent `main`
push, then again after a PR run based on that push (retain the output with
the run IDs and head SHAs):

```bash
gh api --paginate 'repos/ferrum-edge/ferrum-edge/actions/caches?per_page=100' \
  --jq '.actions_caches[] | [.id, .ref, .key, .size_in_bytes, .created_at, .last_accessed_at] | @tsv'
```

Compare the **same entry IDs** across snapshots: entries created before the
later `main` push must still exist afterward and show `last_accessed_at` >
`created_at` after the PR restore. Sum `size_in_bytes` across all pages and
refs, including BuildKit caches, against the 10 GB repository quota; group
by lane to replace the estimates above with measured compressed sizes. A
newly created replacement key is not survival evidence. Confirm `Restored
from cache key …` in Unit Tests, Lint, and Build Test Artifacts logs, and
record Unit Tests' precompile duration. Keep #4643 open until that evidence
is observed; no local execution can establish these acceptance criteria.

#### 5c. CNI Install Lifecycle Live Workflow

**Runs**: `ubuntu-24.04`

`cni-lifecycle-live.yml` is the live install/uninstall recovery proof for issue
#3609. Logic lives in `tests/k8s/cni_lifecycle_live/run.sh`; the workflow stays
a thin launcher (checkout, build `ferrum-edge` + `ferrum-cni`, package the
runtime image, install pinned Kind/kubectl, run the harness, upload
diagnostics). It is **not** a required live-suite check.

Since issue #3908 it carries no workflow-level `paths:` filter: it triggers on
`workflow_dispatch`, every `pull_request`, `merge_group` (`checks_requested`),
and `push` to `main`, and a `changes` job decides relevance from the base
branch's copy of `live_suite_path_filter.py` (`--suite cni-lifecycle`). The
merge-group trigger is the point: a queue entry is a combined commit, so one
pull request renaming a chart value another one's CNI template consumes is
exactly the interaction a per-pull-request `paths:` filter could never catch.

The `cni-lifecycle` suite keeps the retired `paths:` cost envelope — chart
matches stay exact template/values files rather than the whole Helm tree — and
adds the classifier script itself plus the local composite actions the live job
executes (`package-ferrum-runtime-image`, `setup-kubernetes-tools`,
`setup-rust-ci`, and through it `setup-sccache` and `setup-fast-linker`). The
`CNI Lifecycle Live` aggregate runs with `if: always()`: it fails when change
detection fails or returns a non-boolean verdict, reports green when relevance
was proven `false`, and otherwise reports the live job's result.

#### 6. Performance Regression Job

**Runs**: `ubuntu-latest`

Runs on full-mode PRs, pushes to `main`, and manual dispatches. Immediately after
checkout, the job always runs lightweight protocol-perf static validation (no
benchmarks): workflow verifier `--self-test`, repository-contract verification,
evaluator `--self-test`, and `python3 -m py_compile` on
`tests/performance/multi_protocol/run_protocol_regression_scenarios.py`. PRs then
apply a performance-sensitive path filter; unrelated PRs skip the expensive
benchmark and report success. On pull requests and merge-queue groups, changed
files are collected with `git diff --name-only --no-renames` so both sides of a
rename are classified and a move into an irrelevant path cannot suppress the
benchmark. The PR gate covers proxy and connection hot paths,
the file-mode startup path used by this benchmark, performance fixtures, and
dependency/build-graph inputs. Plugin-internal, admin, secrets, and unrelated
operating-mode changes are excluded because this plain HTTP/1.1 file-mode route
cannot observe them. If the PR diff cannot be computed, the benchmark runs to
fail closed. Relevant PRs and all `main` pushes build the gateway in the
`ci-release` profile, build `tests/performance/backend_server`, start both
services, and run:

```bash
python3 tests/performance/ci_overhead_bench.py \
  --gateway-url http://127.0.0.1:8000/api/users \
  --backend-url http://127.0.0.1:3001/api/users \
  --gateway-health-url http://127.0.0.1:8000/health \
  --concurrency 50 \
  --duration 5 \
  --iterations 3 \
  --warmup 2 \
  --overhead-threshold 50 \
  --output tests/performance/ci_results/overhead_results.json
```

`--overhead-threshold 50` is a percentage threshold: the script fails when median gateway overhead across iterations exceeds 50%.

The job's `setup-rust-ci` step keeps shared key `ci-perf` and passes rust-cache
`workspaces` as `. -> target` plus `tests/performance/mesh -> target`. That
covers both the root `ci-release` gateway build and the standalone Criterion
crate under `tests/performance/mesh/` (own `Cargo.lock` / `target/`) without
replacing root coverage. `setup-rust-ci` exposes `workspaces` as an optional
pass-through to Swatinem/rust-cache; omitting it leaves rust-cache's default
`. -> target`, so other jobs keep root-only caching. Do not list only the mesh
workspace, and do not add unrelated workspaces, `cache-all-crates`, or extra
`cache-directories` here.

Until issue #4643 the checksum-pinned installer gave every hosted job a
fresh `mktemp` wrapper path; it now installs to the fixed
`${RUNNER_TEMP}/ferrum-sccache-bin/bin/sccache` path, recreated from scratch
on every job. Swatinem/rust-cache hashes every non-empty `RUST*` and `CARGO*`
variable into its environment key, so a per-run path prevented every lane
(not only `ci-perf`) from restoring the cache seeded by `main`. The
`performance-regression` handling below predates that fix and is kept as a
belt-and-braces guard for its own lane. The `performance-regression` invocation therefore sets
`RUSTC_WRAPPER` and `CARGO_BUILD_RUSTC_WRAPPER` to empty values only on the
`setup-rust-ci` composite step. That step scope makes the nested rust-cache
action omit the runner-unique values while `setup-sccache` still publishes its
checksum-verified path through `FERRUM_SCCACHE_BIN`. Immediately after the
composite returns, the workflow copies that verified executable to the fixed
`${RUNNER_TEMP}/ferrum-performance-sccache/bin/sccache` path and republishes
both wrapper variables, so Cargo's own compiler identity is stable as well as
the rust-cache key. If the installer failed or its verified executable is no
longer available, the step clears both variables and the benchmarks continue
uncached. Do not move the initial empty values to job scope, which would
override the later activation and disable sccache for the builds whose reuse
this cache is intended to accelerate.

Hosted follow-ups that still need measured evidence before changing
measurement fidelity:

- sccache hit rates on the `ci-release` gateway build (thin LTO). Do not
  introduce a dedicated non-LTO perf profile until those stats are attached
  and budgets are re-baselined.

On `pull_request` and `merge_group`, the four Criterion microbenchmarks
(IP restriction, WRR, RoundRobin, AI semantic-cache cleanup) are scheduled
from path matches on their measured sources, fixtures, and verifiers. A
change to `.github/workflows/ci.yml` schedules them only when the `ci.yml`
hunks can affect Criterion behavior: `bench`, `criterion`,
`verify_*_benchmark`, `--min-parallel-speedup`, scaling / ns-per-instance
caps, `--manifest-path`, or this job's `ci-release` / `CARGO_PROFILE` /
`RUSTFLAGS` surface. Workflow-only edits (comments, unrelated `env:`
blocks, path filters on other jobs) do not. If the name-only diff or the
`ci.yml` hunk diff cannot be computed, the microbenchmarks run (fail
closed), matching the smoke benchmark. `push` to `main` and
`workflow_dispatch` still force-run every microbenchmark. The
`verify_*_benchmark.py --self-test` helpers for RoundRobin and WRR run on
every full-mode job, including when the Criterion benches themselves are
skipped.

The WRR parallel-speedup floor stays at 1.10x for its mandatory
high-cardinality fixtures (32 and 129 targets), which genuinely scale. On
a miss, `verify_wrr_selection_benchmark.py` measures an independent-process
CPU control (median of five repeats) at the same thread count. If that
control also misses 1.10x, the runner is oversubscribed and the floor is
advisory (`::warning::`) rather than a required failure. If the control
clears 1.10x, a selection miss is still a hard failure. Its 4-target
small-cardinality fixture is measured but informational, because an Arc
strong-count hotspot dominates it.

The **RoundRobin** guard does not assert a parallel speedup at all
(issue #4484). Its only fixture is a 2-target upstream, whose measurement
is dominated by a shared-line hotspot: hosted runs of an unmodified tree
land near 0.6x-0.7x, so a 1.10x floor sat above the workload's own typical
value and ejected green pull requests from the merge queue. That fixture is
the RoundRobin analogue of the WRR 4-target one, and is now treated the
same way: `verify_rr_selection_benchmark.py` still prints its wall times and
its throughput speedup against `--min-parallel-speedup`, but reports a miss
as a `::notice::` instead of failing on it.

What it enforces instead is a **per-selection contention bound** built from
the same two measurements the fixture already records:

```
contention_ratio = parallel_ns / (8 * serial_ns)
                 = parallel ns/selection / serial ns/selection
```

`contention_ratio` is 1.00x for a workload that scales perfectly and rises
toward 8.00x as the batch serializes on one cache line. The reference for
"serialized on one cache line" is not a constant: the Criterion bench adds
`shared_counter_control_{1,8}_threads`, which drives the same
barrier-synchronized worker pool at the same thread counts over one
genuinely shared `AtomicU64` — the exact cost the sharded `CachePadded`
selection counters exist to avoid, measured on the same runner in the same
run. The gate passes when

```
selection contention_ratio <= 0.50 * shared_counter_control contention_ratio
```

An oversubscribed or coherence-degraded runner inflates both readings
together, so the verdict does not flip; a regression that puts every worker
back on one shared counter drives the selection reading up to the control's
own, whatever absolute value that runner produces that day. This is what
makes the control representative — unlike the independent-process CPU
control, which measures whether cores are free rather than what a contended
cache line costs, and therefore cleared on all three of the readings that
ejected #4466.

Two fallbacks apply the wide absolute backstop `contention_ratio <= 4.00x`
(healthy hosted readings are ~1.3x-1.7x; full serialization is >= 8.00x)
and say so with a `::warning::`: a control below 2.00x, meaning the runner
resolves no shared-line penalty at all so the comparison has no signal; and
an unreadable control fixture, which is fail-closed. Serial-ratio and
missing-artifact contracts stay hard either way. The WRR floor value is not
lowered.

**Failures**:
- Indicate performance regression issues
- Must be fixed before merging

#### 7. Cross-Platform Build Jobs

**Runs**: `ubuntu-latest`, `macos-latest`, `windows-latest`

Full-mode PRs compile the native Linux x86_64 verification binary with
`--profile pr-build`. They also run `verify-pr-linux-gnu-abi`, which builds
both x86_64 GNU release binaries (`ferrum-edge` and `ferrum-cni`) through
the digest-pinned AlmaLinux 8.10 sysroot builder, ABI-scans them against
GLIBC_2.34, and smokes them on digest-pinned AlmaLinux 9.4 and Ubuntu 22.04.
A pull request publishes nothing, so that job runs the same builder the
publishing producers run and scans its outputs as a pre-merge regression
signal; nothing downstream consumes it. `merge_group` keeps all four native
targets as fail-closed compile gates whose outputs are discarded: Linux
x86_64 and Windows x86_64 still `cargo build --profile pr-build` (Windows
MSVC/NASM linkage is the platform-specific failure mode `cargo check`
cannot see); macOS x86_64 and macOS ARM64 run `cargo check --profile
pr-build` because queue binaries are never published. Pushes to `main`
build optimized `release` binaries for Linux x86_64, Linux ARM64, macOS
x86_64, macOS ARM64, and Windows x86_64.

Both Apple cells export `MACOSX_DEPLOYMENT_TARGET` at job level (`10.12` for
x86_64, `11.0` for ARM64, rustc's own defaults) in `ci.yml` and
`release.yml`. Without it, cc-rs, cmake, and configure-driven native crates
(`ring`, `aws-lc-sys`, `rdkafka-sys`, `tikv-jemalloc-sys`, `zstd-sys`,
`libsqlite3-sys`) default to the runner SDK version, so the published binary
declared a 10.12 floor while its C objects were built for macOS 26.5
(issue #4644; ld64.lld logged it as "has version 26.5.0, which is newer than
target minimum of 10.12.0" for every object). rustc reads the same variable,
so raising the floor later moves Rust and C code together.

The x86_64 GNU cell of `build-binaries` does NOT compile on the runner. It
runs `.github/scripts/build_linux_gnu_sysroot.sh`, which builds inside the
digest-pinned AlmaLinux 8.10 sysroot (glibc 2.28) under an isolated
`CARGO_TARGET_DIR=/src/target/linux-gnu-sysroot` so a restored native
`target/<triple>/release` cache cannot contaminate the pinned link, then
copies only the two regular, non-symlink binaries to
`target/x86_64-unknown-linux-gnu/release/`. The job's own `Prepare release
assets` step stages and checksums exactly those files, and before
`Upload artifacts` it re-verifies the `.sha256` sidecars and ABI-scans and
smokes `release-assets/ferrum-edge-linux-x86_64` and
`release-assets/ferrum-cni-linux-x86_64` against GLIBC_2.34 (`libgcc_s.so.1`
/ `libz.so.1` allowlist) on digest-pinned AlmaLinux 9.4 and Ubuntu 22.04.
The bytes that are scanned are therefore the bytes uploaded as
`binary-x86_64-unknown-linux-gnu` and consumed by `latest-release` and the
`docker` images; a floor violation means that artifact never exists.

The protected `build-arm64-cross` job is byte-frozen by trusted Cross
policy, so its ARM64 artifacts cannot be gated from inside it.
`verify-latest-linux-gnu-abi-aarch64` downloads
`binary-aarch64-unknown-linux-gnu`, re-verifies its checksums, and ABI-scans
and smokes the published bytes on `ubuntu-24.04-arm`; it never rebuilds
them. `linux-gnu-abi-latest-gate` joins that job with frozen
`latest-release` (`if: always()` on main pushes) because
`latest-release.needs` is frozen too: the gate fails the workflow unless
both verification and publication succeeded, and it deletes `latest` only
when that prerelease is proven to target the current `GITHUB_SHA`. The
`docker` job needs `[test, build-binaries, build-arm64-cross,
main-publish-gate]` and does not wait on `verify-latest-linux-gnu-abi-aarch64`,
so the arm64 image layer is pushed before that verification. The retraction
gate deletes only the GitHub `latest` prerelease, never the `:latest` /
`:vX.Y.Z` image tags. Native targets share the ordinary matrix; Linux ARM64
runs only after code reaches
`main`, in the isolated `build-arm64-cross` job described below. rust-cache
keys are split by profile lane
(`build-<target>-prbuild` vs `build-<target>-release`) so queue check/pr-build
trees cannot evict push-to-main release artifacts. Each native job installs
the pinned repository `setup-sccache` action and reports `sccache --show-stats`
after compile. The jobs install the same prerequisites as the Release pipeline
— `protoc` on every OS, `libcurl4-openssl-dev` on Linux, and NASM on Windows —
and compile with `--features cloud-secrets` so Vault/AWS/Azure/GCP secret
backends are included. The macOS x86_64 build targets `x86_64-apple-darwin`
with the standard Apple/Rust toolchain (no `cross` needed) and runs on
whichever host architecture GitHub maps `macos-latest` to today (currently
ARM64); pin to a concrete runner image such as `macos-14` if the host
architecture must be guaranteed.

##### Trusted ARM64 Cross boundary

Cross 0.2.5 merges `[package.metadata.cross]` from `Cargo.toml` with the selected
Cross config file, gives `Cross.toml` precedence over Cargo metadata, and then
allows target/build environment variables to override those values. It also
accepts executable or privileged behavior through global Dockerfile,
pre-build, build-mode, and env settings; target-specific image, Dockerfile,
pre-build, runner, build-mode, and env settings; plus container-engine,
container-option, custom-toolchain, and alternate-config inputs. The ARM64
boundary therefore uses a complete allowlist rather than a field denylist:

- `Cross.toml` may contain only the `aarch64-unknown-linux-gnu` target, its exact
  `ghcr.io/cross-rs/aarch64-unknown-linux-gnu:0.2.5` image, the ordered seven
  approved pre-build commands, and the exact fixed-value passthrough entries.
  Global build settings, extra targets/keys, Dockerfiles, runners, build modes,
  volumes, and unfixed passthroughs are rejected.
- `Cargo.toml` must not contain `package.metadata.cross` or
  `workspace.metadata.cross` in table, dotted-key, quoted-key, or inline-table
  form. Unrelated package/workspace metadata, dependency, and version edits
  remain permitted.
- `.cargo/config` is forbidden, and `.cargo/config.toml` is parsed as a complete
  allowlist. The existing build wrapper/incremental values and every target
  linker/rustflags table are exact; only bounded retry and boolean HTTP
  multiplexing transport tuning may vary. Extra build, target, runner, rustc,
  workspace-wrapper, env, alias, credential, registry, or future root keys fail
  closed instead of becoming an alternate executable/toolchain surface.
- `build-arm64-cross` in `ci.yml` and `build-release-arm64-cross` in
  `release.yml` are isolated from the shared native matrix. Their exact job
  blocks, inherited top-level `env` mappings, and workflow trigger blocks are
  hashed by the trusted verifier, and comparison with the current trusted base
  tip rejects any PR-authored mutation while allowing unrelated workflow jobs
  to evolve. Every
  `.yml` and `.yaml` file directly under `.github/workflows`, plus every regular
  file recursively under `.github/actions`, is also compared as a collection.
  The complete `.github/scripts`, `comparison`, `scripts`, `tests/k8s`, and
  `tests/performance` automation roots are semantically compared, and literal
  repo-script edges are resolved transitively; local actions outside
  `.github/actions` and repo commands outside those scanned roots are rejected.
  This prevents moving an invocation into another workflow, action, or helper
  script without freezing benign script edits. Any new or changed Cross
  executable/configuration token outside the isolated jobs is rejected,
  including `env`-wrapped and Cargo-subcommand forms, quoted or nested
  shell/GitHub-interpolated executable spellings, custom step/default `shell`
  templates, YAML block-scalar variants, interpreter input redirection, Python
  process-API positional/keyword forms, literal or command-position
  dynamic GitHub expressions before any Cargo-compatible subcommand or
  toolchain selector, shell-variable executable indirection, partial or whole
  opaque command substitutions, Bash brace expansions and ANSI-C escapes, and
  Cross environment aliases; Bash backslash-newline continuations are
  normalized before scanning. Executable slots are recognized wherever the
  shell creates one, so nested `sh -c`/`bash -lc` scripts, `$(...)`, backtick
  and `<(...)`/`>(...)` substitutions, single-line `case` arms, wrapper
  end-of-options markers (`sudo -- cross`), absolute or home-relative tool
  paths (`/usr/bin/cargo cross`, `~/.cargo/bin/cross`), and Bash aliases bound
  to Cross under `expand_aliases` all resolve to the Cross command word. Because
  an unquoted expansion is word-split before dispatch, each expansion is also
  read as a word separator, so `cross${IFS}build` and
  `cargo${IFS}+stable${IFS}cross build` resolve exactly like literal
  whitespace at the executable, toolchain-selector, and subcommand boundaries.
  A shell can also move Cross out of the command word entirely and still run it
  by dispatching an argument vector that holds it, so a function whose body
  executes its arguments (`run() { "$@"; }`, `go() { exec "$@"; }`, `only() {
  "$1"; }`) makes every call site's argument list a command line, and a command
  line loaded into the positional parameters (`set -- cross build --target
  ...`) is read as one wherever it appears. Which names dispatch their argument
  vector is resolved from the whole program rather than from the line being
  scanned, so a definition and its call site may sit on different lines. A
  function that merely *forwards* its arguments to a named command
  (`f() { curl "$@"; }`) does not dispatch them and stays editable.
  A dynamic expression that occupies a whole command word is replaced by a
  whole command, not just by an executable name, so `run: ${{
  steps.plan.outputs.cmd }}`, a composite action's `run: ${{ inputs.cmd }}`,
  `run: $CMD`, and `run: $(plan)` all fail closed even though no literal
  `build --target` text is left on the line; an expression that is an argument
  to a named command, or that is only data, does not occupy a command word and
  stays editable. Substituting a whole command needs both a line a shell
  evaluates and a slot on it. A raw line scan also reads a workflow's non-`run`
  block scalars and a script's heredoc bodies. Prose block scalars and quoted
  heredoc bodies attached to data-writing commands are not shell-evaluated, so
  no slot on them counts: an expression inside a `prompt: |` block or a
  `cat <<'EOF'` configuration body is data the runner never dispatches,
  backticks there being Markdown rather than substitutions. An interpreter-fed
  heredoc is different: quoting its delimiter suppresses expansion by the outer
  shell, but `python3 <<'PYEOF'` still executes the body as Python, so the body
  is extracted and rescanned in that language. Unquoted heredoc bodies are data
  at line start, but the shell still evaluates command-substitution slots while
  constructing their input, so
  `$()` and backticks there fail closed — and, for the same reason, a
  substitution in such a body is followed as a repository execution edge:
  `cat <<EOF ... $(bash scripts/unsafe.sh) ... EOF` really runs that script, so
  it is recorded and scanned. Only the substitution interior becomes a command;
  the surrounding data line never gains a command slot of its own — including
  for the opaque-ARM64-executable search, which reads a program's command text
  rather than its raw lines, so `cat <<EOF ... $cmd build --target
  aarch64-unknown-linux-gnu ... EOF` is the configuration data it is while the
  same words inside a body `$()` still fail closed. The whole body is joined
  before its substitutions are read, because a substitution may open on one body
  line and close on a later one: `$(` followed by `bash scripts/unsafe.sh` and
  `)` on separate lines runs that script, and reading one physical line at a time
  saw no balanced substitution on the opener and no command slot on the
  continuation, which is still heredoc data. An arithmetic expansion in such a
  body dispatches nothing of its own — `$((scripts/build))` evaluates a division
  — so the expression itself gains no command slot, but the shell still performs
  the command substitutions *inside* an arithmetic expansion before evaluating
  it, so `$(( $(bash scripts/unsafe.sh) + 0 ))` is recursed into and that script
  is recorded and scanned. `$( (cmd) )`, the only spelling that nests a real
  substitution, still executes. Backtick substitutions are paired across
  physical lines too, because the shell permits that spelling and dropping it
  would miss a real execution edge. This can conservatively scan a backtick pair
  in Markdown written by an unquoted documentation heredoc, which is the
  fail-closed side of the ambiguity. Each
  interior runs in a subshell, so it is followed as its own nested program: a
  `cd` inside one resolves that interior's own operands and then ends with the
  subshell, instead of rewriting the working directory every later real line of
  the parent script is resolved against.
  Which bodies are quoted is decided by parsing the delimiter as the shell word
  it is. A shell suppresses body expansion when *any* character of the delimiter
  is quoted and terminates on the dequoted word, so `<<E"OF"` and `<<\EOF` are
  quoted heredocs ending at `EOF`. Reading only a wholly quoted delimiter took
  the first as the unquoted delimiter `E` — leaving the body expandable and
  running the body state past the real terminator — and did not recognize the
  second as a heredoc at all.
  A `<<` inside an arithmetic expansion is the left-shift operator rather than a
  heredoc opener, so a complete balanced `$(( ... ))` is skipped as a unit;
  advancing past only the `$((` left `echo $((1 <<EOF))` able to mark the real
  command lines after it as body data. A heredoc opened after arithmetic on the
  same line is still a heredoc. On a line a shell does evaluate, an
  explicit executable slot — `run:`, a statement
  separator, `$(`, a backtick, a conditional keyword — counts, and so does a bare
  line start, so the same expression alone on its own line inside a `run: |`
  block still fails closed. A raw source line that a backslash continuation
  joins onto the previous one has no line start of its own — `$(printf
  'ferrumedge/ferrum-edge@sha256:%s ' *)` under `docker buildx imagetools create
  ... \` is that command's last argument — so only the bare-line-start allowance
  is withdrawn there; an explicit slot on the continuation line still counts, and
  the joined logical line is scanned in its own right. A wrapper continuation
  (`env \`, `sudo \`, `timeout 30 \`) is the exception that restores the next
  line's slot, because the wrapper has not consumed its executable operand yet —
  but not inside a heredoc body, where the receiving command reads that text as
  input rather than dispatching it, and not when the wrapper is still waiting on
  an option operand. `env -u \` and `sudo -u \` end the line mid-option, so the
  word that follows is the name being unset or the user being assumed, not an
  executable; treating it as a whole-command slot is a deterministic false
  positive rather than a caught dispatch. `timeout` is the same case with a
  positional operand: its duration is mandatory and precedes the command, so
  `timeout --preserve-status \` and `timeout -k 5 \` hand the next line that
  duration, while `timeout 30 \` and `timeout --preserve-status 30 \` have
  already consumed it and do restore the slot. The same mandatory duration is
  modelled in the pattern layer, not only in the token walk: `timeout` is not an
  ordinary wrapper there either, so `timeout --preserve-status $seconds build`
  reads `$seconds` as the duration operand it is and `build` as the executable,
  instead of reporting the benign dynamic duration as an opaque Cross
  executable. The restored raw-line slot also preserves the wrapper's assignment
  semantics: after `env \` or `sudo \`, `FOO=bar $cmd` still dispatches `$cmd`,
  while after `exec \`, `nohup \`, or `timeout 30 \`, `FOO=bar` is the wrapper's
  command argv itself and no later executable slot is invented.
  Leading words that precede the executable without being it do not close the
  slot: a negation (`! cmd`), assignment words (`FOO=bar $cmd`), process
  wrappers, `env` and its options, and any number of spaced or unspaced subshell
  openers (`(`, `((`, `( (`) may all sit between the command start and an opaque
  executable word, in any combination and on either side of the opener. That one
  interleaved layer is shared by every executable-slot matcher, including the
  literal Cross scan, so `env FOO=1 sudo BAR=2 env cross build --target
  aarch64-unknown-linux-gnu` is recognized in workflows and reached shell
  automation alike; a layer that fixed wrappers before assignment words and
  allowed only a single `env` described just one of those orderings. An
  executable assembled from expansions that then dispatches a Cargo or Cross
  subcommand (`"$cmd" build`) is opaque for every target, not only the protected
  ARM64 one, so it fails closed in trusted-automation revalidation as well.
  The cheap check that decides which lines reach that analysis is held to the
  same vocabulary as the analysis itself, because a narrower gate drops a line
  before the substitution can fail closed on it. It therefore accepts the same
  command starts, the same interleaved assignment/wrapper/`env` prefix layer,
  and command substitutions as executable words, so `FOO=1 $cmd build`,
  `env $cmd build`, and `$(pick-cross) build` are all analyzed. It also accepts
  the two further spellings the ordinary Cargo/Cross parser accepts: a literal
  `cross` subcommand, since `$tool cross build` runs Cross when `$tool` is
  `cargo`, and a toolchain selector, since `$tool +nightly build` runs Cross
  when `$tool` is `cross`. A command substitution with nested parentheses is
  one expansion to the scanner but not to the cheap pattern, so every balanced
  `$(...)` span is collapsed to a single placeholder before that gate runs and
  `$( (printf cross) ) build --target aarch64-unknown-linux-gnu` reaches the
  analysis it would otherwise be dropped before. When the substitution or a
  backtick pair spans physical lines, only the newlines inside that one shell
  word are joined before classification; unrelated commands on adjacent lines
  remain separate. Widening that gate reports
  nothing by itself — every admitted line is still decided by the substitution,
  the Cross-subcommand check, and the command-context check.
  The interleaved assignment/wrapper/`env` prefix layer is one model shared by
  every discovery pattern, not only by opaque-executable scanning, so
  `env sudo bash scripts/unsafe.sh`, `sudo FOO=bar bash scripts/unsafe.sh`,
  `env sudo make -C build all`, and `env sudo python3 -m ci.build` are recorded
  as the repository script, dispatcher manifest, and Python module they really
  execute. Every alternative in that layer consumes a whole word, so it widens
  the accepted orderings of prefix words without opening data or argument
  positions.
  A block-scalar body is one string value rather than YAML structure, so prose in
  an action input declares no mapping key, alias, or merge key: `--allowedTools
  "Bash(gh pr comment:*)"` inside a `claude_args: |` body is not a `comment:` key
  aliased to `*)`. The body's text still reaches the action and is still searched
  for the Cross executable, the Cross image, and the protected target.
  A backslash-escaped backtick is literal text and
  opens no slot, so ``echo "- Test: \`${{ matrix.test }}\`"`` writes Markdown in a
  real `run:` block and stays editable. An executable heredoc is unaffected
  throughout: it is extracted and rescanned as its own program, where its lines
  are command lines again. Every queued heredoc on a command is consumed in
  opener order, so a later body in `cat <<D <<'PY' | python3` cannot hide behind
  the first delimiter. Only an outer pipeline attaches a body to an
  interpreter; pipes inside quotes, substitutions, backticks, subshells, or
  process substitutions remain nested command syntax rather than receivers of
  the heredoc.
  Binding Cross to another executable name is itself a Cross surface: linking,
  copying, moving, or installing the Cross binary under a new name, and writing
  a wrapper script whose body runs Cross, are all detected, and every later
  command-start dispatch through that name — including PATH-prepended,
  `./bin/`-relative, and assignment-prefixed forms — is expanded back to the
  Cross command word. A dynamic shim name fails closed. Shim sources are
  tokenized before the Cross token is required, so a quote- or escape-split
  source (`ln -s ~/.cargo/bin/cr"oss" bin/cr`) still binds the shim. Python
  helpers are analyzed through local process-API aliases (`run =
  subprocess.run`) and shell-wrapper argv (`subprocess.run(['sh', '-c', ...])`).
  `asyncio.create_subprocess_shell`/`create_subprocess_exec`, including their
  imported and renamed forms, are tracked alongside `os` and `subprocess`, and
  the variadic-argv APIs (`create_subprocess_exec`, `os.execl*`, `os.spawnl*`)
  have their spread arguments joined into the single command they dispatch.
  In JavaScript, importing `child_process` at all is the dispatch surface, so a
  destructured or renamed binding (`const {execSync} = require('child_process')`,
  `import {spawn as run} from 'node:child_process'`) is protected exactly like
  a `child_process.exec(...)` member call.
  Workflow `run` bodies are dispatched through their effective step, job, or
  workflow-level shell; Python shells and executable Python heredocs therefore
  receive the same AST analysis, while dynamic or unsupported shells fail
  closed. Shell, Python, Perl, PHP, R, JavaScript/TypeScript, PowerShell, awk,
  and BusyBox script launchers are recognized when resolving repository paths.
  Only shell, Python, and PowerShell file bodies have language-aware transitive
  readers; an explicit unsupported interpreter for any repository helper
  therefore fails closed instead of relying on a suffix or being downgraded to
  a bare shell reading.
  Inline interpreter source is dispatched the same way: a `run:` step that
  hands a program to Python (`-c`), PowerShell (`-Command`, any unambiguous
  prefix), Node, Deno, Bun, Perl, Ruby, PHP, Lua, R, Julia, Elixir, Groovy,
  Scala, osascript, awk, or Tcl has that program inspected rather than skipped,
  so `perl -e 'system("cross build ...")'` and `node -e ...` are rejected.
  Python inline source gets the same AST analysis as a Python shell; other
  languages have their string literals read as command text and any other
  process dispatch inside inline source treated as an unresolvable executable.
  Shell-assembled inline source (`perl -e "$PROGRAM"`) and a PowerShell
  `-EncodedCommand` fail closed, while a field reference such as awk's `$1` or
  a Perl `$name` sigil stays readable so ordinary one-liners are not frozen.
  Because shell variables are case-sensitive but equally executable, source
  that is nothing but one parameter expansion (`python3 -c "$cmd"`) and source
  referencing any name — lowercase included — that the enclosing shell program
  assigns are both treated as generated. An inline-source operand attached to
  its option letter (`perl -e'print "safe"'`) or to a single-dash long option
  is parsed as the program it is, rather than being frozen as a missing
  operand. An interpreter that reads its program from stdin is dispatched the
  same way as a shell that does, so `python3 <<< '<source>'` and
  `python3 < <(printf '<source>')` are inspected in the interpreter's own
  language instead of only in POSIX shell. Only an *unescaped* literal producer
  is folded into readable source: `echo` behavior varies between shells and
  `printf` decodes backslash escapes in its format, so `printf '\x63ross ...' |
  bash` and `echo -e '\x63ross ...' | bash` would otherwise be read as harmless
  text while the receiving shell runs Cross. A backslash anywhere in an `echo`
  operand, in a `%s` operand, or in a literal `printf` format therefore leaves
  the produced program opaque, which fails closed. That decision belongs to the
  producer rather than to the executable word, so it is reached from both
  directions: pull-request comparison and exact-tree revalidation of reached
  shell automation both reject an undecodable stdin program. Deciding it only
  under the opaque-executable analysis meant the tree path — which enters
  through the literal scan — accepted on `main` what comparison had rejected on
  the pull request. Literal shell commands extracted from Python process APIs
  re-enter that same opaque-stdin scope, including commands discovered through
  an explicit Python interpreter edge to a suffixless helper or an inline
  `python -c` program.
  A `shell: pwsh`/`powershell` body, a PowerShell `-Command` operand, a
  PowerShell heredoc, and a `SHELL ["pwsh", ...]` Dockerfile selection are
  parsed as PowerShell rather than as POSIX shell: `Start-Process`,
  `Start-Job`, `Start-ThreadJob`, and `Invoke-Command` process operands and the
  `&`/`.` call operators resolve to the executable word, while
  `Invoke-Expression`/`iex`, a computed call-operator target, a
  `[Diagnostics.Process]::Start` dispatch, and an unreadable process operand
  fail closed. A bare `$variable` stays a value expression, because PowerShell
  requires a call operator to execute a computed word.
  `env -S`/`--split-string` operands are tokenized into the argv they become
  rather than discarded as option arguments, in separated, joined
  (`--split-string=...`), and attached (`-S...`) spellings. `flock` and
  `script` are followed to their process operands, both the positional argv
  form after `flock`'s lock operand and the `-c`/`--command` shell-program
  form.
  A remote (non-`./`) `uses:` step is code this repository does not own, so a
  step whose action reference names Cross, whose inputs include a Cross-enabling
  key (`use-cross`, `cross-version`, and equivalents under case and separator
  normalization, in block or flow mappings), or whose input values carry the
  protected ARM64 target, the pinned Cross image, or the `cross` executable is a
  build-execution surface; a dynamic `uses:` reference fails closed. Benign
  pinned actions with unrelated inputs stay editable. A local (`./`) action is
  extracted and scanned as a file of its own, but the workflow's `with:` values
  are part of its executable surface too — a composite action with
  `run: ${{ inputs.cmd }}` executes whatever the call site passes — so a local
  step's inputs are held to the same Cross-input, target, and expression rules;
  only the `./` reference itself is exempt from the literal-reference check.
  The step is read as the
  single YAML mapping it is, so key order does not matter: a `with:` block
  written **above** the `uses:` line is scanned exactly like one written below
  it. Keys and values are read the way the runner parses them, not as raw
  source text: quoted spellings (`'use-cross'`, `"use-cross"`) and
  double-quoted escape sequences (`"use-cross"`, `"uses"` written with an
  escape, `args: "build --target aarch64-unknown-linux-gnu"`, and matrix
  values collected from quoted scalars) are all decoded before any Cross or
  target token is searched for. A double-quoted scalar continued with
  a trailing backslash is folded the way the runner folds it, so a target split
  across two source lines is still detected. A YAML merge key
  (`with: {<<: *cross_inputs}`) supplies inputs the step never spells, and a
  YAML alias, anchor, or tag resolves outside the step in a `uses:` reference
  (`uses: *cargo_action`) and in any value position alike (`with:
  *cargo_inputs`, `args: *arm_target`), so all of them fail closed rather than
  being read as the literal text they appear to be — the runner expands an
  aliased input map into the action's inputs before it runs, so a step that
  spells neither `use-cross: true` nor the protected target can still deliver
  both. A step written entirely as a YAML flow mapping
  (`- {uses: actions-rs/cargo@<sha>, with: {use-cross: true}}`) is the same step
  to the runner, including when the entry spans several source lines, so those
  sequence entries are entered and held to the identical reference and input
  rules instead of being skipped for not starting a line with a key. Input values are resolved rather
  than compared as literal text: an expression such as
  `args: build --target ${{ matrix.target }}` is expanded against the enclosing
  job's `matrix`, `env`, and `inputs` **declarations** — a step's `with:` keys
  are arguments to an action, never definitions, so a self-referential input
  such as `target: ${{ matrix.target }}` cannot shadow the real matrix value.
  Every expression on a line is expanded *together*, because the runner
  concatenates them all before the action sees the value, so
  `--target ${{ matrix.arch }}-${{ matrix.rest }}` assembled from literal
  fragments is caught; a line with more combinations than the enumeration limit
  fails closed. Any expansion reaching the protected target is a surface.
  A value this scanner cannot see is *unknown*, not empty: `secrets.*`,
  `github.*`, `runner.*`, `steps.*`, and `needs.*` are not author-populated
  value sets, and a prior step or job output can be set to the ARM64 target,
  so an unknown value fails closed whenever the same input already declares a
  `--target` argument. Ordinary credential and context inputs carry no target
  argument and stay editable. One narrow exception exists so release downloads
  can be isolated to exact artifact names, which necessarily name the protected
  target: for `actions/download-artifact` **pinned to a full commit SHA**, the
  target string in an artifact `name`/`path`/`pattern` input is not a surface,
  because the action only selects an already-published artifact for the current
  job and cannot start a build. `actions/upload-artifact` names and paths remain
  protected surfaces because they control the artifact identity consumed by
  later publishing jobs. That carve-out accepts the block and flow spellings of
  the same YAML (`with: {name: ...}`) equally, and applies only when every key
  on the line is one of those closed artifact inputs. The
  Cross image, a `cross` executable token, every Cross-enabling input key, any
  other input key, an unpinned reference, and any other action are all still
  surfaces; self-test fixtures assert each of those boundaries.
  Heredoc parsing is quote-aware and rejects unterminated bodies. Repository
  working-directory state changes only after each `cd` execution point and is
  rejected when conditional or loop control flow makes it ambiguous. Dockerfile
  instruction parsing is enabled only for Dockerfile-named inputs containing a
  real `FROM` instruction, so ordinary Python beginning with `from` remains
  Python. Baseline and proposed automation diagnostics are aggregated before
  surface comparison, ensuring a malformed baseline cannot suppress proposed
  findings. Generated-artifact exemptions are limited to an exact allowlist of
  literal build outputs; variable-prefixed pseudo-paths are not allowlisted,
  and a generated-looking *directory prefix* confers no exemption of its own.
  None of `target/`, `results/`, `coverage-report/`, `benchmark-results/`,
  `comparison-results/`, or `tmp/` is ignored by git, so a pull request can
  commit a script under any of them; such a script is ordinary repository code
  and is reported as outside the scanned automation roots unless it is one of
  the exact allowlisted build outputs. Those exact allowlisted outputs are
  exempt only while nothing commits them, so the pull-request comparison
  additionally requires the full proposed repository tree listing
  (`--proposed-tree-listing`, a `git ls-tree -rz --name-only` enumeration of the
  proposed commit) and rejects any commit that adds a file at one of them.
  Checking the materialized `--automation-dir` instead would be vacuous: that
  directory is reconstructed from the approved automation roots alone and could
  never show a committed executable at a repository-root path such as
  `conformance` or `ferrum-edge-linux-x86_64`. The extraction contract requires
  the listing to be passed, so a policy workflow that drops the flag is
  rejected.
  Repo-controlled build dispatchers are followed rather than trusted: a step
  running `make`, `npm`/`pnpm`/`yarn`, `just`, or `task` resolves to the
  matching root or `-C`-relocated `Makefile`, `package.json` `scripts`,
  `justfile`, or `Taskfile`, which is then scanned and frozen like any
  referenced script, and a dispatcher whose manifest is not in the scanned set
  fails closed. Make recipes are read as the shell text make emits rather than
  as raw shell: variables the makefile assigns are substituted with their real
  values, which catches `CARGO = cross` followed by `$(CARGO) build ...`, and
  `$(MAKE)`/`$(MAKE_COMMAND)` resolve to the make executable so an ordinary
  recursive-make recipe is followed as a dispatcher instead of being frozen as
  an opaque command substitution. Every other `$(...)`, including
  `$(shell ...)` and other make functions, stays opaque and keeps failing
  closed. Detection stays anchored to command positions, so prose or a
  comment mentioning `cargo install cross` does not freeze unrelated edits.
  An automation file needs no recognized extension to be executable. A reference
  under a conventional tool directory (`ci/`, `bin/`, `build/`, `scripts/`,
  `tool`, `tools/`, `dev/`, `hack/`) is followed as a repository command even
  when the name carries no suffix, and a reached file that is extensionless —
  and is not a build-dispatcher manifest — is revalidated as shell rather than
  skipped for having no detectable language. Those two halves are what close the
  edge: the first makes `ci/unsafe` and `scripts/build` discoverable without a
  `./` prefix or an interpreter word, the second makes them scannable once
  discovered. Every scanned automation root is spelled there as well —
  `.github/scripts/`, `comparison/`, `tests/k8s/`, and `tests/performance/` —
  because a root this policy already scans is exactly where a direct
  `run: .github/scripts/build` would otherwise go unrecorded, just as omitting
  `scripts/` once left `run: scripts/build` unscanned.
  Python automation reached this way has dynamic process commands rejected
  rather than silently dropped, so an argv assembled into a variable
  (`cmd = ['python3', 'ci/unsafe.py']; subprocess.run(cmd)`) fails closed
  instead of reading as an unresolvable literal. The same rejection applies to a
  Python heredoc a reached shell script executes (`python3 <<'PY' ... PY`),
  which would otherwise be the one Python surface that accepted a variable
  process command.
  The interpreter an invocation names is carried with the path it runs, because
  it is the only evidence of language a file with neither suffix nor shebang
  has. `python3 ci/unsafe` therefore reads that file as Python — extracting and
  checking its process calls — instead of reporting it as automation with no
  scannable interpreter, while the extensionless shell revalidation above still
  runs. The two readings are a union rather than a choice, so nothing an earlier
  class already rejected stops being rejected, and a bare `./ci/unsafe` that
  names no interpreter invents none. A bare extensionless reference is read as
  shell during traversal as well as during revalidation, so `run: scripts/build`
  is followed into the script instead of being reported as automation with no
  scannable interpreter by the very stage whose successor does scan it; an
  explicit interpreter and a build-dispatcher manifest keep their own readings.
  PowerShell provenance is replayed the same way Python provenance is: `pwsh
  scripts/opaque` reaching an extensionless file adds a cmdlet reading to the
  shell one, so `Start-Process cross -ArgumentList 'build --target ...'` — which
  is not a dispatch in POSIX shell at all — still fails closed. Pull-request
  surface comparison receives the same provenance and applies it to both the
  merge-base and the proposed tree, so a proposed no-shebang `scripts/opaque`
  reached by `python3 scripts/opaque` is compared as Python rather than as
  unread text, and the two sides stay symmetric.
  Provenance is applied whenever it appears, not only the first time a path is
  reached. A suffixless script already reached bare and read as shell is re-read
  when a later edge names `python3` or `pwsh` for it, so the process calls inside
  that alternate-language reading are followed too; skipping on reachability
  alone meant `scripts/a` discovered first as shell and later as `python3
  scripts/a` never had its `subprocess.run(['bash', 'scripts/unsafe.sh'])` edge
  added. Provenance only accumulates, so the walk settles in a bounded number of
  passes and reports rather than assumes if it cannot.
  A reached build-dispatcher recipe is shell, so it is scanned with the whole
  trusted-shell surface policy rather than a subset of it: literal Cross, wrapped
  literal Cross, generated inline shell, an opaque ARM64 execution, an opaque
  Cross executable for *any* target (`cmd=$(printf cross); "$cmd" build`), and an
  undecodable stdin producer such as `printf '\x63ross build --target ...' | bash`
  all fail closed during exact-tree revalidation and not only during pull-request
  comparison. A recipe whose producer is an ordinary unescaped literal stays
  readable and stays editable.
  Those raw-text searches read a program's command text rather than its raw
  lines, for the same reason the opaque-ARM64 search does. A reached script that
  *writes* a literal template — `cat <<'EOF'` holding `bash -c "$(render)"` — is
  not executing that inline shell, so the quoted body no longer reports a
  generated inline shell surface that would block safe automation edits. The
  narrowing is not a weakening: an unquoted body's substitutions are re-emitted
  as the command lines they really are, backslash continuations are folded first,
  and an unterminated heredoc withdraws the narrowing and reads the program raw.
  Cross-sensitive jobs, local-action files, and
  reachable scripts are represented by full digests, while unrelated workflow,
  action, and script additions or edits remain permitted. The isolated jobs use
  only pinned external setup actions before revalidation.
- The `needs` fields that connect ARM64 artifacts to `latest-release`, CI and
  release Docker publishing, and `create-release` are separately protected;
  the CI publishers' success conditions are protected too. Only those direct
  publication-control fields are frozen, so unrelated implementation changes
  inside the publishing jobs remain permitted.
- Trusted Cross also freezes Cross-sensitive release jobs by whole-job digest
  under opaque-shell comparison, so `create-release.needs` cannot gain an
  attestation edge from an ordinary pull request. Release image attestation
  therefore stays a dedicated post-manifest job, and
  `release-attestation-gate` joins `create-release` with
  `attest-release-images` so the workflow cannot succeed unless verification
  succeeded. If a GitHub Release is created before attestation finishes and
  attestation then fails, the gate deletes that release. The attestation job's
  dependencies and exact `id-token`/`packages` permission block remain part of
  the required-CI static contract.
- The required-CI static attestation contract separately validates the complete
  signing, SBOM, provenance, verification, and fail-closed publication-gate
  flow.
- The Docker jobs never name the ARM64 artifact literally; they select it
  through matrix values. Their `strategy` block and the two steps that consume
  it — `Download Linux binary` (`name: binary-${{ matrix.binary_target }}` /
  `release-binaries-${{ matrix.binary_target }}`) and `Prepare Docker context`
  (which copies `${{ matrix.binary_asset }}` and `${{ matrix.cni_asset }}` into
  `${{ matrix.arch_dir }}`) — are therefore frozen as one artifact-selection
  contract in both workflows. Without it a pull request could repoint the
  `linux/arm64` row at the x86_64 artifact and publish an ARM64 image
  containing the wrong binary while the protected ARM64 build still succeeded.
  Freezing those two steps alone would still leave the rest of the job able to
  rewrite the context they prepared: a pull request could keep the matrix and
  both steps byte-for-byte identical, add a second download of the x86_64
  artifact, and copy it over `docker-context/bin/arm64/ferrum-edge` before the
  image is built. The **entire `steps:` list** of each Docker publishing job is
  therefore frozen as well, in both workflows and against both the pinned
  contract and the merge base, so no later step — including one that assembles
  the context path out of shell variables, or repoints the build's `context:`
  input — can touch the prepared per-arch binaries. Editing a Docker publishing
  job requires updating `PUBLISH_CONTROL_CONTRACTS` in the same commit; the
  remaining publishing jobs stay editable.
- The manifest jobs that assemble the published tags select their inputs by
  **wildcard**, not by name: `docker-manifest` and `docker-ebpf-manifest`
  download `docker-digest-*`/`docker-ebpf-digest-*` into `/tmp/digests` and
  hand every file in that directory to `docker buildx imagetools create`.
  Freezing the per-platform producers alone therefore left the published
  `latest` and release tags reachable, because artifacts are scoped to the
  **workflow run** rather than to `needs`: a pull request could add an unrelated
  push-only job that uploads one more matching digest and have it collected with
  no edge in the job graph at all. Each manifest job's `needs`, its gating
  condition, its `Download digests` step, and the `imagetools create` commands
  are frozen, `docker-ebpf`'s `needs`, `strategy`, and `Upload digest` step are
  frozen alongside the other producers, and — because freezing the job graph
  cannot stop an *added* job — the digest artifact **name space itself is
  owned**: only `docker` may produce a `docker-digest-*` name and only
  `docker-ebpf` may produce a `docker-ebpf-digest-*` one. A name assembled by an
  expression is ruled out only when its literal prefix already disagrees with
  the wildcard, so `docker-digest-${{ github.actor }}` from any other job is
  rejected while `binary-${{ matrix.target }}` and unrelated artifact names stay
  editable. This is checked against both the pinned contract and the proposed
  tree, so an added job is caught even though it changes no frozen field.
  Ownership does not depend on how the uploading step is written: every
  `actions/upload-artifact` reference is checked whatever its ref (tag, branch,
  SHA, or none), and a repo-local composite action may not produce a digest
  artifact at all, because the job that calls it — and therefore whether it is
  the frozen owner — is not knowable from the action file.
- Every job that publishes by **wildcard** freezes its whole `steps:` list, not
  only the download that feeds it. `latest-release` and `create-release` publish
  whatever is left in `release-assets/` (`files: release-assets/*` and
  `gh release create ... release-assets/*`), and the manifest jobs publish
  whatever digests the download produced. Freezing only the download list or the
  `needs` graph therefore left every other step of those jobs — including one
  whose stated purpose is release notes — free to add a wildcard download, copy
  an extra file into `release-assets`, or hard-code an additional digest into a
  published tag. The frozen step lists are `latest-release` and `docker-manifest`
  in CI and `create-release`, `docker-manifest`, and `docker-ebpf-manifest` in
  the release workflow. Changing one is a trusted-base change on `main`, exactly
  like the protected ARM64 build job; the published outputs themselves are
  unchanged.
- Flow-spelled YAML is normalized before scanning. `- {uses: ./evil-action}`,
  `- {run: ./evil.sh}`, `with: {name: docker-digest-evil}`, and
  `defaults: {run: {shell: python}}` are the same documents to the runner as
  their block spellings, but every line-oriented scan — local-action roots,
  repository-script following, artifact-name ownership, and workflow shell
  selection — independently loses sight of them. Rather than teach each scan a
  second syntax, one shared layer renders the flow spellings into the block lines
  they stand for and the existing scans are repeated over that rendering, with
  reported line numbers mapped back to the physical source line. The raw pass is
  unchanged, so the normalized pass can only add findings: no anchor, alias,
  merge-key, expression, literal-value-set, shell, local-action, artifact
  ownership, generated-command, or frozen-contract protection is replaced by it.
  Block-scalar bodies are left alone — `- {a: b}` inside a `run: |` script is a
  shell argument, not a step — and a malformed flow collection is reported rather
  than read as an absent one.
- The two protected workflows reach the trusted pull-request gate only through
  their own comparison, because `ci.yml` and `release.yml` are excluded from the
  generic workflow collection. That comparison read only the raw rendering, so a
  flow-spelled step outside the protected ARM64 job produced no surface on either
  side and compared equal. The proposed and merge-base copies of both workflows
  are now scanned through the same flow-normalized second pass the absolute
  contract uses, and the digest-ownership scan the comparison already ran against
  the proposed tree is repeated over that rendering. **Deliberate boundary:** the
  hash-frozen protected job, top-level `env`, and trigger stay *comparisons*
  against the live trusted base rather than absolute re-validations of the
  proposed file, so a base that predates the contract — or the bootstrap commit
  that introduces it — is not retroactively frozen. Everything that is a policy
  rule rather than a base-relative digest is enforced against the proposed tree
  directly.
- A repo-local composite action is checked for digest uploads on the **proposed**
  side of a pull request, not only in the trusted baseline. Adding an
  `actions/upload-artifact` step named `docker-digest-*` to an existing action
  such as `setup-sccache` introduces no Cross token, so the Cross-surface
  comparison sees no change; the action would pass the gate and then contribute
  an extra digest to the wildcard manifest job on the next `main` or tag run. The
  guard is absolute rather than compared, because a local action may never own a
  digest name at all, and it runs over the flow rendering as well.
- Committed Python bytecode is rejected instead of being skipped by suffix. A
  `.pyc` under a scanned automation root is executable automation that no reader
  here can inspect, and `cd scripts && python evil.pyc` is a spelling the command
  scanner did not even recognize, so Cross or publishing code inside the bytecode
  was never examined. Bytecode operands are now recognized and rejected wherever
  they are invoked, committed `.pyc`/`.pyo` paths are rejected from the proposed
  tree listing and from every git-reconstructed automation tree — including
  nested `__pycache__` directories — and the live working copy still ignores the
  interpreter's own untracked cache, which `git ls-tree` never reports, so a
  generated file cannot produce a false positive.
- A relative command operand is resolved from the directory the shell is
  actually in. `cd docs; bash scripts/coverage.sh` runs `docs/scripts/coverage.sh`,
  but the tracked directory was previously applied only to slashless names, so
  the policy recorded and scanned the approved-root `scripts/coverage.sh` while
  the runner executed an unscanned same-name path. Every relative repository
  command now inherits the tracked directory, `..` is normalized across nested
  and repeated `cd`s instead of discarding the directory state, and anything that
  leaves the tree — an absolute path, `~`, `cd -`, an expansion, a conditional
  `cd`, or a traversal above the repository root — fails closed. Absolute
  handling and correct root-relative resolution are unchanged.
- `python -m <module>` is an executable repository dispatch. Only inline `-c`
  programs were extracted, so `python -m cross build --target
  aarch64-unknown-linux-gnu` read as a benign Python invocation even though
  Python loads a module from the checkout. Interpreter options are now parsed
  through `-m` — including bundled clusters (`-Im`), attached modules (`-mpkg`),
  and operand-taking options (`-W`, `-X`) — and a literal module is resolved
  against the tracked directory to `<module>.py` or `<module>/__main__.py`, which
  must be a scanned automation file. A computed module name, an unmodeled option
  that could move the module slot, an unknown working directory, or a module that
  resolves outside the approved roots all fail closed. Modules that ship with the
  interpreter or an installed tool (`py_compile`, `pip`, `venv`, `unittest`,
  `json.tool`, and the rest of the allowlist) stay usable, and `-c`, `-`, and
  ordinary script-path invocations are untouched.
- `rustup run <toolchain> <command>` executes its command operand like `nice` or
  `timeout`, with a mandatory toolchain operand in between, so executable
  dispatch follows it: `rustup run stable ./cross build --target ...` is read as
  the `./cross` invocation it is. Subcommands that only manage toolchains and
  components (`component`, `toolchain`, `target`, `update`, and the rest) execute
  nothing the caller named and are not followed, so ordinary
  `rustup component add clippy` stays editable and no trust is extended to
  repository executables outside the approved automation roots.
- `latest-release` and `create-release` download the five build artifacts by
  exact name instead of by a `binary-*`/`release-binaries-*` wildcard, so an
  unrelated job cannot contribute a colliding upload to a published release.
  Each then copies a closed, auditable list of exact trusted files, asserts
  that the published set equals that list exactly, and verifies every `.sha256`
  sidecar before publishing. Native and protected ARM64 publishing are both
  preserved: the ARM64 artifact is downloaded under its own exact name.
- The Cross process starts through `env -i` with an explicit minimal host
  environment and fixed compiler variables. This removes `CROSS_CONFIG`, every
  `CROSS_BUILD_*`/`CROSS_TARGET_*` alias, image/Dockerfile/pre-build/runner
  overrides, custom-toolchain and compatibility flags, Docker/Podman engine and
  option overrides, remote mode, Cargo default-target overrides, and arbitrary
  inherited `CARGO_*` passthrough values before Cross reads configuration.

The trusted `pull_request_target` job checks out only the base SHA with
read-only contents permission, and verifies that the checkout is exactly the
triggering base SHA because it is the only code the job executes. Because
`main` can advance after the event is created, the job then fetches the live
base branch tip into a fixed local ref, requires it to descend from the
triggering base SHA, and pins it to one immutable commit SHA that every
baseline extraction and comparison reads; a live tip that does not descend from
the triggering base is a rewritten or confused ref and fails closed. It fetches
the PR head without checking it out,
requires the fetched object to equal the immutable head SHA from the triggering
event, then extracts `Cross.toml`, `Cargo.toml`, `.cargo/config.toml`, the
complete proposed and live-base workflow and repo-local action directories,
and the approved automation roots plus the root build-dispatcher manifests as
hostile data. The verifier it executes, and every trusted contract that
verifier reads — `ci.yml`, `release.yml`, the workflow, local-action, and
automation baselines, and the trusted policy workflow itself — are all
extracted from that one pinned live trusted tip, never from the possibly stale
event-base checkout, so a Cross surface that only the newer live-base verifier
recognizes is still enforced. GitHub loads the policy workflow file itself from
the event base and it therefore cannot be re-executed from the live tip; that
extraction contract is instead authenticated by comparison and fails closed
when the trusted tip has moved it, which self-heals as soon as the pull
request's base is updated. Each NUL-delimited
`git ls-tree` result is materialized and its status checked before consumption;
regular blobs may use letters, digits, `.`, `_`, `+`, `@`, `~`, spaces, and
`-`, while dot-dot components, symlinks, gitlinks, and NULs fail closed. A
proposed legacy `.cargo/config` is surfaced and rejected. Proposed executable
and configuration surfaces are compared with the live trusted base tip,
preventing both a stale branch and a stale event base from restoring a surface
removed from main. The verifier and trusted workflow themselves are compared
with `<live base>...<PR head>`, preserving merge-base behavior only for the
question of whether the PR authored a protected-file modification, mode change,
rename, or deletion. The verifier enforces this shape on the trusted workflow
itself, rejecting a baseline read from the stale event-base checkout as well as
an unfetched, unpinned, or unauthenticated live base. On pull
requests, the ordinary `CI Plan` executes the base branch's
trusted verifier when it exists and never imports or runs the proposed script.
For this one bootstrap PR, where no base verifier or base-loaded trusted
workflow can exist yet, CI syntax-compiles and executes the reviewed proposed
verifier; all later PRs necessarily execute the protected base copy. Every
verifier invocation uses Python isolated mode so the script directory,
`PYTHONPATH`, and user site cannot redirect its standard-library imports. This
policy step runs before every other repository Python entry point in the plan
job, and the subsequent planner self-test and its imported live-suite path
filter are also extracted from the base branch on pull requests. The planner
example consumes the exact `origin/${BASE_REF}` fetched by the immediately
preceding policy step, so those adjacent steps have an intentional ordering
dependency.

##### Trusted-base relevance for required live gates

`mesh-e2e-sidecar-live.yml` and `multicluster-federation-live.yml` publish
required status checks that may legitimately skip their expensive live job when
a pull request touches nothing relevant. That skip is a security boundary: if
the relevance verdict were computed by the pull request's own copy of
`.github/scripts/live_suite_path_filter.py`, a pull request could widen
`SUITE_PATTERNS`, declare itself irrelevant, skip the live job, and still turn
the required gate green.

Both workflows therefore share one byte-identical relevance job, frozen in the
trusted verifier as `LIVE_SUITE_RELEVANCE_JOB_TEMPLATE` and enforced absolutely
by `live_suite_relevance_errors` in exact validation *and* in pull-request
comparison. Only the display name, temp-file slug, and `--suite` selector
differ. Its load-bearing properties:

- The relevance script comes from the base-branch tip of the **base**
  repository, never from the pull-request checkout. This holds for fork pull
  requests too, because `github.base_ref` always names a branch in the base
  repository and `origin` is the base repository.
- That tip is resolved **once** to a full 40-hex commit id, and every later read
  goes through that id and then through the blob's own object id, so a push to
  `main` between validation and execution cannot swap the script (TOCTOU).
- `github.base_ref` is untrusted text: it is charset- and shape-validated before
  it can reach a refspec, so no option, pathspec, or revision-syntax
  metacharacter (`-`, `..`, `:`, `^`, `~`, `@{`, glob characters) can be
  smuggled into a git invocation.
- The tree entry must be a single regular blob (`100644`/`100755`) at the pinned
  path and at most 256 KiB. A symlink (`120000`), gitlink (`160000`), tree,
  missing entry, multi-entry match, or oversized blob fails closed.
- Every failure path exits non-zero, and the emitted verdict must literally be
  `true` or `false`, so acquisition or execution failure fails the gate instead
  of defaulting to "irrelevant".
- The filter runs under `python3 -I`, so nothing the pull request committed can
  be imported into the trusted interpreter.

Freezing the relevance job alone would not be enough — a pull request could
leave it untouched and instead rewrite the live job's `needs`/`if`. The binding
`needs: changes` plus `if: needs.changes.outputs.relevant == 'true'` is
therefore part of the same contract, and deleting a governed workflow outright
is rejected as well.

The change set the job hands the classifier is a newline-delimited
`git diff --name-only --no-renames "${trusted_sha}...HEAD" | sort` listing.
Git C-quotes any pathname carrying a newline, a quote, a backslash, or a
non-ASCII byte, so a quoted record names a *different* path than the one on
disk. `live_suite_path_filter.py` therefore refuses to classify any record that
is not a normal repository-relative pathname (conservative
`[A-Za-z0-9._+@~ /-]` charset; no absolute path, `.`/`..`/empty component,
trailing slash, or surrounding whitespace). Refused records are withheld from
pattern matching and from the step summary, and their presence forces
`relevant=true`: a record the classifier cannot read must never be mistaken for
"no relevant file changed". The suite is also forced to run on `push` and
`workflow_dispatch` through `--force-run`.

###### Optional suites on the same pattern

Issue #3908 moved three optional suites off pull-request-supplied `paths:`
triggers and onto the same posture:

- `node-waypoint-ebpf-live.yml` already had a trusted-base classifier — the
  `production-dockerfile-plan` job reading `ci_runtime_plan.py` — so it did not
  get a second one. Two relevance jobs gating one live job is precisely the
  "either gate bypasses the other" hazard; the existing planner stayed the sole
  authority and only the trigger and the aggregate changed. Its planner,
  bindings, and aggregates are now frozen by `NODE_WAYPOINT_RELEVANCE_CONTRACT`
  (see below).
- `istio-status-cas-live.yml` and `cni-lifecycle-live.yml` gained a `changes`
  job matching the `LIVE_SUITE_RELEVANCE_JOB_TEMPLATE` text above apart from
  the display name, slug, and `--suite` selector. Both are now entries in
  `LIVE_SUITE_RELEVANCE_CONTRACTS`, so that text match is a freeze.

These three aggregates (`NodeWaypoint eBPF Live`, `Istio Status CAS Live`,
`CNI Lifecycle Live`) are **not** branch-protection-required and must not be
added to `REQUIRED_MERGE_GROUP_WORKFLOWS` or `DEDICATED_REQUIRED_CHECKS`;
`verify_required_ci.py` asserts that, and asserts each keeps the canonical
input-less `pull_request`, `merge_group` with exactly `checks_requested`,
and `push: branches: [main]` trigger shape. Freezing the *shape* of an optional
gate is not the same as making it required, and neither contract below makes
one required.

###### NodeWaypoint relevance contract

`node-waypoint-ebpf-live.yml` cannot be carried by
`LIVE_SUITE_RELEVANCE_CONTRACTS`: its relevance job is
`production-dockerfile-plan` rather than `changes`, it runs `ci_runtime_plan.py`
rather than `live_suite_path_filter.py`, one trusted read emits **two** verdicts
(`relevant` for the production-image smoke and `node_waypoint_relevant` for the
live datapath), and its live job binds fail-closed as
`always() && … != 'false'` rather than `== 'true'`. Widening the shared
mechanism to absorb those four differences would put the branch-protection-
required live gates behind a more permissive, more parameterised template for
the sake of one gate that is deliberately not required.

Trusted policy therefore carries a second, additive contract —
`NODE_WAYPOINT_RELEVANCE_CONTRACT` plus `NODE_WAYPOINT_FROZEN_JOBS`, enforced by
`node_waypoint_relevance_errors` from both `validate_workflow_collection` and
`compare_pr_workflow_collection`, absolute in exact and pull-request mode alike:

| Job | Frozen |
|---|---|
| `production-dockerfile-plan` | whole job |
| `production-dockerfile-smoke` | whole job (aggregate) |
| `node-waypoint-ebpf-live-gate` | whole job (aggregate) |
| `production-dockerfile-smoke-default` | `needs` + `if` only |
| `production-dockerfile-smoke-ebpf` | `needs` + `if` only |
| `node-waypoint-ebpf-live` | `needs` + `if` only |

The planner is frozen whole because its base-ref charset/shape validation,
single object-id pin, blob type/mode/size checks, `python3 -I` isolation,
`true|false` verdict guard, and both `emit_suite_verdict` calls are one
fail-closed unit. The two aggregates are frozen whole because their condition
chains are the entire difference between "skipped because the trusted base
proved irrelevance" and "green because the live job never ran". The three
consumer jobs keep only their binding frozen, because their bodies are ordinary
build and live-test recipes that must stay editable. Deleting the workflow is
rejected too: a contract a `git rm` retires is the same weaker-than-it-looks
coverage issue #3908 was filed for.

With both contracts in place, issue #3908 is durably complete: neither new
`changes` job nor the NodeWaypoint planner-to-live-to-aggregate posture can be
rewritten by a pull request. The temporary `--list-suites` bootstrap handshake
that carried the CNI and Istio suite names through their adoption window is
deleted from `live_suite_path_filter.py`; both names are on `main` and the
frozen relevance template never invoked the flag.

##### Admitted fuzz/property lane

Issue #2461 requires a short deterministic property/fuzz smoke in ordinary CI
and a longer sanitizer-backed scheduled lane. The trusted policy rejects any new
Cross-readable executable surface in `ci.yml` outside the protected ARM64 job,
so rather than relaxing that rule the policy admits **exactly two** byte-frozen
shapes and nothing else:

- `CI_FUZZ_SMOKE_JOB` — the entire `fuzz-smoke` job in `ci.yml`. A repository
  that has not adopted it may omit it; once the trusted base carries it, a pull
  request may neither remove nor alter it. Its surfaces, and only its surfaces,
  are then withheld from the `ci.yml` surface comparison; a top-level surface
  and every other job's surfaces are unaffected. Every command, action pin,
  toolchain pin (`nightly-2025-07-01`), tool version (`cargo-fuzz 0.13.1`),
  target name, and libFuzzer bound (`-runs`, `-max_total_time`, `-max_len`,
  `-timeout`, `-rss_limit_mb`) is part of the contract. All automation commands
  are inline and cannot be redirected through a repository-supplied script;
  the read-only job necessarily compiles and executes pull-request-authored Rust
  tests and fuzz targets. The frozen job installs `protobuf-compiler` before
  invoking Cargo because the workspace build script requires `protoc`. Its
  1024 MiB RSS cap leaves bounded headroom above the roughly 400 MiB baseline
  of the fully linked, sanitizer-instrumented fuzz binaries.

  Because a whole-job freeze cannot express an edit, a change to *where* each
  half of the lane runs (#3902, #4238) or to *which targets* the budget covers
  (#4442) is admitted as two byte-frozen **generations** with a one-way
  transition between them (`CI_FUZZ_SMOKE_JOB_GENERATIONS`, oldest first) — the
  same shape as the admitted `release.yml` image-family adoption. See
  [Admitted `fuzz-smoke` lane-split generation](#admitted-fuzz-smoke-lane-split-generation).
- `FUZZ_WORKFLOW` — the whole of `.github/workflows/fuzz.yml`. A repository
  that has not adopted it may omit it; once the trusted base carries it, a pull
  request may neither remove nor alter it. Whole-file
  equality is the contract because a scheduled lane's triggers, permissions, and
  concurrency are as security-relevant as its steps. It is `schedule` +
  input-less `workflow_dispatch` only (no untrusted head can schedule it),
  read-only at workflow and job level, references no secret, pins every action
  to a full commit SHA, bounds every libFuzzer run in wall time / input length /
  per-input timeout / RSS, re-checks the matrix target against a literal
  allowlist before it reaches a command line, rejects symlinks and other
  non-regular crash-artifact objects, and bounds regular artifacts by size and
  count **before** publication — with the upload gated on that bounding step
  having succeeded, from one fixed path, at short retention. Its environment
  carries the same empty wrapper and `RUSTFLAGS` overrides as the smoke job.
  Each matrix job gives cold sanitizer compilation a 90-minute outer deadline
  and uses 16 codegen units; the target itself remains independently capped at
  300 seconds, so build variance cannot widen the actual fuzzing budget.

A lane nothing observes is not a gate, so adopting `CI_FUZZ_SMOKE_JOB` also has
to make it a required input of the `test` (`Tests`) aggregate. That aggregate is
Cross-sensitive to the pull-request scan, so its per-job digest surface moves the
moment the wiring lands. The policy therefore admits **exactly three** further
lines, each byte-exact and each anchored immediately after the trusted-base
`lint` line it must follow (`CI_FUZZ_SMOKE_AGGREGATE_INSERTIONS`):

- `      - fuzz-smoke` in the aggregate `needs` list, after `      - lint`;
- `add_row "Fuzz Smoke" "${{ needs.fuzz-smoke.result }}"`, after the `Lint` row;
- `require_success "Fuzz Smoke" "${{ needs.fuzz-smoke.result }}"`, after the
  `Lint` assertion.

Only those three lines are withheld, only when the `fuzz-smoke` job itself is
present and byte-identical, and they are withheld from *both* sides of the
comparison — so every other byte of the aggregate is still compared against the
trusted base. A missing, duplicated, tampered, relocated, or advisory-only
reference, and any unrelated aggregate edit, is still rejected. Withholding is
symmetric, so a separate one-way check
(`ci_fuzz_smoke_aggregate_removal_errors`) keeps a pull request from taking the
wiring back out once the trusted base carries it. The aggregate `test` job is not
otherwise exempt, and no other job, action, automation surface, publisher
contract, top-level `env`/trigger, or Cross token is affected.

No admitted generation, and not the scheduled lane, names the protected ARM64
target or the Cross executable, requests write permission, or references a
secret; the verifier self-tests assert each of those directly, plus rejection of
budget widening, unpinned or mutable action/tool pins, local-action
substitution, shell indirection, untrusted interpolation, broadened triggers or
permissions, arbitrary target selection, ungated publication, and widened
artifact paths.

Because only the repository-root Cargo configuration is validated, a committed
`.cargo/config[.toml]` anywhere below the root is now rejected outright
(`validate_nested_cargo_configuration_tree`): the fuzz lane runs with
`working-directory: fuzz`, and a nested Cargo configuration there would be an
unreviewed place to set a target linker, runner, or rustflags.

###### Admitted `fuzz-smoke` lane-split generation

The whole job is frozen, so neither moving the lane nor extending its target
list can be an edit. `CI_FUZZ_SMOKE_JOB_GENERATIONS` therefore lists the job's
admitted texts oldest first, and a generation retires once its successor is on
`main`. The pair currently carries issue #4442.

- `CI_FUZZ_SMOKE_RETIRED_JOB` — the shape issue #4238 landed. `Fuzz Smoke` had
  been the longest job in required pull-request CI (roughly 47 minutes, of which
  roughly 46 were compilation) because the six sanitizer-instrumented libFuzzer
  targets were rebuilt from scratch on every pull request to buy about 48
  seconds of actual fuzzing. #3902 moved that budget off the pull-request path
  and added the checksum-pinned `setup-sccache` compiler cache; #4238 moved it
  off `merge_group` as well, because a hosted-runner reclamation (`exit 143`)
  inside the ~38-minute window ejected the queue entry and cascaded a rebuild of
  everything behind it with no defect in the ejected change. In this shape the
  deterministic property smoke is the required `pull_request` and `merge_group`
  gate, and the six-target bounded budget runs on the push to `main` and on
  `workflow_dispatch` only.
- `CI_FUZZ_SMOKE_JOB` — the adopted shape (#4442): identical, plus a seventh
  bounded libFuzzer invocation for `datagram_client_address`.

  That target parses the Datagram PROXY v2 envelope — address block, the `0xE0`
  authentication-tag and `0xE1` freshness TLVs, and the freshness value — on
  attacker-controlled UDP input, entirely **before** the MAC decision. It had
  been registered, corpus-seeded, and property-tested since #3289/#3862, but
  neither libFuzzer lane executed it, so no lane was actually fuzzing that
  parser.

  It is invoked on its own rather than appended to the six-target loop because
  its documented input budget is 64 KiB (`fuzz_support::MAX_FUZZ_INPUT_BYTES`),
  not the loop's 4 KiB. The scheduled `fuzz.yml` lane runs every target at
  `-max_len=65536`; running this one at 4 KiB here would leave the same parser's
  length boundaries reachable in one required lane and unreachable in the other.
  Every other bound — `-runs=512`, `-max_total_time=8`, `-timeout=2`,
  `-rss_limit_mb=1024` — is byte-identical to the loop's, so the budget is
  widened by one target rather than relaxed.

What is invariant across both generations:

- the property smoke runs the same `cargo test --locked` and is the required
  full-mode `pull_request` and `merge_group` gate;
- the six-target loop is byte-identical. The self-test asserts
  `CI_FUZZ_SMOKE_BOUNDED_BUDGET` — the six `Fuzz smoke target:` markers, the
  `cargo fuzz run --codegen-units 16` invocation, and `-runs=512`,
  `-max_total_time=8`, `-max_len=4096`, `-timeout=2`, `-rss_limit_mb=1024` —
  appears exactly once in every generation, so a generation can never move or
  extend the lane and relax its bounds in the same change;
- the seventh invocation is frozen the same way in the adopted generation only.
  `CI_FUZZ_SMOKE_DATAGRAM_BUDGET` must appear exactly once in
  `CI_FUZZ_SMOKE_JOB` and never in `CI_FUZZ_SMOKE_RETIRED_JOB`, and the
  self-test separately asserts its 64 KiB `-max_len` and each shared bound;
- the bounded budget is gated by an **allow-list** —
  `if: github.event_name == 'push' || github.event_name == 'workflow_dispatch'`
  — not by excluding events. The self-test rejects a `!=` form outright;
- compiler caching is admitted only through the repository's own
  `./.github/actions/setup-sccache`, the single local action the contract
  permits. That action installs a checksum-pinned sccache release, never enables
  the credential-bearing sccache GHA backend, never persists
  `ACTIONS_RUNTIME_TOKEN` / `ACTIONS_RESULTS_URL` into later
  pull-request-controlled steps, asserts those variables are absent before any
  build runs, and clears the wrapper entirely if the install fails. Local
  actions are not exempt from the policy: `validate_action_collection` and
  `compare_pr_action_collection` reject a Cross executable or configuration
  input in any of them, and the action's own surfaces are attributed to
  `actions/<name>`, never withheld with the job's;
- the job does not pin `RUSTC_WRAPPER` at job level — a job-level `env` entry
  would override the installer's fail-closed `GITHUB_ENV` decision — while
  `RUSTFLAGS: ""` stays, because the root Cargo configuration still selects a
  mold linker this lane does not install;
- the sccache directory is persisted by the pinned `Swatinem/rust-cache` step
  under `save-if: ${{ github.event_name == 'push' && github.ref == 'refs/heads/main' }}`
  and nothing else. That predicate is the cache-quota control: `pull_request`
  (same-repository PR refs and forks), `merge_group`, and `workflow_dispatch`
  may restore a `fuzz-smoke` cache but cannot publish one;
- telemetry: the job prints `Fuzz property smoke seconds`, `Fuzz sanitizer lane
  seconds`, sccache statistics before and after the sanitizer build, the lane
  shape it took, and the on-disk cache size — so a hosted log shows whether the
  sanitizer build actually reused work, and warns explicitly when sccache was
  unavailable.

The transition is exact on both ends and one-way. `admitted_fuzz_smoke_errors`
accepts a `fuzz-smoke` job only at one of these two texts (or absent);
`admitted_fuzz_smoke_removal_errors` refuses both removal and a move to a lower
generation. That direction check is load-bearing rather than decorative: every
admitted generation is withheld from *both* sides of the surface comparison, so
the digest comparison alone would accept a revert. The self-test drives the full
transition through `compare_pr_workflow_job` in both directions, re-runs every
shared tamper mutation against each generation, and adds adopted-generation
mutations covering what #3902, #4238, and #4442 introduced — restoring the
sanitizer budget to pull requests, dropping it from the push to `main`,
re-adding it to the merge queue, skipping the property gate on pull requests,
allowing untrusted cache writes, substituting an unpinned third-party sccache
installer, enabling the credential-bearing GHA backend, widening the cached
directory, deleting the `datagram_client_address` invocation, re-bounding it to
the generic 4 KiB ceiling, and pointing it at a target the loop already covers.

The scheduled lane's own contract carries the same target inventory: the
`fuzz.yml` freeze includes `datagram_client_address` in both the matrix and the
shell allowlist, and the self-test rejects a revision that drops it from either.

The aggregate wiring is unaffected: this is still one job named `fuzz-smoke`,
so `CI_FUZZ_SMOKE_AGGREGATE_INSERTIONS` and the `require_success "Fuzz Smoke"`
assertion are byte-identical across the transition.

Delete `CI_FUZZ_SMOKE_RETIRED_JOB` from `CI_FUZZ_SMOKE_JOB_GENERATIONS` — and the
`("retired fuzz-smoke generation", CI_FUZZ_SMOKE_RETIRED_JOB)` self-test row with
it — once the adopted generation is on `main` and no supported base still carries
the retired one.

##### Admitted release image-family adoption (`-ebpf-tools`)

Every job in `release.yml` that publishes by wildcard is frozen byte for byte, so
adding a third production image family is not something an ordinary pull request
can express: the new publisher, the new digest name space, and the new
attestation subjects all live inside frozen text. Rather than relaxing that
freeze, the policy admits **exactly two** shapes of the release workflow and one
transition between them (`RELEASE_IMAGE_FAMILY_GENERATIONS`):

- **two-family** — the shape on `main` today: `:<tag>` and `:<tag>-ebpf`. In this
  shape the `-ebpf-tools` family may not be named anywhere in the file at all.
- **three-family** — the same workflow plus the complete `-ebpf-tools` contract:
  the `docker-ebpf-tools-manifest` job (its `needs` and its whole step list,
  including the `docker-ebpf-tools-digest-*` download pattern, the
  `/tmp/digests-tools` working directory, and every published tag); the tools
  build/export/upload steps inside the single `docker-ebpf` job; sole ownership
  of the `docker-ebpf-tools-digest-` wildcard by that same job; the extended
  `create-release` `needs`, the gating rationale comment that shares its `name:`
  field block, and its release notes; and an `attest-release-images` job
  that resolves, cross-registry-compares, SBOMs, provenances, signs, attests, and
  verifies all three families in both registries.

The credentialed `docker-ebpf` producer is closed over its complete ordered
job-field set and its entire `steps:` list in both shapes; the tools manifest is
closed the same way after adoption. An extra context-rewrite step, an alternate
runner, `continue-on-error`, `if`, `environment`, `container`, `services`, or
any other added job control is therefore a contract violation even when every
named build/upload fragment remains unchanged.

A revision is classified from itself, and is then held to the complete contract of
the shape it claims — so a partial adoption, an extra publisher or tag, an
alternate action/runner/permission/`needs`/step, a missing attestation operation,
and a mixed digest name space are all rejected. Which transitions are legal is a
separate, comparative question decided from the trusted base
(`release_image_family_transition_errors`), never from the proposal: while the
base is still two-family a pull request may leave the workflow byte-identical or
move it in one step to the complete three-family shape, and once the base carries
the three-family shape reverting to two-family is refused. The
`docker-ebpf-tools-digest-` prefix is refused to repo-local composite actions in
both generations, because a local action is never a digest owner in any shape.

The publication contract is only half of the gate. The generic pull-request scan
also hashes every job it reads as Cross-sensitive and requires the two revisions
to agree, and the adoption moves frozen text inside such jobs by design — the
extended `create-release` `needs` names `build-release-arm64-cross`. That
comparison therefore rejected the complete admitted shape, which made the
transition unreachable. It is repaired by a projection rather than an exemption
(`release_family_transition_surface_contents`): once both revisions have
classified, the proposal has validated against the whole three-family contract,
and the base carries every two-family frozen text verbatim, the proposal is
re-rendered in the two-family text it came from — each frozen fragment
substituted back to its original, the new manifest job removed whole — and the
surface comparison then reads the same bytes on both sides. The substitution
table is derived from the two contract tables themselves, so it cannot drift from
them; every substitution must match exactly once or the projection is abandoned
and the unmodified revisions are compared. Nothing outside those frozen fragments
is withheld — the only non-contract text the projection removes is the comments
and blank lines inside the removed manifest job, which that job's closed
field set and frozen `steps:` list already prevent from carrying any surface — so
a Cross command, a `CROSS_*` input, or any other executable
surface added anywhere in the file — including elsewhere inside a transitioned
job — is still rejected while the adoption is in flight, and the projection never
applies to any other workflow, to an unchanged release workflow, or to a
rollback.

The trusted-base verifier is what reads the base and executes; the proposed
verifier never decides its own pull request's safety. Adopting this admission
layer therefore takes two stages, exactly like the original trusted-CI bootstrap:
a policy-only pull request that lands the admission (its own
`Trusted Cross Build Policy` check fails by design, because that check refuses any
modification of the verifier it protects, and the landing is administrative after
root review), then an ordinary pull request that adopts the release workflow
under the now-trusted policy and runs the full hosted matrix.

##### Admitted `fips-build.yml` generation transition (issue #3888 lineage / issue #4018, temporary)

The temporary whole-file SHA-256 admission first used for PR #3889 (retired by
#3943), then re-armed for PR #3950 and spent when #3950 landed, is **re-armed
for exactly one transition**: the issue #4018 mitigation for the
`fips-test-build` job.

`Precompile FIPS test binaries for consumers` is killed with `exit code 143`
and `The runner has received a shutdown signal` on a large minority of runs.
The log always ends the same way — the dependency graph finishes, the run goes
silent for several minutes while Cargo builds `unit_tests` and
`integration_tests`, and the runner dies mid-tail with no diagnostic. That is
the hosted runner's memory ceiling, not a compile error: `[profile.dev]` sets
`debug = true` and the `test` profile inherits it, so every concurrent codegen
thread holds a full-debuginfo LLVM module for the whole crate.

The destination adds a job-level `env` capping `CARGO_BUILD_JOBS` at 3 and
setting `line-tables-only` debuginfo on the `dev` **and** `test` profiles (both,
rather than relying on `test` inheriting from `dev`), plus a best-effort
additive 8 GiB Ferrum-owned swapfile immediately before that step. The swap
step is deliberately not fail-closed — it is insurance rather than a
correctness gate, and this file is digest-frozen. It never disables, removes,
or rewrites the runner image's existing swap; failure cleanup targets only
`/mnt/ferrum-fips-swapfile`. It cannot pass silently: any failure raises a
warning annotation and the resulting `SwapTotal` is always printed.

The pair is exact and one-way: trusted-base
`17bfb40fbd31e80e6ae1a0efca922069c54ec485ec7a611c3420840da3e5e9e1` (the workflow
after PR #3950's landed artifact handoff — the previous admission's adopted end)
→ `7d995d79d9932c9595d3f19eddf16c1dbd1a0d2842230f1d92eb1b24502ca401`. Recompute
and re-pin if review changes the workflow bytes. The digest is over
universal-newline-decoded text. RETIREMENT IS MANDATORY once the mitigation
lands, exactly as #3943 retired the #3889 pair. Any other `fips-build.yml` edit
is still compared by the normal fail-closed Cross surface scan.

##### Coverage-shard compile-memory knobs (issues #4099 / #4368)

`Coverage Shard (lib-unit)` can be killed with `exit code 143` and "The runner
has received a shutdown signal" **during the instrumented compile**, before any
test runs. The log matches `fips-test-build` (issue #4018): the last
`Compiling` line is followed by tens of minutes of silence, then a shutdown
signal. Because `Merge Coverage` depends on the shards and is a required check,
that ejects otherwise-green PRs from the merge queue under concurrent
merge-group load — exactly when the queue is trying to drain. Coverage adds
`-C instrument-coverage` on top of `[profile.dev] debug = true` (inherited by
`test`), so the per-thread LLVM module is even larger than the FIPS
test-binary tail.

Issue #4368 is that recurrence after the `#4099` mitigation: jobs=3, line-table
debug info, additive swap, and `timeout-minutes: 75` still sat on both hosted
ceilings. The repair lowers peak compile concurrency and raises the job
deadline; it does not drop `--lib` or `--test unit_tests`, and it does not split
the combined llvm-cov invocation.

The `coverage-shard` job therefore mirrors the **safe** FIPS knobs that do not
require a Cross generation transition. Only `coverage-merge` is digest-frozen
by `WORKFLOW_DIRECTORY_JOB_GENERATION_TRANSITIONS`; this subsection does not
admit any new pair, and `coverage-merge` stays byte-identical.

| Knob | FIPS `fips-test-build` (#4018) | Coverage `coverage-shard` (#4099 / #4368) |
|---|---|---|
| `CARGO_BUILD_JOBS` | Job-level env `3`; caps rustc codegen threads inside the large crates | Job-level env **`2`**. `#4099` kept `3`; `#4368` lowered it after PR #4336 run `33219849557` job `99020110238` reproduced the compile-phase exit-143 stall at `Compiling testcontainers v0.27.3` with jobs=3, line-tables, and additive swap already on |
| `timeout-minutes` | Job-specific (FIPS compile/test budget) | **`timeout-minutes: 120`**. The `#4099` comment claimed the combined lib+`unit_tests` invocation fit 75 minutes; PR #4347 run `33223661366` attempt 1 job `99027333486` was still passing tests when that deadline canceled it. GitHub cannot set per-matrix-row timeouts, so the shared `coverage-shard` job carries the lib-unit budget; integration shards still finish far earlier |
| `line-tables-only` on `dev` **and** `test` | `CARGO_PROFILE_{DEV,TEST}_DEBUG` | Added in `#4099`. Drops variable-level DWARF only. Line/region attribution comes from `-C instrument-coverage` mapping, not DWARF locals, so `cargo llvm-cov` reports stay equivalent |
| Additive swapfile | Best-effort 8 GiB `/mnt/ferrum-fips-swapfile` (workflow is digest-frozen, so the step must not fail-close) | **Not added.** `coverage-shard` already enlarges swap with a fail-closed 12 GiB `/mnt/ferrum-swapfile` (same pattern as `ci.yml` `test-unit`). A second Ferrum swapfile would be redundant; converting the existing step to best-effort would not lower compile memory |

Instrumentation, shard matrix, test filters, and `cargo llvm-cov` /
nextest invocation flags are unchanged. No coverage shard is removed or
narrowed. Action pins and tool installs are unchanged. `.github/scripts/verify_coverage_workflow.py`
pins `CARGO_BUILD_JOBS=2`, `timeout-minutes: 120`, and the combined `--lib` /
`--test unit_tests` invocation so those knobs cannot drift without failing
Coverage Plan.

##### Admitted CI job SHA-256 generation transitions (temporary)

`ci.yml` is a protected workflow. The ARM64 job stays digest-frozen; every other
job the pull-request scan reads as Cross-sensitive is compared by its whole-job
SHA-256. The CI optimization tranche rewrites some of those jobs. Rather than
relaxing the scan, the trusted policy admits exact retired→adopted pairs
(`CI_JOB_GENERATION_TRANSITIONS` in `.github/scripts/verify_cross_build_policy.py`):

| Job | Retired SHA-256 (trusted base) | Adopted SHA-256 | Destination |
|---|---|---|---|
| `performance-regression` | `74673023dee4c0970a8b8d3c9a99089be2f28eddf57ddb7337febdf22bd5a7e4` | `e7d9a4c0ea26a14efd92844998a42219ca2fb1379072776a313de6dd9b720986` | PR #3911 / issue #3906 |
| `ebpf-live` | `b7596b48641c850f797c84710dd5646013414d6ba01c30f4d4b2805737c8c26c` | `9aa3332bff5c4538f797f31133be0ef7dfc9767a72e7212b39be33ed58dcca87` | PR #3915 / issue #3900 |
| `netns-capture-live` | `db543d5c35bfbd4a7b987a52635b359ea6268669257cd313146324f5ca79f598` | `b71296ba5929c78cd786301cc8ed677905cca82cd605be46880021b88c243e32` | PR #3915 / issue #3900 |
| `two-cluster-mesh-live` | `0586ab0b5b8b803f2ee3663b608c40caca06f9c92e58d4cb28c2080d68f23f27` | `9c3d5b4dfbc6a209e801a47bceabd31fe8aa7df033d49989ad8f88a3e4ed73e7` | PR #3915 / issue #3900 |

The three `#3915` pairs admit the per-suite planner-gate split (the union
`run_ebpf_live` output becomes `run_ebpf_kernel_live` /
`run_netns_capture_live` / `run_two_cluster_live`); the adopted digests are
pinned against #3915's branch after merging latest `main`
(`grok/issue-3900-ebpf-gates`, merged text `d95ea4796`). #3915's `ci-plan` /
`test` changes are planner-body and aggregate-summary edits that today's scan
does not read as Cross-sensitive, so those need no pair here.

PR #3916's `build-binaries` pair is retired: its destination is main's live
value, so the tuple admitted a transition between two states `main` is not in
and only widened what a pull request could claim.

PR #4355's `build-binaries` / `build-release-binaries` pairs (issue #4301) are
retired for the same reason, and more strongly: both destinations landed on
`main`, and the issue #4423 predecessor has since moved both jobs again on
`main` directly, so neither end of either pair is a state `main` is in.
Keeping them would only widen what a pull request may claim. Both producers
are held to `main`'s own text by the ordinary whole-job surface comparison,
and absolutely by `linux_gnu_producer_contract_errors` — see the standing
contract below.

Each digest is the SHA-256 of `extract_job_block` text. Both ends are exact, the
binding includes the job name, the move is one-way, and only that job's
`job:<name>:*` surfaces are withheld for that one pair. The candidate supplies
no digest. `fuzz-smoke` is not in this table; it uses
`CI_FUZZ_SMOKE_JOB_GENERATIONS`.

Jobs omitted because a single predecessor cannot name a unique merged text:

- `test-pkcs11-softhsm` — #3889 already rewrote this job on `main`. #3913
  rewrites it from a different retired text. #3913 must merge latest `main` and
  needs a follow-up predecessor if the remaining PKCS path-gate still moves a
  Cross-sensitive digest.
- `ci-plan` / `test` for #3915 (issue #3900) — different destination hashes from
  #3913. After #3913 is the trusted base, #3915 needs a follow-up predecessor.

Lint (`#3909`) and optional live-suite `changes`
jobs (`#3919`) are not admitted here. They are not folded into this
predecessor; if hosted Cross disagrees after a latest-`main` merge, they need
their own exact pair rather than a wildcard. Coverage planning (`#3917`) is
admitted, but in the workflow-directory table below because `coverage.yml` is
not a protected workflow.

##### Published x86_64 GNU producer contract (standing)

`linux_gnu_producer_contract_errors` is an ABSOLUTE check on the proposed
revision, not a comparison against the trusted base, and it is permanent
rather than a transition admission. It binds as soon as the repository
references `.github/scripts/build_linux_gnu_sysroot.sh`, so a revision that
predates the builder is unaffected and the trusted-policy predecessor could
land before the workflow change.

For each of the two producers — `build-binaries` in `ci.yml` and
`build-release-binaries` in `release.yml` (`release.yml` has no separate table
or contract of its own: the binding includes the job name, so a `release.yml`
job is named here directly) — the check requires the job to:

- run the pinned sysroot builder exactly once, under
  `matrix.target == 'x86_64-unknown-linux-gnu'`;
- exclude that target from every publishing native compile;
- ABI-scan and smoke `release-assets/ferrum-{edge,cni}-linux-x86_64` before
  `Upload artifacts`;
- never hand the scanner a `target/x86_64-unknown-linux-gnu/...` build-tree
  path;
- be the only job that uploads the canonical artifact name;
- pin the sysroot image, the protoc archive digest, and both baseline smoke
  images in its job-level `env:`, to the literals the trusted policy hardcodes
  (issue #4423 — see "GNU sysroot identity pins" below);
- set `persist-credentials: false` on its `actions/checkout` step (issue
  #4423): the job bind-mounts the whole workspace read-write into a root
  container that installs packages and runs every dependency's `build.rs`, so
  the checkout must not leave `http.https://github.com/.extraheader` in
  `.git/config`.

##### GNU sysroot identity pins (issue #4423)

`.github/linux-gnu-abi.toml` names the container image that compiles the
published x86_64 GNU binaries and the protoc archive that image executes as
`build.rs`'s code generator. That file is pull-request-editable, and
`verify_linux_gnu_abi.py` — which reads it — runs from the pull request's own
checkout. Before issue #4423 the only constraint on the image reference was
that *some* `@sha256:` digest was present, and the only constraint on
`protoc_url` was that its archive hashed to the 64-character hex string the
same pull request supplied. A merged change to
`image = "ghcr.io/<attacker>/almalinux@sha256:…"` would have produced the
released `ferrum-edge-linux-x86_64` / `ferrum-cni-linux-x86_64` bytes, their
`.sha256` sidecars, the moving `latest` prerelease, and the default container
images, with every gate green.

The identity now lives in the trusted base, in two places that must agree:

1. Each producer job pins `LINUX_GNU_SYSROOT_IMAGE`,
   `LINUX_GNU_PROTOC_SHA256`, `LINUX_GNU_SMOKE_FLOOR_IMAGE`, and
   `LINUX_GNU_SMOKE_UBUNTU2204_IMAGE` in its own job-level `env:`.
   `build_linux_gnu_sysroot.sh` and `smoke_linux_gnu_baseline.sh` already
   refuse to run when those disagree with the TOML, so a pull request that
   edits the contract file alone breaks the build. The literals themselves are
   held to the trusted constants by `linux_gnu_producer_contract_errors`, an
   absolute check — so a pull request that moves the TOML **and** the matching
   `env:` pin together is refused on the `env:` half.
2. `linux_gnu_contract_pin_errors` re-validates `.github/linux-gnu-abi.toml`
   itself against the same constants. It reads the file through
   `--linux-gnu-contract`, whose default resolves inside the
   `cross-build-policy.yml` checkout — the pinned trusted base — because
   asking the contract file to certify itself from the pull request's tree is
   the defect being closed. The build image, both baseline smoke images, and
   the protoc archive digest are compared for exact equality (an unqualified
   Docker Hub reference, so equality also refuses a registry-host prefix and a
   renamed repository), and `protoc_url` must start with
   `https://github.com/protocolbuffers/protobuf/releases/download/`.

A deliberate image or protoc bump is consequently a direct-to-`main`
predecessor: the constants in `verify_cross_build_policy.py`, the two producer
`env:` blocks, and the TOML all move in one commit. The policy's `--self-test`
drives both halves with fixtures: a producer missing the pins or the
credential-free checkout, and a contract file with a substituted digest,
registry, repository, protoc host, or smoke image.

##### Admitted workflow-directory job SHA-256 generation transitions (temporary)

The `CI_JOB_GENERATION_TRANSITIONS` table above only reaches `ci.yml`, which
has its own dedicated comparison. Every other workflow is compared by the
generic directory scan, where a Cross-flagged job carries a whole-job
`job:<name>:<digest>` surface — so even a benign edit inside such a job moves
its surface and is refused. `WORKFLOW_DIRECTORY_JOB_GENERATION_TRANSITIONS` in
`.github/scripts/verify_cross_build_policy.py` admits exact retired→adopted
pairs for those jobs, keyed by the workflow filename AND the job name:

| Workflow | Job | Retired SHA-256 (trusted base) | Adopted SHA-256 | Destination |
|---|---|---|---|---|
| `coverage.yml` | `coverage-merge` | `5acba780094766b03f72059b8ac229c7bcc4a722ce0130060da7ed0d1ba5850f` | `28c3ff517027c36ba2ca7ce8a80adc43d2e8475e46c4d5cb0106819dd3f1c152` | PR #3917 / issue #3907 |

The pair admits #3917's shard-scoped coverage-merge reshape (planned-shard
artifact selection, plugin gate, planned-shard outcome enforcement), pinned
against #3917's branch after merging latest `main` and inheriting the current
checksum-pinned `taiki-e/install-action` update
(`grok/issue-3907-coverage-shards-r1`; recompute and re-pin if review changes
the job bytes). Each digest is the SHA-256 of `extract_job_block` text. Both
ends are exact, the binding includes the filename and job name, the move is
one-way, and on the exact admitted pair only that job's `job:<name>:*`
surfaces are withheld — an explicit Cross surface anywhere else in the same
file, or any other revision pair of the named job, is scanned as before.
RETIREMENT IS MANDATORY: once each destination is on `main`, delete that
tuple.

##### Admitted `setup-rust-ci` generation transitions (temporary)

`.github/actions/setup-rust-ci/action.yml` carries a two-step chain decided by
this trusted policy (`LOCAL_ACTION_GENERATION_TRANSITIONS`), starting from PR
#3889's landed file (SHA-256
`fc4e41818dffdea880c057c8dfa0881a629cd01c917b43f69a9f2e5e9bd90dda`):

- Step 1 — the cache-budget generation: rust-cache `save-if` gated to a
  trusted `refs/heads/main` run so pull requests and merge groups restore
  without saving (see the cache-budget policy in the Ambient section):
  `b6ca6315ff9f2a206c1011b6b0166de3a340370fd75bf3e9cffe41e872008924`
- Step 2 — PR #3911 / issue #3906 rebased onto step 1, preserving every
  cache-safety change plus #3911's optional `workspaces` input/pass-through:
  `219187bdb0366d929577e67f48947b8c1096998dd7e04eafdffdb53dc3faa925`

Each pair is exact, path-bound, one-way, and fail-closed. The candidate
supplies no digest, allowlist, or fallback. A dest-to-dest rewrite, a one-byte
drift, or any other path is scanned as an ordinary Cross surface change. The
former direct #3889→#3911 destination
(`57a99a179ddc2935af187f518a803bf167eb9e33593c37b7b29f7151ec994da2`) is
superseded by this chain; #3911 must rebase to the combined step-2 text.
#3910's comment-only `setup-rust-ci` tweak is not admitted here; drop or
re-pin it after merging latest `main`.

##### Remaining CI-tranche predecessor sequence

This predecessor is the maximum safe consolidation. Preserve every original
issue-closing implementation PR; this policy PR tracks those issues and does
not close them.

1. Land this predecessor (admin; `Trusted Cross Build Policy` expected RED).
   PR #3889 is already on `main`; this change retires the FIPS whole-file
   admission and rebinds `setup-rust-ci` to the current-main → combined #3911
   pair.
2. Merge latest `main` into #3910 and land it. Helm Chart admits the
   setup-kubernetes-tools move via this predecessor's extracted checker.
   #3912 is superseded by this PR; do not merge #3912 itself (it would revert
   later Cross policy).
3. Merge latest `main` into #3918 and land the destination `ci.yml` (the
   policy-only first commit is already in this predecessor). Then retire
   `CI_FUZZ_SMOKE_RETIRED_JOB`.
4. Merge latest `main` into #3913 and land it (`ci-plan` / `test` pairs).
   #3889 already rewrote `test-pkcs11-softhsm` on `main`, so #3913 must merge
   that result and may need a new PKCS job pair.
5. Merge latest `main` into #3909, #3916, and #3917 and land them as ordinary
   implementation PRs unless hosted Cross names a new frozen surface. #3917's
   `coverage-merge` reshape is admitted by the workflow-directory job pair
   above (added by a follow-up predecessor once the directory scan refused
   the moved whole-job surface).
6. Merge latest `main` into #3911 and land it. This predecessor now admits the
   combined `setup-rust-ci` destination; the `performance-regression` pair
   remains valid if that job is untouched.
7. #3915 (issue #3900) after #3913: remaining predecessor for `ci-plan` /
   `test` (hashes differ from #3913).
8. #3919: destination freeze plus optional live-suite `changes` jobs. Do not
   self-admit its verifier `LIVE_SUITE_RELEVANCE_CONTRACTS`; those are absolute
   and fail without the matching workflow jobs. Classifier bootstrap until it
   is on `main`.

#### 8. Latest Release and Docker Jobs

**Runs**: `ubuntu-latest`

On pushes to `main`, the `main-publish-gate` job runs after the native build matrix and the `Tests` aggregate, then waits for successful same-commit push runs of the frozen three-workflow polling array (Coverage, Gateway API Conformance, and Mesh E2E Sidecar Live Datapath). Each requirement is queried through its canonical workflow-file endpoint and accepted only when the server-reported workflow path, display name, commit SHA, `push` event, and `main` branch all match. A different workflow that reuses the display name therefore cannot satisfy a missing canonical run, and every matching canonical run must conclude `success`, so one passing duplicate cannot mask a failed run of the same workflow for the same commit. A missing, still-running, failed, cancelled, stale, malformed, identity-mismatched, or timed-out dedicated run fails the gate closed. Each Actions API query receives up to three bounded attempts with short backoff; exhausting those attempts also fails closed. The gate polls for at most 60 minutes inside a 75-minute job timeout, runs only on `main` pushes so it never holds a runner on a pull request, and grants only `actions: read` because it checks out no code. The protected Cross verifier freezes the complete gate job and rejects workflow-wide run defaults that could alter a protected publishing shell's failure semantics, while the required-CI verifier independently pins the gate's exact digest, checks the three workflow file/name bindings and their unconditional `main` push triggers, and validates the publisher dependencies. Comments cannot stand in for executable gate fields, and changing the gate or either publishing dependency requires a trusted-base update. Publication of the mutable `latest` release and the `latest` / `main-<sha>` Docker tags additionally requires the `Gateway API Conformance` run to succeed via its embedded `main-publication-required-checks` job, which enforces the remaining five publish-blocking contexts in the complete nine-check inventory (see [Publish-blocking required checks](#publish-blocking-required-checks)). The `latest-release` job and the per-architecture Linux Docker publishing job keep their direct dependencies on the `Tests` aggregate, the native build matrix, and the protected `build-arm64-cross` job, and additionally require a successful `main-publish-gate`; they can run in parallel only once all four succeed. The `docker-manifest` job runs after the Docker digests are pushed. A Docker failure on `main` does not block replacing the `latest` prerelease, but neither publish path can start until every inventoried publish-blocking check passes for the exact SHA. Version-tag releases are stricter and gate GitHub Release creation on `docker-manifest`. Docker Hub publishing requires the `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN` repository secrets. GHCR publishing uses `GITHUB_TOKEN` and the job-level `packages: write` permission. The Docker manifests publish both `latest` and `main-<sha>` tags (where `<sha>` is the full commit SHA from `github.sha`).

## Release Pipeline (release.yml)

The Release pipeline creates official releases when a version tag is pushed. It
first verifies that the tag is exactly `v` followed by the `[package]` version
from `Cargo.toml`. It then resolves the tag to its target commit and runs
`validate-release-sha`, which enforces the complete publish-blocking required-check
set (`.github/required-publication-checks.json`; see
[Publish-blocking required checks](#publish-blocking-required-checks)) for that
exact SHA before any release binary or image job starts. A version mismatch fails
immediately, and every build and publishing job depends transitively on this
guard.

Release runs use `concurrency.group: release-${{ github.ref }}` with `cancel-in-progress: false`, so a versioned release is never canceled by a later tag push.

### Trigger

Push a tag matching the pattern `v*`:

```bash
# Create and push tag
git tag v0.2.0
git push origin v0.2.0
```

### Validate Release Version Job

**Runs**: `ubuntu-latest`

Extracts the `[package]` version from `Cargo.toml` and requires
`GITHUB_REF_NAME` to equal `v${CARGO_VERSION}`. A mismatch produces a clear
workflow error and stops the release before CI polling, builds, registry pushes,
or GitHub Release creation. The guard adds no secrets or elevated permissions.

### Validate Release SHA Job

**Runs**: `ubuntu-latest`

Validates that the tag name matches the release pattern, that the tag target
resolves to a commit, and that the commit is an ancestor of `origin/main`. It
then runs `.github/scripts/verify_publication_gate.py --enforce release` over
the COMPLETE canonical inventory
(`.github/required-publication-checks.json`; see
[Publish-blocking required checks](#publish-blocking-required-checks)), which is
the same inventory consumed by the `main` publisher.

Every inventoried required check must be successful for the exact tag target
under canonical workflow identity, the expected event, and the expected branch.
Manual workflow dispatches do not satisfy this gate. Dedicated workflows are
queried on their canonical endpoints; `Tests` is bound instead to the named
GitHub Actions check run owned by each canonical `ci.yml` push run, so failures
in later publisher jobs do not replace the `Tests` result. The job holds only
`actions: read`, `checks: read`, and `contents: read`, waits for still-running
or transiently unreadable state, and fails closed at its deadline rather than
publishing anything on an unproven result.

### Release Build Job

**Runs**: `ubuntu-latest`, `macos-latest`, `windows-latest` (four-target native
matrix plus the isolated Linux ARM64 job)

Depends on `Validate release SHA`, then builds optimized release binaries for all target platforms:

**Targets**:
- `x86_64-unknown-linux-gnu` - Linux x86_64
- `aarch64-unknown-linux-gnu` - Linux ARM64
- `x86_64-apple-darwin` - macOS x86_64
- `aarch64-apple-darwin` - macOS ARM64 (Apple Silicon)
- `x86_64-pc-windows-msvc` - Windows x86_64

**Build Process**:
1. Checkout code at tag commit
2. Install Rust toolchain with target
3. macOS and Windows: install protobuf compiler plus platform prerequisites (Windows NASM) and `cargo build --release --features cloud-secrets` on the runner. The x86_64 GNU cell is excluded from that step (`matrix.target != 'x86_64-unknown-linux-gnu'`) and instead runs `.github/scripts/build_linux_gnu_sysroot.sh`, which builds `ferrum-edge` and `ferrum-cni` inside a digest-pinned AlmaLinux 8.10 sysroot (glibc 2.28) with `LIBZ_SYS_STATIC=1`, a checksum-pinned `protoc`, `clang-devel` plus a pinned `LIBCLANG_PATH=/usr/lib64` (bindgen build scripts such as `zstd-sys` abort without a `libclang.so*`, and the builder fails closed if one is not present), empty `RUSTFLAGS` and `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_RUSTFLAGS` so the workspace mold rustflags cannot apply, `CARGO_TARGET_X86_64_UNKNOWN_LINUX_GNU_LINKER=cc`, and `CARGO_TARGET_DIR=/src/target/linux-gnu-sysroot` so native runner caches cannot contaminate the pinned link. dnf compiler/linker packages are unpinned against the live AlmaLinux 8.10 repo (GPG-signed; pinning NVRs would break on security-update rotations); the ABI scanner is the fail-closed bound on the published `DT_NEEDED` / GLIBC version-need set. Only the two regular, non-symlink binaries are then copied to the canonical `target/x86_64-unknown-linux-gnu/release/` paths. The declared runtime floor is GLIBC_2.34; `libgcc_s.so.1` and `libz.so.1` are the only non-glibc dynamic libraries the gate allows. The scanner also rejects a `DT_RPATH`/`DT_RUNPATH` and an `e_machine` that does not match the advertised `*-x86_64` / `*-aarch64` asset (or `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu` path).
4. Generate SHA256 checksum
5. x86_64 GNU only: re-verify the `.sha256` sidecars, then ABI-scan and smoke `release-assets/ferrum-edge-linux-x86_64` and `release-assets/ferrum-cni-linux-x86_64` — the exact staged bytes, before they are uploaded
6. Upload artifact

**One producer, one artifact identity.** The sysroot bytes are copied by the
job's own `Copy binary` step into `release-assets/`, checksummed there,
scanned and smoked there, and uploaded from there as
`release-binaries-x86_64-unknown-linux-gnu`. `create-release`, the `.sha256`
sidecars published in the release notes, the `docker` image build context,
`docker-manifest`, and the Cosign/attestation jobs all consume that same
artifact. There is no second build, so nothing can be verified that was not
published. If the ABI gate fails, the artifact is never uploaded and every
downstream job fails closed with it.

**GNU ABI gate** (`verify-linux-gnu-abi-aarch64`, versioned release path):
- ARM64 only. The x86_64 GNU floor is enforced inside `build-release-binaries` before its artifact exists.
- Downloads the trusted `release-binaries-aarch64-unknown-linux-gnu` artifact on `ubuntu-24.04-arm`, re-checks its SHA-256 sidecars, and scans the published bytes — it never rebuilds them
- Rejects GLIBC symbols above 2.34, unexpected `DT_NEEDED` entries, a `DT_RPATH`/`DT_RUNPATH`, and an ELF `e_machine` that does not match the advertised `*-x86_64` / `*-aarch64` asset
- Smokes both binaries and their operator commands (`ferrum-edge version --json` / `validate` / `run` + `health`; `ferrum-cni VERSION` / `install` / `uninstall` / ADD / CHECK / DEL) on digest-pinned AlmaLinux 9.4 (the GLIBC_2.34 floor) and Ubuntu 22.04 via `bash .github/scripts/smoke_linux_gnu_baseline.sh`
- `linux-gnu-abi-release-gate` joins `create-release` with this job (`if: always()`). The ARM64 producer and `create-release.needs` are both frozen by trusted Cross policy, so the ARM64 scan can only join after publication; the gate fails the workflow and deletes the GitHub Release if that job did not succeed. Checksums, Cosign signatures, and container publish jobs are unchanged: the retraction does not delete `:latest` / `:vX.Y.Z` image tags.

**GNU ABI gate** (`verify-latest-linux-gnu-abi-aarch64`, main-push `latest` path):
- ARM64 only, for the same reason. The x86_64 GNU floor is enforced inside `build-binaries` before `binary-x86_64-unknown-linux-gnu` exists.
- Downloads `binary-aarch64-unknown-linux-gnu` on `ubuntu-24.04-arm`, re-checks its checksums, ABI-scans both `ferrum-edge` and `ferrum-cni`, and runs the same digest-pinned AlmaLinux 9.4 / Ubuntu 22.04 smoke matrix as the versioned path
- `linux-gnu-abi-latest-gate` joins frozen `latest-release` with this job (`if: always()` on main pushes). The protected ARM64 policy freezes `latest-release.needs`, `build-arm64-cross`, and `main-publish-gate`, so ABI cannot be added there. On ABI failure the gate deletes `latest` only when that prerelease is proven to target the current `GITHUB_SHA`; it leaves an older known-good `latest` in place if the current publisher did not replace it. The workflow fails unless both verification and publication succeeded. The `docker` job does not wait on this ABI job, so the arm64 image layer is already pushed; retraction never deletes `:latest` / `:vX.Y.Z` image tags.

**GNU ABI gate** (`verify-pr-linux-gnu-abi`, full-mode pull requests):
- Builds both x86_64 GNU release binaries through `build_linux_gnu_sysroot.sh` (isolated `CARGO_TARGET_DIR=/src/target/linux-gnu-sysroot`, then a controlled canonical copy)
- ABI-scans `target/x86_64-unknown-linux-gnu/release/ferrum-edge` and `ferrum-cni`, then smokes both on digest-pinned AlmaLinux 9.4 and Ubuntu 22.04
- Job env `LINUX_GNU_SMOKE_FLOOR_IMAGE` / `LINUX_GNU_SMOKE_UBUNTU2204_IMAGE` are cross-checked against `.github/linux-gnu-abi.toml` when set (the same optional pattern as `LINUX_GNU_SYSROOT_IMAGE` in the builder)
- Contents-read-only, pinned checkout/toolchain/images, exact output paths, not added to frozen publisher `needs`

**Cross-Compilation**:
- Linux ARM64 uses checksum-verified `cross` 0.2.5 in the isolated protected invocation job; `cross` requires Docker on the build host. Those artifacts already target an older glibc than GLIBC_2.34 and are re-checked as published by `verify-linux-gnu-abi-aarch64` and, on the main-push `latest` path, `verify-latest-linux-gnu-abi-aarch64`.
- Other targets use standard `cargo build`; macOS x86_64 builds on the `macos-latest` runner (currently ARM64) with the standard Apple/Rust target tooling — pin to a concrete runner image such as `macos-14` if the host architecture must be guaranteed.

**Output**:
- Binary: `ferrum-edge-{platform}`
- Checksum: `ferrum-edge-{platform}.sha256`

### Create Release Job

**Depends On**: Release Build Job, Docker Manifest Job, Docker eBPF Manifest
Job, and Docker eBPF Tools Manifest Job

Creates a GitHub Release with all binaries and checksums after the versioned
Docker manifests have been pushed. Durable release publication still fails
closed on attestation: `release-attestation-gate` requires
`attest-release-images` to succeed and deletes the GitHub Release if
attestation verification fails. Trusted Cross freezes `create-release.needs`,
so attestation cannot be added there directly. The Linux GNU ABI contract
does not need that shape for x86_64: the GLIBC_2.34 floor (AlmaLinux 8.10
sysroot, `libgcc_s.so.1` / `libz.so.1` allowlist) is proven inside
`build-release-binaries` on the staged, checksummed assets before they are
uploaded, so an unverified x86_64 artifact never reaches publication at all.
Only ARM64, whose producer and consumer `needs` are both frozen, is joined
after the fact: `linux-gnu-abi-release-gate` requires
`verify-linux-gnu-abi-aarch64` and deletes the GitHub Release if it did not
succeed, and `linux-gnu-abi-latest-gate` does the same for the moving
`latest` prerelease, deleting it only when it is proven to target the
current `GITHUB_SHA`.

**Release Content**:
1. Release title: Version tag (e.g., `v0.2.0`)
2. Release description: Generated release notes including:
   - List of binary platforms
   - SHA256 checksums for verification
   - Download instructions
3. Attachments: All platform-specific gateway binaries, plus Linux `ferrum-cni` binaries for manual CNI installs

**Release Notes Example**:
````markdown
# Release v0.2.0

## Binaries

Pre-built binaries for all supported platforms:

| Platform | Binary |
|----------|--------|
| Linux x86_64 | `ferrum-edge-linux-x86_64` |
| Linux x86_64 CNI plugin | `ferrum-cni-linux-x86_64` |
| Linux ARM64 | `ferrum-edge-linux-aarch64` |
| Linux ARM64 CNI plugin | `ferrum-cni-linux-aarch64` |
| macOS x86_64 | `ferrum-edge-macos-x86_64` |
| macOS ARM64 (Apple Silicon) | `ferrum-edge-macos-aarch64` |
| Windows x86_64 | `ferrum-edge-windows-x86_64.exe` |

## Docker

```bash
docker pull ferrumedge/ferrum-edge:v0.2.0
docker pull ghcr.io/ferrum-edge/ferrum-edge:v0.2.0
```

## Checksums

Verify the integrity of downloaded binaries:

```
abc123... ferrum-edge-linux-x86_64
def456... ferrum-edge-linux-aarch64
...
```

## Usage

Download the binary for your platform and make it executable:

```bash
chmod +x ferrum-edge-linux-x86_64
FERRUM_MODE=file FERRUM_FILE_CONFIG_PATH=config.yaml ./ferrum-edge-linux-x86_64 run
```
````

## Process supervision

Shipping profiles (`release`, `ci-release`, and `max-perf`) set
`panic = "abort"` (issue #4166). A panic anywhere in the process — including a
background poller, accept loop, or notification callback — terminates the
gateway immediately. There is no in-process panic recovery in shipping
binaries.

Run `ferrum-edge` under a process supervisor (systemd, Kubernetes
`restartPolicy`, or equivalent) so the host restarts the process. Background-task
supervisors still restart on non-panic unexpected exits (I/O errors, unexpected
completion, cancellation) and keep serving last-known-good config where that
policy already exists.

Dev, test, and `pr-build` keep `panic = "unwind"` so the suite can observe
`JoinError::is_panic()`. Those panic-recovery tests do not represent shipping
behavior. See PRODUCTION_READINESS.md (*Deliberate decisions*) and
`tests/unit/gateway_core/build_profile_panic_strategy_tests.rs`.

## How Releases Work

### Version Management

**Current Version**: Defined in `Cargo.toml`

```toml
[package]
name = "ferrum-edge"
version = "<version>"
```

**Release Process**:
1. Record notable changes in `CHANGELOG.md` under `Unreleased`
2. Update `Cargo.toml` version to the intended release version before tagging
3. Tag: `git tag v<version>` (matching the new version exactly)
4. Release: GitHub Actions automatically builds and publishes

During active build-out, any breaking change to configuration shapes,
environment variables, schema, defaults, or other user-facing behavior must add
an `Unreleased` changelog entry in the same pull request. Release preparation
moves those entries under the new version heading.

### Version Numbering

Follow semantic versioning:

- **MAJOR.MINOR.PATCH** (e.g., `1.2.3`)
- **v** prefix for tags (e.g., `v1.2.3`)
- **Examples**:
  - `v0.1.0` - Initial release
  - `v0.2.0` - Minor feature addition
  - `v0.2.1` - Bug fix
  - `v1.0.0` - Major release

### Git Tag Naming

Always use `v` prefix and match `Cargo.toml` version:

```bash
# Correct
git tag v0.2.0   # matches Cargo.toml version = "0.2.0"

# Incorrect (won't trigger release)
git tag 0.2.0
git tag release-0.2.0

# Incorrect (workflow fails because Cargo.toml still says 0.2.0)
git tag v0.3.0
```

## Creating a New Release

### Prerequisites

- Modify `Cargo.toml` with new version
- Move the relevant `CHANGELOG.md` entries from `Unreleased` to the new version heading
- Successful `CI` and `Coverage` workflow runs for the exact commit that will be tagged
- GitHub repo with Actions enabled
- Write permission to repository

### Step-by-Step

**1. Update Version in Cargo.toml**

```bash
# Edit the existing [package] version line in Cargo.toml.
$EDITOR Cargo.toml
```

**2. Commit Changes**

```bash
git add Cargo.toml
git commit -m "chore: bump version to 0.2.0"
git push origin main
```

**3. Wait for CI to Pass**

- Push to main triggers CI and Coverage
- Wait for both workflows to pass for the exact commit you will tag
- Check GitHub Actions tab for status

**4. Create and Push Version Tag**

```bash
# Create tag pointing to HEAD
git tag -a v0.2.0 -m "Release version 0.2.0"

# Push tag to GitHub
git push origin v0.2.0
```

**5. Release Triggered Automatically**

- GitHub Actions detects tag matching `v*`
- Release pipeline starts automatically
- The tag is checked against the `Cargo.toml` package version before any publishing work
- The tag target SHA is validated against successful CI and Coverage runs before publishing starts
- Binaries built for all platforms
- Release created with checksums

**6. Verify Release**

```bash
# GitHub CLI
gh release view v0.2.0

# Check binaries
gh release download v0.2.0 --dir ./binaries

# Verify checksums
sha256sum -c ferrum-edge-*.sha256
```

### Alternative: Manual Release Creation

If automatic release fails:

Before building on each host, complete the
[one-time bootstrap](../CONTRIBUTING.md#one-time-local-bootstrap), including its platform
requirements or explicit wrapper/system-linker fallback.

```bash
# Build binaries manually with the same release features as CI. Install protoc
# for every host first. Linux hosts also need libcurl4-openssl-dev, Windows
# MSVC builds need NASM in PATH. For Linux ARM64, install the pinned Cross 0.2.5
# binary and copy the exact `env -i` invocation from build-release-arm64-cross;
# do not substitute an unpinned `cargo install cross` or inherited environment.
# On a Linux host:
cargo build --features cloud-secrets --release --target x86_64-unknown-linux-gnu
# Then run the complete pinned ARM64 command from build-release-arm64-cross in
# .github/workflows/release.yml (including its revalidation and `env -i` block).

# On a macOS host:
cargo build --features cloud-secrets --release --target x86_64-apple-darwin
cargo build --features cloud-secrets --release --target aarch64-apple-darwin

# On a Windows host:
cargo build --features cloud-secrets --release --target x86_64-pc-windows-msvc

# Stage platform-suffixed assets before checksums/upload, matching CI asset names.
# Run these POSIX staging commands from one checkout after copying in the built
# artifacts from the Linux, macOS, and Windows hosts. On Windows-only recovery,
# use equivalent PowerShell commands or copy the .exe back to a POSIX shell.
mkdir -p dist
cp target/x86_64-unknown-linux-gnu/release/ferrum-edge dist/ferrum-edge-linux-x86_64
cp target/aarch64-unknown-linux-gnu/release/ferrum-edge dist/ferrum-edge-linux-aarch64
cp target/x86_64-apple-darwin/release/ferrum-edge dist/ferrum-edge-macos-x86_64
cp target/aarch64-apple-darwin/release/ferrum-edge dist/ferrum-edge-macos-aarch64
cp target/x86_64-pc-windows-msvc/release/ferrum-edge.exe dist/ferrum-edge-windows-x86_64.exe

# Generate per-asset checksums, matching CI release assets.
(cd dist && for asset in \
  ferrum-edge-linux-x86_64 \
  ferrum-edge-linux-aarch64 \
  ferrum-edge-macos-x86_64 \
  ferrum-edge-macos-aarch64 \
  ferrum-edge-windows-x86_64.exe
do
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$asset" > "$asset.sha256"
  else
    shasum -a 256 "$asset" > "$asset.sha256"
  fi
done)

# Create release in GitHub UI or via gh:
# The glob matches both binaries and their .sha256 sidecars.
gh release create v0.2.0 \
  dist/ferrum-edge-* \
  --title "Release v0.2.0" \
  --generate-notes
```

This manual GitHub Release fallback only recreates release assets. If the tag workflow also failed before Docker publishing completed, rerun/fix the release workflow or manually publish the Docker Hub and GHCR images before treating the version release as complete.
Generated notes are acceptable for this fallback, but they do not include the workflow's curated Docker pull and checksum sections.

## Binaries and Downloads

### GitHub Releases Page

All released binaries available at:
```
https://github.com/ferrum-edge/ferrum-edge/releases
```

### Download Latest Release

Published gateway binaries use raw asset names such as `ferrum-edge-linux-x86_64` with adjacent `.sha256` sidecars. Pin an explicit published tag (`latest` for the current prerelease stream). Do not rely on GitHub's `/releases/latest` redirect or the `releases/latest` API endpoint for a prerelease tag.

```bash
# Using GitHub CLI (explicit tag; resolves tag name `latest` even when prerelease)
gh release download --repo ferrum-edge/ferrum-edge latest -p 'ferrum-edge-linux-x86_64*'
sha256sum -c ferrum-edge-linux-x86_64.sha256
chmod +x ferrum-edge-linux-x86_64

# Using curl
set -euo pipefail
TAG=latest  # or replace with another explicit published tag
BASE="https://github.com/ferrum-edge/ferrum-edge/releases/download/${TAG}"
curl -fsSLO "${BASE}/ferrum-edge-linux-x86_64"
curl -fsSLO "${BASE}/ferrum-edge-linux-x86_64.sha256"
sha256sum -c ferrum-edge-linux-x86_64.sha256
chmod +x ferrum-edge-linux-x86_64
```

### Platform-Specific Binaries

**Linux x86_64** (Intel/AMD 64-bit)
```bash
gh release download v0.2.0 -p "ferrum-edge-linux-x86_64"
chmod +x ferrum-edge-linux-x86_64
./ferrum-edge-linux-x86_64 run
```

**Linux ARM64** (ARM 64-bit, Graviton, etc.)
```bash
gh release download v0.2.0 -p "ferrum-edge-linux-aarch64"
chmod +x ferrum-edge-linux-aarch64
./ferrum-edge-linux-aarch64 run
```

**macOS x86_64** (Intel Macs)
```bash
gh release download v0.2.0 -p "ferrum-edge-macos-x86_64"
chmod +x ferrum-edge-macos-x86_64
./ferrum-edge-macos-x86_64 run
```

**macOS ARM64** (Apple Silicon M1/M2/M3)
```bash
gh release download v0.2.0 -p "ferrum-edge-macos-aarch64"
chmod +x ferrum-edge-macos-aarch64
./ferrum-edge-macos-aarch64 run
```

**Windows x86_64** (Intel/AMD 64-bit)
```powershell
gh release download v0.2.0 -p "ferrum-edge-windows-x86_64.exe"
./ferrum-edge-windows-x86_64.exe run
```

### Checksum Verification

Always verify binary integrity using SHA256:

```bash
# Download release files
gh release download v0.2.0

# Verify checksums
sha256sum -c *.sha256

# Expected output:
# ferrum-edge-linux-x86_64: OK
# ferrum-edge-linux-aarch64: OK
# ferrum-edge-macos-x86_64: OK
# ferrum-edge-macos-aarch64: OK
# ferrum-edge-windows-x86_64.exe: OK
```

### Docker Images

Pre-built Docker images are published to Docker Hub and GitHub Container Registry by the main-push and version-tag workflows. Docker Hub credentials must be configured before those publish workflows run:

```bash
docker pull ferrumedge/ferrum-edge:latest
docker pull ferrumedge/ferrum-edge:main-<sha>
docker pull ferrumedge/ferrum-edge:v1.2.3
docker pull ferrumedge/ferrum-edge:1.2.3
docker pull ferrumedge/ferrum-edge:1.2

docker pull ghcr.io/ferrum-edge/ferrum-edge:latest
docker pull ghcr.io/ferrum-edge/ferrum-edge:main-<sha>
docker pull ghcr.io/ferrum-edge/ferrum-edge:v1.2.3
docker pull ghcr.io/ferrum-edge/ferrum-edge:1.2.3
docker pull ghcr.io/ferrum-edge/ferrum-edge:1.2
```

The Docker `latest` tag tracks the latest successful `main` publish, not necessarily the newest stable version tag. The `main-<sha>` tag uses the full commit SHA from `github.sha`.

Publishing logs in to both registries before pushing, so a green publish job never proves that a first-time user can pull anonymously. The `anonymous-pull-smoke` job in `ci.yml` therefore runs after `docker-manifest` on every `main` push with an empty `DOCKER_CONFIG` (`scripts/smoke_anonymous_pull.sh`): it acquires an anonymous pull token, resolves the `main-<sha>` manifest, pulls the image, and runs `ferrum-edge version --json`. The Docker Hub path is the documented install path and fails the job when it is not anonymously consumable; the GHCR path is checked in `--warn-only` mode until the `ferrum-edge` package's visibility is set to public in the organization's package settings (a GHCR package inherits no visibility from the source repository; a private package answers anonymous token requests with `401`). The same script can be run by hand against any published reference, for example `bash scripts/smoke_anonymous_pull.sh docker.io/ferrumedge/ferrum-edge:v0.9.2`.

The GHCR path is `ghcr.io/${{ github.repository }}` in the workflows, so it auto-tracks the GitHub repository owner/name if the repository is moved or forked. The Docker Hub repo `ferrumedge/ferrum-edge` is hardcoded in both `ci.yml` and `release.yml`; forks must edit that `name=` value (and configure their own `DOCKERHUB_USERNAME` / `DOCKERHUB_TOKEN`) before Docker Hub pushes will succeed.

## Image Signatures, SBOMs, and Provenance

Every version-tag release signs and attests the final standard, `-ebpf`, and
`-ebpf-tools` multi-architecture image digests in both Docker Hub and GHCR. The
per-platform push-by-digest builds deliberately retain `provenance: false`:
enabling BuildKit provenance there turns each platform output into a manifest
list and breaks the existing `docker buildx imagetools create` assembly
contract. The dedicated `attest-release-images` job instead runs after all three
final manifests exist and:

1. resolves each canonical `vX.Y.Z` / `vX.Y.Z-ebpf` / `vX.Y.Z-ebpf-tools` tag to
   an immutable digest;
2. requires exactly the `linux/amd64` and `linux/arm64` descriptors and verifies
   that Docker Hub and GHCR contain the same per-platform manifests;
3. scans each registry's immutable platform images with the digest-pinned Syft
   image and produces two SPDX JSON inventories for each final manifest;
4. creates SLSA provenance v1 describing the tag, source commit, GitHub Actions
   workflow invocation, final registry repository, and assembled platform
   digests;
5. keylessly signs each immutable final digest and attaches the provenance plus
   both platform SBOMs with Cosign; and
6. verifies the Fulcio identity and GitHub OIDC claims, transparency-log-backed
   signature, provenance type and source commit, attestation subject digest,
   and at least two non-empty SPDX predicates.

`create-release` depends on all three manifest jobs, so the GitHub Release —
whose notes advertise all three tag families — cannot publish unless every
advertised manifest exists. It deliberately does **not** depend on
`attest-release-images`: adding that edge would let a signing failure leave the
binaries unpublished as well, and the trusted contract rejects it. The
`release-attestation-gate` job instead joins `create-release` with
`attest-release-images` under `if: always()`: the release workflow cannot
succeed unless attestation verification succeeded, and a GitHub Release created
before attestation finishes is deleted when attestation fails. That retraction
covers the `-ebpf-tools` family exactly like the other two, because a failure in
any family's resolve/SBOM/sign/verify step fails the whole attestation job.

The `-ebpf-tools` family is a first-class release image family in the trusted
contracts: `DIGEST_ARTIFACT_OWNERS` owns the `docker-ebpf-tools-digest-*`
wildcard and assigns it solely to the `docker-ebpf` job that builds both eBPF
variants from one source tree, and `PUBLISH_ARTIFACT_STEP_CONTRACTS` /
`PUBLISH_CONTROL_CONTRACTS` freeze that job's tools build, digest export and
upload steps together with the whole `docker-ebpf-tools-manifest` job — its
`needs`, its download pattern, its working directory, and every published tag.

The signatures and attestations are stored beside the immutable subject in each
registry; neither registry is treated as a mutable pointer or as a fallback for
the other. Only `attest-release-images` receives `id-token: write`. Its other
permission is `packages: write` for GHCR, while the manifest and release jobs
retain their existing least-privilege grants. The static contract in
`.github/scripts/verify_release_image_attestations.py`, invoked by required CI,
guards these properties and requires all external actions and the Syft runtime
image to remain immutable.

### Consumer verification

Install Cosign 3.x and Docker Buildx, then verify an immutable digest rather
than a tag. Set `IMAGE` to either registry. For the eBPF variants, append
`-ebpf` or `-ebpf-tools` to `IMAGE_TAG`; the signing identity still uses the
release tag because the workflow itself runs at `refs/tags/vX.Y.Z`.

```bash
RELEASE_TAG=v1.2.3
IMAGE=ferrumedge/ferrum-edge
# Alternative registry:
# IMAGE=ghcr.io/ferrum-edge/ferrum-edge
IMAGE_TAG="$RELEASE_TAG"
# eBPF variant:
# IMAGE_TAG="${RELEASE_TAG}-ebpf"
# Ambient UDP lifecycle (tools-capable) variant:
# IMAGE_TAG="${RELEASE_TAG}-ebpf-tools"

DIGEST="$(
  docker buildx imagetools inspect \
    "${IMAGE}:${IMAGE_TAG}" \
    --format '{{json .Manifest}}' |
    jq -er '.digest | select(test("^sha256:[0-9a-f]{64}$"))'
)"
IMAGE_REF="${IMAGE}@${DIGEST}"
CERT_IDENTITY="https://github.com/ferrum-edge/ferrum-edge/.github/workflows/release.yml@refs/tags/${RELEASE_TAG}"
OIDC_ISSUER="https://token.actions.githubusercontent.com"

cosign verify \
  --certificate-identity "$CERT_IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  "$IMAGE_REF"
```

Verify SLSA provenance and require its authenticated statement to name the
expected manifest digest:

```bash
EXPECTED_SHA256="${DIGEST#sha256:}"
cosign verify-attestation \
  --certificate-identity "$CERT_IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  --type slsaprovenance1 \
  "$IMAGE_REF" |
  jq -e --arg digest "$EXPECTED_SHA256" '
    [
      .[].payload
      | @base64d
      | fromjson
      | select(.predicateType == "https://slsa.dev/provenance/v1")
      | select(any(.subject[]?; .digest.sha256 == $digest))
    ] | length > 0
  '
```

Verify the SPDX attestations and require both platform inventories to be
non-empty and bound to the same final manifest digest:

```bash
cosign verify-attestation \
  --certificate-identity "$CERT_IDENTITY" \
  --certificate-oidc-issuer "$OIDC_ISSUER" \
  --type spdxjson \
  "$IMAGE_REF" |
  jq -e --arg digest "$EXPECTED_SHA256" '
    [
      .[].payload
      | @base64d
      | fromjson
      | select(any(.subject[]?; .digest.sha256 == $digest))
      | select(.predicate.spdxVersion | startswith("SPDX-"))
      | select(.predicate.packages | type == "array" and length > 0)
    ] | length >= 2
  '
```

To inspect the authenticated predicates after verification, replace the final
`jq` program with:

```jq
.[].payload | @base64d | fromjson | .predicate
```

## GitHub Actions Secrets

Configure secrets for Docker image publishing and releases.

### Accessing Secrets Settings

1. Go to GitHub repository
2. Settings → Secrets and variables → Actions
3. Create new repository secrets

### Required Secrets

#### Docker Registry

Required for pushing Docker Hub images. The workflows unconditionally run the Docker Hub login step on main-push and version-tag Docker jobs, so missing secrets fail publishing:

- `DOCKERHUB_USERNAME` - Docker Hub username
- `DOCKERHUB_TOKEN` - Docker Hub access token

**Generate Docker Token**:
1. Log in to Docker Hub
2. Account Settings → Security
3. Create new access token
4. Copy token to `DOCKERHUB_TOKEN`

For GHCR publishing, the workflows use `GITHUB_TOKEN`. The workflows declare
job-level `permissions: { contents: write }` for release creation,
`permissions: { contents: read, packages: write }` for Docker/GHCR publishing,
and `permissions: { id-token: write, packages: write }` only for release image
signing and attestation. Repository **Settings → Actions → General → Workflow
permissions** must allow read/write access (including `packages: write`) for
those per-job grants to take effect.

### Secret Usage in Workflows

The Docker Hub login steps use:

```yaml
with:
  username: ${{ secrets.DOCKERHUB_USERNAME }}
  password: ${{ secrets.DOCKERHUB_TOKEN }}
```

### Setting Secrets

```bash
# Using GitHub CLI
gh secret set DOCKERHUB_USERNAME --body "your-username"
gh secret set DOCKERHUB_TOKEN --body "your-token"

# Via web UI
1. Settings → Secrets and variables → Actions → New repository secret
2. Name: DOCKERHUB_USERNAME
3. Value: your-username
4. Click "Add secret"
```

## Root Merge Gate Attestation

`root-merge-gate-attestation.yml` supplies the approval for the active no-bypass
`main` ruleset. The repository currently has a single human administrator, so the
ruleset's one-approval requirement is satisfied only after that human has
independently reviewed one exact PR head and then dispatches this workflow with
matching inputs.

This workflow is **not** a ruleset bypass. The active ruleset has **no
bypass actors**. The workflow only supplies the required approval for **one
exact root-reviewed head SHA**. All other protections still apply:

- required hosted CI checks (including coverage and release-critical live checks)
- every review thread resolved
- stale approvals dismissed on material pushes
- merge-queue validation of the combined result before landing

`require_last_push_approval` is intentionally `false`: the owner removed the
separate requirement that the latest reviewable push be approved by someone
other than its pusher. Exact-head attestation, stale-review dismissal, hosted CI,
thread resolution, and merge-queue checks remain mandatory.

### Security and audit contract

| Boundary | Enforcement |
|---|---|
| Trigger surface | `workflow_dispatch` only; no `pull_request`, `pull_request_target`, `merge_group`, `push`, or schedule triggers |
| Trusted workflow copy | Runs only when `github.ref` is `refs/heads/main` in `ferrum-edge/ferrum-edge`; any other ref or repository fails closed |
| Human authorization | `github.actor` and `github.triggering_actor` must both be `jeremyjpj0916`; unauthorized dispatches and reruns fail visibly |
| Permissions | `contents: read` and `pull-requests: write` only |
| Code execution | No checkout and no execution of PR or repository code; GitHub API calls only |
| Input validation | `pr_number` must be a positive integer; `expected_head_sha` must be exactly 40 lowercase hex characters; inputs are never interpolated into shell syntax, paths, or API endpoints before validation |
| PR eligibility | PR must be open, non-draft, target `main`, originate from this repository (not a fork), and its live head SHA must equal `expected_head_sha` |
| Review threads | All review threads are fetched with GraphQL pagination; any unresolved thread, query error, or malformed/missing field fails closed |
| Race safety | Approval is submitted with an explicit `commit_id`; the full PR eligibility validation (open, non-draft, base `main`, same repository, exact head SHA) is re-run immediately before submission so a push or state change between validation and approval cannot approve a newer or ineligible head |
| Actions approval setting | Repository setting `can_approve_pull_request_reviews` (“Allow GitHub Actions to create and approve pull requests”) must remain enabled and is audited before the no-bypass ruleset is activated. GitHub’s documented behavior counts enabled Actions reviews toward required approvals; this repository was independently verified as enabled. The live #3040 merge-queue exercise will prove that an attestation approval satisfies the actual ruleset |
| Concurrency | `root-merge-gate-attestation-<pr_number>` with `cancel-in-progress: false` so overlapping dispatches do not cancel an in-flight attestation |

### Operator inputs

Dispatch the workflow from the `main` branch copy in the Actions UI (or
equivalent API) with:

1. **`pr_number`** — the pull request to attest.
2. **`expected_head_sha`** — the full 40-character lowercase hex SHA of the PR
   head the root orchestrator independently reviewed. It must match the PR's
   current head at dispatch time.

If the PR head moves after review, dispatch again with the new SHA only after
re-reviewing that exact head.

### Audit evidence

Each successful attestation leaves two linked records:

1. **Workflow run** — the Actions run URL shows the authorized actor, inputs,
   and pass/fail outcome.
2. **Pull request review** — a single `APPROVE` review whose body states that
   it is the root merge-gate attestation, repeats the bound head SHA, names the
   authorizing actor, and links the workflow run. The review is bound to
   `commit_id` and does not quote or incorporate PR-authored text.

## Customizing CI/CD

### Adding New Targets

For a new native target, edit both `.github/workflows/ci.yml`
(`build-binaries`) and `.github/workflows/release.yml`
(`build-release-binaries`):

```yaml
strategy:
  matrix:
    include:
      # Example: add a Linux musl target
      - os: ubuntu-latest
        target: x86_64-unknown-linux-musl
        artifact_name: ferrum-edge
        asset_name: ferrum-edge-linux-x86_64-musl
```

Musl targets need their own toolchain setup. Add `musl-tools` before a native
`cargo build`. Merge-queue compile gates for discarded artifacts live in the
`build-binaries` compile-gate step (`cargo check` on `*-apple-darwin`, linked
`pr-build` elsewhere); do not feed queue outputs into Prepare/Upload. A
Cross-backed target requires a separate isolated invocation job, a complete
Cross configuration allowlist, fixed empty environment, and an updated trusted
verifier contract; do not add an unguarded Cross invocation to the native
matrix.

### Skipping Steps

Skip the entire workflow run for a commit:

```bash
# Skip CI for documentation changes
git commit -m "docs: update README [skip ci]"

# Skips the whole GitHub Actions workflow run for this commit
```

### Custom Build Flags

Modify build commands in workflows:

```yaml
- name: Build with custom features
  run: cargo build --release --features "cloud-secrets"
```

### Notification Integration

Add notifications to CI failures:

```yaml
- name: Notify Slack
  if: failure()
  uses: slackapi/slack-github-action@v1
  with:
    webhook-url: ${{ secrets.SLACK_WEBHOOK }}
```

## Troubleshooting

### Release Not Triggering

**Check**:
- Tag format: Must be `v*` (e.g., `v0.2.0`)
- Tag exists: `git tag` lists tags
- Push origin: `git push origin v0.2.0`

```bash
# Verify tag
git tag -l "v*"
git show v0.2.0

# Check GitHub Actions
# Settings → Actions → All workflows
```

### Build Failures

**Check logs**:
1. Go to GitHub Actions tab
2. Click failing workflow
3. Expand job logs for details

**Common Issues**:
- Build prerequisites: CI installs `protoc` on every OS, `libcurl4-openssl-dev` on Linux, and NASM on Windows
- Missing dependencies: Check `Cargo.toml` and the release Build Process prerequisites above
- Rust version: Workflows use `stable` Rust toolchain

### Docker Push Failing

**Verify secrets**:
```bash
gh secret list
# Should show DOCKERHUB_USERNAME and DOCKERHUB_TOKEN
```

**Test credentials**:
```bash
# Local login test
printf '%s' "$PASSWORD" | docker login -u "$USERNAME" --password-stdin

# Update secrets if needed
gh secret set DOCKERHUB_TOKEN --body "new-token"
```

## See Also

- [Docker Deployment](docker.md) - Building and running Docker images
- [Main README](../README.md) - Project overview and configuration
- [GitHub Actions Documentation](https://docs.github.com/en/actions)

### Test artifact profile reuse experiment (#4667)

The gateway, ferrum-cni, and nextest archive producer use the dev/test output
family with debug info disabled. Keeping the gateway in a separate `pr-build`
directory duplicated dependency compilation before any integration or functional
shard could start. Artifact names, `target/debug` paths, archive profiles, and
shipping release profiles are unchanged.

Baseline PR run [34005446618](https://github.com/ferrum-edge/ferrum-edge/actions/runs/34005446618)
spent 12m08s building the gateway, 7m33s building ferrum-cni, and 10m14s building
the integration archive. Compare these individual steps and the final `Tests`
completion time on the experiment PR; record cache restores alongside timings.
The expected saving is dependency reuse in the second binary build, not removal
of tests. Dev-dependency feature unification can still require recompilation
when the archive build starts. Repository-wide cache capacity is tracked in
[#4643](https://github.com/ferrum-edge/ferrum-edge/issues/4643).
