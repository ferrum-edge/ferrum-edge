# Protocol Performance Regression

Scheduled and manually runnable multi-protocol performance regression for
Ferrum Edge. This lane tracks throughput, error rate, and latency percentiles
across the supported protocol matrix, plus connection churn, long-lived soak /
resource plateaus, and reload-under-load coverage.

It is **not** a required pull-request check for the scheduled multi-protocol
benchmark itself. Required PR CI does run lightweight static contracts for this
lane inside the `Performance Regression Check` job in `.github/workflows/ci.yml`
(workflow verifier self-test + repository contract, evaluator self-test, and a
`python3 -m py_compile` check of the scenario harness) before optional
benchmark/build gating. That PR job has read-only contents permission and does
not persist checkout credentials while running PR-controlled code. The
lightweight HTTP/1 overhead gate in `ci.yml`
remains the PR path for measured overhead. That same job caches both the root
workspace (`. -> target`) and the standalone `tests/performance/mesh`
Criterion workspace through `setup-rust-ci`'s optional rust-cache `workspaces`
pass-through (`shared-key: ci-perf`). Omitting `workspaces` on other
`setup-rust-ci` callers keeps rust-cache's root-only default. Noisy
shared-runner microbenchmarks stay out of branch protection.

## Documented runner and build profile

| Setting | Value | Notes |
|---|---|---|
| Runner class | `ubuntu-latest` | GitHub-hosted; expect noisy-neighbor variance |
| Gateway build profile | `ci-release` | Stable CI-oriented release profile from root `Cargo.toml` |
| Harness build profile | `release` | `tests/performance/multi_protocol` is not a workspace member and uses its local `release` profile |
| Workflow | `.github/workflows/protocol-perf-regression.yml` | `schedule` (Sundays 05:00 UTC) + `workflow_dispatch` |

Do not treat numbers from this lane as production SLOs until absolute floors are
filled in after measured runner variance.

## What it records

Per supported protocol (gateway path):

- Throughput (RPS)
- Error rate
- Latency p50 / p95 / p99

Additional scenarios from
`tests/performance/multi_protocol/run_protocol_regression_scenarios.py`:

- **Connection churn** — HTTP/1 with keep-alive / idle pool disabled
- **Long-lived soak** — `proto_bench saturate` hold window
- **Resource plateau** — RSS, FD count, and task/thread samples from `/proc`
  after the connection ramp, comparing early/late three-sample medians
- **Reload under load** — file-mode `SIGHUP` while traffic is flowing

## Budgets and trends

Versioned budgets live in
`tests/performance/multi_protocol/protocol_perf_budgets.json`.

- `enforcement` starts as `alert` (warnings only for **measured** budget
  breaches; soft product regressions stay green) so shared-runner variance
  does not block the schedule.
- **Harness / data-completeness failures are always hard failures**, even
  while `enforcement` is `alert`: missing expected protocol samples,
  missing per-iteration RPS/error/p50/p95/p99 fields, zero-total/invalid
  metrics, non-finite or malformed numeric fields (NaN, Infinity, non-numeric
  counts/rates/plateau arrays), missing or malformed runner-health/history
  evidence, nonzero scenario benchmark exits, an undelivered reload `SIGHUP`,
  missing required scenario output, and insufficient RSS/FD/task sampling all
  fail the job.
  Finite measured product regressions such as zero RPS or large latency stay
  alert-only under `enforcement=alert`.
- Absolute `min_gateway_rps` / `max_p*_us` floors are intentionally `null`
  until operators measure variance on `ubuntu-latest` + `ci-release` and fill
  them in. Do not invent floors from unexecuted local runs.
- When prior trend artifacts exist, the evaluator also applies a rolling
  median ± MAD comparison (`rolling` block in the budgets file). History is
  accepted only from the newest successful `main` run, validated against schema
  version 1, filtered to the same runner/build profile, and bounded to the
  configured rolling window.
- Each run publishes machine-readable artifacts:
  - `combined_results.json`
  - `budget_report.json`
  - `protocol_perf_trends.json`
  - `runner_health.json` / `runner_health.log`

Evaluator:
`tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py`.

## Distinguishing product regressions from noisy neighbors

Retain and inspect:

- `runner_health.json` — CPU steal sample, scheduler jitter, `nproc`
- Multi-iteration matrix outputs (`matrix_run*.json`)
- Budget alerts vs hard failures (`enforcement`)
- Scenario resource series under `scenarios/resource_plateau`

If steal/jitter is elevated or CV across iterations is high, treat throughput
and latency alerts as provisional.

## Manual dispatch

Actions → **Protocol Performance Regression** → Run workflow.

Optional inputs: duration, concurrency, iterations, and one protocol selection
(or `all` for the complete matrix).

## Local static checks (no benchmarks)

```bash
python3 .github/scripts/verify_protocol_perf_regression_workflow.py --self-test
python3 .github/scripts/verify_protocol_perf_regression_workflow.py
python3 tests/performance/multi_protocol/evaluate_protocol_perf_budgets.py --self-test
python3 -m py_compile tests/performance/multi_protocol/run_protocol_regression_scenarios.py
```

Full-mode PR CI runs the same static set in `Performance Regression Check`
immediately after checkout.

## Historical-baseline H1 TLS POST check

`.github/workflows/h1-tls-post-regression.yml` (daily, plus manual dispatch)
answers the question the scheduled lanes above cannot: *is today's `main`
slower than a known historical revision on the HTTP/1.1 TLS POST/echo
workload?* Issue [#5505](https://github.com/ferrum-edge/ferrum-edge/issues/5505)
found a June-to-September throughput loss on that workload that only surfaced
by eye in `gateways-protocol-benchmark.yml` output; absolute RPS from
different runs cannot guard it because hosted runners change CPU class between
runs.

The check therefore measures **two revisions on one runner**:

1. Build the reference revision pinned in
   `tests/performance/multi_protocol/h1_tls_post_reference.json` and the
   candidate (`main` tip) with the same toolchain and the `ci-release`
   profile; build `proto_backend` / `proto_bench` once from the candidate tree.
2. Start one `proto_backend`; for each round start the reference and candidate
   gateways in alternating order (reference first on odd rounds) with an
   identical environment and `configs/http1_tls_e2e_perf.yaml` (TLS on both
   hops, `backend_read_timeout_ms` / `backend_write_timeout_ms` at their
   production values), warm up, then measure every payload size for
   `duration_secs` at `concurrency` connections.
3. Gate the **paired ratio** `candidate_rps / reference_rps` per round and
   payload size. The median paired ratio must stay at or above
   `thresholds.<size>.min_ratio`.

Runner-variance handling:

- Every measured sample must verify every echo (`total_errors == 0`); errors,
  missing rounds, duplicate samples, or missing provenance fail the job in any
  enforcement mode.
- If either side's three-round throughput spread exceeds
  `runner_variance.max_round_spread`, the runner was noisy and a below-floor
  ratio is downgraded to a **provisional alert** instead of a failure.
- With at least `rolling.min_samples` prior scheduled runs of the same
  reference and workload, a ratio below `median − mad_multiplier × MAD` raises
  a non-blocking alert even when it clears the floor, catching gradual slides.
- The pre-benchmark step records CPU steal and scheduler jitter alongside the
  evidence; treat verdicts as provisional when steal exceeds 5%.

The artifact `h1-tls-post-comparison-<sha>` retains every individual sample
(`samples/*.json`), gateway/backend logs, `rows.json`, `provenance.json`
(revision SHAs, binary and harness digests, toolchain, host), `report.json`,
and the extended `h1_tls_post_trends.json` ratio history.

Contract rules: `reference.sha` is an immutable commit; raise `min_ratio`
toward `1.0` as the gap closes and never lower it or change the workload to
make a production regression disappear. A manual dispatch may pass
`reference_sha` to compare the dispatched ref against any other revision on the
same runner — the matched-host bisect tool for future attribution work. Manual
runs do not extend the rolling history.

Local static checks:

```bash
python3 .github/scripts/h1_tls_post_comparison.py self-test
bash -n .github/scripts/run_h1_tls_post_comparison.sh
```

## Native harness cert paths

The scheduled workflow runs `run_protocol_test.sh` **natively** (not in Docker).
Backend TLS configs use a `CA_PATH` placeholder in committed YAML; the harness
substitutes `tests/performance/multi_protocol/certs/ca.pem` at gateway start.
Docker comparison benches (`run_gateway_protocol_bench.sh`,
`run_connection_saturation_bench.sh`) rewrite the same placeholder to
`/etc/ferrum/tls/ca.pem` before mounting configs into containers. Committed
native perf YAML must not hardcode `/etc/ferrum/tls` paths — the workflow
verifier enforces this contract.

## Mesh in-process vs E2E suites

`tests/performance/mesh/` is the **in-process** Criterion crate (`authz_match`,
`ip_restriction`, `slice_apply`, `xds_translation`). HBONE tunnel throughput and
mesh DNS proxy resolution latency are **not** criterion micro-benches; they ship
as live E2E harnesses that spin up `ferrum-edge` plus stub peers:

| Suite | Path | Measures | Residual |
|---|---|---|---|
| In-process mesh Criterion | `tests/performance/mesh/` | `authz_match`, `ip_restriction`, `slice_apply`, `xds_translation` | Hosted collection workflow landed; `baseline.md` result cells stay `_TBD_` until a successful artifact is published — [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) |
| HBONE gateway overhead | `tests/performance/mesh-hbone-e2e/` | Gateway-to-mesh HBONE outbound throughput over H2 CONNECT/mTLS | Same two-stage publication residual — [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) |
| Mesh DNS proxy | `tests/performance/mesh-dns-e2e/` | Transparent mesh DNS proxy latency/QPS over UDP and TCP | Same two-stage publication residual — [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332) |

Hosted collection (stage 1) lives in
`.github/workflows/mesh-performance-baselines.yml` and is dispatched after the
trusted workflow lands on `main`. Collection is pinned to GitHub-hosted
`ubuntu-24.04` (no arbitrary/self-hosted runner
input). It records provenance, Criterion trees, HBONE/DNS JSON (≥3 repetitions),
`runner_health.json` + per-E2E and per-mesh Criterion workload-interval steal probes, `summary.json`, and draft markdown
under the `mesh-performance-baselines-<sha>` artifact. Selected-suite acceptance
fails the job when required gates are false (undersampling, missing DNS rows,
nonzero errors, nonzero DNS NXDOMAIN counts, missing mesh Criterion / E2E
interval steal evidence, or CPU steal > 5.0%); artifacts still upload. Stage 2 copies
only zero-error hosted aggregates into the three `baseline.md` tables.
Manual and reusable workflow callers are limited to 3–5 E2E repetitions so a
misconfigured reusable caller cannot consume an unbounded hosted-runner budget.

`tests/performance/mesh/README.md` is a **frozen Trusted Cross automation
surface**: every path under `tests/performance/` is treated as protected
executable/configuration prose, including Markdown. Its historical
"Benches deferred (not yet implemented)" section is **not** the current
backlog source of truth and must remain unchanged. Live suite status,
`mesh-hbone-e2e` / `mesh-dns-e2e` pointers, and the [#3332](https://github.com/ferrum-edge/ferrum-edge/issues/3332)
baseline-publication residual are documented here (and in
[`docs/backlog/issue_2110_register.md`](backlog/issue_2110_register.md))
instead of rewriting that protected README.

## Related surfaces

- Mesh/HBONE/DNS baseline collection: `.github/workflows/mesh-performance-baselines.yml`,
  with its non-literal computation in `.github/scripts/mesh_baseline_ledger.py`,
  `.github/scripts/mesh_baseline_runner_health.py`, and
  `.github/scripts/mesh_baseline_step_summary.py` (the workflow itself keeps a
  literal command surface; see `verify_mesh_performance_baselines_workflow.py`)
- Manual exploratory matrix: `.github/workflows/perf-benchmark.yml`
- PR overhead gate: `tests/performance/ci_overhead_bench.py` via `ci.yml`
- Connection saturation headlines: `docs/connection_saturation_benchmark.md`
- Suite index: `tests/performance/README.md`
- Scheduled lane details: this document (performance suite READMEs stay
  unchanged so trusted Cross automation digests are not rewritten)
