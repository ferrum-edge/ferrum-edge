# Agent 20 — Perf / CI / packaging launch-readiness verdict

**Agent:** Ferrum Edge Launch-Readiness Agent 20
**Domain:** Perf, CI, packaging, launch verdict aggregator
**Mode:** Investigation only. No production Rust changes.
**Ports reserved:** `127.0.0.1:22900-22999` (unused; no live proxy started)
**Prefix:** `fe-agent-20-`

## Verdict

**blocked**

The five charter HOLD items remain closed as documented. They are **not**
re-opened. The domain is still not launch-ready because:

1. The only recurring 10k/30k scale gate is red (`#4116`).
2. The only scheduled multi-protocol regression lane has **never** been green
   (`#4388`, filed this pass).
3. Two high launch-blocker release/packaging issues are still open (`#4301`,
   `#4302`) with PRs in flight. Other agents own those product/release edits.

HOLD remainders that need a direct-to-`main` policy edit stay frozen. That is
policy, not a new CI bug.

## SHA under test

| Ref | SHA | Note |
|---|---|---|
| Requested floor | `bf05855f8429e466511610f9072f666b45cd309a` | `Merge pull request #4319` (CLI FIPS doc) |
| **Recorded / tested** | **`1719e6dc32a24e4faa1053383c96697e58d7545e`** | `origin/main` at investigation time; `Merge pull request #4354` |

`bf05855f` was current when this agent started. `origin/main` advanced during
the run. Workflow/YAML claims below were re-checked on `1719e6dc`.

## Compile (Agent 11 light)

**pass** — `cargo check --bin ferrum-edge` only.

- `CARGO_BUILD_JOBS=2`
- `RUSTC_WRAPPER` / `CARGO_BUILD_RUSTC_WRAPPER` cleared (no sccache on this VM)
- mold + clang + protoc + `libcurl4-openssl-dev` + `libstdc++` installed locally
- **Not run:** unfiltered `cargo test`, `cargo test --lib`, `unit_tests` link
  (would OOM-link on this 15 GiB / 0 swap host)

```
Finished `dev` profile [unoptimized + debuginfo] target(s) in 5m 06s
exit 0
```

Static contracts (no binary tests):

- `verify_protocol_perf_regression_workflow.py --self-test` + contract: pass
- `evaluate_protocol_perf_budgets.py --self-test` + `py_compile` scenarios: pass
- `verify_scaling_regression_workflow.py --self-test` + contract: pass

## Charter HOLD items (do not reopen)

### #3908 CI path-filtered live suites — CLOSED, HOLD (policy freeze)

https://github.com/ferrum-edge/ferrum-edge/issues/3908

**On `1719e6dc`:** `node-waypoint-ebpf-live.yml`, `istio-status-cas-live.yml`,
and `cni-lifecycle-live.yml` all trigger `pull_request` + `merge_group` +
`push: main` + `workflow_dispatch`. None use a workflow-level `paths:` filter.
Closing comment (`b96cfaadd`) froze NodeWaypoint planner/aggregate `needs`/`if`
in `verify_cross_build_policy.py`. Further edits to those six jobs are
direct-to-`main` only.

**Remainder:** policy freeze. Not a launch product bug.

### #3892 Scaling Regression harness JWT/503 — CLOSED, HOLD

https://github.com/ferrum-edge/ferrum-edge/issues/3892

Closed by #3895 (JWT TTL + documented-503 retry). Workflow timeout is now 300
minutes (`scaling-regression.yml`). Freshness publisher exists
(`scaling-gate-freshness.yml`).

**The gate is still red**, but the *current* failure is not the #3892 JWT
expiry. Durable signal is **#4116** (see below). Do not reopen #3892.

### #3904 rebuild-6x / cache lanes — CLOSED, HOLD

https://github.com/ferrum-edge/ferrum-edge/issues/3904

On `1719e6dc`, four live workflows share `shared-key: "ci-live-pr-build"`:
`gateway-api-conformance.yml`, `mesh-e2e-sidecar-live.yml`,
`multicluster-federation-live.yml`, `multicluster-poller-partition-live.yml`.
`cni-lifecycle-live`, `node-waypoint-ebpf-live`, and `ambient-host-udp-live`
keep private lanes (cni binary / `cloud-secrets,ebpf` / dev profile). Orphan
`ci-test-functional` is gone. Cross-workflow artifact reuse remains
**deliberately deferred** (trusted-producer bar). Remainder is policy/design,
not a new issue.

### #4018 FIPS exit 143 — CLOSED, HOLD

https://github.com/ferrum-edge/ferrum-edge/issues/4018

Mitigation landed in #4047. `fips-build.yml` now has `CARGO_BUILD_JOBS: "3"`,
`CARGO_PROFILE_DEV_DEBUG: line-tables-only`, and an additive 8 GiB swap step.
Further whole-file edits stay Cross-frozen.

Recent `main` FIPS runs were green through `eea4e9eb6` (2026-08-30 06:26Z).
Runs on `bf05855f` and `1719e6dc` were **cancelled** by later `main` pushes
(`cancel-in-progress` on the shared `push`/`refs/heads/main` concurrency
group). That is operational, not a return of exit 143. Do not reopen #4018.

### #3942 protocol-bench H2 −13% — CLOSED, HOLD

https://github.com/ferrum-edge/ferrum-edge/issues/3942

Product fix #4020 (`Skip SizeLimitedIncoming on unlimited ordinary direct-H2`)
is on `main`. Unit/integration contracts still pin the unlimited-path skip
(`tests/unit/gateway_core/proxy_tests.rs`, `tests/integration/connection_pool_tests.rs`).
`docs/size_limits.md` documents the Jun 19 hot path.

**No post-fix GHA `gateways-protocol-benchmark` rerun.** Latest scoreboard
artifacts are still run 21 (`31873567792`, `53b33098`, 2026-08-15) — the
regression snapshot. Local #4020 comment claimed recovery toward the Jun 19
host median. HOLD: do not reopen; do not treat the scheduled native lane
(#4388) as an #3942 oracle until it can start HTTP/2.

## Domain findings that *do* block launch

### Scaling gate still red — #4116 (open, do not dupe)

https://github.com/ferrum-edge/ferrum-edge/issues/4116

Latest scheduled run [33248565869](https://github.com/ferrum-edge/ferrum-edge/actions/runs/33248565869)
(`b96cfaadd`, 2026-08-29):

| Leg | Result |
|---|---|
| 30k SQLite | success |
| 30k PostgreSQL | success |
| 30k MongoDB | success |
| 10k PostgreSQL load stress | **failure** |

Panic (job 99090164230):

```
Failed to provision resources: "Batch plugin create failed: 400 -
  {\"error\":\"Batch validation failed\",\"validation_errors\":[
    \"PluginConfig 'keyauth-2457' proxy reference check failed:
     Database unavailable — operation failed\"]}"
```

That classification is **#4377** (product: DB `Err` during batch reference
validation returned as 400). Fix PR **#4379** is open. Freshness run
[33262067192](https://github.com/ferrum-edge/ferrum-edge/actions/runs/33262067192)
correctly kept #4116 open.

One dispatched success exists (run 33083053662, 2026-08-27). The auto-close
contract requires the *latest* main scheduled/dispatched run to be green.

**Agent 20 does not own the product 400→503 fix.**

### Protocol-perf scheduled lane never green — #4388 (filed this pass)

https://github.com/ferrum-edge/ferrum-edge/issues/4388

**Observed:** four consecutive Sunday failures, identical `http2_perf.yaml`
startup error: `backend_tls_server_ca_cert_path` = `/etc/ferrum/tls/ca.pem`
does not exist on the hosted runner. No successful workflow run exists.

**Expected:** native `run_protocol_test.sh` uses
`tests/performance/multi_protocol/certs/ca.pem` (the files `start_gateway`
already waits for).

**RCA:** Docker comparison benches mount `$CERT_DIR` at `/etc/ferrum/tls`.
The scheduled workflow is native. `start_gateway` injects frontend TLS from
`$SCRIPT_DIR/certs` but does not rewrite the backend CA path. Envoy configs
already substitute `CA_PATH`; Ferrum YAML does not. `FERRUM_TLS_NO_VERIFY=true`
does not skip fail-closed CA-file validation. `http3_perf.yaml` has the same
path; `all` dies at HTTP/2 first.

Not a dupe of closed #3942.

### Packaging / release (other agents own the edits)

| Issue | Title | PR | Agent 20 note |
|---|---|---|---|
| [#4301](https://github.com/ferrum-edge/ferrum-edge/issues/4301) | Linux GNU artifacts require GLIBC_2.39; README presents them as generic | [#4355](https://github.com/ferrum-edge/ferrum-edge/pull/4355) | Confirmed `release.yml` still builds GNU x86_64 on moving `ubuntu-latest` with `cargo build --release` (fat LTO, `codegen-units = 1`). No ABI-floor gate in this workflow. |
| [#4302](https://github.com/ferrum-edge/ferrum-edge/issues/4302) | Publish gates wait on a subset of the required-check set | [#4324](https://github.com/ferrum-edge/ferrum-edge/pull/4324) | Confirmed `release.yml:128-143` still waits CI + Coverage + Mesh E2E + two multicluster lives; omits Gateway API Conformance and Ambient Host UDP. |

### Release LTO memory

`Cargo.toml` `[profile.release]` is `lto = "fat"` + `codegen-units = 1`.
`release.yml` `build-release-binaries` has **no** `CARGO_BUILD_JOBS` cap and
**no** swap step (unlike `ci.yml` `test-unit` / `fips-build.yml`).

**No observed exit-143 / OOM on a current release-tag build** in this pass
(recent `release.yml` runs are old tag-validation failures, not LTO kills).
Last completed successful **CI** `main` push was
[33094251786](https://github.com/ferrum-edge/ferrum-edge/actions/runs/33094251786)
on `b96cfaadd` (2026-08-27), which includes the fat-LTO `build-binaries`
matrix. Residual risk only; **no new issue** (would be speculative).

`[profile.ci-release]` (`lto = "off"`, `codegen-units = 256`) remains the
scheduled protocol-perf build profile — correct, unused until #4388 is fixed.

### Main-push CI cancellation (note, not a new issue)

`ci.yml` concurrency is
`ci-publish-${{ github.event_name }}-${{ ... || github.ref }}` with
`cancel-in-progress: true`. Every new `main` push cancels the previous
`push` CI/FIPS/live set. During this investigation, `bf05855f` and
`1719e6dc` CI/FIPS runs were cancelled by later merges. Merge-queue required
checks still apply per-SHA; mutable `latest` publication on `main` is the
surface already tracked by #4302. Not filed separately.

## Product bugs other agents own (not Agent 20)

These affect perf/CI signal or packaging but are **not** this agent's
implementation work:

| Issue | Why it is out of scope here |
|---|---|
| [#4377](https://github.com/ferrum-edge/ferrum-edge/issues/4377) / PR [#4379](https://github.com/ferrum-edge/ferrum-edge/pull/4379) | Batch DB `Err` → 400; current #4116 red cause |
| [#4301](https://github.com/ferrum-edge/ferrum-edge/issues/4301) / [#4355](https://github.com/ferrum-edge/ferrum-edge/pull/4355) | GNU ABI floor |
| [#4302](https://github.com/ferrum-edge/ferrum-edge/issues/4302) / [#4324](https://github.com/ferrum-edge/ferrum-edge/pull/4324) | Publish-gate inventory |
| [#4280](https://github.com/ferrum-edge/ferrum-edge/issues/4280), [#4281](https://github.com/ferrum-edge/ferrum-edge/issues/4281) | Pool-key / `rr_counters` product perf (launch-blocker medium) |
| [#4293](https://github.com/ferrum-edge/ferrum-edge/issues/4293), [#4270](https://github.com/ferrum-edge/ferrum-edge/issues/4270) | DNS cache product |
| [#4313](https://github.com/ferrum-edge/ferrum-edge/issues/4313) | 2026-08-28 launch-audit merge-order meta |
| Mesh/security launch-blockers `#4249`–`#4309`, `#4261`–`#4299` | Other domain agents |

## Issues filed this pass

| Issue | URL |
|---|---|
| #4388 | https://github.com/ferrum-edge/ferrum-edge/issues/4388 |

Not filed (already tracked or HOLD): #3908, #3892, #3904, #4018, #3942,
#4116, #4301, #4302, #4377.

## What would flip this domain to pass

1. #4116 closes on a green scheduled or dispatched Scaling Regression on `main`
   (needs #4377/#4379 or equivalent, then a full four-leg success).
2. #4388 lands; one dispatched Protocol Performance Regression `all` run on
   `main` produces HTTP/2 + HTTP/3 samples (alert-only budgets may warn).
3. #4301 and #4302 merge (or are explicitly accepted as launch exceptions by
   a human). Other agents own those PRs.
4. Optional, not required for this verdict: a post-#4020
   `gateways-protocol-benchmark` dispatch so #3942 has a GHA scoreboard, not
   only the local host comment.

## Evidence index

- Scaling latest red: https://github.com/ferrum-edge/ferrum-edge/actions/runs/33248565869
- Protocol-perf latest red: https://github.com/ferrum-edge/ferrum-edge/actions/runs/32620228061
- Last green CI `main` (completed): https://github.com/ferrum-edge/ferrum-edge/actions/runs/33094251786 (`b96cfaadd`)
- Last green FIPS `main` (completed): https://github.com/ferrum-edge/ferrum-edge/actions/runs/33296884623 (`eea4e9eb6`)
- Protocol-bench scoreboard still at #3942 run 21: https://github.com/ferrum-edge/ferrum-edge/actions/runs/31873567792
