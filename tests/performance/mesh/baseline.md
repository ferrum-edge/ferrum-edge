# Mesh Performance Baseline

**Directional reference numbers only.** Hardware-specific absolute values are
not universal product targets. Only defensible normalized/self-relative
guardrails (for example the hosted `ip_restriction` scaling ceilings already
enforced in CI) become gates. Treat the tables below as a same-runner reference
shape, not a laptop SLA.

> **Publication status (issue #3332):** Published 2026-08-20 from hosted
> collection at Ferrum SHA `5c3a58cd5fc1083911796621d5f2cd0237946c09`
> ([Actions run 31820671032](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31820671032),
> artifact
> `mesh-performance-baselines-5c3a58cd5fc1083911796621d5f2cd0237946c09`).
> Published evidence used here: **mesh Criterion microbenchmarks** (`mesh_complete=true`,
> `runner_health_ok=true`, max CPU steal 0.0%). HBONE and DNS baselines in
> sibling directories are suite-gated separately: HBONE shares this accepted
> hosted collection, while DNS uses the later collection in the combined
> provenance note below. The same all-suite run also attempted DNS
> with `--protocol both`; that portion failed acceptance (`dns_complete=false`,
> `ready_to_publish_baselines=false` on that run) because the upstream stub
> lacked TCP DNS — do not treat that run's aggregate flag or failed DNS blobs as
> DNS evidence.

## Combined provenance (all three baseline documents)

Mesh Criterion and HBONE E2E rows share one hosted collection; DNS E2E rows
come from a later DNS-only collection after the TCP stub repair. Each suite
passed its own fail-closed acceptance fields — the earlier all-suite workflow
was **not** globally green.

| Suite | Ferrum SHA | Actions run | Artifact |
|---|---|---|---|
| Mesh Criterion | `5c3a58cd5fc1083911796621d5f2cd0237946c09` | [31820671032](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31820671032) | `mesh-performance-baselines-5c3a58cd5fc1083911796621d5f2cd0237946c09` |
| HBONE E2E | `5c3a58cd5fc1083911796621d5f2cd0237946c09` | [31820671032](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31820671032) | `mesh-performance-baselines-5c3a58cd5fc1083911796621d5f2cd0237946c09` |
| DNS E2E | `a7921ea2176360c7812da6d2c2dff356ad99f5d8` | [31917782760](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31917782760) | `mesh-performance-baselines-a7921ea2176360c7812da6d2c2dff356ad99f5d8` |

New hosted collections use `ubuntu-26.04`. The published measurements below
retain their original Ubuntu 24.04 provenance and must not be compared as
absolute regression gates across runner images.

## Reference environment (mesh Criterion collection)

| Field | Value |
|---|---|
| Ferrum commit SHA | `5c3a58cd5fc1083911796621d5f2cd0237946c09` |
| Collected at (UTC) | 2026-08-14T16:44:57Z |
| Runner class | `ubuntu-24.04` (GitHub-hosted Linux; pinned) |
| CPU model / topology | AMD EPYC 9V74 80-Core Processor; 4 vCPU (2 cores × 2 threads × 1 socket) |
| RAM | 15.61 GiB |
| OS / kernel / arch | Linux 6.17.0-1022-azure / x86_64 |
| Rust toolchain | rustc 1.97.1 (8bab26f4f 2026-07-14); cargo 1.97.1; `rust-toolchain.toml` → `stable` |
| Criterion / harness | Criterion 0.5.1; `tests/performance/mesh` (`mesh-perf`) |
| Build profile / features | Criterion `bench` profile inherits `release`; default features |
| Non-default settings | none beyond harness defaults |
| Warmup / measurement | `--warm-up-time 3 --measurement-time 15` per bench |
| Runner health | max CPU steal 0.0% (pre-collection + per-bench `/proc/stat` deltas) |
| Raw artifacts | [run 31820671032](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31820671032) → `mesh/criterion/**`, `summary.json`, `provenance.json` |

## Commands

```bash
# Preferred: hosted collection
# Actions → "Mesh Performance Baselines" → suites=mesh (or all)

# Equivalent Criterion invocation used by the workflow:
cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench authz_match \
  -- --warm-up-time 3 --measurement-time 15
cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench ip_restriction \
  -- --warm-up-time 3 --measurement-time 15
cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench slice_apply \
  -- --warm-up-time 3 --measurement-time 15
cargo bench --manifest-path tests/performance/mesh/Cargo.toml --bench xds_translation \
  -- --warm-up-time 3 --measurement-time 15
```

## authz_match

`policy::evaluate_mesh_authorization_policies` over N synthetic ALLOW policies, request that misses every rule (worst case — every policy is fully traversed before the implicit-deny return).

Criterion means ± σ from `estimates.json` (single hosted run, not averaged across repetitions).

| Policies (N) | Mean per call | Notes |
|---|---|---|
| 10 | 144.3 ns (σ 3.0 ns) | |
| 100 | 741.3 ns (σ 6.7 ns) | |
| 1 000 | 7.186 µs (σ 105.3 ns) | |
| 10 000 | 91.666 µs (σ 396.3 ns) | Worth tracking — fleets ship 1k–10k AuthorizationPolicy resources in larger Istio installations. |

## ip_restriction

`IpRestriction::on_request_received` over 10,000 sparse exact IPv4 intervals.
The authoritative client IP cache is initialized before timing so the result
isolates the async plugin hook and compiled interval lookup. The hosted
`Performance Regression Check` runs all four cases, pairs each with a 100-rule
same-run reference, enforces the guardrails below, and retains Criterion output.

| Decision shape | Instances | Mean per iteration | Notes |
|---|---:|---|---|
| Deny miss above every interval | 1 | 43.1 ns (σ 0.2 ns) | Worst-case ordered miss; 10,000 rules. |
| Deny miss above every interval | 4 | 158.3 ns (σ 0.9 ns) | Supported multiple scoped-instance composition. |
| Allow match in final interval | 1 | 44.0 ns (σ 0.2 ns) | High-address match. |
| Allow match in final interval | 4 | 165.1 ns (σ 1.3 ns) | High-address match across multiple instances. |

Hosted guardrails are intentionally generous and separate from the directional
reference numbers in this file. For each decision shape and instance count, the
10,000-rule Criterion mean must be at most 8x its 100-rule same-run mean and at
most 10 microseconds per plugin instance. The self-relative limit detects a
return to rule-count-proportional scans; the absolute ceiling also catches a
catastrophic regression in the cached client-IP or constant-time hook overhead.

## slice_apply

`MeshSlice::from_gateway_config(&GatewayConfig, MeshSliceRequest)` over N synthetic workloads + matching MeshService rows.

| Workloads (N) | Mean per call | Notes |
|---|---|---|
| 100 | 78.296 µs (σ 517.1 ns) | Criterion mean |
| 1 000 | 791.907 µs (σ 2.711 µs) | Criterion mean |
| 5 000 | 3.985 ms (σ 34.463 µs) | Criterion mean |

## xds_translation

`xds::translator::translate_mesh_slice_to_snapshot(&MeshSlice)` over a slice with N workloads + 1 service each.

| Workloads (N) | Mean per call | Notes |
|---|---|---|
| 100 | 535.059 µs (σ 2.034 µs) | Criterion mean |
| 1 000 | 5.163 ms (σ 37.299 µs) | Criterion mean |
| 5 000 | 27.133 ms (σ 297.988 µs) | Criterion mean |

## Overhead formula

These microbenchmarks have no direct-vs-gateway comparison. For E2E suites the
shared throughput overhead definition is:

`overhead_percent = ((direct_throughput - gateway_throughput) / direct_throughput) * 100`

where throughput is RPS (HBONE) or QPS (DNS upstream-forward). Latency quantiles
are reported beside the overhead column and are not folded into it.

## Rerun procedure

1. Push the candidate SHA (or use the PR branch).
2. Run Actions → **Mesh Performance Baselines** → `suites=mesh` or `all`.
3. Download artifact `mesh-performance-baselines-<sha>`.
4. Confirm `summary.json` → `acceptance_gate.mesh_complete == true` and
   `acceptance_gate.runner_health_ok == true` (CPU steal ≤ 5.0% across the
   pre-collection vmstat sample, each selected mesh Criterion workload-interval
   `/proc/stat` steal delta, and each selected E2E workload-interval delta;
   see `runner_health.json` and `logs/runner_health_probes.jsonl`).
5. Copy Criterion means (and σ / CI from `estimates.json`) into the tables above.
6. Link the artifact from the reference-environment table.
7. Re-check interpretation notes below for harness bottlenecks before treating
   numbers as gateway capacity.

When refreshing all three baseline documents together, collect mesh and HBONE
from one run (or separate runs) and DNS from a DNS-only run with a TCP-capable
upstream stub; combine suite-by-suite only when each suite's acceptance gate
passes. Do not publish partial DNS rows from an all-suite run whose aggregate
`ready_to_publish_baselines` is false solely because DNS failed.

## Bottleneck review

- These are **single-threaded** Criterion micro-benches. Production paths can
  amortise across cores; per-call times are a per-CPU upper bound, not aggregate
  throughput.
- `authz_match` measures the worst-case linear scan. The plugin layer caches
  PolicyScope filter results per-request; that cache is _not_ exercised here.
- `ip_restriction` measures the compiled O(log n) lookup after canonical
  client-IP caching; policy construction and rule parsing are outside the timed
  loop.
- `slice_apply` measures the cold rebuild. The ArcSwap swap itself is ~constant
  time and is not included in the bench window.
- `xds_translation` runs on the CP side; DP fingerprint-dedup downstream means
  most translations get reused, so production hit rate is high.

## Refresh cadence

Refresh this table when any of the following land on `main`:

- Material changes to mesh authz evaluation, `ip_restriction` lookup, slice
  apply, or xDS translation hot paths.
- Criterion / harness dependency bumps that change measurement semantics.
- Runner-class changes for the hosted collection workflow.
- At least once per minor release train, or sooner if a sustained CI
  self-relative guardrail alert fires.

Re-run via `.github/workflows/mesh-performance-baselines.yml` and publish only
zero-error hosted results whose suite-specific acceptance gate passes.
