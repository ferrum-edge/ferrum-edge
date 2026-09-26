# Mesh HBONE E2E Baseline Numbers

**Directional reference numbers only.** Absolute RPS/latency depend on the
GitHub-hosted runner class and are not universal product targets. Prefer the
same-run overhead percent (and self-relative CI guardrails elsewhere) over raw
RPS when interpreting regressions.

> **Publication status (issue #3332):** Published 2026-08-20 from hosted
> collection at Ferrum SHA `5c3a58cd5fc1083911796621d5f2cd0237946c09`
> ([Actions run 31820671032](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31820671032),
> artifact
> `mesh-performance-baselines-5c3a58cd5fc1083911796621d5f2cd0237946c09`).
> Published evidence used here: **HBONE E2E** (`hbone_complete=true`, `hbone_errors_ok=true`,
> 3 clean repetitions per scenario, all `total_errors=0`, `runner_health_ok=true`,
> max CPU steal 0.0%). The same run's DNS portion failed acceptance and was
> not published; its aggregate `ready_to_publish_baselines=false` reflects that
> DNS gap, not HBONE invalidity. DNS baselines live in
> `tests/performance/mesh-dns-e2e/baseline.md` from a separate DNS-only
> collection. See combined provenance in `tests/performance/mesh/baseline.md`.

## Test environment

| Field | Value |
|---|---|
| CPU | AMD EPYC 9V74 80-Core Processor; 4 vCPU (2 cores × 2 threads × 1 socket) |
| RAM | 15.61 GiB |
| OS / kernel | Linux 6.17.0-1022-azure (Ubuntu 24.04 runner image) |
| Architecture | x86_64 |
| Ferrum Edge revision | `5c3a58cd5fc1083911796621d5f2cd0237946c09` |
| Collected at (UTC) | 2026-08-14T16:44:57Z |
| Runner class | `ubuntu-24.04` (GitHub-hosted Linux; pinned) |
| Rust / harness versions | rustc 1.97.1; cargo 1.97.1; `mesh-hbone-e2e-perf`; hdrhistogram 7.5.4 |
| Build profile | `--release` |
| Feature flags | default (no `--features`) |
| Non-default Ferrum/env settings | harness `run.sh` trusted-projection fixture (`hbone_perf_fixture`) + generated SVID/trust-bundle paths; `FERRUM_BACKEND_ALLOW_IPS=private` |
| Warmup / repetitions | steady-state loadgen after gateway ready; **3 clean repetitions** per row |
| Commands | see below |
| Runner health | max CPU steal 0.0% (pre-collection + per-run workload-interval deltas) |
| Raw artifacts | [run 31820671032](https://github.com/ferrum-edge/ferrum-edge/actions/runs/31820671032) → `hbone/**/run_*.txt`, `summary.json`, `provenance.json` |

## Aggregation semantics

Published RPS and latency quantiles are **arithmetic means across the three
clean repetitions** per scenario. Run-to-run RPS ranges are listed in the Notes
column. Latency p50/p95/p99 are means of per-run hdrhistogram quantiles and are
not inputs to the overhead percent. All retained repetitions had
`total_errors=0`.

## Overhead formula

```text
overhead_percent = ((direct_rps - gateway_hbone_rps) / direct_rps) * 100
```

Computed from the mean RPS across clean repetitions of the same scenario.

## Commands

```bash
# Hosted (required for publication):
# Actions → "Mesh Performance Baselines" → suites=hbone|all, iterations=3

# Row-shaped invocations (used by the workflow after one release build):
cd tests/performance/mesh-hbone-e2e
./run.sh --skip-build --json --duration 30 --concurrency 50 --payload-size 1024
./run.sh --skip-build --json --duration 30 --concurrency 50 --payload-size 16384
./run.sh --skip-build --json --duration 60 --concurrency 100 --payload-size 262144
```

## 1 KiB payload, concurrency 50, 30 s

| Path              | RPS    | p50    | p95    | p99    | Overhead vs direct |
|-------------------|--------|--------|--------|--------|--------------------|
| Direct baseline   | 96,109 | 492 µs | 873 µs | 1.08 ms | —                  |
| Gateway + HBONE   | 8,477  | 5.79 ms | 8.11 ms | 9.35 ms | 91.2 %             |

Notes: direct RPS range 95,753–96,641; gateway RPS range 8,344–8,573.

## 16 KiB payload, concurrency 50, 30 s

| Path              | RPS    | p50    | p95    | p99    | Overhead vs direct |
|-------------------|--------|--------|--------|--------|--------------------|
| Direct baseline   | 74,449 | 626 µs | 1.16 ms | 1.49 ms | —                  |
| Gateway + HBONE   | 4,496  | 10.40 ms | 15.16 ms | 17.55 ms | 94.0 %             |

Notes: direct RPS range 73,562–75,686; gateway RPS range 4,474–4,538.

## 256 KiB payload, concurrency 100, 60 s

| Path              | RPS    | p50    | p95    | p99    | Overhead vs direct |
|-------------------|--------|--------|--------|--------|--------------------|
| Direct baseline   | 14,019 | 6.81 ms | 11.72 ms | 14.53 ms | —                  |
| Gateway + HBONE   | 573    | 173.01 ms | 206.38 ms | 222.12 ms | 95.9 %             |

Notes: direct RPS range 13,971–14,107; gateway RPS range 572–574.

## Rerun procedure

1. Trigger **Mesh Performance Baselines** on the candidate SHA (`suites=hbone` or `all`).
2. Download `mesh-performance-baselines-<sha>`.
3. Require `summary.json` → `acceptance_gate.hbone_complete` and `hbone_errors_ok`.
4. Require `repetition_evidence` showing 3–5 clean gateway and direct samples per
   scenario (matching the bounded workflow input).
5. Require `acceptance_gate.runner_health_ok` (CPU steal ≤ 5.0% in the
   pre-collection sample, each selected mesh Criterion workload-interval
   `/proc/stat` steal delta, and each per-run HBONE workload-interval delta);
   reject the collection for publication when exceeded.
6. Reject any repetition with non-zero `total_errors`; do not average failures away.
7. Publish mean RPS / latency across remaining clean runs and the overhead percent
   from the formula above.
8. Attach or link the raw `hbone/**/run_*.txt` JSON blobs from the artifact.

When combining with mesh and DNS baseline refreshes, treat each suite's
acceptance gate independently; an all-suite run whose aggregate
`ready_to_publish_baselines` is false because DNS failed does not invalidate
accepted HBONE rows from the same artifact.

## Bottleneck review

Before treating Gateway+HBONE RPS as “gateway capacity”:

- Topology is localhost loadgen → trusted-projection fixture → stub sidecar → echo backend.
- mTLS + H2 CONNECT setup is amortized; numbers are steady-state, not handshake cost.
- Direct baseline bypasses gateway **and** sidecar; overhead includes tunnel relay,
  not only `ferrum-edge` proxy overhead.
- Shared GitHub runners can show CPU steal; publication fails closed when steal
  exceeds **5.0%** (re-run rather than publishing impaired numbers).
- Userspace HBONE relay (no `splice` fast path through TLS) dominates large payloads.

## Refresh cadence

Refresh after HBONE pool / mTLS / outbound mesh-tag routing changes, harness
dependency SYNC bumps (`rustls`/`h2`), runner-class changes, or each minor
release train. Always re-collect on GitHub-hosted runners via
`.github/workflows/mesh-performance-baselines.yml`.
