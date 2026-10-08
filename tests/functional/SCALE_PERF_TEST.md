# Scale Performance Test

## Overview

`functional_scale_perf_test.rs` measures how gateway throughput and latency degrade as the number of configured proxies grows from 0 to 30,000. Each proxy is secured with `key_auth` + `access_control` plugins and has a unique consumer, making this a realistic simulation of a large multi-tenant deployment.

## What It Tests

1. **Throughput degradation at scale** -- Does the gateway maintain acceptable RPS as the route table and plugin/consumer indexes grow from 3,000 to 30,000 entries?

2. **Latency distribution at scale** -- How do p50, p95, p99, and max latencies change as config size increases?

3. **Config update resiliency** -- Resources are added between perf windows to the running gateway process (no restart). The DB poller picks up each new wave, exercising the atomic config swap and cache rebuild paths, and every wave must converge before the next window is measured. Load is not applied while a wave is being provisioned, so this test does not measure throughput *during* a reload.

4. **Auth + ACL hot path at scale** -- Every request goes through key_auth (O(1) consumer index lookup) and access_control (consumer allowlist check), verifying these remain fast with 30k consumers in the index.

5. **Batch API throughput** -- The test uses the `POST /batch` endpoint to create resources in bulk (100 at a time), testing transactional batch insert performance across different databases.

## Test Variants

### SQLite (`test_scale_perf_30k_proxies`)

Uses a SQLite database file in a temporary directory -- always available, no external dependencies. Good baseline for testing gateway hot-path performance, though SQLite's single-writer lock limits admin API write throughput at scale.

### PostgreSQL (`test_scale_perf_30k_proxies_postgres`)

Uses a PostgreSQL Docker container for realistic production-like write performance. PostgreSQL handles concurrent writes much better than SQLite, so batch creation times should be significantly faster.

**Prerequisite**: Start the PostgreSQL container:

```bash
docker run -d --name ferrum-scale-test-pg \
  -e POSTGRES_USER=ferrum \
  -e POSTGRES_PASSWORD=ferrum-scale-test \
  -e POSTGRES_DB=ferrum_scale \
  -p 127.0.0.1:25432:5432 postgres:16
```

The test automatically skips if the container isn't running.

### MongoDB (`test_scale_perf_30k_proxies_mongodb`)

Uses a MongoDB Docker container to measure how the document-store backend scales. The gateway stores its config collections in the `ferrum_scale` database (`FERRUM_MONGO_DATABASE`) and creates the production indexes automatically on startup.

**A replica set is required, not standalone.** The benchmark provisions resources through `POST /batch`, which is all-or-nothing (issue #2401) and therefore needs MongoDB multi-document transactions; a standalone `mongod` refuses the import with `501` instead of applying part of a graph. A replica set also exercises the incremental `config_changes` polling path, since change records are only transactionally coupled to resource writes there.

**Prerequisite**: Start MongoDB as a single-node replica set. `--network host` with a real port matters: a replica-set member advertises its own `host:port` and the driver reconnects to whatever is advertised, so a `-p` mapping would send the driver to the wrong port.

```bash
docker run -d --name ferrum-scale-test-mongo --network host \
  mongo:7 --replSet rs0 --port 27117 --bind_ip 127.0.0.1
docker exec ferrum-scale-test-mongo mongosh --quiet --port 27117 --eval \
  'rs.initiate({_id: "rs0", members: [{_id: 0, host: "127.0.0.1:27117"}]})'
export FERRUM_MONGO_REPLICA_SET=rs0
```

The test automatically skips if the container isn't running, and drops the `ferrum_scale` database (via `docker exec ... mongosh --port 27117`) at the start of each run for a clean baseline.

## Test Structure

The test runs in 10 batches. Each batch:

1. Creates 12,000 resources for 3,000 new proxies via the **batch admin API** (`POST /batch`):
   - 3,000 consumers (with unique `keyauth` API keys), sent in chunks of 100
   - 3,000 proxies (unique listen paths `/svc/0` through `/svc/29999`), sent in chunks of 100
   - 6,000 plugin configs (key_auth + access_control per proxy), sent in chunks of 100
   - All proxies route to the same echo backend
2. Waits for the highest deferred-apply cursor to be accepted by the poller
3. Proves end-to-end data-plane convergence across the oldest proxy and the first, middle, and last proxies in the new batch
4. Sends **5 seconds of discarded warmup traffic**, then runs a **complete 30-second measured window** with 50 concurrent workers hitting all accumulated proxies round-robin, each request authenticated with the correct API key. Only requests that complete inside the window count; RPS is successful requests ÷ window, latency percentiles cover successful requests, and the gateway process's CPU time over the window is divided by the requests it served (`CPU/req`). A route-miss 404 ends and discards the partial window, re-runs the bounded convergence gate, and restarts the full window once; a second interrupted window fails as convergence instability rather than being reported as a routing-throughput regression.

After all 10 batches, a summary table is printed comparing RPS and latency percentiles across each scale point (3k, 6k, 9k, ... 30k).

## Reload Under Load (`test_scale_reload_under_load`)

The scale test above measures steady state *between* waves. This variant
answers a different question: **does traffic to existing proxies keep flowing
while config changes are written and hot-applied?**

It is local-only, like the 30k scale and 10k load-stress suites: the CI and
coverage functional lanes exclude it by name.

For each change it starts 50 workers on every already-live proxy, sends 5 s of
discarded warmup, measures a 10 s steady baseline, and then, with load still
running, writes the change through `POST /batch?apply=async`, waits for the
apply cursor, proves the new routes are live, and measures 10 s more. Three kinds of change repeat up to 30,000 proxies:

| Kind | Change | Reload path |
|---|---|---|
| `full` | 3,000 proxies with new consumers (12,000 resources) | Full rebuild: exceeds the poller's 10,000-row change-log limit |
| `small+consumers` | 100 proxies with new `key_auth` consumers (400 resources) | Incremental: consumer changes escalate to a full reload only while load-time quarantine is active or a changed consumer carries `hmac_auth` (issue #6060) |
| `small-proxies` | 100 proxies whose plugins admit existing consumers (300 resources) | Incremental |

The two small changes run after the initial wave and after every full wave.

Every second records successful requests, p50/p99, errors, gateway CPU
(cores), gateway RSS, load-generator CPU, the host 1-minute load average, and
the CPU every other process used (host-wide busy cores minus the gateway and
this test process).
Each change reports four phases: `steady`; `change` (admin writes + apply +
convergence); `apply` (from the last admin write to the confirmed apply, i.e.
the reload alone); and `post`.

**Any error from an already-live proxy fails the test** (non-2xx, timeout, or
route-miss 404), which checks that an atomic config swap never drops or stalls
existing routes. Degradation is reported, not asserted, because it depends on
the host: a warning prints when a second during the change runs below 50% of
steady RPS, when its p99 exceeds 10× steady p99, or when other processes used
more than 2 cores on average (or 4 in any one second) during the change (they
competed for CPU and the numbers are noisy).

```bash
cargo build --release --bin ferrum-edge
FERRUM_RELOAD_RESULTS_JSON=reload-under-load.json \
cargo test --profile ci-release --test functional_tests -- --ignored --nocapture \
  --exact functional::functional_scale_perf_test::test_scale_reload_under_load

# On a shared machine, wait (up to 10 min) before each change until host-wide
# CPU over 3 seconds is below 30% of the CPU count
FERRUM_RELOAD_WAIT_FOR_QUIET_HOST=1 FERRUM_RELOAD_RESULTS_JSON=reload-under-load.json \
cargo test --profile ci-release --test functional_tests -- --ignored --nocapture \
  --exact functional::functional_scale_perf_test::test_scale_reload_under_load

# Shorter local run: stop at 9,000 proxies
FERRUM_SCALE_TOTAL_PROXIES=9000 cargo test --profile ci-release --test functional_tests -- \
  --ignored --nocapture --exact functional::functional_scale_perf_test::test_scale_reload_under_load
```

The JSON contains every phase plus the full per-second series for charting.
Admin writes run inside the gateway process, so the `change` phase includes the
CPU cost of handling those writes as well as the reload; `apply` isolates the
reload. Run it on a quiet machine: another build or test competing for CPU shows
up as dips with *low* gateway CPU and high other-process CPU.

## How to Run

```bash
# Release build (the harness also runs `cargo build --release --bin ferrum-edge`
# itself, a no-op after this, and falls back to a debug binary with a warning;
# debug numbers are not meaningful)
cargo build --release --bin ferrum-edge

# SQLite variant (no external dependencies). `--exact` keeps the filter from
# also matching the _postgres and _mongodb variants. `--profile ci-release`
# optimizes the test binary, which hosts the load generator and echo backend;
# a debug test binary can become the bottleneck and hide gateway slowdown.
# Use it for any number you publish (CI's regression gate uses the debug
# profile and compares batches only against each other).
FERRUM_SCALE_RESULTS_JSON=scale-results.json \
cargo test --profile ci-release --test functional_tests -- --ignored --nocapture \
  --exact functional::functional_scale_perf_test::test_scale_perf_30k_proxies

# PostgreSQL variant (requires the Docker container above)
cargo test --test functional_tests test_scale_perf_30k_proxies_postgres \
  -- --ignored --nocapture

# MongoDB variant (requires the Docker container above)
cargo test --test functional_tests test_scale_perf_30k_proxies_mongodb \
  -- --ignored --nocapture
```

Set `FERRUM_SCALE_RESULTS_JSON=/path/to/scale.json` to also write every batch
result (RPS, latency percentiles, gateway CPU per request) plus the run
parameters and commit as JSON.

The load generator and echo backend run inside the test process on the same
host as the gateway. On a laptop they compete with the gateway for cores, so a
client-side ceiling can hide part of a gateway slowdown: compare `CPU/req`
across batches as well as RPS. CPU per request is measured on the gateway
process alone and is not capped by the client.

Do not add `--all-features`: it enables both `crypto-ring` and `fips`, which is a
compile error. `--nocapture` is needed to see the progress output and results
table. `.github/workflows/scaling-regression.yml` runs the same tests in CI.

## Configuration

Constants at the top of the test file control the test parameters:

| Constant                 | Default | Description                                      |
|--------------------------|---------|--------------------------------------------------|
| `BATCH_SIZE`             | 3,000   | Proxies/consumers/plugins created per batch       |
| `TOTAL_PROXIES`          | 30,000  | Total proxies to create (must be multiple of batch size) |
| `PERF_WARMUP_SECS`       | 5       | Discarded warmup traffic before each window       |
| `PERF_TEST_DURATION_SECS`| 30      | Seconds each measured window runs                 |
| `CONCURRENCY`            | 50      | Number of concurrent HTTP workers per load test   |
| `API_BATCH_CHUNK`        | 100     | Resources per batch API call                      |

## Batch Admin API

The test uses the `POST /batch` endpoint to keep admin writes fast at scale. Instead of 12,000 individual HTTP requests per batch (4 resources x 3,000), it sends ~120 batch requests (3,000 / 100 chunks x 4 resource types). Each request is persisted in a single database transaction covering its whole graph, eliminating per-row transaction overhead. Because the request is all-or-nothing, any non-success response means nothing from that request was applied.

Every chunk posts with **`?apply=async`** (issue #4139): the graph commits durably and the gateway answers `202 Accepted` with an `X-Ferrum-Config-Cursor` header instead of paying one synchronous poll-loop reload per chunk (reload time grows with total config size, which pushed the MongoDB leg past its job budget, issue #4136). The harness keeps the highest cursor it saw across the wave and, before each measurement, proves the whole wave live with one blocking `GET /config/apply-status?epoch=E&sequence=S&wait_ms=30000`; a `rejected` or `unverifiable` cursor aborts the run. The data-plane convergence gate (probing sample proxies end to end) then runs as the routability proof. This is the recommended bulk-provisioning recipe for any client doing high-churn admin writes at scale.

## Example Output

```
--- Batch 1/10: creating proxies 0 to 2999 ---
  Created 3000 resources in 0.6s (4972 resources/s)
  Verified proxy /svc/0 is routable

  Running 30-second perf test against 3000 proxies (concurrency=50)...
┌─────────────────────────────────────────────────────────┐
│  Proxies:   3000  │  Duration:  30.0s                   │
├─────────────────────────────────────────────────────────┤
│  Total requests:          644838                       │
│  Successful:              644838                       │
│  Failed:                       0                       │
│  RPS:                    21489.9                       │
├─────────────────────────────────────────────────────────┤
│  Avg latency:           2293 µs (   2.3 ms)            │
│  P50 latency:           2049 µs (   2.0 ms)            │
│  P95 latency:           3949 µs (   3.9 ms)            │
│  P99 latency:           6403 µs (   6.4 ms)            │
│  Max latency:         143004 µs ( 143.0 ms)            │
└─────────────────────────────────────────────────────────┘
```

(Numbers above are from a real run -- actual results depend on hardware.)

## Baseline Results (SQLite, release build, Apple M4)

Run 2026-10-06 at commit `e5c7616` on an Apple M4 (10 cores, 16 GB, macOS
26.6.1): gateway `cargo build --release`, test binary `--profile ci-release`,
5 s warmup + 30 s measured window per wave, 50 workers. Raw JSON:
[`tests/performance/published/2026-10-06-apple-m4/scale-sqlite.json`](../performance/published/2026-10-06-apple-m4/scale-sqlite.json).

| Proxies | RPS | Avg(ms) | P50(ms) | P95(ms) | P99(ms) | Max(ms) | CPU/req(µs) | % Baseline |
|---------|------|---------|---------|---------|---------|---------|-------------|------------|
| 3,000 | 88,874 | 0.6 | 0.5 | 0.8 | 1.0 | 3.3 | 56.5 | 100% |
| 6,000 | 88,355 | 0.6 | 0.5 | 0.8 | 1.0 | 3.2 | 56.3 | 99% |
| 9,000 | 88,229 | 0.6 | 0.5 | 0.8 | 1.0 | 3.7 | 56.9 | 99% |
| 12,000 | 87,465 | 0.6 | 0.6 | 0.8 | 1.0 | 3.3 | 58.0 | 98% |
| 15,000 | 86,972 | 0.6 | 0.6 | 0.9 | 1.0 | 20.8 | 57.5 | 98% |
| 18,000 | 87,024 | 0.6 | 0.6 | 0.9 | 1.0 | 4.3 | 58.3 | 98% |
| 21,000 | 86,967 | 0.6 | 0.6 | 0.9 | 1.0 | 3.2 | 58.6 | 98% |
| 24,000 | 86,762 | 0.6 | 0.6 | 0.9 | 1.1 | 3.2 | 58.5 | 98% |
| 27,000 | 86,663 | 0.6 | 0.6 | 0.9 | 1.1 | 13.9 | 57.9 | 98% |
| 30,000 | 86,736 | 0.6 | 0.6 | 0.9 | 1.0 | 3.0 | 59.0 | 98% |

**2.4% throughput change** from 3k to 30k proxies; 0 failed out of
26,221,987 measured requests. Gateway CPU per authenticated request rose from
56.5 µs to 59.0 µs.

### Historical results (undated, provenance unrecorded)

An earlier undated run recorded ~49k RPS at 3k proxies and 13.8% degradation to
30k. It had no warmup, counted failed requests in RPS, and its commit, host, and test
profile were not recorded, so it is kept only for context:

| Proxies | RPS | Avg(ms) | P50(ms) | P95(ms) | P99(ms) | Max(ms) | % Baseline |
|---------|------|---------|---------|---------|---------|---------|------------|
| 3,000 | 49,236 | 1.0 | 1.0 | 1.5 | 2.0 | 24.9 | 100% |
| 6,000 | 48,788 | 1.0 | 1.0 | 1.5 | 2.1 | 85.0 | 99% |
| 9,000 | 48,892 | 1.0 | 1.0 | 1.5 | 2.1 | 16.6 | 99% |
| 12,000 | 48,448 | 1.0 | 1.0 | 1.5 | 2.1 | 24.0 | 98% |
| 15,000 | 47,562 | 1.0 | 1.0 | 1.6 | 2.3 | 34.0 | 97% |
| 18,000 | 47,324 | 1.0 | 1.0 | 1.6 | 2.2 | 52.0 | 96% |
| 21,000 | 46,656 | 1.1 | 1.0 | 1.6 | 2.3 | 32.0 | 95% |
| 24,000 | 45,612 | 1.1 | 1.0 | 1.7 | 2.4 | 25.6 | 93% |
| 27,000 | 44,363 | 1.1 | 1.0 | 1.7 | 2.5 | 26.2 | 90% |
| 30,000 | 42,434 | 1.2 | 1.1 | 1.9 | 2.8 | 113.2 | 86% |

## Interpreting Results

- **RPS % of baseline**: How current throughput compares to the first batch (3k proxies). Ideally stays above 70%.
- **Latency growth**: Small increases in avg/p50 are expected. Large jumps in p99/max may indicate lock contention or cache rebuild overhead.
- **Failed requests**: Route-miss 404s are convergence signals, not throughput samples: the harness discards one interrupted window and restarts only after convergence is proved again. A second interruption fails loudly as convergence instability. Other request failures remain in the completed window, whose success rate must stay above 50%.
- **Creation speed (resources/s)**: With the batch API, expect 3,000-5,500+ resources/s on SQLite, potentially higher on PostgreSQL. Compare against the baseline of ~5-100/s with individual API calls.
- **Throughput degradation > 70%**: The test prints a warning. This would indicate a scaling issue in the router, plugin cache, or consumer index.
