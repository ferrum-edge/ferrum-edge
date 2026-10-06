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

## How to Run

```bash
# Release build (the harness also runs `cargo build --release` itself and falls
# back to a debug binary with a warning; debug numbers are not meaningful)
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

## Baseline Results (SQLite, release build, Apple Silicon)

Results from a real run on a MacBook, showing proxy hot-path performance as config scales from 3k to 30k. Always use `cargo build --release` for meaningful performance numbers — debug builds have significant overhead from disabled optimizations and extra bounds checking. The echo backend uses hyper with HTTP/1.1 keep-alive, and the test runtime uses `multi_thread` flavor for realistic async throughput.

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

**13.8% throughput degradation** from 3k to 30k proxies, 100% success rate, zero failures. ~49k RPS baseline with 1.0ms P50 latency on a release build.

Batch API creation speed: ~3,200-3,900 resources/s (vs ~5-116/s with individual API calls).

## Interpreting Results

- **RPS % of baseline**: How current throughput compares to the first batch (3k proxies). Ideally stays above 70%.
- **Latency growth**: Small increases in avg/p50 are expected. Large jumps in p99/max may indicate lock contention or cache rebuild overhead.
- **Failed requests**: Route-miss 404s are convergence signals, not throughput samples: the harness discards one interrupted window and restarts only after convergence is proved again. A second interruption fails loudly as convergence instability. Other request failures remain in the completed window, whose success rate must stay above 50%.
- **Creation speed (resources/s)**: With the batch API, expect 3,000-5,500+ resources/s on SQLite, potentially higher on PostgreSQL. Compare against the baseline of ~5-100/s with individual API calls.
- **Throughput degradation > 70%**: The test prints a warning. This would indicate a scaling issue in the router, plugin cache, or consumer index.
