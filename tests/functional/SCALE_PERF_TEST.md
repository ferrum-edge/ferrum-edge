# Scale Performance Test

## Overview

`functional_scale_perf_test.rs` measures how gateway throughput and latency degrade as the number of configured proxies grows from 0 to 30,000. Each proxy is secured with `key_auth` + `access_control` plugins and has a unique consumer, making this a realistic simulation of a large multi-tenant deployment.

## What It Tests

1. **Throughput degradation at scale** -- Does the gateway maintain acceptable RPS as the route table and plugin/consumer indexes grow from 3,000 to 30,000 entries?

2. **Latency distribution at scale** -- How do p50, p95, p99, and max latencies change as config size increases?

3. **Config update resiliency** -- Resources are added between perf runs while the gateway continues serving traffic. The DB poller picks up new config mid-flight, exercising the atomic config swap and incremental cache rebuild paths.

4. **Auth + ACL hot path at scale** -- Every request goes through key_auth (O(1) consumer index lookup) and access_control (consumer allowlist check), verifying these remain fast with 30k consumers in the index.

5. **Batch API throughput** -- The test uses the `POST /batch` endpoint to create resources in bulk (100 at a time), testing transactional batch insert performance across different databases.

## Test Variants

### SQLite (`test_scale_perf_30k_proxies`)

Uses an in-memory SQLite database -- always available, no external dependencies. Good baseline for testing gateway hot-path performance, though SQLite's single-writer lock limits admin API write throughput at scale.

### PostgreSQL (`test_scale_perf_30k_proxies_postgres`)

Uses a PostgreSQL Docker container for realistic production-like write performance. PostgreSQL handles concurrent writes much better than SQLite, so batch creation times should be significantly faster.

**Prerequisite**: Start the PostgreSQL container:

```bash
docker run -d --name ferrum-scale-test-pg \
  -e POSTGRES_USER=ferrum \
  -e POSTGRES_PASSWORD=ferrum-scale-test \
  -e POSTGRES_DB=ferrum_scale \
  -p 25432:5432 postgres:16
```

The test automatically skips if the container isn't running.

## Test Structure

The test runs in 10 batches. Each batch:

1. Creates 3,000 resources via the **batch admin API** (`POST /batch`):
   - 3,000 consumers (with unique `keyauth` API keys), sent in chunks of 100
   - 3,000 proxies (unique listen paths `/svc/0` through `/svc/29999`), sent in chunks of 100
   - 6,000 plugin configs (key_auth + access_control per proxy), sent in chunks of 100
   - All proxies route to the same echo backend
2. Waits for the DB poller to load the new config
3. Verifies a sample proxy is routable with its consumer's key
4. Runs a **30-second load test** with 50 concurrent workers hitting all accumulated proxies round-robin, each request authenticated with the correct API key

After all 10 batches, a summary table is printed comparing RPS and latency percentiles across each scale point (3k, 6k, 9k, ... 30k).

## How to Run

```bash
# Build the gateway binary first
cargo build

# SQLite variant (no external dependencies)
cargo test --test functional_tests test_scale_perf_30k_proxies \
  --all-features -- --ignored --nocapture

# PostgreSQL variant (requires Docker container above)
cargo test --test functional_tests test_scale_perf_30k_proxies_postgres \
  --all-features -- --ignored --nocapture
```

The `--nocapture` flag is important -- without it you won't see the progress output or the results table.

## Configuration

Constants at the top of the test file control the test parameters:

| Constant                 | Default | Description                                      |
|--------------------------|---------|--------------------------------------------------|
| `BATCH_SIZE`             | 3,000   | Proxies/consumers/plugins created per batch       |
| `TOTAL_PROXIES`          | 30,000  | Total proxies to create (must be multiple of batch size) |
| `PERF_TEST_DURATION_SECS`| 30      | Seconds each load test runs                       |
| `CONCURRENCY`            | 50      | Number of concurrent HTTP workers per load test   |
| `API_BATCH_CHUNK`        | 100     | Resources per batch API call                      |

## Batch Admin API

The test uses the `POST /batch` endpoint introduced to improve admin write throughput at scale. Instead of 12,000 individual HTTP requests per batch (4 resources x 3,000), it sends ~120 batch requests (3,000 / 100 chunks x 4 resource types). Each batch is persisted in a single database transaction, eliminating per-row transaction overhead.

## Example Output

```
--- Batch 1/10: creating proxies 0 to 2999 ---
  Created 3000 resources in 4.2s (714 resources/s)
  Verified proxy /svc/0 is routable

  Running 30-second perf test against 3000 proxies (concurrency=50)...
┌─────────────────────────────────────────────────────────┐
│  Proxies:   3000  │  Duration:  30.0s                   │
├─────────────────────────────────────────────────────────┤
│  Total requests:           256000                      │
│  Successful:               256000                      │
│  Failed:                       0                       │
│  RPS:                      8533.3                       │
├─────────────────────────────────────────────────────────┤
│  Avg latency:          5800 µs (   5.8 ms)            │
│  P50 latency:          5450 µs (   5.5 ms)            │
│  P95 latency:          6900 µs (   6.9 ms)            │
│  P99 latency:         10600 µs (  10.6 ms)            │
│  Max latency:        110000 µs ( 110.0 ms)            │
└─────────────────────────────────────────────────────────┘
```

(Numbers above are illustrative -- actual results depend on hardware.)

## Baseline Results (SQLite, debug build, Apple Silicon)

Results from a real run on a MacBook (2026-03-28), showing proxy hot-path performance as config scales from 3k to 30k:

| Proxies | RPS | Avg(ms) | P50(ms) | P95(ms) | P99(ms) | Max(ms) | % Baseline |
|---------|-----|---------|---------|---------|---------|---------|------------|
| 3,000 | 7,168 | 7.0 | 6.5 | 8.8 | 14.3 | 101.0 | 100% |
| 6,000 | 7,238 | 6.9 | 6.4 | 8.6 | 14.3 | 117.1 | 101% |
| 9,000 | 6,680 | 7.5 | 6.8 | 10.5 | 21.6 | 107.9 | 93% |
| 12,000 | 6,964 | 7.2 | 6.6 | 9.5 | 14.1 | 106.8 | 97% |
| 15,000 | 6,842 | 7.3 | 6.7 | 9.9 | 14.8 | 65.4 | 95% |
| 18,000 | 6,445 | 7.8 | 7.1 | 10.9 | 16.1 | 95.6 | 90% |
| 21,000 | 5,975 | 8.4 | 7.5 | 13.0 | 24.4 | 96.2 | 83% |
| 24,000 | 5,962 | 8.4 | 7.7 | 12.0 | 24.9 | 80.2 | 83% |
| 27,000 | 6,253 | 8.0 | 7.4 | 10.9 | 17.7 | 103.5 | 87% |
| 30,000 | 6,264 | 8.0 | 7.4 | 10.7 | 17.6 | 93.5 | 87% |

**12.6% throughput degradation** from 3k to 30k proxies, 100% success rate, zero failures. Consistent RPS across all batches with no cold-start anomalies.

Batch API creation speed: ~5,300-5,500 resources/s (vs ~5-116/s with individual API calls).

## Interpreting Results

- **RPS % of baseline**: How current throughput compares to the first batch (3k proxies). Ideally stays above 70%.
- **Latency growth**: Small increases in avg/p50 are expected. Large jumps in p99/max may indicate lock contention or cache rebuild overhead.
- **Failed requests**: A small number of failures during config reloads is acceptable. The test asserts success rate stays above 50% (a very conservative floor).
- **Creation speed (resources/s)**: With the batch API, expect 3,000-5,500+ resources/s on SQLite, potentially higher on PostgreSQL. Compare against the baseline of ~5-100/s with individual API calls.
- **Throughput degradation > 70%**: The test prints a warning. This would indicate a scaling issue in the router, plugin cache, or consumer index.
