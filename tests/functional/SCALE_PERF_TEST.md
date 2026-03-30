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

## Baseline Results (SQLite, debug build, Apple Silicon)

Results from a real run on a MacBook (2026-03-30), showing proxy hot-path performance as config scales from 3k to 30k. The echo backend uses hyper with HTTP/1.1 keep-alive, and the test runtime uses `multi_thread` flavor for realistic async throughput.

| Proxies | RPS | Avg(ms) | P50(ms) | P95(ms) | P99(ms) | Max(ms) | % Baseline |
|---------|------|---------|---------|---------|---------|---------|------------|
| 3,000 | 21,490 | 2.3 | 2.0 | 3.9 | 6.4 | 143.0 | 100% |
| 6,000 | 22,458 | 2.2 | 2.0 | 3.6 | 5.1 | 94.1 | 105% |
| 9,000 | 22,713 | 2.2 | 2.0 | 3.6 | 6.1 | 101.5 | 106% |
| 12,000 | 20,966 | 2.4 | 2.2 | 3.7 | 5.5 | 81.9 | 98% |
| 15,000 | 17,262 | 2.9 | 2.6 | 4.8 | 8.1 | 247.7 | 80% |
| 18,000 | 17,690 | 2.8 | 2.6 | 4.6 | 6.8 | 99.3 | 82% |
| 21,000 | 16,722 | 3.0 | 2.8 | 4.8 | 6.5 | 90.8 | 78% |
| 24,000 | 15,396 | 3.2 | 3.0 | 5.3 | 7.2 | 97.5 | 72% |
| 27,000 | 13,127 | 3.8 | 3.5 | 6.3 | 8.6 | 102.5 | 61% |
| 30,000 | 13,715 | 3.6 | 3.4 | 6.1 | 8.0 | 98.3 | 64% |

**36.2% throughput degradation** from 3k to 30k proxies, 100% success rate, zero failures. ~21k RPS baseline with 2ms P50 latency on a debug build.

Batch API creation speed: ~3,000-5,300 resources/s (vs ~5-116/s with individual API calls).

## Interpreting Results

- **RPS % of baseline**: How current throughput compares to the first batch (3k proxies). Ideally stays above 70%.
- **Latency growth**: Small increases in avg/p50 are expected. Large jumps in p99/max may indicate lock contention or cache rebuild overhead.
- **Failed requests**: A small number of failures during config reloads is acceptable. The test asserts success rate stays above 50% (a very conservative floor).
- **Creation speed (resources/s)**: With the batch API, expect 3,000-5,500+ resources/s on SQLite, potentially higher on PostgreSQL. Compare against the baseline of ~5-100/s with individual API calls.
- **Throughput degradation > 70%**: The test prints a warning. This would indicate a scaling issue in the router, plugin cache, or consumer index.
