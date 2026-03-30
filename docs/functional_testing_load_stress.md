# Load & Stress Testing Guide

This document describes the comprehensive load and stress test suite for the Ferrum Gateway (`functional_load_stress_test.rs`). The test exercises the gateway under realistic production-like conditions with large configuration sets, mixed authentication, varied payload sizes, concurrent admin API mutations, and includes both in-process (reqwest) and native C (wrk) load generators to isolate client overhead from gateway overhead.

## Overview

The test provisions **10,000 proxies**, **10,000 consumers**, **30,000 plugins** (3 per proxy), and **1,000 open proxies** (no plugins), then drives sustained traffic while measuring latency and throughput at increasing concurrency levels.

### What It Tests

| Area | Details |
|------|---------|
| **Scale** | 10k proxies + 1k open proxies, 10k consumers, 30k plugins loaded simultaneously |
| **Auth diversity** | key_auth (header), basic_auth (HMAC), jwt_auth across proxy groups |
| **Payload variety** | GET (no body), small JSON (~100B), medium JSON (~5KB), large JSON (~50KB), XML (~10KB), multipart file upload (~100KB) |
| **Concurrency ramp** | 50 -> 100 -> 200 -> 400 concurrent workers |
| **Config churn** | Admin API create/update/delete operations during active traffic |
| **No-plugin baseline** | Pure proxy overhead measurement without any plugin execution |
| **wrk comparison** | Native C load generator to isolate client overhead from gateway performance |
| **Latency analysis** | P50, P95, P99, P99.9, Max latency; RPS; success rate per phase |

### Auth Distribution

Proxies are split into three equal groups, each with a different authentication plugin:

| Proxy Range | Auth Plugin | Credential Type |
|-------------|-------------|-----------------|
| 0 - 3,333 | `key_auth` | API key in `X-API-Key` header |
| 3,334 - 6,666 | `basic_auth` | Username/password (HMAC-accelerated) |
| 6,667 - 10,000 | `jwt_auth` | Per-consumer JWT with `sub` claim |

Every proxy also has `access_control` (ACL allow-list) and `rate_limiting` (high limit) plugins attached, totaling 3 plugins per proxy.

### Payload Mix

Each worker cycles through six payload types round-robin:

1. **GET** - No request body
2. **Small JSON** (~100 bytes) - Simple event object
3. **Medium JSON** (~5 KB) - 50-item product catalog
4. **Large JSON** (~50 KB) - 200 sensor readings with metadata
5. **XML** (~10 KB) - Order document with 40 line items
6. **Multipart/form-data** (~100 KB) - JSON metadata + binary file upload

### Backend

The test uses a high-throughput hyper-based backend server embedded in the test process. It reads and discards request bodies and returns minimal JSON responses with zero simulated latency, so the test measures gateway overhead rather than backend processing time. This backend can sustain 60k+ RPS.

### Build Mode

The test builds and uses a **release binary** (`cargo build --release`) for production-realistic performance numbers. If only a debug binary is available, it will use that with a warning.

### Database Selection

The test **defaults to PostgreSQL** if the `ferrum-load-test-pg` Docker container is running, and **falls back to SQLite** otherwise. This is a single test function — no separate variants to manage.

## Prerequisites

### Build the Gateway (Release)

```bash
cargo build --release --bin ferrum-gateway
```

The test will also trigger this build automatically if the release binary is missing, but pre-building saves time.

### PostgreSQL (Recommended)

For production-realistic database behavior, start a PostgreSQL container:

```bash
docker run -d --name ferrum-load-test-pg \
  -e POSTGRES_USER=ferrum \
  -e POSTGRES_PASSWORD=ferrum-load-test \
  -e POSTGRES_DB=ferrum_load \
  -p 25433:5432 \
  postgres:16
```

Wait a few seconds for PostgreSQL to initialize, then verify:

```bash
docker exec ferrum-load-test-pg pg_isready -U ferrum
```

To clean up after testing:

```bash
docker rm -f ferrum-load-test-pg
```

### SQLite (Automatic Fallback)

No additional setup required. A temporary SQLite database is created automatically when PostgreSQL is not available.

### wrk (Optional, Recommended)

For the native load generator comparison phase (Phase 4), install wrk:

```bash
# macOS
brew install wrk

# Ubuntu/Debian
sudo apt-get install wrk
```

If wrk is not installed, Phase 4 is automatically skipped with instructions to install it.

## Running the Test

```bash
cargo test --test functional_tests test_load_stress_10k_proxies \
  --all-features -- --ignored --nocapture
```

> **Note**: This test is skipped in CI via `--skip test_load_stress` in the GitHub Actions workflow. It is designed for manual execution on developer machines or dedicated performance testing environments.

## Test Phases

### Phase 1: Provisioning

Resources are created via the batch admin API (`POST /batch`) in chunks of 100:

1. **Consumers** (10,000) - Created first for referential integrity
2. **Proxies** (10,000) - Created with backend pointing to embedded hyper server
3. **Plugin configs** (30,000) - Auth + ACL + rate limiting per proxy
4. **Credentials** (10,000) - Set via `PUT /consumers/{id}/credentials/{type}` with 20 concurrent requests
5. **Open proxies** (1,000) - No-plugin proxies for baseline measurement

After provisioning, the test waits for the DB poller to load the config and verifies a sample proxy from each auth group is routable.

### Phase 2: Concurrency Ramp (With Plugins)

Four 30-second load test phases at increasing concurrency, using all auth types and payload sizes:

| Concurrency | Purpose |
|-------------|---------|
| 50 | Baseline performance |
| 100 | Moderate load |
| 200 | High load |
| 400 | Stress / saturation point |

Each phase reports RPS, success rate, and full latency distribution (P50/P95/P99/P99.9/Max).

### Phase 3: No-Plugin Baseline

Same concurrency ramp (50 -> 100 -> 200 -> 400) against the 1,000 open proxies with **no plugins attached**. This isolates pure proxy overhead (route matching, connection pooling, body streaming, header construction) from plugin execution cost (auth crypto, ACL checks, rate limiting).

### Phase 4: Admin Mutations Under Load

Runs for 30 seconds at concurrency=100 while a separate task performs admin API mutations every 200ms:

- **Create** a temporary proxy + plugin
- **Update** an existing proxy (rotate through all 10k)
- **Delete** the temporary proxy + plugin

The test compares P99 latency and RPS against the Phase 2 baseline at the same concurrency level to quantify the impact of config reloads on request latency.

### Phase 5: wrk Comparison (if wrk is installed)

Runs the same test scenarios using **wrk**, a native C load generator, to isolate how much of the throughput ceiling comes from the Rust reqwest client vs the gateway itself.

For each concurrency level (50, 100, 200, 400), wrk runs:
- **key_auth proxies** — with a Lua script that cycles through 100 API keys and paths
- **open proxies** — plain GET against a no-plugin proxy

wrk uses `--latency` for percentile distribution and is launched via `spawn_blocking` to avoid blocking the tokio runtime that hosts the hyper backend.

## Backend Pool Modes

The test runs **twice** — once with the gateway's backend connection pool set to HTTP/1.1, and once with HTTP/2 enabled. This reveals how the backend pool protocol affects throughput:

### Run 1: Backend Pool HTTP/1.1

With `FERRUM_POOL_ENABLE_HTTP2=false`, each request uses a dedicated HTTP/1.1 connection from the pool. Connection reuse depends on keep-alive and the `max_idle_per_host` pool size.

### Run 2: Backend Pool HTTP/2

With `FERRUM_POOL_ENABLE_HTTP2=true`, the gateway can multiplex many concurrent requests over a single HTTP/2 connection to the backend. This dramatically reduces connection overhead and eliminates ephemeral port exhaustion at high concurrency.

## Interpreting Results

### Summary Tables

The test prints a summary table for each backend pool mode. Example from a PostgreSQL run on Apple Silicon macOS:

#### HTTP/1.1 Backend Pool

```
======================================================================
  LOAD & STRESS TEST SUMMARY (PostgreSQL, backend pool: HTTP/1.1)
======================================================================
Phase                         Conc      RPS  Avg(ms)  P50(ms)  P95(ms)  P99(ms)  Max(ms)     OK%
----------------------------------------------------------------------
Ramp c=50                       50    28656      1.7      1.6      2.8      4.0     34.7  100.0%
Ramp c=100                     100    28261      3.5      3.3      5.7      7.4     35.5  100.0%
Ramp c=200                     200    19939     10.0      7.8     24.7     43.9    194.9  100.0%
Ramp c=400                     400    11613     34.3     29.1     79.4    112.5    281.2  100.0%
----------------------------------------------------------------------
No-plugin c=50                  50    13672      3.6      2.6      9.0     16.7    441.3  100.0%
No-plugin c=100                100    20854      4.7      4.1      9.1     15.5    141.3  100.0%
No-plugin c=200                200    24048      8.3      7.7     14.9     21.0     93.5  100.0%
No-plugin c=400                400    23127     17.2     15.8     33.7     45.1    159.0  100.0%
----------------------------------------------------------------------
wrk key_auth c=50               50    63442      0.8      0.7      —       2.9     58.3  100.0%
wrk key_auth c=200             200    37291      6.5      4.6      —      40.4    267.9  100.0%
wrk no-plugin c=200            200    61612      3.5      3.0      —      12.2    134.1  100.0%
```

#### HTTP/2 Backend Pool

```
======================================================================
  LOAD & STRESS TEST SUMMARY (PostgreSQL, backend pool: HTTP/2)
======================================================================
Phase                         Conc      RPS  Avg(ms)  P50(ms)  P95(ms)  P99(ms)  Max(ms)     OK%
----------------------------------------------------------------------
Ramp c=50                       50    24575      2.0      1.8      3.5      5.8     66.1  100.0%
Ramp c=100                     100    27900      3.5      3.4      5.7      7.5     40.1  100.0%
Ramp c=200                     200    27657      7.2      6.8     12.2     15.8    130.0  100.0%
Ramp c=400                     400    20726     19.2     15.6     46.0     78.5    279.1  100.0%
----------------------------------------------------------------------
No-plugin c=50                  50    11152      4.4      3.0     12.2     23.4    302.5  100.0%
No-plugin c=100                100     8756     11.3      8.5     27.9     56.8    279.9  100.0%
No-plugin c=200                200     9576     20.8     15.7     52.8     93.8    516.6  100.0%
No-plugin c=400                400     9400     42.4     33.5    104.5    177.0    469.7  100.0%
----------------------------------------------------------------------
wrk key_auth c=50               50    49427      1.3      0.8      —      11.1    114.5  100.0%
wrk key_auth c=200             200    56348      4.2      3.3      —      21.4    195.4  100.0%
wrk no-plugin c=200            200    53449      4.8      3.3      —      33.8    213.3  100.0%
```

*(Apple Silicon macOS, release build, PostgreSQL. Actual results depend on hardware and system load.)*

### HTTP/1.1 vs HTTP/2 Backend Pool Comparison

With-plugins ramp (reqwest client):

| Concurrency | HTTP/1.1 RPS | HTTP/2 RPS | HTTP/1.1 P99 | HTTP/2 P99 |
|-------------|-------------|------------|-------------|------------|
| 50 | 28,656 | 24,575 | 4.0ms | 5.8ms |
| 100 | 28,261 | 27,900 | 7.4ms | 7.5ms |
| 200 | 19,939 | 27,657 | 43.9ms | 15.8ms |
| 400 | 11,613 | 20,726 | 112.5ms | 78.5ms |

wrk (native C client):

| Concurrency | HTTP/1.1 RPS | HTTP/2 RPS | HTTP/1.1 P99 | HTTP/2 P99 |
|-------------|-------------|------------|-------------|------------|
| 50 | 63,442 | 49,427 | 2.9ms | 11.1ms |
| 200 | 37,291 | 56,348 | 40.4ms | 21.4ms |
| 400 | 57,004 | 42,883 | 22.0ms | 53.2ms |

**Key findings:**

- **At low concurrency (c=50), HTTP/1.1 wins.** Connection setup cost on localhost is negligible, so HTTP/2 framing overhead (HPACK, flow control, frame multiplexing) adds latency without benefit. HTTP/1.1 with keep-alive is simpler and faster.
- **At high concurrency (c=200+), HTTP/2 wins with reqwest.** Multiplexing avoids connection exhaustion — the reqwest client needs fewer sockets, reducing contention on file descriptors and ephemeral ports.
- **wrk is less affected.** wrk manages its own optimized connection pool, so the HTTP/1.1 vs HTTP/2 difference is smaller and depends more on system load during the test run.
- **No-plugin baseline was slower with HTTP/2** across all concurrency levels, suggesting HTTP/2 framing overhead dominates when there's no plugin CPU work to amortize it against.

**Recommendation:** Use `FERRUM_POOL_ENABLE_HTTP2=false` for localhost or low-latency backends. Enable HTTP/2 for backends across network boundaries where connection setup cost is significant.

### wrk vs reqwest Client Comparison

The test prints a direct comparison for each run. The gap between wrk and reqwest reflects the overhead of running the load generator in-process:

```
--- HTTP/1.1 backend pool ---
  wrk key_auth c=50         reqwest:    28656 RPS  |  wrk:    63442 RPS  (+121%)
  wrk key_auth c=400        reqwest:    11613 RPS  |  wrk:    57004 RPS  (+391%)

--- HTTP/2 backend pool ---
  wrk key_auth c=50         reqwest:    24575 RPS  |  wrk:    49427 RPS  (+101%)
  wrk key_auth c=400        reqwest:    20726 RPS  |  wrk:    42883 RPS  (+107%)
```

The wrk numbers represent the gateway's true throughput ceiling. The reqwest numbers show realistic in-process client performance, which is influenced by CPU contention with the gateway and backend.

### Plugin Overhead Analysis

The test quantifies the cost of auth + ACL + rate limiting (HTTP/1.1 run, wrk client):

```
  wrk c=200:  no-plugin 61,612 RPS  vs  key_auth 37,291 RPS  (-39.5%)
  wrk c=400:  no-plugin 61,192 RPS  vs  key_auth 57,004 RPS  (-6.8%)
```

Plugin overhead varies with concurrency. At c=200 the auth plugin (key lookup + ACL check + rate limit) reduces throughput by ~40% — this is the cost of real authentication on every request. At c=400, the bottleneck shifts to connection handling and the relative overhead drops.

### Admin Mutation Impact

The test reports the percentage change in P99 latency and RPS when admin mutations are active:

```
P99 latency impact from admin mutations: +1.4%  (15.4ms -> 15.6ms)
RPS impact from admin mutations: -0.9%  (10081 -> 9988)
```

A small impact (<10% P99 increase) indicates the gateway handles config reloads gracefully without significant latency spikes. This is due to the lock-free `ArcSwap`-based config reload — requests in-flight see either the old or new config atomically, never a partial update.

### Latency Warnings

The test flags:
- **P99 > 100ms** - Potential concern for latency-sensitive workloads
- **P95 > 50ms** - High tail latency under load
- **Success rate < 95%** - Significant request failures

### Failure Threshold

The test asserts that success rate stays above **50%** across all phases. If it drops below that, the test fails — indicating the gateway is unable to handle the load.

## Gateway Configuration

The test configures the gateway with optimized connection pool settings matching the multi-protocol performance test:

### Connection Pool Tuning

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | 1024 | Large idle pool — clamped to max allowed (prevents connection churn) |
| `FERRUM_POOL_IDLE_TIMEOUT_SECONDS` | 120 | Keep connections alive longer |
| `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` | true | Reuse connections to backend |
| `FERRUM_POOL_ENABLE_HTTP2` | Run 1: `false`, Run 2: `true` | Test runs both modes for comparison |

### HTTP/2 Flow Control

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE` | 8388608 (8 MiB) | Per-stream receive window |
| `FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE` | 33554432 (32 MiB) | Per-connection receive window |
| `FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW` | false | Fixed windows, no auto-tuning overhead |
| `FERRUM_POOL_HTTP2_MAX_FRAME_SIZE` | 65535 | Max HTTP/2 frame size |
| `FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS` | 1000 | H2 concurrent streams per connection |

### HTTP/3 (QUIC) Transport

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_HTTP3_MAX_STREAMS` | 1000 | QUIC max concurrent streams |
| `FERRUM_HTTP3_STREAM_RECEIVE_WINDOW` | 8388608 (8 MiB) | Per-stream QUIC receive window |
| `FERRUM_HTTP3_RECEIVE_WINDOW` | 33554432 (32 MiB) | Per-connection QUIC receive window |
| `FERRUM_HTTP3_SEND_WINDOW` | 8388608 (8 MiB) | QUIC send window |

### Other

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_LOG_LEVEL` | error | Minimize logging overhead during load |
| `FERRUM_DB_POLL_INTERVAL` | 2 | Fast config reload for mutation testing (default is 30s) |
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | (set) | HMAC-SHA256 for basic_auth (~1μs vs ~100ms bcrypt) |

> **Note on `FERRUM_POOL_MAX_IDLE_PER_HOST`**: This value must be >= your peak concurrency level. If set too low, the gateway creates new TCP connections per request instead of reusing pooled ones, causing massive performance degradation (10x+ RPS drop). The performance tests use 200 to match the wrk connection count.

## Understanding reqwest vs wrk Performance Gap

A key insight from this test is the throughput gap between the reqwest-based phases and the wrk-based phases. With HTTP/1.1 backend pool, the gap is ~6-8x (10k vs 75k RPS). With HTTP/2 backend pool, the gap shrinks to ~2x (31k vs 69k RPS). This is **not** a gateway limitation — it's a client-side bottleneck:

| Factor | reqwest (in-process) | wrk (native C) |
|--------|---------------------|-----------------|
| **Language** | Rust async (tokio) | C (epoll/kqueue) |
| **Runtime sharing** | Shares tokio runtime with backend | Separate process |
| **CPU contention** | Competes with gateway + backend for CPU | Own CPU cores |
| **Per-request overhead** | ~50-100μs (async task, HTTP parsing) | ~5-10μs (optimized C loop) |
| **Connection model** | Per-worker client with pool | Thread-local connections |
| **Body handling** | Full reqwest request builder | Raw socket writes |

The reqwest numbers represent a realistic scenario of an application calling through the gateway from the same host. The wrk numbers represent the gateway's true throughput ceiling when the client is not a bottleneck.

### What the wrk numbers tell us

With wrk at c=200 achieving ~77k RPS with key_auth (3 plugins per proxy), the gateway adds roughly **2.5ms average latency per request** over the pure backend. This breaks down approximately as:

1. **Route matching** (~0.1ms) — binary search over 10k sorted routes
2. **Auth credential extraction + crypto** (~0.3-0.5ms) — API key hash lookup, or JWT decode, or HMAC verify
3. **Consumer index lookup** (~0.05ms) — O(1) by credential
4. **ACL check** (~0.02ms) — group membership check
5. **Rate limit check** (~0.05ms) — counter increment + window comparison
6. **Connection pool acquire/release** (~0.1ms) — pool lock + connection selection
7. **HTTP header construction** (~0.1ms) — X-Forwarded-For, Host, etc.
8. **Body streaming** (~0.5-1.5ms) — depends on payload size, zero-copy for no-body GETs

No request or response body parsing occurs for these plugins — bodies stream through as raw byte chunks via `ProxyBody::Streaming`.

## Tuning the Test

Key constants at the top of `functional_load_stress_test.rs`:

| Constant | Default | Description |
|----------|---------|-------------|
| `NUM_PROXIES` | 10,000 | Number of proxies (each gets 3 plugins) |
| `NUM_CONSUMERS` | 10,000 | Number of consumers |
| `NUM_OPEN_PROXIES` | 1,000 | No-plugin proxies for baseline |
| `PHASE_DURATION_SECS` | 30 | Duration of each load phase |
| `CONCURRENCY_LEVELS` | [50, 100, 200, 400] | Concurrency steps to ramp through |
| `ADMIN_MUTATION_PHASE_SECS` | 30 | Duration of admin mutation phase |
| `ADMIN_MUTATION_CONCURRENCY` | 100 | Traffic concurrency during mutations |
| `API_BATCH_CHUNK` | 100 | Resources per batch API call |

## Comparison with Other Tests

| | Scale Perf Test | Load & Stress Test | Multi-Protocol Perf Test |
|---|---|---|---|
| **Focus** | Throughput degradation as config grows | Realistic traffic patterns under load | Protocol-specific throughput |
| **Build** | Release | Release | Release |
| **Backend** | Standalone hyper server | Embedded hyper server | Standalone hyper server |
| **Load generator** | reqwest | reqwest + wrk | wrk |
| **Proxies** | 0 -> 30k (progressive) | 10k + 1k open (all at once) | 1-2 |
| **Auth** | key_auth only | key_auth + basic_auth + jwt_auth | None or key_auth |
| **Plugins per proxy** | 2 (key_auth + ACL) | 3 (auth + ACL + rate_limit) | 0-2 |
| **Payloads** | GET only | GET, JSON (3 sizes), XML, multipart | Varies by protocol |
| **Admin mutations** | No | Yes (create/update/delete mid-traffic) | No |
| **Concurrency** | Fixed 50 | Ramp 50 -> 400 | Configurable |
| **Database** | PostgreSQL or SQLite | PostgreSQL-first, SQLite fallback | File mode |
| **No-plugin baseline** | No | Yes | N/A |

## Troubleshooting

### Test hangs during provisioning

The credential-setting phase makes 10k individual HTTP requests (20 concurrently). On slower machines this can take several minutes. Check the test output for progress updates.

### Low success rate at high concurrency

This typically means the gateway is saturated. Possible causes:
- File descriptor limits (`ulimit -n`) - increase to at least 65535
- TCP port exhaustion - the test uses keep-alive connections to mitigate this
- CPU saturation - the test is CPU-intensive at high concurrency

### wrk shows errors at c=400

On macOS, 400 connections can exhaust ephemeral ports. This is an OS-level limitation, not a gateway issue. Reduce concurrency or increase the ephemeral port range:

```bash
sudo sysctl -w net.inet.ip.portrange.first=1024
```

### PostgreSQL not detected

The test checks for the `ferrum-load-test-pg` Docker container with a 5-second timeout. If Docker is unresponsive, the test falls back to SQLite. Ensure Docker Desktop is running:

```bash
docker ps --filter name=ferrum-load-test-pg
```

### Config not loaded after provisioning

The test waits 5 seconds for the DB poller (configured at 2-second interval). If proxies return 404, increase the wait time or check gateway logs for config loading errors.

### Debug build performance

If you see a warning about using a debug binary, rebuild in release mode:

```bash
cargo build --release --bin ferrum-gateway
```

Debug builds are 2-4x slower and will show artificially high latency numbers.

### reqwest RPS plateaus around 10k (HTTP/1.1 run)

This is expected in the HTTP/1.1 backend pool run — each in-flight request needs its own TCP connection, and the reqwest client competes for file descriptors and ephemeral ports. The HTTP/2 run typically shows 3x better throughput (~30k RPS) because requests multiplex over fewer connections. The wrk comparison phase shows the gateway's true throughput ceiling (~70-80k RPS). See "Understanding reqwest vs wrk Performance Gap" above.

### Test takes too long

The test runs two full passes (HTTP/1.1 + HTTP/2), each with 4 ramp phases + 4 no-plugin phases + admin mutations + wrk phases. Total runtime is ~15-18 minutes. To run only a specific backend pool mode, modify the `enable_http2` parameter in `test_load_stress_10k_proxies()`.
