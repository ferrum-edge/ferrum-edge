# Load & Stress Testing Guide

This document describes the load and stress test in `tests/functional/functional_load_stress_test.rs`. It drives the gateway with a large configuration, mixed authentication, varied payload sizes, and concurrent admin API mutations, using both an in-process (reqwest) and a native C (wrk) load generator to separate client overhead from gateway overhead.

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
| **Latency analysis** | P50, P95, P99, P99.9, Max latency; RPS; success rate per phase (see [Measurement Boundary](#measurement-boundary)) |

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

The test runs `cargo build --release --bin ferrum-edge` before starting and uses the release binary for production-realistic numbers. If only a debug binary exists, it uses that with a warning.

### Database Selection

The test **defaults to PostgreSQL** if the `ferrum-load-test-pg` Docker container is running, and **falls back to SQLite** otherwise. Both cases run from the single test function.

## Prerequisites

### Build the Gateway (Release)

```bash
cargo build --release --bin ferrum-edge
```

The test always runs this build first; pre-building makes that step a quick no-op.

### PostgreSQL (Recommended)

For production-realistic database behavior, start a PostgreSQL container:

```bash
docker run -d --name ferrum-load-test-pg \
  -e POSTGRES_USER=ferrum \
  -e POSTGRES_PASSWORD=ferrum-load-test \
  -e POSTGRES_DB=ferrum_load \
  -p 127.0.0.1:25433:5432 \
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

For the native load generator comparison (Phase 4), install wrk:

```bash
# macOS
brew install wrk

# Ubuntu/Debian
sudo apt-get install wrk
```

If wrk is not installed, Phase 4 is automatically skipped with instructions to install it. Once wrk is found, every Phase 4 run must produce a result (see [Failure Threshold](#failure-threshold)). The scheduled `scaling-regression.yml` workflow installs wrk, so Phase 4 always runs there.

## Running the Test

```bash
cargo test --test functional_tests test_load_stress_10k_proxies -- --ignored --nocapture
```

Do not add `--all-features`: the `crypto-ring` and `fips` features are mutually exclusive.

> **Note**: PR CI excludes this test (the `ci.yml` nextest filter `not test(/test_load_stress_10k_proxies/)`). It runs weekly against PostgreSQL in the scheduled `.github/workflows/scaling-regression.yml` workflow, and can be run manually on developer machines or dedicated performance environments.

## Test Phases

Phase numbers match the test's console output.

### Provisioning

Resources are created via the batch admin API (`POST /batch?apply=async`, issue #4139) in chunks of 100. Each chunk commits durably and answers `202 Accepted` with an `X-Ferrum-Config-Cursor`, so no chunk waits for a synchronous reload. The harness then makes one blocking `GET /config/apply-status` call on the highest cursor to prove the whole graph is live:

1. **Consumers** (10,000) - Created first for referential integrity, with their credentials inline in the same batch (issue #4116)
2. **Proxies** (10,000) - Backend points at the embedded hyper server
3. **Plugin configs** (30,000) - Auth + ACL + rate limiting per proxy
4. **Open proxies** (1,000) - No-plugin proxies for baseline measurement

After the apply cursor is live, bounded convergence gates (up to 5 minutes) confirm sample proxies from each auth group and the open-proxy set are routable.

### Phase 1: Concurrency Ramp (With Plugins)

Four 30-second load test phases at increasing concurrency, using all auth types and payload sizes:

| Concurrency | Purpose |
|-------------|---------|
| 50 | Baseline performance |
| 100 | Moderate load |
| 200 | High load |
| 400 | Stress / saturation point |

Each phase reports attempt RPS, 2xx-status success rate, and a response-head latency distribution (P50/P95/P99/P99.9/Max). See [Measurement Boundary](#measurement-boundary).

### Phase 2: No-Plugin Baseline

Same concurrency ramp (50 -> 100 -> 200 -> 400) against the 1,000 open proxies with **no plugins attached**. Comparing it with Phase 1 separates plugin execution cost (auth crypto, ACL checks, rate limiting) from the rest of the request path up to the response head (route matching, connection pooling, request forwarding, header construction). The reqwest client never reads the response body, so neither phase measures response-body streaming or end-of-body latency, and the comparison is not an isolated gateway-overhead figure: the in-process client shares the host and CPU with the gateway and backend.

### Measurement Boundary

The reqwest phases (1, 2, and the traffic in 3) measure the following:

- **Latency** runs from request start until reqwest's `send()` completes, that is, until the response head arrives. The response body is dropped without being read.
- **Success** means a 2xx response status. A body error after a 2xx head cannot turn a recorded success into a failure.
- **RPS** is attempts (successes and failures) divided by wall-clock time. Latency samples include failed attempts.

The console labels these as `Attempt RPS`, `Response-head latency`, and `2xx-status success rate`. wrk rows (Phase 4) show wrk's own `Requests/sec` and latency figures; their failures are wrk's non-2xx/3xx responses plus socket errors.

### Phase 3: Admin Mutations Under Load

Runs for 30 seconds at concurrency=100 while a separate task runs admin API mutation cycles, pausing 200ms between cycles:

- **Create** a temporary proxy (`POST /proxies`, expects `201`) and a plugin on it (`POST /plugins/config`, expects `201`)
- **Update** an existing proxy, rotating through all 10k (`PUT /proxies/{id}`, expects `200`)
- **Delete** the temporary plugin (`DELETE /plugins/config/{id}`, expects `204`) and proxy (`DELETE /proxies/{id}`, expects `204`)

The writes use the default `?apply=sync` mode, so each documented success status means a covering config generation was already live on the gateway when it answered. Every write is classified against its expected status as accepted, rejected (any other HTTP status, including other 2xx codes), or transport-failed (no response, including the 30-second client timeout). Only accepted writes count as successful, and only their latencies feed the per-operation averages. The phase prints attempted/accepted/rejected/transport-failed counts per operation, the number of cycles in which all five writes were accepted, and up to 10 failure diagnostics (status plus a response-body excerpt, or the transport error).

The test compares P99 latency and attempt RPS against the Phase 1 ramp result at the same concurrency level to estimate the impact of config reloads on response-head latency.

### Phase 4: wrk Comparison (if wrk is installed)

Runs the same test scenarios using **wrk**, a native C load generator, to isolate how much of the throughput ceiling comes from the Rust reqwest client vs the gateway itself.

For each concurrency level (50, 100, 200, 400), wrk runs:
- **key_auth proxies** — with a Lua script that cycles through 100 API keys and paths
- **open proxies** — plain GET against a no-plugin proxy

wrk uses `--latency` for percentile distribution and is launched via `spawn_blocking` to avoid blocking the tokio runtime that hosts the hyper backend. A run counts as a result only when wrk's output has a positive `N requests in` total. A wrk invocation error, a failed blocking task, or output with no positive request total is reported as a missing result and fails the test. A nonzero wrk exit status with a positive parsed total is still accepted.

## Backend Pool Settings

The test runs **twice**: once with `FERRUM_POOL_ENABLE_HTTP2=false` and once with `FERRUM_POOL_ENABLE_HTTP2=true`. The console labels each run by that setting.

Both runs use the same embedded backend, which speaks **plaintext HTTP/1.1 only** (`hyper::server::conn::http1::Builder` with keep-alive, and every route uses `backend_scheme: http`). `FERRUM_POOL_ENABLE_HTTP2` only permits HTTP/2 when the backend supports it, and this backend never does. Neither run is therefore an observed HTTP/1.1-versus-HTTP/2 backend comparison, and differences between the runs must not be attributed to HTTP/2 framing or multiplexing. A real protocol comparison would need an HTTP/2-capable backend, an explicit client path, a forced-HTTP/1.1 control, and an assertion of the negotiated protocol at the backend.

## Interpreting Results

### Summary Tables

The test prints a summary table for each backend pool setting. The example below is historical output from one PostgreSQL run with `FERRUM_POOL_ENABLE_HTTP2=false` on Apple Silicon macOS (release build), shown with the current header to illustrate the report format; it is not a current measurement. Its reqwest rows use the [measurement boundary](#measurement-boundary) above (attempt RPS, response-head latency).

```
======================================================================
  LOAD & STRESS TEST SUMMARY (PostgreSQL, FERRUM_POOL_ENABLE_HTTP2=false, backend: plaintext HTTP/1.1)
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

*(Actual results depend on hardware and system load.)*

**Interpretation:** Differences between the `false` and `true` runs cannot be attributed to HTTP/2 framing, HPACK, flow control, or multiplexing, because no backend leg speaks HTTP/2. This fixture does not identify their cause; run-to-run system load also varies. This fixture is not a basis for choosing a backend transport policy. Use an HTTP/2-capable backend with the controls described in [Backend Pool Settings](#backend-pool-settings) for that.

### wrk vs reqwest Client Comparison

For each run the test prints each wrk phase next to the matching reqwest phase (`reqwest: <n> attempt RPS | wrk: <n> RPS (+<x>%)`). wrk usually reports higher throughput than the in-process reqwest client. These reqwest phases share the runtime and host with the backend, while wrk uses a separate process and different request scenarios, so client contention can affect throughput; this comparison does not isolate its cause or establish the gateway's maximum throughput.

### Plugin Overhead Analysis

The test prints the with-plugins (auth + ACL + rate limiting) ramp against the no-plugin phase at each concurrency (attempt RPS and response-head P99 for each). Plugin overhead varies with concurrency, so compare it at the concurrency you plan to run.

### Admin Mutation Impact

The test prints the mutation accounting, then the percentage change in response-head P99 latency and attempt RPS when admin mutations are active. Illustrative shape:

```
  Admin mutations: attempted=500 accepted=500 rejected=0 transport_failed=0 | cycles: attempted=100 fully_accepted=100
    create_proxy (expect 201): attempted=100 accepted=100 rejected=0 transport_failed=0, accepted avg=40.0ms max=90.0ms
    ...
  P99 latency impact from admin mutations: +1.4%  (15.4ms -> 15.6ms)
  RPS impact from admin mutations: -0.9%  (10081 -> 9988)
```

The impact figures describe a reload workload only when the accounting shows accepted writes; the final gate enforces this (see [Failure Threshold](#failure-threshold)). A small impact (<10% P99 increase) indicates config reloads did not produce significant response-head latency spikes. Config publication uses `ArcSwap`, so in-flight requests see either the old or new config atomically, never a partial update.

### Latency Warnings

The test flags:
- **P99 > 100ms** - Potential concern for latency-sensitive workloads
- **P95 > 50ms** - High tail latency under load
- **Success rate < 95%** - Significant request failures

### Failure Threshold

Each backend pool run ends with one gate that lists every failure it found:

- Every phase that ran (Phase 1, Phase 2, the Phase 3 traffic, and each Phase 4 wrk result) must report a positive request count and a success rate **above 50%**. A phase with zero requests fails.
- When wrk is available, each of the eight attempted wrk runs must have produced a result. A missing result fails the test; it is not dropped from the comparison.
- The admin mutation phase must have at least one cycle in which all five writes were accepted, and accepted writes must be more than 50% of attempted writes.

A reqwest load worker that panics also fails its phase. Before measurement starts, provisioning, the live-apply cursor, and convergence have their own strict gates.

## Gateway Configuration

The test configures the gateway with tuned connection pool and flow-control settings:

### Connection Pool Tuning

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | 1024 | Large idle pool at the maximum allowed (prevents connection churn) |
| `FERRUM_POOL_IDLE_TIMEOUT_SECONDS` | 120 | Keep connections alive longer |
| `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` | true | Reuse connections to backend |
| `FERRUM_POOL_ENABLE_HTTP2` | Run 1: `false`, Run 2: `true` | Test runs both modes for comparison |

### Frontend HTTP/2 Flow Control (client → gateway)

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_FRONTEND_H2_INITIAL_STREAM_WINDOW_SIZE` | 8388608 (8 MiB) | Frontend per-stream receive window (default 256 KiB; raised for load testing) |
| `FERRUM_FRONTEND_H2_INITIAL_CONNECTION_WINDOW_SIZE` | 33554432 (32 MiB) | Frontend per-connection receive window (default 2 MiB; raised for load testing) |
| `FERRUM_FRONTEND_H2_MAX_FRAME_SIZE` | 1048576 (1 MiB) | Frontend max frame size (default 16 KiB; raised for load testing) |

### Backend HTTP/2 Pool Flow Control (gateway → upstream)

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE` | 8388608 (8 MiB) | Backend per-stream receive window |
| `FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE` | 33554432 (32 MiB) | Backend per-connection receive window |
| `FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW` | false | Fixed windows, no auto-tuning overhead |
| `FERRUM_POOL_HTTP2_MAX_FRAME_SIZE` | 65535 | Backend max HTTP/2 frame size |
| `FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS` | 1000 | H2 concurrent streams per backend connection |

### Frontend HTTP/3 (QUIC) Transport (client → gateway)

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_HTTP3_MAX_STREAMS` | 1000 | QUIC max concurrent streams |
| `FERRUM_HTTP3_STREAM_RECEIVE_WINDOW` | 8388608 (8 MiB) | Frontend per-stream QUIC receive window (default 256 KiB; raised for load testing) |
| `FERRUM_HTTP3_RECEIVE_WINDOW` | 33554432 (32 MiB) | Frontend per-connection QUIC receive window (default 2 MiB; raised for load testing) |
| `FERRUM_HTTP3_SEND_WINDOW` | 8388608 (8 MiB) | Frontend QUIC send window (default 2 MiB; raised for load testing) |

### Other

| Env Var | Value | Purpose |
|---------|-------|---------|
| `FERRUM_LOG_LEVEL` | error | Minimize logging overhead during load |
| `FERRUM_DB_POLL_INTERVAL` | 30 | Production default. Wave-end convergence is driven by the blocking `GET /config/apply-status` cursor gate (which raises an immediate poll wake), not the interval; a 2s interval kept the poller in continuous full reloads during deferred provisioning and starved the database (issue #4139) |
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | (set) | HMAC-SHA256 hashing for `basic_auth` |

> **Note on `FERRUM_POOL_MAX_IDLE_PER_HOST`**: This value must be >= your peak concurrency level. If set too low, the gateway opens new TCP connections instead of reusing pooled ones, causing a large (10x+) RPS drop. The shell-based performance scripts under `tests/performance/` use 200 to match the wrk connection count.

## Understanding reqwest vs wrk Performance Gap

The reqwest-based phases usually report lower throughput than the wrk phases. The in-process reqwest client is the likely bottleneck, though this fixture does not isolate the cause:

| Factor | reqwest (in-process) | wrk (native C) |
|--------|---------------------|-----------------|
| **Language** | Rust async (tokio) | C (epoll/kqueue) |
| **Runtime sharing** | Shares tokio runtime with backend | Separate process |
| **CPU contention** | Competes with gateway + backend for CPU | Own CPU cores |
| **Per-request overhead** | ~50-100μs (async task, HTTP parsing) | ~5-10μs (optimized C loop) |
| **Connection model** | Per-worker client with pool | Thread-local connections |
| **Body handling** | Full reqwest request builder | Raw socket writes |

These reqwest phases share the runtime and host with the backend; wrk uses a separate process and different request scenarios, so client contention can affect throughput and neither number establishes the gateway's maximum throughput.

### What the wrk numbers tell us

In one earlier wrk run at c=200 with key_auth (3 plugins per proxy), the gateway added roughly **2.5ms average latency per request** over the pure backend. Approximate breakdown:

1. **Route matching** (~0.1ms) — longest-prefix match over 10k pre-sorted routes, with a bounded (host, path) lookup cache
2. **Auth credential extraction + crypto** (~0.3-0.5ms) — API key hash lookup, or JWT decode, or HMAC verify
3. **Consumer index lookup** (~0.05ms) — O(1) by credential
4. **ACL check** (~0.02ms) — group membership check
5. **Rate limit check** (~0.05ms) — counter increment + window comparison
6. **Connection pool acquire/release** (~0.1ms) — pool lock + connection selection
7. **HTTP header construction** (~0.1ms) — X-Forwarded-For, Host, etc.
8. **Body streaming** (~0.5-1.5ms) — depends on payload size, zero-copy for no-body GETs

No request or response body parsing occurs for these plugins — bodies stream through as raw byte chunks (`ProxyBody` streaming variants in `src/proxy/body.rs`).

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

Provisioning posts 21,000 resources plus 30,000 plugin configs in batches of 100 and then waits for the apply cursor. On slower machines this can take several minutes. Check the test output for per-phase progress.

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

The test waits on the batch apply cursor and then polls sample routes for up to 5 minutes (`CONFIG_CONVERGENCE_MAX_WAIT_SECS` in `tests/common/scheduled_scaling.rs`). If that gate fails, its panic message lists the last per-sample outcomes; check gateway logs for config loading errors.

### Debug build performance

If you see a warning about using a debug binary, rebuild in release mode:

```bash
cargo build --release --bin ferrum-edge
```

Debug builds are 2-4x slower and will show artificially high latency numbers.

### reqwest RPS plateaus around 10k (`FERRUM_POOL_ENABLE_HTTP2=false` run)

The in-process reqwest client competes with the gateway and backend for CPU, file descriptors, and ephemeral ports. Historical runs showed higher reqwest throughput with `FERRUM_POOL_ENABLE_HTTP2=true`, but the backend is HTTP/1.1-only, so that difference is not evidence of backend HTTP/2 multiplexing (see [Backend Pool Settings](#backend-pool-settings)). The wrk comparison phase shows how much of the gap comes from the client. See "Understanding reqwest vs wrk Performance Gap" above.

### Test takes too long

The test runs two full passes (`FERRUM_POOL_ENABLE_HTTP2=false`, then `true`), each with 4 ramp phases + 4 no-plugin phases + admin mutations + wrk phases. Total runtime is ~15-18 minutes. To run only one setting, modify the `enable_http2` parameter in `test_load_stress_10k_proxies()`.
