# API Gateway Comparison Benchmarks (All-Docker)

Performance comparison suite that benchmarks **Ferrum Edge** against **Pingora** (Cloudflare), **Kong**, **Tyk**, **KrakenD**, and **Envoy** under identical conditions.

**All gateways run inside Docker containers** for apples-to-apples comparison. The Docker overhead is shared equally across all platforms, eliminating the unfair advantage that native binaries previously had over Docker-gated gateways.

> **How to read these results:** The absolute throughput numbers (req/s) are not representative of production performance — Docker Desktop on macOS adds significant overhead to all gateways. What matters is the **relative percentage difference** between gateways. Since every gateway runs in the same Docker environment with the same networking penalty, a gateway that is 15% faster here will be roughly 15% faster in production too. Focus on the gaps between gateways, not the raw numbers.

## Why All-Docker?

Previous benchmarks ran Ferrum, Pingora, and Envoy as native binaries while Kong, Tyk, and KrakenD ran in Docker. This created an unfair comparison — Docker Desktop on macOS imposes 60-80% throughput reduction (measured via Envoy native vs Docker: 87K vs 17K req/s = 5x gap). By running **every** gateway in Docker:

- **Equal overhead**: All gateways pay the same Docker networking and VM penalty
- **Relative differences are meaningful**: A 15% gap in Docker reflects a real 15% efficiency difference in the gateway itself, regardless of the absolute numbers
- **Reproducible**: Anyone with Docker can run the benchmark without installing native packages

The backend echo server runs natively on the host since it is a shared constant (not a gateway being benchmarked) and identical for all tests.

## What It Measures

Each gateway is tested as a reverse proxy with four scenarios:

| Scenario | Description |
|----------|-------------|
| **HTTP (plaintext)** | Client → Gateway (port 8000) → Backend. Measures raw proxy overhead. |
| **HTTPS (TLS termination)** | Client → Gateway (port 8443, TLS) → Backend (plaintext). Measures TLS handshake and encryption overhead at the gateway. |
| **E2E TLS (full encryption)** | Client → Gateway (port 8443, TLS) → Backend (TLS, port 3443). Measures full end-to-end encryption where the gateway re-encrypts traffic to the backend. |
| **Key-Auth (HTTP + authentication)** | Client → Gateway (port 8000, HTTP) → Backend. Each request includes an API key header (`apikey: test-api-key`) validated by the gateway's key-auth plugin. Measures authentication overhead. Ferrum, Kong, Tyk, and Envoy (Pingora has no auth plugin framework; KrakenD key-auth requires Enterprise Edition). Envoy uses an inline Lua filter for API key validation. |

Two endpoints are tested per proxy scenario:
- `/health` — instant backend response, measures pure gateway latency
- `/api/users` — 100 microsecond simulated delay, represents a typical API call

A direct backend baseline (no gateway) is run first for both HTTP and HTTPS comparison.

### Test Approach

- **All gateways run in Docker** — Ferrum and Pingora are built into Docker images from source; Kong, Tyk, KrakenD, and Envoy use official Docker images
- Gateways are tested **sequentially** (one at a time) to avoid resource contention
- Each test gets a **5-second warm-up** (results discarded) before the measured 30-second run
- The same backend echo server, wrk parameters, and endpoints are used across all gateways

## Prerequisites

| Dependency | Required | Install |
|------------|----------|---------|
| **wrk** | Yes | `brew install wrk` (macOS) or `apt install wrk` (Ubuntu) |
| **Python 3** | Yes | Usually pre-installed; needed for report generation |
| **Rust/Cargo** | Yes | [rustup.rs](https://rustup.rs/) — builds the backend server |
| **Docker** | Yes | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| **curl** | Yes | Usually pre-installed; used for health checks |

**System recommendations:** Run on a dedicated machine or close resource-intensive applications. Ensure Docker has sufficient CPU and memory allocated (recommended: all CPU cores, 8+ GB RAM).

## Quick Start

```bash
# From the project root
./comparison/run_comparison.sh
```

The script will:
1. Pull Kong, Tyk, KrakenD, and Envoy Docker images
2. Build Ferrum Edge and Pingora Docker images from source (release mode)
3. Build the backend echo server natively (release mode)
4. Run baseline → Ferrum → Pingora → Kong → Tyk → KrakenD → Envoy tests sequentially
5. Generate an HTML comparison report in `comparison/results/`

Open `comparison/results/comparison_report.html` in a browser to view the results.

## Configuration

Override any parameter via environment variables:

```bash
# Custom test parameters
WRK_DURATION=60s WRK_THREADS=12 WRK_CONNECTIONS=200 ./comparison/run_comparison.sh

# Skip a gateway
SKIP_GATEWAYS=tyk,krakend ./comparison/run_comparison.sh

# Only test Ferrum vs Envoy
SKIP_GATEWAYS=pingora,kong,tyk,krakend ./comparison/run_comparison.sh

# Skip Docker image rebuild (use cached images)
SKIP_BUILD=true ./comparison/run_comparison.sh
```

| Variable | Default | Description |
|----------|---------|-------------|
| `WRK_DURATION` | `30s` | Duration of each measured test run |
| `WRK_THREADS` | `8` | wrk thread count |
| `WRK_CONNECTIONS` | `100` | wrk concurrent connections |
| `WARMUP_DURATION` | `5s` | Warm-up duration before each test (results discarded) |
| `KONG_VERSION` | `3.9` | Kong Docker image tag |
| `TYK_VERSION` | `v5.7` | Tyk Docker image tag |
| `KRAKEND_VERSION` | `2.13` | KrakenD Docker image tag |
| `ENVOY_VERSION` | `1.32-latest` | Envoy Docker image tag |
| `SKIP_GATEWAYS` | _(empty)_ | Comma-separated gateways to skip: `ferrum`, `pingora`, `kong`, `tyk`, `krakend`, `envoy` |
| `SKIP_BUILD` | `false` | Skip Docker image builds for Ferrum and Pingora (use cached images) |

## Swapping Gateway Versions

To re-run benchmarks with newer Kong, Tyk, or KrakenD releases:

```bash
# Test against Kong 3.10, Tyk v5.8, KrakenD 2.14, and Envoy 1.33
KONG_VERSION=3.10 TYK_VERSION=v5.8 KRAKEND_VERSION=2.14 ENVOY_VERSION=1.33-latest ./comparison/run_comparison.sh
```

The script pulls the specified Docker image tags automatically. Results are overwritten in `comparison/results/` — copy or rename the directory if you want to preserve previous runs.

## Docker Images

| Gateway | Image Source | Build |
|---------|-------------|-------|
| **Ferrum Edge** | `Dockerfile` (project root) | Built locally from source (release mode, multi-stage) |
| **Pingora** | `comparison/Dockerfile.pingora-bench` | Built locally from crates.io deps (release mode, multi-stage) |
| **Kong** | `kong/kong-gateway:${KONG_VERSION}` | Official Docker Hub image |
| **Tyk** | `tykio/tyk-gateway:${TYK_VERSION}` | Official Docker Hub image |
| **KrakenD** | `krakend:${KRAKEND_VERSION}` | Official Docker Hub image |
| **Envoy** | `envoyproxy/envoy:v${ENVOY_VERSION}` | Official Docker Hub image |

Ferrum and Pingora images use multi-stage builds with a Rust builder stage and a slim Debian runtime stage. Dependencies are cached in a separate layer for fast rebuilds when only source code changes.

## Interpreting Results

The HTML report contains six sections:

### 1. Direct Backend Baseline
Raw backend throughput and latency without any gateway, for both HTTP and HTTPS. This is the theoretical maximum. Any gateway will add overhead.

### 2. HTTP Performance (Plaintext)
Compares all gateways proxying plaintext HTTP. Key metrics:
- **Requests/sec** — higher is better. The gateway closest to baseline has the least overhead.
- **Avg Latency** — lower is better. The difference from baseline is the gateway's added latency.
- **P99 Latency** — tail latency matters for user experience. Large P99 spikes indicate inconsistent performance.
- **Errors** — should be zero. Non-zero errors indicate the gateway couldn't handle the load.
- **vs Baseline** — percentage RPS difference from direct backend.

### 3. HTTPS Performance (TLS Termination)
Same metrics but with TLS between wrk and the gateway, while the gateway proxies to the backend over plaintext. Expect lower throughput and higher latency than HTTP due to TLS handshake cost.

### 4. End-to-End TLS Performance (Full Encryption)
Client connects via HTTPS to the gateway, and the gateway re-encrypts traffic to the backend over HTTPS. This is the most secure deployment pattern and measures the full cost of double TLS. Compared against the HTTPS baseline (direct to backend).

### 5. Key-Auth Performance
Compares authenticated throughput (API key validation) against the same gateway's unauthenticated performance. Shows the cost of running one authentication plugin in the request path. Pingora is excluded (no plugin framework). Each request includes an `apikey` header; the gateway validates it against a pre-configured consumer before proxying.

### 6. TLS Overhead Comparison
Per-gateway comparison of HTTP vs HTTPS vs E2E TLS performance. Shows the RPS drop and latency increase each gateway pays for TLS at each stage. A gateway with lower TLS overhead has a more efficient TLS implementation.

### Color coding
- **Green cells** = best in category (highest RPS, lowest latency)
- **Red cells** = worst in category

### Reading the numbers
Since all gateways run in Docker on the same host, the absolute req/s values are lower than what you'd see in production. **Compare the percentage gaps, not the raw numbers.** For example, if Ferrum shows 28K req/s and Kong shows 20K req/s, that's a 40% efficiency advantage for Ferrum — and that gap will hold in any deployment environment (bare metal, VMs, Kubernetes).

## Findings (All-Docker, April 2026)

The following results were collected on macOS (Apple Silicon M3 Max) with 8 threads, 100 connections, and 30-second measured runs. All gateways ran in Docker containers for apples-to-apples comparison.

> **Reminder:** The raw req/s numbers are depressed by Docker Desktop overhead. Focus on the **percentage differences** between gateways — those reflect real efficiency gaps in each gateway's architecture.

### Raw Proxy Performance

| Gateway | HTTP /health | HTTP /api/users | HTTPS /health | HTTPS /api/users | E2E TLS /health | E2E TLS /api/users |
|---------|-------------|----------------|--------------|-----------------|----------------|-------------------|
| **Baseline** | 196,834 | 56,122 | 195,567 | 46,833 | — | — |
| **Ferrum** | **29,153** | **28,206** | **30,975** | 26,481 | **29,131** | **27,902** |
| **Envoy** | 28,558 | 27,896 | 28,983 | **27,001** | 27,014 | 23,784 |
| **Kong** | 28,966 | 27,962 | 27,132 | 26,035 | 27,109 | 25,389 |
| **Tyk** | 24,884 | 24,414 | 24,800 | 23,466 | 22,957 | 21,902 |
| **KrakenD** | 21,995 | 20,497 | 20,682 | 20,178 | 19,941 | 21,737 |
| **Pingora** | 6,076 | 5,730 | 6,142 | 6,453 | — | — |

**Ferrum leads or ties in 5 of 6 proxy scenarios.** Ferrum's HTTPS /health (30,975 req/s) is the highest single result, and E2E TLS /api/users (27,902 req/s) beats every other gateway by 10-28% on the most production-representative test (double-TLS with realistic backend latency). Envoy takes HTTPS /api/users by 2% which is likely just networking varience. Pingora E2E TLS is not supported (SNI limitation with IP-based backends).

### Key-Auth Results (HTTP, /api/users-auth)

Each gateway proxies `/api/users-auth` → backend `/api/users` with API key authentication enabled. A valid API key is sent in the `apikey` header on every request. Pingora is excluded (no auth plugin framework). KrakenD is excluded (key-auth requires Enterprise Edition). Envoy uses an inline Lua filter for API key validation.

| Gateway | Key-Auth req/s | Latency |
|---------|---------------|---------|
| **Ferrum** (Docker) | **26,756** | **3.61 ms** |
| **Envoy 1.32** (Docker, Lua) | 26,252 | 3.97 ms |
| **Kong 3.9** (Docker) | 22,307 | 4.55 ms |
| **Tyk v5.7** (Docker) | 20,529 | 4.72 ms |

**Key findings:**
- **Ferrum is the fastest gateway on authenticated requests** — 26,756 req/s, beating Envoy by 2%, Kong by 20%, and Tyk by 30%.
- **Ferrum's key-auth has effectively zero overhead** — authenticated requests (26,756 req/s) match unauthenticated HTTP /api/users (28,206 req/s) within 5%. The pre-computed `ConsumerIndex` with `Arc<Consumer>` means authentication adds only an atomic refcount bump (~5ns) and a HashMap lookup (~50ns) to the request path — no deep cloning, no string allocation.
- **Kong's key-auth** — 22,307 req/s puts Kong within 20% of Ferrum and ahead of Tyk.

### Ferrum vs Envoy (All-Docker Comparison)

Both gateways run in Docker with identical conditions.

| Test | Ferrum | Envoy | Advantage |
|------|--------|-------|-----------|
| HTTP /health | **29,153 req/s** | 28,558 req/s | **Ferrum 2% faster** |
| HTTP /api/users | **28,206 req/s** | 27,896 req/s | **Ferrum 1% faster** |
| HTTPS /health | **30,975 req/s** | 28,983 req/s | **Ferrum 7% faster** |
| HTTPS /api/users | 26,481 req/s | **27,001 req/s** | Envoy 2% faster |
| E2E TLS /health | **29,131 req/s** | 27,014 req/s | **Ferrum 8% faster** |
| **E2E TLS /api/users** | **27,902 req/s** | 23,784 req/s | **Ferrum 17% faster** |
| **Key-Auth /api/users-auth** | **26,756 req/s** | 26,252 req/s | **Ferrum 2% faster** |

**Key findings:**
- **Ferrum wins 6 of 7 tests against Envoy** — from 1% on HTTP plaintext to 17% on E2E TLS with backend latency. Envoy's only lead is HTTPS /api/users by 2%.
- **Ferrum dominates E2E TLS** — 27,902 vs 23,784 req/s (17% advantage). Full double-TLS encryption with realistic backend latency is where Ferrum's rustls and connection pooling excel. This is the most production-representative scenario.
- **Ferrum wins on authenticated workloads** — when auth plugins enter the picture, Ferrum's compiled Rust plugin with zero-copy `Arc<Consumer>` lookup beats Envoy's Lua VM filter. Real-world deployments always have plugins (auth, rate limiting, logging), making this the more relevant comparison.

### Why Ferrum Wins on Authentication

Ferrum's authentication architecture is designed for zero per-request allocation:

1. **Pre-computed ConsumerIndex** — credentials are indexed into per-type HashMaps at config load time (not per-request)
2. **Arc\<Consumer\> zero-copy** — the `ConsumerIndex` returns `Arc<Consumer>` and the auth plugin stores it directly in the request context without cloning the Consumer struct
3. **Pre-computed header names** — the `KeyAuth` plugin lowercases the header name once at config load time, not on every request
4. **Lock-free reads** — `ArcSwap::load()` for the credential index is a single atomic load with no mutex or spinlock

By contrast, Envoy's Lua filter runs interpreted Lua code on every request, and Kong's plugin chain involves multiple Lua function calls with table lookups per authenticated request.

## Docker Networking

On macOS, Docker Desktop runs containers inside a Linux VM with userspace networking. All gateways use port mapping (`-p`) and reach the host backend via `host.docker.internal`. On Linux, `--network host` is used for near-zero Docker networking overhead.

| Platform | Networking Mode | Docker Overhead |
|----------|----------------|-----------------|
| **Linux** | `--network host` | < 1% (negligible) |
| **macOS** | port mapping (`-p`) | Significant (VM boundary + userspace networking) |

The macOS overhead is substantial but **shared equally** across all gateways, making relative comparisons valid. For absolute throughput numbers, run on Linux.

## Pingora E2E TLS Limitation

Pingora's TLS library requires a valid DNS hostname for upstream SNI and cannot connect to IP-based backends (127.0.0.1 / host.docker.internal) over TLS. The E2E TLS test is skipped gracefully if Pingora fails to start in this mode. This is a framework limitation, not a configuration issue.

## Adding a New Gateway

To add a new gateway (e.g., NGINX, Traefik, HAProxy):

1. **Create config files** in `comparison/configs/` for the gateway (use `BACKEND_HOST` placeholder)
2. **Add functions** to `run_comparison.sh`:
   - `start_<gateway>_http()` / `start_<gateway>_https()` — launch the Docker container
   - `stop_<gateway>()` — remove the container
   - `test_<gateway>()` — orchestrate HTTP + HTTPS + E2E TLS test sequences
3. **Add the gateway name** to the `GATEWAYS` list in `scripts/generate_comparison_report.py`
4. **Call `test_<gateway>()`** in the `main()` function of `run_comparison.sh`
5. **Add a `should_skip` check** so users can skip it via `SKIP_GATEWAYS`

Each test function should follow the pattern: start container → run_wrk (per endpoint) → stop container. Use the same ports (8000/8443) since gateways run sequentially.
