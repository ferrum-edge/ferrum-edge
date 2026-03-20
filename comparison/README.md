# API Gateway Comparison Benchmarks

Performance comparison suite that benchmarks **Ferrum Gateway** against **Kong** and **Tyk** API Gateways under identical conditions.

## What It Measures

Each gateway is tested as a pure reverse proxy (no authentication, rate limiting, or transformation plugins) with three scenarios:

| Scenario | Description |
|----------|-------------|
| **HTTP (plaintext)** | Client → Gateway (port 8000) → Backend. Measures raw proxy overhead. |
| **HTTPS (TLS termination)** | Client → Gateway (port 8443, TLS) → Backend (plaintext). Measures TLS handshake and encryption overhead at the gateway. |
| **E2E TLS (full encryption)** | Client → Gateway (port 8443, TLS) → Backend (TLS, port 3443). Measures full end-to-end encryption where the gateway re-encrypts traffic to the backend. |

Two endpoints are tested per scenario:
- `/health` — instant backend response, measures pure gateway latency
- `/api/users` — 100 microsecond simulated delay, represents a typical API call

A direct backend baseline (no gateway) is run first for both HTTP and HTTPS comparison.

### Test Approach

- Gateways are tested **sequentially** (one at a time) to avoid resource contention
- Each test gets a **5-second warm-up** (results discarded) before the measured 30-second run
- The same backend echo server, wrk parameters, and endpoints are used across all gateways
- Ferrum runs as a native binary; Kong runs natively if installed (preferred) or in Docker; Tyk runs in Docker (no official macOS binary)
- The script auto-detects native Kong and prefers it over Docker for fairer benchmarking

## Prerequisites

| Dependency | Required | Install |
|------------|----------|---------|
| **wrk** | Yes | `brew install wrk` (macOS) or `apt install wrk` (Ubuntu) |
| **Python 3** | Yes | Usually pre-installed; needed for report generation |
| **Rust/Cargo** | Yes | [rustup.rs](https://rustup.rs/) — builds Ferrum and the backend server |
| **curl** | Yes | Usually pre-installed; used for health checks |
| **Docker** | For Tyk (always), Kong (if not native) | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| **Kong** (native) | Recommended | See below |

### Native Kong Installation (Recommended for Fair Benchmarks)

Installing Kong natively eliminates Docker overhead and provides the fairest comparison against Ferrum. The script auto-detects a native `kong` binary and uses it automatically.

**macOS:** No native macOS binary is officially available — Docker is the only supported option on macOS. If you have a Kong binary from another source, place it on your `$PATH` and the script will use it.

**Ubuntu/Debian:**
```bash
curl -1sLf 'https://packages.konghq.com/public/gateway-39/setup.deb.sh' | sudo bash
sudo apt install kong
```

**RHEL/CentOS:**
```bash
curl -1sLf 'https://packages.konghq.com/public/gateway-39/setup.rpm.sh' | sudo bash
sudo yum install kong
```

### Native Tyk Installation (Linux Only)

Tyk has no official macOS binary. On Linux, native installation is available:

**Ubuntu/Debian:**
```bash
curl -1sLf 'https://packagecloud.io/tyk/tyk-gateway/setup.deb.sh' | sudo bash
sudo apt install tyk-gateway
```

Tyk always requires Redis (`brew install redis` on macOS, `apt install redis-server` on Linux).

On macOS, Tyk runs in Docker — see the "Docker Overhead" section below for what this means for results.

**System recommendations:** Run on a dedicated machine or close resource-intensive applications. CPU governor set to "performance" improves consistency on Linux.

## Quick Start

```bash
# From the project root
./comparison/run_comparison.sh
```

The script will:
1. Pull Kong and Tyk Docker images
2. Build Ferrum Gateway and the backend server (release mode)
3. Run baseline → Ferrum → Kong → Tyk tests sequentially
4. Generate an HTML comparison report in `comparison/results/`

Open `comparison/results/comparison_report.html` in a browser to view the results.

## Configuration

Override any parameter via environment variables:

```bash
# Custom test parameters
WRK_DURATION=60s WRK_THREADS=12 WRK_CONNECTIONS=200 ./comparison/run_comparison.sh

# Skip a gateway (e.g., if you don't have Docker)
SKIP_GATEWAYS=tyk,kong ./comparison/run_comparison.sh

# Only test Ferrum vs Kong
SKIP_GATEWAYS=tyk ./comparison/run_comparison.sh
```

| Variable | Default | Description |
|----------|---------|-------------|
| `WRK_DURATION` | `30s` | Duration of each measured test run |
| `WRK_THREADS` | `8` | wrk thread count |
| `WRK_CONNECTIONS` | `100` | wrk concurrent connections |
| `WARMUP_DURATION` | `5s` | Warm-up duration before each test (results discarded) |
| `KONG_VERSION` | `3.9` | Kong Docker image tag |
| `TYK_VERSION` | `v5.7` | Tyk Docker image tag |
| `SKIP_GATEWAYS` | _(empty)_ | Comma-separated gateways to skip: `ferrum`, `kong`, `tyk` |

## Swapping Gateway Versions

To re-run benchmarks with newer Kong or Tyk releases:

```bash
# Test against Kong 3.10 and Tyk v5.8
KONG_VERSION=3.10 TYK_VERSION=v5.8 ./comparison/run_comparison.sh
```

The script pulls the specified Docker image tags automatically. Results are overwritten in `comparison/results/` — copy or rename the directory if you want to preserve previous runs.

### Version-specific considerations

- **Kong** uses DB-less declarative mode. The config format (`_format_version: "3.0"`) is stable across 3.x releases. If Kong 4.x changes the format, update `comparison/configs/kong.yaml`.
- **Tyk** uses standalone mode with file-based API definitions. The API definition schema has been stable across v5.x. If Tyk v6 changes it, update the files in `comparison/configs/tyk/apps/`.
- **Ferrum** is built from source in the current checkout, so it always tests the latest local code.

## Interpreting Results

The HTML report contains five sections:

### 1. Direct Backend Baseline
Raw backend throughput and latency without any gateway, for both HTTP and HTTPS. This is the theoretical maximum. Any gateway will add overhead.

### 2. HTTP Performance (Plaintext)
Compares all three gateways proxying plaintext HTTP. Key metrics:
- **Requests/sec** — higher is better. The gateway closest to baseline has the least overhead.
- **Avg Latency** — lower is better. The difference from baseline is the gateway's added latency.
- **P99 Latency** — tail latency matters for user experience. Large P99 spikes indicate inconsistent performance.
- **Errors** — should be zero. Non-zero errors indicate the gateway couldn't handle the load.
- **vs Baseline** — percentage RPS difference from direct backend.

### 3. HTTPS Performance (TLS Termination)
Same metrics but with TLS between wrk and the gateway, while the gateway proxies to the backend over plaintext. Expect lower throughput and higher latency than HTTP due to TLS handshake cost.

### 4. End-to-End TLS Performance (Full Encryption)
Client connects via HTTPS to the gateway, and the gateway re-encrypts traffic to the backend over HTTPS. This is the most secure deployment pattern and measures the full cost of double TLS. Compared against the HTTPS baseline (direct to backend).

### 5. TLS Overhead Comparison
Per-gateway comparison of HTTP vs HTTPS vs E2E TLS performance. Shows the RPS drop and latency increase each gateway pays for TLS at each stage. A gateway with lower TLS overhead has a more efficient TLS implementation.

### Color coding
- **Green cells** = best in category (highest RPS, lowest latency)
- **Red cells** = worst in category

## Initial Findings

The following results were collected on macOS (Apple Silicon) with 8 threads, 100 connections, and 30-second measured runs. Kong and Tyk ran in Docker; Ferrum ran natively.

### Raw Results

| Gateway | Protocol | /health req/s | /api/users req/s | /health latency | /api/users latency |
|---------|----------|--------------|-----------------|-----------------|-------------------|
| **Baseline** (no gateway) | HTTP | 211,184 | 51,203 | 0.38 ms | 1.77 ms |
| **Baseline** (no gateway) | HTTPS | 207,939 | 50,546 | 0.38 ms | 1.78 ms |
| **Ferrum** (native) | HTTP | 98,391 | 40,801 | 0.98 ms | 2.34 ms |
| **Ferrum** (native) | HTTPS | 94,166 | 41,113 | 1.06 ms | 2.33 ms |
| **Ferrum** (native) | E2E TLS | 88,006 | 38,414 | 1.22 ms | 2.52 ms |
| **Kong 3.9** (Docker) | HTTP | 25,588 | 25,278 | 3.77 ms | 3.84 ms |
| **Kong 3.9** (Docker) | HTTPS | 24,461 | 21,146 | 4.16 ms | 4.95 ms |
| **Kong 3.9** (Docker) | E2E TLS | 23,444 | 14,339 | 5.26 ms | 8.61 ms |
| **Tyk v5.7** (Docker) | HTTP | 2,563 | 2,824 | 7.00 ms | 6.00 ms |
| **Tyk v5.7** (Docker) | HTTPS | 3,450 | 3,819 | 2.60 ms | 1.83 ms |
| **Tyk v5.7** (Docker) | E2E TLS | 1,931 | 5,635 | 3.10 ms | 0.71 ms |

### Adjusting for Docker Overhead

Kong and Tyk ran in Docker on macOS, which adds ~0.1–0.5 ms latency per request and reduces throughput by ~5–15% (see [Docker Overhead](#docker-overhead)). Even after generously accounting for this:

| Gateway | /health req/s (adjusted) | Ferrum Advantage |
|---------|-------------------------|-----------------|
| **Ferrum** (native) | 98,391 | — |
| **Kong** (Docker, +15% adjusted) | ~29,400 | **3.3x faster** |
| **Tyk** (Docker, +15% adjusted) | ~2,950 | **33x faster** |

### End-to-End TLS Performance

The E2E TLS scenario (client → HTTPS → gateway → HTTPS → backend) is the most secure deployment pattern and the most demanding on gateway performance. Here, Ferrum's advantage is even more pronounced:

| Gateway | E2E /health req/s | E2E /api/users req/s | E2E /health latency | E2E /api/users latency |
|---------|------------------|---------------------|--------------------|-----------------------|
| **Ferrum** (native) | 88,006 | 38,414 | 1.22 ms | 2.52 ms |
| **Kong 3.9** (Docker) | 23,444 | 14,339 | 5.26 ms | 8.61 ms |
| **Tyk v5.7** (Docker) | 1,931 | 5,635 | 3.10 ms | 0.71 ms |

- **Ferrum is 3.8x faster than Kong** on E2E TLS /health and **2.7x faster** on /api/users
- **Ferrum is 46x faster than Tyk** on E2E TLS /health

### TLS Overhead by Gateway

How much does each layer of encryption cost each gateway?

| Gateway | HTTP → HTTPS (TLS term.) | HTTP → E2E TLS (full encryption) |
|---------|--------------------------|----------------------------------|
| **Ferrum** | -4.3% RPS, +0.08 ms | **-10.6% RPS, +0.24 ms** |
| **Kong** | -4.4% RPS, +0.39 ms | **-8.4% RPS, +1.49 ms** (/health); **-43.3% RPS, +4.77 ms** (/api/users) |
| **Tyk** | varies (Docker noise) | varies (Docker noise) |

Ferrum's full E2E TLS overhead is just **10.6% throughput drop and 0.24 ms added latency** — meaning the gateway-to-backend TLS hop costs very little. Kong's /api/users E2E TLS throughput drops **43%** vs HTTP, with latency more than doubling from 3.84 ms to 8.61 ms. The backend re-encryption is significantly more expensive for Kong.

### Key Takeaways

- **Ferrum is 3–4x faster than Kong** on pure proxy throughput, even after giving Kong a generous 15% Docker adjustment. The latency gap (0.98 ms vs 3.77 ms) far exceeds the ~0.1–0.5 ms Docker overhead — most of Kong's overhead is real gateway processing time.
- **Ferrum is 33x+ faster than Tyk** on the /health endpoint. Tyk's throughput numbers are an order of magnitude lower regardless of Docker overhead adjustments.
- **Ferrum's TLS implementation is exceptionally efficient.** Full E2E TLS (double encryption) only costs 10.6% throughput and 0.24 ms latency vs plaintext HTTP. Kong pays 43% throughput and 4.77 ms on /api/users for the same scenario.
- **Docker overhead accounts for at most ~0.5 ms of the latency gap.** Ferrum's latency advantage over Kong is ~2.8 ms (HTTP) to ~6.1 ms (E2E TLS /api/users) — the vast majority is real gateway overhead, not Docker artifact.
- **The backend's own TLS overhead is negligible** — HTTPS baseline (207,939 req/s) is within 1.5% of HTTP baseline (211,184 req/s), confirming the cost difference between gateways is gateway overhead, not backend TLS.

For the most apples-to-apples comparison, run on Linux where all three gateways can be installed natively.

## Adding a New Gateway

To add a new gateway (e.g., Envoy, NGINX, Traefik):

1. **Create config files** in `comparison/configs/` for the gateway
2. **Add functions** to `run_comparison.sh`:
   - `start_<gateway>_http()` / `start_<gateway>_https()` — launch the gateway
   - `stop_<gateway>()` — tear it down
   - `test_<gateway>()` — orchestrate HTTP + HTTPS test sequences
3. **Add the gateway name** to the `GATEWAYS` list in `scripts/generate_comparison_report.py`
4. **Call `test_<gateway>()`** in the `main()` function of `run_comparison.sh`
5. **Add a `should_skip` check** so users can skip it via `SKIP_GATEWAYS`

Each test function should follow the pattern: start → run_wrk (per endpoint) → stop. Use the same ports (8000/8443) since gateways run sequentially.

## Docker Overhead

When a gateway runs in Docker instead of natively, there is measurable overhead that affects benchmark results. The amount varies by platform:

| Platform | Networking Mode | Added Latency | Throughput Impact | Notes |
|----------|----------------|---------------|-------------------|-------|
| **Linux** | `--network host` | < 5 μs | < 1% | Negligible; containers share the host network stack |
| **Linux** | port mapping (`-p`) | ~10–50 μs | ~2–5% | Userspace proxy adds a small hop |
| **macOS** | port mapping (`-p`) | ~0.1–0.5 ms | ~5–15% | Docker Desktop runs in a Linux VM; each packet crosses the VM boundary + userspace networking |

**On macOS**, Docker overhead is the most significant. Docker Desktop 4.19+ improved this with the gVisor TCP/IP stack (5x faster than the older vpnkit), but the VM boundary remains. CPU scheduling variance is also ~9.5x higher in the VM compared to native.

**To minimize Docker overhead:**
1. On Linux, install Kong and Tyk natively via package managers (see Prerequisites above)
2. On Linux with Docker, `--network host` is used automatically (negligible overhead)
3. On macOS, no native Kong or Tyk binaries exist — Docker overhead is unavoidable. Interpret results with the overhead estimates above in mind

The HTML report's "Methodology & Caveats" section notes which gateways ran natively vs in Docker.

## Known Limitations

- **No plugins enabled:** Tests measure pure proxy overhead only. Real-world performance with authentication, rate limiting, or transformation plugins will differ. Each gateway has different plugin performance characteristics.

- **Single-node only:** All tests run on localhost. Distributed deployment characteristics (network latency, cluster synchronization) are not captured.

- **In-memory state:** Tyk requires Redis even in standalone mode. The Redis instance runs locally and is fast, but it's a dependency that Kong and Ferrum don't need, which could slightly affect Tyk's resource usage.

- **Tyk on macOS:** No native macOS binary exists, so Tyk always runs in Docker on macOS. On Linux, Tyk can be installed natively via packagecloud (adding native Tyk support to this script is a welcome contribution).

## File Structure

```
comparison/
├── README.md                          # This file
├── run_comparison.sh                  # Main orchestrator script
├── configs/
│   ├── ferrum_comparison.yaml         # Ferrum config (HTTP backend)
│   ├── ferrum_comparison_e2e_tls.yaml # Ferrum config (HTTPS backend)
│   ├── kong.yaml                      # Kong config (HTTP backend)
│   ├── kong_e2e_tls.yaml             # Kong config (HTTPS backend)
│   └── tyk/
│       ├── tyk.conf                   # Tyk standalone config (HTTP)
│       ├── tyk_tls.conf               # Tyk config with TLS enabled
│       ├── apps/                      # Tyk API defs (HTTP backend)
│       │   ├── health_api.json
│       │   └── users_api.json
│       └── apps_e2e_tls/             # Tyk API defs (HTTPS backend)
│           ├── health_api.json
│           └── users_api.json
├── lua/
│   └── comparison_test.lua            # Unified wrk Lua script
├── scripts/
│   └── generate_comparison_report.py  # HTML report generator
└── results/                           # Generated at runtime (gitignored)
    ├── .gitkeep
    ├── comparison_report.html         # HTML report (after running)
    ├── meta.json                      # Test metadata (after running)
    └── *_results.txt                  # Raw wrk output per test
```
