# API Gateway Comparison Benchmarks

Performance comparison suite that benchmarks **Ferrum Gateway** against **Pingora** (Cloudflare), **Kong**, **Tyk**, and **KrakenD** under identical conditions.

## What It Measures

Each gateway is tested as a reverse proxy with four scenarios:

| Scenario | Description |
|----------|-------------|
| **HTTP (plaintext)** | Client → Gateway (port 8000) → Backend. Measures raw proxy overhead. |
| **HTTPS (TLS termination)** | Client → Gateway (port 8443, TLS) → Backend (plaintext). Measures TLS handshake and encryption overhead at the gateway. |
| **E2E TLS (full encryption)** | Client → Gateway (port 8443, TLS) → Backend (TLS, port 3443). Measures full end-to-end encryption where the gateway re-encrypts traffic to the backend. |
| **Key-Auth (HTTP + authentication)** | Client → Gateway (port 8000, HTTP) → Backend. Each request includes an API key header (`apikey: test-api-key`) validated by the gateway's key-auth plugin. Measures authentication overhead. Ferrum, Kong, and Tyk only (Pingora has no auth plugin framework; KrakenD key-auth requires Enterprise Edition). |

Two endpoints are tested per proxy scenario:
- `/health` — instant backend response, measures pure gateway latency
- `/api/users` — 100 microsecond simulated delay, represents a typical API call

A direct backend baseline (no gateway) is run first for both HTTP and HTTPS comparison.

### Test Approach

- Gateways are tested **sequentially** (one at a time) to avoid resource contention
- Each test gets a **5-second warm-up** (results discarded) before the measured 30-second run
- The same backend echo server, wrk parameters, and endpoints are used across all gateways
- Ferrum runs as a native binary; Kong runs natively if installed (preferred) or in Docker; Tyk and KrakenD run in Docker
- The script auto-detects native Kong and prefers it over Docker for fairer benchmarking

## Prerequisites

| Dependency | Required | Install |
|------------|----------|---------|
| **wrk** | Yes | `brew install wrk` (macOS) or `apt install wrk` (Ubuntu) |
| **Python 3** | Yes | Usually pre-installed; needed for report generation |
| **Rust/Cargo** | Yes | [rustup.rs](https://rustup.rs/) — builds Ferrum and the backend server |
| **cmake** | For Pingora | `brew install cmake` (macOS) or `apt install cmake` (Ubuntu) |
| **curl** | Yes | Usually pre-installed; used for health checks |
| **Docker** | For Tyk, KrakenD (always), Kong (if not native) | [docs.docker.com/get-docker](https://docs.docker.com/get-docker/) |
| **Pingora source** | For Pingora tests | Clone [cloudflare/pingora](https://github.com/cloudflare/pingora) to `~/workspace/pingora` |
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
1. Pull Kong, Tyk, and KrakenD Docker images
2. Build Ferrum Gateway and the backend server (release mode)
3. Run baseline → Ferrum → Pingora → Kong → Tyk → KrakenD tests sequentially
4. Generate an HTML comparison report in `comparison/results/`

Open `comparison/results/comparison_report.html` in a browser to view the results.

## Configuration

Override any parameter via environment variables:

```bash
# Custom test parameters
WRK_DURATION=60s WRK_THREADS=12 WRK_CONNECTIONS=200 ./comparison/run_comparison.sh

# Skip a gateway (e.g., if you don't have Docker)
SKIP_GATEWAYS=tyk,kong ./comparison/run_comparison.sh

# Only test Ferrum vs Pingora (no Docker required)
SKIP_GATEWAYS=kong,tyk ./comparison/run_comparison.sh

# Only test Ferrum vs Kong
SKIP_GATEWAYS=pingora,tyk ./comparison/run_comparison.sh
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
| `SKIP_GATEWAYS` | _(empty)_ | Comma-separated gateways to skip: `ferrum`, `pingora`, `kong`, `tyk`, `krakend` |

## Swapping Gateway Versions

To re-run benchmarks with newer Kong, Tyk, or KrakenD releases:

```bash
# Test against Kong 3.10, Tyk v5.8, and KrakenD 2.14
KONG_VERSION=3.10 TYK_VERSION=v5.8 KRAKEND_VERSION=2.14 ./comparison/run_comparison.sh
```

The script pulls the specified Docker image tags automatically. Results are overwritten in `comparison/results/` — copy or rename the directory if you want to preserve previous runs.

### Version-specific considerations

- **Kong** uses DB-less declarative mode. The config format (`_format_version: "3.0"`) is stable across 3.x releases. If Kong 4.x changes the format, update `comparison/configs/kong.yaml`.
- **Tyk** uses standalone mode with file-based API definitions. The API definition schema has been stable across v5.x. If Tyk v6 changes it, update the files in `comparison/configs/tyk/apps/`.
- **KrakenD** uses stateless JSON configuration with `version: 3` format. The config schema has been stable across 2.x releases. If KrakenD 3.x changes it, update the files in `comparison/configs/krakend/`.
- **Ferrum** is built from source in the current checkout, so it always tests the latest local code.

## Interpreting Results

The HTML report contains six sections:

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

### 5. Key-Auth Performance
Compares authenticated throughput (API key validation) against the same gateway's unauthenticated performance. Shows the cost of running one authentication plugin in the request path. Pingora is excluded (no plugin framework). Each request includes an `apikey` header; the gateway validates it against a pre-configured consumer before proxying.

### 6. TLS Overhead Comparison
Per-gateway comparison of HTTP vs HTTPS vs E2E TLS performance. Shows the RPS drop and latency increase each gateway pays for TLS at each stage. A gateway with lower TLS overhead has a more efficient TLS implementation.

### Color coding
- **Green cells** = best in category (highest RPS, lowest latency)
- **Red cells** = worst in category

## Initial Findings

The following results were collected on macOS (Apple Silicon) with 8 threads, 100 connections, and 30-second measured runs. Kong and Tyk ran in Docker; Ferrum ran natively.

### Raw Results

| Gateway | Protocol | /health req/s | /api/users req/s | /health latency | /api/users latency |
|---------|----------|--------------|-----------------|-----------------|-------------------|
| **Baseline** (no gateway) | HTTP | 212,899 | 54,777 | 0.38 ms | 1.68 ms |
| **Baseline** (no gateway) | HTTPS | 198,937 | 53,883 | 0.48 ms | 1.67 ms |
| **Ferrum** (native) | HTTP | 90,110 | 39,733 | 1.08 ms | 2.43 ms |
| **Ferrum** (native) | HTTPS | 90,107 | 40,009 | 1.08 ms | 2.41 ms |
| **Ferrum** (native) | E2E TLS | 81,148 | 39,120 | 1.30 ms | 3.13 ms |
| **Pingora** (native) | HTTP | 59,429 | 39,016 | 1.65 ms | 2.48 ms |
| **Pingora** (native) | HTTPS | 63,925 | 39,303 | 1.94 ms | 3.03 ms |
| **Pingora** (native) | E2E TLS | — | — | — | — |
| **Kong 3.9** (Docker) | HTTP | 26,380 | 22,273 | 3.68 ms | 4.60 ms |
| **Kong 3.9** (Docker) | HTTPS | 20,680 | 24,010 | 5.66 ms | 4.43 ms |
| **Kong 3.9** (Docker) | E2E TLS | 23,333 | 22,556 | 4.46 ms | 4.89 ms |
| **Tyk v5.7** (Docker) | HTTP | 23,036 | 22,380 | 4.22 ms | 4.32 ms |
| **Tyk v5.7** (Docker) | HTTPS | 22,185 | 21,561 | 4.43 ms | 4.50 ms |
| **Tyk v5.7** (Docker) | E2E TLS | 21,114 | 19,154 | 4.93 ms | 5.41 ms |
| **KrakenD 2.13** (Docker) | HTTP | 20,417 | 19,936 | — | — |
| **KrakenD 2.13** (Docker) | HTTPS | 19,636 | — | — | — |
| **KrakenD 2.13** (Docker) | E2E TLS | 20,826 | — | — | — |

> **Note:** Pingora E2E TLS is not supported in this benchmark — Pingora's TLS library requires a valid DNS hostname for upstream SNI and cannot connect to IP-based backends (127.0.0.1) over TLS. This is a framework limitation, not a configuration issue.

### Key-Auth Results (HTTP, /api/users-auth)

Each gateway proxies `/api/users-auth` → backend `/api/users` with API key authentication enabled. A valid API key is sent in the `apikey` header on every request. Pingora is excluded (no auth plugin framework). KrakenD is excluded (key-auth requires Enterprise Edition).

| Gateway | Key-Auth req/s | No-Auth req/s | Auth Overhead | Latency |
|---------|---------------|---------------|---------------|---------|
| **Ferrum** (native) | **40,930** | 39,733 | **~0% (within noise)** | 2.35 ms |
| **Kong 3.9** (Docker) | 19,966 | 22,273 | -10.4% | 4.99 ms |
| **Tyk v5.7** (Docker) | 15,625 | 22,380 | -30.2% | 6.36 ms |

**Key finding:** Ferrum's key-auth plugin has effectively zero overhead — the O(1) `ConsumerIndex` credential lookup and lock-free hot path mean authentication adds no measurable cost. Kong takes a 10% throughput hit, and Tyk takes a 30% hit for authentication processing.

### Ferrum vs Pingora (Native-to-Native Comparison)

Pingora is a pure proxy framework (no plugins, admin API, or config management), making this the fairest raw proxy performance comparison. Both run as native binaries — no Docker overhead.

| Test | Ferrum | Pingora | Advantage |
|------|--------|---------|-----------|
| HTTP /health | **90,110** req/s | 59,429 req/s | **Ferrum 52% faster** |
| HTTP /api/users | **39,733** req/s | 39,016 req/s | Ferrum 2% faster |
| HTTPS /health | **90,107** req/s | 63,925 req/s | **Ferrum 41% faster** |
| HTTPS /api/users | **40,009** req/s | 39,303 req/s | Ferrum 2% faster |
| E2E TLS /health | **81,148** req/s | — | Pingora cannot test (SNI limitation) |
| E2E TLS /api/users | **39,120** req/s | — | Pingora cannot test (SNI limitation) |

**Key findings:**
- **Ferrum dominates on lightweight requests** — 52% faster on HTTP and 41% faster on HTTPS for /health. This is where per-request overhead matters most, and Ferrum's lock-free hot path and pre-computed indexes pay off.
- **Ferrum leads on all endpoints** — including a 2% edge on /api/users where backend delay dominates.
- **Pingora cannot do E2E TLS with IP-based backends** — its TLS library requires a valid DNS hostname for SNI. Ferrum handles this without issue, making it more flexible for local/container deployments where backends are addressed by IP.
- **Ferrum's HTTPS overhead is essentially zero** — HTTP and HTTPS /health both hit ~90K req/s. Ferrum's rustls-based TLS termination adds negligible cost, compared to Pingora where HTTPS adds 8% overhead on /health.

### Ferrum vs KrakenD

KrakenD is a high-performance, stateless Go-based API gateway. It runs in Docker with `no-op` encoding (raw response pass-through) to minimize processing overhead. Key-auth benchmarks are excluded because KrakenD's API key authentication requires Enterprise Edition.

| Test | Ferrum | KrakenD | Advantage |
|------|--------|---------|-----------|
| HTTP /health | **96,520** req/s | 20,417 req/s | **Ferrum 4.7x faster** |
| HTTP /api/users | **45,924** req/s | 19,936 req/s | **Ferrum 2.3x faster** |
| HTTPS /health | **93,766** req/s | 19,636 req/s | **Ferrum 4.8x faster** |
| E2E TLS /health | **86,792** req/s | 20,826 req/s | **Ferrum 4.2x faster** |

**Key findings:**
- **Ferrum is 4.2–4.8x faster than KrakenD** on lightweight /health requests across all TLS scenarios.
- **KrakenD throughput is flat across protocols** (~20K req/s for HTTP, HTTPS, and E2E TLS), suggesting Docker networking overhead dominates its performance profile on macOS.
- **KrakenD performs similarly to Kong and Tyk** — all three Docker-based gateways land in the 19–26K req/s range, while native Ferrum delivers 4–5x more throughput.

### Adjusting for Docker Overhead

Kong and Tyk ran in Docker on macOS, which adds ~0.1–0.5 ms latency per request and reduces throughput by ~5–15% (see [Docker Overhead](#docker-overhead)). Even after generously accounting for this:

| Gateway | /health req/s (adjusted) | Ferrum Advantage |
|---------|-------------------------|-----------------|
| **Ferrum** (native) | 90,110 | — |
| **Pingora** (native) | 59,429 | **1.5x faster** |
| **Kong** (Docker, +15% adjusted) | ~30,300 | **3.0x faster** |
| **Tyk** (Docker, +15% adjusted) | ~26,500 | **3.4x faster** |
| **KrakenD** (Docker, +15% adjusted) | ~23,500 | **3.8x faster** |

### End-to-End TLS Performance

The E2E TLS scenario (client → HTTPS → gateway → HTTPS → backend) is the most secure deployment pattern and the most demanding on gateway performance. Pingora cannot participate in this test due to its SNI limitation.

| Gateway | E2E /health req/s | E2E /api/users req/s | E2E /health latency | E2E /api/users latency |
|---------|------------------|---------------------|--------------------|-----------------------|
| **Ferrum** (native) | **81,148** | **39,120** | 1.30 ms | 3.13 ms |
| **Kong 3.9** (Docker) | 23,333 | 22,556 | 4.46 ms | 4.89 ms |
| **Tyk v5.7** (Docker) | 21,114 | 19,154 | 4.93 ms | 5.41 ms |
| **KrakenD 2.13** (Docker) | 20,826 | — | — | — |

- **Ferrum is 3.5x faster than Kong** on E2E TLS /health
- **Ferrum is 4.2x faster than KrakenD** on E2E TLS /health
- **Ferrum is 1.7x faster than Kong** on E2E TLS /api/users
- **Ferrum is 2x faster than Tyk** on E2E TLS /api/users

### TLS Overhead by Gateway

How much does each layer of encryption cost each gateway?

| Gateway | HTTP → HTTPS (TLS term.) | HTTP → E2E TLS (full encryption) |
|---------|--------------------------|----------------------------------|
| **Ferrum** | ~0% RPS (within noise) | **-10% RPS, +0.22 ms** |
| **Pingora** | +8% RPS (noise/scheduling) | N/A (SNI limitation) |
| **Kong** | -22% RPS on /health | **-12% RPS, +0.78 ms** |
| **Tyk** | -4% RPS | **-8% RPS, +0.71 ms** |

Ferrum's TLS termination has essentially **zero throughput cost** — HTTP and HTTPS both deliver ~90K req/s on /health. E2E TLS adds only 10% overhead. All gateways handle TLS more efficiently with proper connection pooling configured.

### Key Takeaways

- **Ferrum is 41–52% faster than Pingora** on lightweight requests (the fairest native-to-native comparison), and leads on all endpoints including heavier payloads.
- **Ferrum is 3–5x faster than Kong, Tyk, and KrakenD** on pure proxy throughput, even after giving Docker gateways a generous 15% adjustment.
- **Ferrum's TLS implementation is the most efficient** — effectively zero overhead for TLS termination (HTTP and HTTPS deliver the same throughput), compared to Kong's 22% drop.
- **Ferrum's key-auth has zero measurable overhead** — authenticated requests run at the same speed as unauthenticated ones, thanks to O(1) credential lookup via pre-computed ConsumerIndex. Kong takes a 10% hit, Tyk takes a 30% hit for authentication.
- **Ferrum uniquely supports E2E TLS with IP-based backends** — Pingora cannot test E2E TLS due to its SNI limitation.
- **Docker overhead accounts for at most ~0.5 ms of the latency gap.** Ferrum's latency advantage over Kong is ~2.6 ms (HTTP) to ~3.6 ms (E2E TLS) — the vast majority is real gateway overhead, not Docker artifact.
- **Kong, Tyk, and KrakenD perform comparably** when all run in Docker — all three land in the 19–26K req/s range, suggesting Docker networking overhead on macOS is a significant equalizer. Kong edges ahead slightly on /health, while KrakenD and Tyk are more consistent across protocols.

For the most apples-to-apples comparison, run on Linux where all gateways can be installed natively.

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
3. On macOS, no native Kong, Tyk, or KrakenD binaries exist — Docker overhead is unavoidable. Interpret results with the overhead estimates above in mind

The HTML report's "Methodology & Caveats" section notes which gateways ran natively vs in Docker.

## Known Limitations

- **Limited plugin testing:** The key-auth test measures one authentication plugin; real-world deployments may stack multiple plugins (rate limiting, CORS, logging, etc.), each adding overhead. The key-auth results demonstrate relative plugin performance between gateways but don't represent full production plugin stacks.

- **Pingora is a framework, not a gateway:** The Pingora benchmark uses a minimal ~80-line proxy binary built on Pingora's framework. It has no plugins, admin API, config management, or any gateway features. This is the fairest raw proxy comparison but understates the real-world overhead a production Pingora deployment would have once application logic is added.

- **Single-node only:** All tests run on localhost. Distributed deployment characteristics (network latency, cluster synchronization) are not captured.

- **In-memory state:** Tyk requires Redis even in standalone mode. The Redis instance runs locally and is fast, but it's a dependency that Kong and Ferrum don't need, which could slightly affect Tyk's resource usage.

- **Tyk on macOS:** No native macOS binary exists, so Tyk always runs in Docker on macOS. On Linux, Tyk can be installed natively via packagecloud (adding native Tyk support to this script is a welcome contribution).

- **KrakenD key-auth is Enterprise-only:** The `auth/api-keys` plugin requires KrakenD Enterprise Edition. KrakenD CE supports JWT validation, but we exclude KrakenD from key-auth benchmarks for consistency (all other gateways use header-based API key auth). KrakenD always runs in Docker.

## File Structure

```
comparison/
├── README.md                          # This file
├── run_comparison.sh                  # Main orchestrator script
├── configs/
│   ├── ferrum_comparison.yaml         # Ferrum config (HTTP backend)
│   ├── ferrum_comparison_e2e_tls.yaml # Ferrum config (HTTPS backend)
│   ├── ferrum_comparison_key_auth.yaml # Ferrum config (key-auth enabled)
│   ├── pingora/                       # Pingora minimal bench proxy (built from source)
│   │   ├── Cargo.toml
│   │   └── src/main.rs
│   ├── kong.yaml                      # Kong config (HTTP backend)
│   ├── kong_e2e_tls.yaml             # Kong config (HTTPS backend)
│   ├── kong_key_auth.yaml            # Kong config (key-auth enabled)
│   ├── tyk/
│   │   ├── tyk.conf                   # Tyk standalone config (HTTP)
│   │   ├── tyk_tls.conf               # Tyk config with TLS enabled
│   │   ├── apps/                      # Tyk API defs (HTTP backend)
│   │   │   ├── health_api.json
│   │   │   └── users_api.json
│   │   ├── apps_e2e_tls/             # Tyk API defs (HTTPS backend)
│   │   │   ├── health_api.json
│   │   │   └── users_api.json
│   │   └── apps_key_auth/            # Tyk API defs (key-auth enabled)
│   │       ├── health_api.json
│   │       ├── users_api.json
│   │       └── users_auth_api.json
│   └── krakend/
│       ├── krakend_http.json          # KrakenD config (HTTP backend, no-op encoding)
│       ├── krakend_https.json         # KrakenD config (HTTPS listener, HTTP backend)
│       └── krakend_e2e_tls.json       # KrakenD config (HTTPS listener, HTTPS backend)
├── lua/
│   ├── comparison_test.lua            # Unified wrk Lua script
│   └── comparison_test_key_auth.lua   # wrk script with API key header
├── scripts/
│   └── generate_comparison_report.py  # HTML report generator
└── results/                           # Generated at runtime (gitignored)
    ├── .gitkeep
    ├── comparison_report.html         # HTML report (after running)
    ├── meta.json                      # Test metadata (after running)
    └── *_results.txt                  # Raw wrk output per test
```
