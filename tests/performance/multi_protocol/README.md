# Multi-Protocol Performance Tests

Performance test suite that benchmarks Ferrum Edge across all supported protocols: HTTP/1.1, HTTP/1.1+TLS, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, TCP, TCP+TLS, UDP, and UDP+DTLS.

Each test runs a **three-tier setup**: `proto_bench` (load generator) &rarr; `ferrum-edge` (proxy) &rarr; `proto_backend` (echo backend), then a direct baseline without the gateway for comparison.

## Quick Start

```bash
cd tests/performance/multi_protocol

# Run a single protocol test
./run_protocol_test.sh http2

# Run all protocol tests sequentially
./run_protocol_test.sh all

# Custom parameters
./run_protocol_test.sh grpc --duration 60 --concurrency 200

# JSON output (for CI / scripting)
./run_protocol_test.sh tcp --json

# Compare Ferrum Edge vs Envoy (requires envoy in PATH)
./run_protocol_test.sh all --envoy

# Compare a single protocol against Envoy
./run_protocol_test.sh http2 --envoy --duration 30 --concurrency 200
```

## Supported Protocols

| Protocol | Client &rarr; Gateway | Gateway &rarr; Backend | Gateway Port | Backend Port |
|----------|----------------------|----------------------|--------------|--------------|
| HTTP/1.1 | HTTP (POST /echo)    | HTTP (echo)          | 8000         | 3001         |
| HTTP/1.1+TLS | HTTPS (ALPN http/1.1, POST /echo) | HTTP (echo) | 8443   | 3001         |
| HTTP/2   | HTTPS + ALPN h2 (POST /echo) | HTTPS + H2 (echo) | 8443     | 3443         |
| HTTP/3   | QUIC / HTTP3 (POST /echo) | QUIC / HTTP3 (echo) | 8443     | 3445         |
| WebSocket| ws:// upgrade        | ws://                | 8000         | 3003         |
| gRPC     | h2c (HTTP/2 clear)   | h2c                  | 8000         | 50052        |
| TCP      | raw TCP              | raw TCP              | 5010         | 3004         |
| TCP+TLS  | TLS &rarr; gateway terminates | raw TCP       | 5001         | 3004         |
| UDP      | raw UDP              | raw UDP              | 5003         | 3005         |
| UDP+DTLS | DTLS &rarr; gateway terminates | raw UDP      | 5004         | 3005         |

## Architecture

```
                ┌───────────┐         ┌───────────────┐         ┌──────────────┐
                │proto_bench│ ──────► │ferrum-edge  │ ──────► │proto_backend │
                │(load gen) │         │(reverse proxy) │         │(echo server) │
                └───────────┘         └───────────────┘         └──────────────┘
                                           │
                proto_bench ───────────────►│ (direct baseline, no gateway)
```

### proto_backend

Multi-protocol echo backend that starts all servers on fixed ports:

| Server       | Port  | Description                         |
|-------------|-------|--------------------------------------|
| HTTP/1.1    | 3001  | HTTP/1.1 with keep-alive            |
| HTTP/2 h2c  | 3002  | Cleartext HTTP/2 with prior knowledge|
| HTTPS/H2    | 3443  | HTTP/2 over TLS (ALPN negotiated)    |
| WebSocket   | 3003  | WS echo (text + binary)             |
| gRPC h2c    | 50052 | Protobuf BenchService (UnaryEcho)   |
| TCP echo    | 3004  | Bidirectional byte echo             |
| TCP+TLS     | 3444  | TLS-wrapped TCP echo                |
| UDP echo    | 3005  | Datagram echo                       |
| HTTP/3      | 3445  | QUIC/HTTP3 server                   |
| DTLS echo   | 3006  | DTLS-wrapped datagram echo          |

Self-signed TLS certificates are generated at startup into `./certs/` (gitignored).

### proto_bench

Load testing binary with subcommands for each protocol:

```
proto_bench <http1|http2|http3|ws|grpc|tcp|udp> [OPTIONS]

Options:
  --target <URL|ADDR>     Target URL or address
  --duration <SECS>       Test duration (default: 30)
  --concurrency <N>       Concurrent connections (default: 100)
  --payload-size <BYTES>  Payload for echo tests (default: 64)
  --tls                   Use TLS/DTLS for TCP/UDP tests
  --json                  Output JSON instead of text
```

## Configuration

Gateway configs are in `configs/`. Each protocol has its own YAML file that configures the appropriate `backend_scheme` and ports.

Key environment variables set by the test runner:

| Variable | Value | Purpose |
|----------|-------|---------|
| `FERRUM_MODE` | `file` | File-based config |
| `FERRUM_LOG_LEVEL` | `error` | Minimize logging overhead during benchmarks |
| `FERRUM_ADD_VIA_HEADER` | `false` | Skip Via header to reduce per-request overhead |
| `FERRUM_ADD_FORWARDED_HEADER` | `false` | Skip Forwarded header construction |
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | `0` | Disable request body size checking (no plugins = safe) |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | `0` | Take fastest streaming path (no size limit checks) |
| `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` | `0` | Disable slowloris timer (avoids per-connection timer overhead) |
| `FERRUM_MAX_CONNECTIONS` | `0` | Disable connection semaphore (unlimited) |
| `FERRUM_MAX_HEADER_COUNT` | `0` | Disable per-request header count check |
| `FERRUM_MAX_URL_LENGTH_BYTES` | `0` | Disable per-request URL length check |
| `FERRUM_MAX_QUERY_PARAMS` | `0` | Disable per-request query param count check |
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | `200` | Prevent connection churn |
| `FERRUM_POOL_WARMUP_ENABLED` | `true` | Pre-establish backend connections at startup |
| `FERRUM_TLS_NO_VERIFY` | `true` | Accept self-signed certs |
| `FERRUM_ENABLE_HTTP3` | `true` | Enable QUIC listener (HTTP/3 test) |
| `FERRUM_FRONTEND_TLS_CERT_PATH` | `certs/cert.pem` | Gateway TLS cert |
| `FERRUM_DTLS_CERT_PATH` | `certs/cert.pem` | Gateway DTLS cert |
| `FERRUM_POOL_HTTP2_*` | (tuned) | H2 flow control: 8 MiB stream, 32 MiB conn windows |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | `1000` | Server-side H2 stream limit |
| `FERRUM_HTTP3_*` | (tuned) | H3/QUIC: 8 MiB stream, 32 MiB conn, 1000 max streams |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | `8` | QUIC connections per backend |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | H3 pool idle eviction timeout |
| `FERRUM_GRPC_POOL_READY_WAIT_MS` | `1` | gRPC pool sender wait before opening another backend H2 connection |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | `30` | Pool cleanup sweep interval (all pools) |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Max concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | UDP session cleanup interval |
| `FERRUM_UDP_RECVMMSG_BATCH_SIZE` | `64` | Batched UDP recv (Linux only, falls back to try_recv_from on macOS) |

## Metrics Output

Text output (wrk-like format):

```
Running 30s test @ https://127.0.0.1:8443/api/users
  Protocol: HTTP/2
  100 concurrent connections

  Latency     Avg         Stdev       Max         +/- Stdev
              1.23ms      456.78us    12.34ms     72.31%

  Latency Distribution
     50%    1.05ms
     75%    1.45ms
     90%    2.10ms
     99%    5.80ms

  158340 requests in 30.00s, 22.45MB read
  Errors: 0

Requests/sec:  5278.00
Transfer/sec:      0.75MB
```

JSON output (`--json`):

```json
{
  "protocol": "HTTP/2",
  "target": "https://127.0.0.1:8443/api/users",
  "duration_secs": 30,
  "concurrency": 100,
  "total_requests": 158340,
  "total_errors": 0,
  "rps": 5278.0,
  "latency_avg_us": 1230,
  "latency_stdev_us": 456,
  "latency_max_us": 12340,
  "p50_us": 1050,
  "p75_us": 1450,
  "p90_us": 2100,
  "p99_us": 5800,
  "total_bytes": 23534280,
  "throughput_mbps": 6.28
}
```

## Benchmark Results

**Date**: 2026-04-12
**Environment**: macOS Darwin 25.4.0, Apple Silicon
**Duration**: 10s per test, 200 concurrent connections
**Payload**: 10 KB echo (POST with body, backend echoes full payload) for HTTP, H2, H3, WebSocket, gRPC, TCP, TCP+TLS; 2 KB for UDP, UDP+DTLS
**Build**: Release build with native H3 backend dispatch (h3+quinn replacing reqwest for HTTP/3 backend, unified H3 frontend with main proxy dispatch)

### Through Gateway (client → gateway → backend)

| Protocol | Payload | Requests/sec | Avg Latency | P50 | P99 | Max | Errors |
|----------|---------|-------------|-------------|------|------|------|--------|
| HTTP/1.1 | 10 KB | 87,702 | 2.28ms | 2.18ms | 4.65ms | 36.51ms | 0 |
| HTTP/1.1+TLS | 10 KB | 76,041 | 2.62ms | 2.51ms | 5.34ms | 58.56ms | 0 |
| HTTP/2 (TLS) | 10 KB | 28,671 | 6.97ms | 6.80ms | 11.89ms | 33.28ms | 0 |
| HTTP/3 (QUIC) | 10 KB | 6,216 | 32.17ms | 34.24ms | 79.10ms | 3.04s | 0 |
| WebSocket | 10 KB | 98,709 | 2.02ms | 1.98ms | 3.31ms | 34.27ms | 0 |
| gRPC | 10 KB | 26,358 | 7.58ms | 7.50ms | 12.89ms | 38.37ms | 0 |
| TCP | 10 KB | 91,550 | 2.18ms | 2.16ms | 2.67ms | 13.49ms | 0 |
| TCP+TLS | 10 KB | 86,294 | 2.31ms | 2.29ms | 3.18ms | 26.59ms | 0 |
| UDP | 2 KB | 81,353 | 2.46ms | 2.48ms | 2.95ms | 13.56ms | 0 |
| UDP+DTLS | 2 KB | 76,067 | 2.61ms | 2.34ms | 7.03ms | 201.73ms | 0 |

### Direct Backend (client → backend, no gateway)

| Protocol | Payload | Requests/sec | Avg Latency | P50 | P99 | Max |
|----------|---------|-------------|-------------|------|------|------|
| HTTP/1.1 | 10 KB | 200,268 | 996μs | 972μs | 2.00ms | 47.30ms |
| HTTP/1.1+TLS | 10 KB | 200,126* | 997μs | 973μs | 1.99ms | 28.67ms |
| HTTP/2 (TLS) | 10 KB | 145,204 | 1.38ms | 1.17ms | 4.75ms | 131.33ms |
| HTTP/3 (QUIC) | 10 KB | 5,008 | 39.97ms | 37.34ms | 88.58ms | 144.38ms |
| WebSocket | 10 KB | 187,129 | 1.07ms | 1.04ms | 2.15ms | 34.27ms |
| gRPC | 10 KB | 111,337 | 1.79ms | 1.53ms | 6.13ms | 125.31ms |
| TCP | 10 KB | 180,514 | 1.11ms | 1.08ms | 1.47ms | 8.58ms |
| TCP+TLS | 10 KB | 146,955 | 1.36ms | 1.29ms | 3.03ms | 40.64ms |
| UDP | 2 KB | 254,386 | 785μs | 730μs | 1.46ms | 13.87ms |
| UDP+DTLS | 2 KB | 109,130 | 1.82ms | 1.84ms | 2.41ms | 22.11ms |

*\*HTTP/1.1+TLS direct baseline uses plain HTTP since the backend has no TLS; the TLS overhead is entirely at the gateway.*

### Gateway Overhead

| Protocol | Gateway RPS | Direct RPS | Overhead | Notes |
|----------|------------|------------|----------|-------|
| HTTP/1.1 | 87,702 | 200,268 | ~56% | reqwest connection pool with keep-alive, 10 KB echo |
| HTTP/1.1+TLS | 76,041 | 200,126 | ~62% | TLS termination + 10 KB body crypto overhead |
| HTTP/2 (TLS) | 28,671 | 145,204 | ~80% | H2 multiplexing with 10 KB framed bodies |
| HTTP/3 (QUIC) | 6,216 | 5,008 | +24%‡ | Native h3+quinn; gateway faster than direct backend |
| WebSocket | 98,709 | 187,129 | ~47% | Tunnel mode (raw TCP copy, no frame parsing) |
| gRPC | 26,358 | 111,337 | ~76% | H2 multiplexing + protobuf passthrough, 10 KB payload |
| TCP | 91,550 | 180,514 | ~49% | Bidirectional copy with adaptive buffer sizing |
| TCP+TLS | 86,294 | 146,955 | ~41% | TLS termination + bidirectional copy |
| UDP | 81,353 | 254,386 | ~68% | Per-datagram session lookup + forwarding, 2 KB |
| UDP+DTLS | 76,067 | 109,130 | ~30% | DTLS termination + plain UDP forwarding, 2 KB |

‡*HTTP/3 gateway outperforming the direct backend is an artifact of the h3-quinn echo server being CPU-bound at 10 KB × 200 concurrency — the direct backend bottlenecks on QUIC crypto overhead.*

### Impact of 10 KB Payloads vs Prior 64-Byte Results

Prior results used GET requests to a fixed JSON endpoint (no request body, ~60-byte response). Current results use POST with 10 KB request body echoed back (10 KB response). UDP uses 2 KB payloads in both runs.

| Protocol | 64B RPS (prior) | 10KB RPS (current) | Delta | Notes |
|----------|----------------|-------------------|-------|-------|
| HTTP/1.1 | 97,179 | 87,702 | -9.8% | Body copy + larger transfer overhead |
| HTTP/1.1+TLS | 97,765 | 76,041 | -22.2% | TLS encryption of 10 KB body is significant |
| HTTP/2 (TLS) | 57,257 | 28,671 | -49.9% | H2 framing + flow control scales with body size |
| HTTP/3 (QUIC) | 7,534 | 6,216 | -17.5% | Already slow; QUIC crypto adds proportional overhead |
| WebSocket | 103,404 | 98,709 | -4.5% | Tunnel mode — minimal frame overhead with larger payload |
| gRPC | 34,564 | 26,358 | -23.7% | Protobuf serialization + H2 framing for larger payloads |
| TCP | 104,609 | 91,550 | -12.5% | Larger buffer copies |
| TCP+TLS | 105,519 | 86,294 | -18.2% | TLS encryption of 10 KB chunks |
| UDP | 81,166 | 81,353 | +0.2% | 2 KB payload in both; within run-to-run variance |

> **Key insight — payload size reveals true protocol cost**: With 64-byte payloads, per-request framing overhead dominates and all protocols look similar. With 10 KB payloads, the cost of body encryption (TLS/QUIC), H2/H3 framing, and serialization becomes visible. WebSocket tunnel mode and raw TCP show the smallest payload-size penalty because they bypass frame parsing. HTTP/2 shows the largest penalty (-50%) because H2 flow control and framing scale poorly with body size at high concurrency.

> **HTTP/3 remains regressed**: The native h3+quinn backend dispatch (#349) continues to show poor throughput (6,216 RPS via gateway). The prior reqwest-backed path auto-negotiated HTTP/2 via ALPN which outperformed native QUIC. This confirms the CLAUDE.md warning: "Don't replace reqwest with H3 pool for HTTP/3 frontend→backend."

> **Note:** Benchmark numbers vary between runs due to system load, thermal
> throttling, and background processes. Focus on the overhead ratios and relative
> comparisons rather than absolute RPS numbers.

> Tuning note: in one back-to-back local comparison, lowering the gRPC pool
> sender-ready wait from `5ms` to `1ms` improved gateway throughput by about
> `3.8%` (`64,278` -> `66,734` requests/sec at `10s`, `200` concurrency).
> Ferrum now defaults this knob to `1ms` via `FERRUM_GRPC_POOL_READY_WAIT_MS`.

## Envoy Comparison Mode

The `--envoy` flag runs each protocol benchmark through both Ferrum Edge and Envoy (native binary), using the **same backend, same load generator, same ports** — a true apples-to-apples comparison.

```bash
# Compare all supported protocols
./run_protocol_test.sh all --envoy --duration 30 --concurrency 200

# Compare a single protocol
./run_protocol_test.sh grpc --envoy
```

### How It Works

For each protocol, the runner:

1. Starts Ferrum Edge with its config, runs `proto_bench`, captures JSON results, stops Ferrum
2. Starts Envoy with an equivalent config, runs `proto_bench`, captures JSON results, stops Envoy
3. Runs the direct-backend baseline (same for both)
4. After all protocols, prints a comparison table

Both gateways run natively (no Docker), bind the same ports (sequentially), and connect to the same `proto_backend` echo server.

### Envoy-Compared Protocols

| Protocol | Envoy Config | Notes |
|----------|-------------|-------|
| HTTP/1.1 | `configs/envoy/http1.yaml` | `http_connection_manager` with `codec_type: HTTP1` |
| HTTP/1.1+TLS | `configs/envoy/http1_tls.yaml` | Downstream TLS termination, plain HTTP to backend |
| WebSocket | `configs/envoy/ws.yaml` | `upgrade_configs: websocket` on HCM |
| gRPC | `configs/envoy/grpc.yaml` | h2c (cleartext HTTP/2) on both sides |
| TCP | `configs/envoy/tcp.yaml` | `tcp_proxy` network filter |
| TCP+TLS | `configs/envoy/tcp_tls.yaml` | Downstream TLS + `tcp_proxy` |
| UDP | `configs/envoy/udp.yaml` | `udp_proxy` listener filter with matcher-based routing |

**Skipped protocols:**
- **HTTP/2** — hyper's raw h2c client gets `ConnectionReset` from Envoy on macOS (known h2c compatibility issue); gRPC already covers HTTP/2 semantics via tonic which works fine
- **HTTP/3 (QUIC)** — Envoy's QUIC support requires a special build with BoringSSL
- **UDP+DTLS** — No native Envoy DTLS termination

### Envoy Tuning

Envoy configs are tuned to match Ferrum Edge where applicable:

- HTTP/2 flow control: 8 MiB stream window, 32 MiB connection window, 1000 max concurrent streams
- Access logging disabled (`access_log: []`)
- Log level: `error` (`-l error`)
- Worker threads: auto (`--concurrency auto`, matches CPU cores)
- Admin interface on port 15000 (not benchmarked)

### Sample Comparison Output

Results from a prior local run on macOS (Apple Silicon M4 Max), 10s duration, 200 concurrent connections, 64-byte payload (pre-echo refactor), Envoy 1.37.1.

```
=========================================================================================================
  Ferrum Edge vs Envoy — Through-Gateway Comparison
  Duration: 10s | Concurrency: 200 | Payload: 64 bytes
=========================================================================================================

| Protocol       |   Ferrum RPS |    Envoy RPS |    Δ RPS |  Winner |  Ferrum P50 |   Envoy P50 |  Ferrum P99 |   Envoy P99 |  Ferrum Avg |   Envoy Avg |
|----------------|--------------|--------------|----------|---------|-------------|-------------|-------------|-------------|-------------|-------------|
| http1          |       96,623 |       92,766 |    +4.2% |  Ferrum |      1.97ms |      1.64ms |      4.36ms |     14.40ms |      2.07ms |      2.25ms |
| http1-tls      |      101,445 |       95,403 |    +6.3% |  Ferrum |      1.90ms |      1.68ms |      3.83ms |     13.56ms |      1.97ms |      2.20ms |
| ws             |      106,788 |      106,781 |    +0.0% |   ~tie  |      1.85ms |      1.48ms |      2.60ms |      6.72ms |      1.87ms |      1.89ms |
| grpc           |       37,920 |       81,798 |   -53.6% |  Envoy  |      5.24ms |      1.19ms |      8.07ms |     25.20ms |      5.27ms |      2.96ms |
| tcp            |      107,097 |      106,779 |    +0.3% |   ~tie  |      1.85ms |      1.44ms |      2.53ms |      4.72ms |      1.86ms |      1.89ms |
| tcp-tls        |      106,404 |      105,858 |    +0.5% |   ~tie  |      1.85ms |      1.43ms |      2.64ms |      7.00ms |      1.88ms |      1.91ms |
| udp            |       82,734 |      135,843 |   -39.1% |  Envoy  |      2.43ms |      1.45ms |      2.88ms |      2.17ms |      2.42ms |      1.55ms |

======================================================================
  Gateway Overhead vs Direct Backend
======================================================================

| Protocol       |   Direct RPS |   Ferrum RPS |  Ferrum OH |    Envoy RPS |   Envoy OH |
|----------------|--------------|--------------|------------|--------------|------------|
| http1          |      207,867 |       96,623 |       ~53% |       92,766 |       ~55% |
| http1-tls      |      207,308 |      101,445 |       ~51% |       95,403 |       ~54% |
| ws             |      205,168 |      106,788 |       ~48% |      106,781 |       ~48% |
| grpc           |      211,749 |       37,920 |       ~82% |       81,798 |       ~61% |
| tcp            |      208,072 |      107,097 |       ~48% |      106,779 |       ~49% |
| tcp-tls        |      204,016 |      106,404 |       ~48% |      105,858 |       ~48% |
| udp            |      281,766 |       82,734 |       ~71% |      135,843 |       ~52% |
```

### Ferrum Edge vs Envoy 1.37.1

| Protocol | Ferrum RPS | Envoy RPS | Δ RPS | Winner | Ferrum P99 | Envoy P99 |
|----------|-----------|-----------|-------|--------|-----------|-----------|
| HTTP/1.1 | 96,623 | 92,766 | +4.2% | Ferrum | 4.36ms | 14.40ms |
| HTTP/1.1+TLS | 101,445 | 95,403 | +6.3% | Ferrum | 3.83ms | 13.56ms |
| WebSocket | 106,788 | 106,781 | +0.0% | ~tie | 2.60ms | 6.72ms |
| gRPC | 37,920 | 81,798 | -53.6% | Envoy | 8.07ms | 25.20ms |
| TCP | 107,097 | 106,779 | +0.3% | ~tie | 2.53ms | 4.72ms |
| TCP+TLS | 106,404 | 105,858 | +0.5% | ~tie | 2.64ms | 7.00ms |
| UDP | 82,734 | 135,843 | -39.1% | Envoy | 2.88ms | 2.17ms |

> **Note:** HTTP/2, HTTP/3, and UDP+DTLS are omitted from the Envoy comparison:
> HTTP/2 (hyper h2c client incompatible with Envoy on macOS — gRPC covers H2 semantics),
> HTTP/3/UDP+DTLS (no standard Envoy equivalent).

### Analysis

**Where Ferrum Edge wins:**

1. **HTTP/1.1 (+4.2%)** — Ferrum beats Envoy on raw throughput with significantly better P99 tail latency (4.36ms vs 14.40ms — 3.3× better). The reqwest connection pool with keep-alive, response body coalescing, and frequency-aware router cache provide consistent performance.

2. **HTTP/1.1+TLS (+6.3%)** — Ferrum's largest advantage. TLS termination via rustls outperforms Envoy's BoringSSL at this concurrency level, with P99 of 3.83ms vs 13.56ms (3.5× better). This confirms rustls is highly competitive for TLS proxy workloads.

3. **TCP (~tie, +0.3%)** — Near-identical throughput with bidirectional `copy_bidirectional` and adaptive buffer sizing. On Linux, `splice(2)` zero-copy relay further reduces CPU overhead for plaintext TCP paths. Ferrum's P99 is 1.9× better (2.53ms vs 4.72ms).

4. **TCP+TLS (~tie, +0.5%)** — TLS termination + raw TCP proxying is effectively tied on throughput, with Ferrum again showing 2.7× better P99 (2.64ms vs 7.00ms).

5. **WebSocket (~tie, +0.0%)** — Tunnel mode (raw TCP copy with no frame parsing) matches Envoy's WebSocket proxying. Ferrum's P99 is 2.6× better (2.60ms vs 6.72ms).

**Where Envoy wins:**

1. **gRPC (-53.6%)** — Envoy's largest advantage. Envoy's native HTTP/2 codec (C++ with writev scatter-gather I/O) achieves 82K RPS vs Ferrum's 38K RPS for small (64-byte) gRPC payloads. However, Ferrum's P99 is 3.1× better (8.07ms vs 25.20ms), meaning Ferrum delivers more predictable latency despite lower peak throughput. As payload size increases (see `tests/performance/payload_size/`), Ferrum's H2 response coalescing closes the gap and wins at 10KB+ payloads.

2. **UDP (-39.1%)** — Envoy uses GRO (Generic Receive Offload) to batch UDP datagrams at the kernel level. Ferrum's `recvmmsg(2)` batching is Linux-only; on macOS it falls back to per-datagram `try_recv_from`. Re-benchmark on Linux where `FERRUM_UDP_RECVMMSG_BATCH_SIZE=64` enables batched recv to close this gap.

**P99 tail latency — Ferrum's consistent advantage:**

Across every protocol where both proxies are compared, Ferrum delivers **1.9-3.5× better P99 tail latency**:

| Protocol | Ferrum P99 | Envoy P99 | Ratio |
|----------|-----------|-----------|-------|
| HTTP/1.1 | 4.36ms | 14.40ms | 3.3× better |
| HTTP/1.1+TLS | 3.83ms | 13.56ms | 3.5× better |
| WebSocket | 2.60ms | 6.72ms | 2.6× better |
| gRPC | 8.07ms | 25.20ms | 3.1× better |
| TCP | 2.53ms | 4.72ms | 1.9× better |
| TCP+TLS | 2.64ms | 7.00ms | 2.7× better |
| UDP | 2.88ms | 2.17ms | 0.8× (Envoy better) |

This means Ferrum provides more predictable latency under load — critical for SLA-sensitive traffic where P99 matters more than peak throughput.

## Prerequisites

- **Rust toolchain** (cargo, rustc)
- **protoc** (protobuf compiler) for gRPC support
- **Envoy** (optional, for `--envoy` comparison mode)
- The following ports must be free: 3001-3006, 3010, 3443-3445, 5001, 5003-5004, 5010, 8000, 8443, 50052
- Port 15000 must also be free when using `--envoy` (Envoy admin)

Install dependencies:
```bash
# macOS
brew install protobuf
brew install envoy   # optional, for --envoy mode

# Ubuntu/Debian
sudo apt-get install protobuf-compiler
# See https://www.envoyproxy.io/docs/envoy/latest/start/install for Envoy
```

## Adding a New Protocol Test

1. Add a backend server in `proto_backend.rs`
2. Add a load generator subcommand in `proto_bench.rs`
3. Create a gateway config in `configs/<protocol>_perf.yaml`
4. Add `test_<protocol>()` and `stop_gateway` call in `run_protocol_test.sh`
5. (Optional) Add an Envoy config in `configs/envoy/<protocol>.yaml` and register in `envoy_compare_protocol()`
