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
| HTTP/1.1 | HTTP                 | HTTP                 | 8000         | 3001         |
| HTTP/1.1+TLS | HTTPS (ALPN http/1.1) | HTTP              | 8443         | 3001         |
| HTTP/2   | HTTPS + ALPN h2      | HTTPS + H2           | 8443         | 3443         |
| HTTP/3   | QUIC / HTTP3         | QUIC / HTTP3         | 8443         | 3445         |
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

Gateway configs are in `configs/`. Each protocol has its own YAML file that configures the appropriate `backend_protocol` and ports.

Key environment variables set by the test runner:

| Variable | Value | Purpose |
|----------|-------|---------|
| `FERRUM_MODE` | `file` | File-based config |
| `FERRUM_LOG_LEVEL` | `error` | Minimize logging overhead during benchmarks |
| `FERRUM_ADD_VIA_HEADER` | `false` | Skip Via header to reduce per-request overhead |
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | `200` | Prevent connection churn |
| `FERRUM_POOL_WARMUP_ENABLED` | `true` | Pre-establish backend connections at startup |
| `FERRUM_TLS_NO_VERIFY` | `true` | Accept self-signed certs |
| `FERRUM_ENABLE_HTTP3` | `true` | Enable QUIC listener (HTTP/3 test) |
| `FERRUM_FRONTEND_TLS_CERT_PATH` | `certs/cert.pem` | Gateway TLS cert |
| `FERRUM_DTLS_CERT_PATH` | `certs/cert.pem` | Gateway DTLS cert |
| `FERRUM_POOL_HTTP2_*` | (tuned) | H2 flow control: 8 MiB stream, 32 MiB conn windows |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | `1000` | Server-side H2 stream limit |
| `FERRUM_HTTP3_*` | (tuned) | H3/QUIC: 8 MiB stream, 32 MiB conn, 1000 max streams |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | `4` | QUIC connections per backend |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | H3 pool idle eviction timeout |
| `FERRUM_GRPC_POOL_READY_WAIT_MS` | `1` | gRPC pool sender wait before opening another backend H2 connection |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | `30` | Pool cleanup sweep interval (all pools) |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Max concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | UDP session cleanup interval |

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

Results from a local run on macOS (Apple Silicon), 10s duration, 200 concurrent connections, 64-byte echo payload.

### Through Gateway (client → gateway → backend)

| Protocol | Requests/sec | Avg Latency | P50 | P99 | Max | Errors |
|----------|-------------|-------------|------|------|------|--------|
| HTTP/1.1 | 102,183 | 1.96ms | 1.89ms | 3.85ms | 28.41ms | 0 |
| HTTP/1.1+TLS | 101,317 | 1.97ms | 1.90ms | 3.84ms | 26.25ms | 0 |
| HTTP/2 (TLS) | 108,138 | 1.85ms | 1.67ms | 6.38ms | 120.19ms | 0 |
| HTTP/3 (QUIC) | 53,085 | 3.76ms | 3.51ms | 5.87ms | 150.91ms | 0 |
| WebSocket | 103,830 | 1.92ms | 1.88ms | 3.15ms | 15.27ms | 0 |
| gRPC | 68,352 | 2.92ms | 2.53ms | 12.02ms | 128.06ms | 0 |
| TCP | 108,841 | 1.83ms | 1.83ms | 2.59ms | 10.63ms | 0 |
| TCP+TLS | 107,340 | 1.86ms | 1.84ms | 2.68ms | 13.35ms | 0 |
| UDP | 82,042 | 2.44ms | 2.46ms | 2.93ms | 10.24ms | 0 |
| UDP+DTLS | 76,107 | 2.61ms | 2.61ms | 3.69ms | 11.81ms | 0 |

### Direct Backend (client → backend, no gateway)

| Protocol | Requests/sec | Avg Latency | P50 | P99 | Max |
|----------|-------------|-------------|------|------|------|
| HTTP/1.1 | 209,910 | 951μs | 939μs | 1.81ms | 4.54ms |
| HTTP/1.1+TLS | 209,361* | 953μs | 941μs | 1.81ms | 5.24ms |
| HTTP/2 (TLS) | 355,544 | 561μs | 486μs | 1.53ms | 126.40ms |
| HTTP/3 (QUIC) | 83,592 | 2.39ms | 2.38ms | 2.80ms | 4.93ms |
| WebSocket | 207,507 | 962μs | 952μs | 1.72ms | 3.16ms |
| gRPC | 205,927 | 970μs | 821μs | 3.15ms | 90.81ms |
| TCP | 214,113 | 933μs | 928μs | 1.65ms | 8.48ms |
| TCP+TLS | 207,103 | 964μs | 949μs | 1.78ms | 9.51ms |
| UDP | 276,526 | 722μs | 682μs | 1.27ms | 3.48ms |
| UDP+DTLS | 101,839 | 1.95ms | 1.96ms | 2.47ms | 4.75ms |

*\*HTTP/1.1+TLS direct baseline uses plain HTTP since the backend has no TLS; the TLS overhead is entirely at the gateway.*

### Gateway Overhead

| Protocol | Gateway RPS | Direct RPS | Overhead | Notes |
|----------|------------|------------|----------|-------|
| HTTP/1.1 | 102,183 | 209,910 | ~51% | reqwest connection pool with keep-alive |
| HTTP/1.1+TLS | 101,317 | 209,361 | ~52% | TLS termination at gateway, plain HTTP to backend |
| HTTP/2 (TLS) | 108,138 | 355,544 | ~70% | hyper-native H2 pool with two-phase ready() multiplexing |
| HTTP/3 (QUIC) | 53,085 | 83,592 | ~37% | QUIC connection pool via quinn |
| WebSocket | 103,830 | 207,507 | ~50% | Upgrade overhead amortized over many messages |
| gRPC | 68,352 | 205,927 | ~67% | H2 multiplexing + protobuf passthrough |
| TCP | 108,841 | 214,113 | ~49% | Bidirectional copy, minimal per-byte overhead |
| TCP+TLS | 107,340 | 207,103 | ~48% | TLS termination + bidirectional copy (cached TLS config) |
| UDP | 82,042 | 276,526 | ~70% | Per-datagram session lookup + forwarding |
| UDP+DTLS | 76,107 | 101,839 | ~25% | DTLS termination + plain UDP forwarding |

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

Results from a local run on macOS (Apple Silicon M4 Max), 10s duration, 200 concurrent connections, 64-byte payload, Envoy 1.37.1.

```
=========================================================================================================
  Ferrum Edge vs Envoy — Through-Gateway Comparison
  Duration: 10s | Concurrency: 200 | Payload: 64 bytes
=========================================================================================================

| Protocol       |   Ferrum RPS |    Envoy RPS |    Δ RPS |  Winner |  Ferrum P50 |   Envoy P50 |  Ferrum P99 |   Envoy P99 |  Ferrum Avg |   Envoy Avg |
|----------------|--------------|--------------|----------|---------|-------------|-------------|-------------|-------------|-------------|-------------|
| http1          |       98,349 |       89,238 |   +10.2% |  Ferrum |      1.89ms |      1.55ms |      4.06ms |     16.48ms |      2.03ms |      2.24ms |
| http1-tls      |       89,973 |       81,584 |   +10.3% |  Ferrum |      2.06ms |      1.72ms |      4.54ms |     13.24ms |      2.22ms |      2.45ms |
| ws             |      102,200 |      106,593 |    -4.1% |  Envoy  |      1.88ms |      1.42ms |      3.32ms |      7.77ms |      1.95ms |      1.87ms |
| grpc           |       33,554 |       63,122 |   -46.8% |  Envoy  |      4.97ms |      2.18ms |     11.89ms |     48.00ms |      5.95ms |      3.16ms |
| tcp            |      107,439 |      105,222 |    +2.1% |  Ferrum |      1.82ms |      1.50ms |      2.85ms |     11.46ms |      1.86ms |      1.90ms |
| tcp-tls        |      105,433 |      105,461 |    -0.0% |   ~tie  |      1.85ms |      1.42ms |      3.27ms |      9.45ms |      1.89ms |      1.89ms |
| udp            |       81,170 |      126,355 |   -35.8% |  Envoy  |      2.47ms |      1.36ms |      3.02ms |      2.79ms |      2.46ms |      1.58ms |

======================================================================
  Gateway Overhead vs Direct Backend
======================================================================

| Protocol       |   Direct RPS |   Ferrum RPS |  Ferrum OH |    Envoy RPS |   Envoy OH |
|----------------|--------------|--------------|------------|--------------|------------|
| http1          |      200,684 |       98,349 |       ~50% |       89,238 |       ~55% |
| http1-tls      |      208,192 |       89,973 |       ~56% |       81,584 |       ~60% |
| ws             |      208,887 |      102,200 |       ~51% |      106,593 |       ~48% |
| grpc           |      189,130 |       33,554 |       ~82% |       63,122 |       ~66% |
| tcp            |      210,367 |      107,439 |       ~48% |      105,222 |       ~49% |
| tcp-tls        |      207,864 |      105,433 |       ~49% |      105,461 |       ~49% |
| udp            |      259,017 |       81,170 |       ~68% |      126,355 |       ~51% |
```

> **Key findings:** Ferrum Edge wins on HTTP/1.1 (+10%), HTTP/1.1+TLS (+10%), and TCP (+2%) with
> significantly better P99 tail latencies (2-4x lower across HTTP and TCP protocols). Envoy wins on
> gRPC throughput (+47% RPS) and UDP throughput (+36% RPS). WebSocket and TCP+TLS are effectively
> tied. Despite lower gRPC RPS, Ferrum's P99 latency is 4x better (11.89ms vs 48ms).

> **Note:** Benchmark numbers vary between runs. Focus on relative comparisons rather than absolute numbers.

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
