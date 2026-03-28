# Multi-Protocol Performance Tests

Performance test suite that benchmarks Ferrum Gateway across all supported protocols: HTTP/1.1, HTTP/1.1+TLS, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, TCP, TCP+TLS, UDP, and UDP+DTLS.

Each test runs a **three-tier setup**: `proto_bench` (load generator) &rarr; `ferrum-gateway` (proxy) &rarr; `proto_backend` (echo backend), then a direct baseline without the gateway for comparison.

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
                │proto_bench│ ──────► │ferrum-gateway  │ ──────► │proto_backend │
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
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | `200` | Prevent connection churn |
| `FERRUM_TLS_NO_VERIFY` | `true` | Accept self-signed certs |
| `FERRUM_ENABLE_HTTP3` | `true` | Enable QUIC listener (HTTP/3 test) |
| `FERRUM_PROXY_TLS_CERT_PATH` | `certs/cert.pem` | Gateway TLS cert |
| `FERRUM_DTLS_CERT_PATH` | `certs/cert.pem` | Gateway DTLS cert |
| `FERRUM_POOL_HTTP2_*` | (tuned) | H2 flow control: 8 MiB stream, 32 MiB conn windows |
| `FERRUM_HTTP3_*` | (tuned) | H3/QUIC: 8 MiB stream, 32 MiB conn, 1000 max streams |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | `4` | QUIC connections per backend |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | H3 pool idle eviction timeout |
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
| HTTP/1.1 | 90,063 | 2.22ms | 2.12ms | 4.70ms | 30.51ms | 0 |
| HTTP/1.1+TLS | 89,046 | 2.24ms | 2.14ms | 4.84ms | 42.17ms | 0 |
| HTTP/2 (TLS) | 100,530 | 1.99ms | 1.82ms | 6.13ms | 127.04ms | 0 |
| HTTP/3 (QUIC) | 49,188 | 4.06ms | 3.77ms | 7.54ms | 123.07ms | 0 |
| WebSocket | 111,852 | 1.78ms | 1.74ms | 3.15ms | 23.66ms | 0 |
| gRPC | 60,689 | 3.29ms | 2.96ms | 11.11ms | 47.65ms | 0 |
| TCP | 112,037 | 1.78ms | 1.74ms | 3.08ms | 24.72ms | 0 |
| TCP+TLS | 112,017 | 1.78ms | 1.74ms | 3.19ms | 19.65ms | 0 |
| UDP | 81,924 | 2.44ms | 2.45ms | 3.00ms | 10.96ms | 0 |
| UDP+DTLS | 75,150 | 2.53ms | 2.54ms | 4.41ms | 33.18ms | 0 |

### Direct Backend (client → backend, no gateway)

| Protocol | Requests/sec | Avg Latency | P50 | P99 | Max |
|----------|-------------|-------------|------|------|------|
| HTTP/1.1 | 221,572 | 901μs | 866μs | 1.82ms | 9.38ms |
| HTTP/1.1+TLS | 219,383* | 909μs | 865μs | 1.89ms | 76.48ms |
| HTTP/2 (TLS) | 354,711 | 562μs | 489μs | 1.74ms | 73.86ms |
| HTTP/3 (QUIC) | 90,448 | 2.21ms | 2.19ms | 3.26ms | 25.66ms |
| WebSocket | 222,932 | 895μs | 870μs | 1.74ms | 7.20ms |
| gRPC | 162,602 | 1.23ms | 974μs | 4.42ms | 366.08ms |
| TCP | 223,859 | 892μs | 865μs | 1.75ms | 16.43ms |
| TCP+TLS | 222,303 | 898μs | 869μs | 1.78ms | 6.67ms |
| UDP | 247,271 | 808μs | 738μs | 1.71ms | 6.81ms |
| UDP+DTLS | 101,452 | 1.87ms | 1.87ms | 2.95ms | 23.20ms |

*\*HTTP/1.1+TLS direct baseline uses plain HTTP since the backend has no TLS; the TLS overhead is entirely at the gateway.*

### Gateway Overhead

| Protocol | Gateway RPS | Direct RPS | Overhead | Notes |
|----------|------------|------------|----------|-------|
| HTTP/1.1 | 90,063 | 221,572 | ~59% | reqwest connection pool with keep-alive |
| HTTP/1.1+TLS | 89,046 | 219,383 | ~59% | TLS termination at gateway, plain HTTP to backend |
| HTTP/2 (TLS) | 100,530 | 354,711 | ~72% | hyper-native H2 pool with two-phase ready() multiplexing |
| HTTP/3 (QUIC) | 49,188 | 90,448 | ~46% | QUIC connection pool via quinn |
| WebSocket | 111,852 | 222,932 | ~50% | Upgrade overhead amortized over many messages |
| gRPC | 60,689 | 162,602 | ~63% | H2 multiplexing + protobuf passthrough |
| TCP | 112,037 | 223,859 | ~50% | Bidirectional copy, minimal per-byte overhead |
| TCP+TLS | 112,017 | 222,303 | ~50% | TLS termination + bidirectional copy (cached TLS config) |
| UDP | 81,924 | 247,271 | ~67% | Per-datagram session lookup + forwarding |
| UDP+DTLS | 75,150 | 101,452 | ~26% | DTLS termination + plain UDP forwarding |

## Prerequisites

- **Rust toolchain** (cargo, rustc)
- **protoc** (protobuf compiler) for gRPC support
- The following ports must be free: 3001-3006, 3010, 3443-3445, 5001, 5003-5004, 5010, 8000, 8443, 50052

Install protoc:
```bash
# macOS
brew install protobuf

# Ubuntu/Debian
sudo apt-get install protobuf-compiler
```

## Adding a New Protocol Test

1. Add a backend server in `proto_backend.rs`
2. Add a load generator subcommand in `proto_bench.rs`
3. Create a gateway config in `configs/<protocol>_perf.yaml`
4. Add `test_<protocol>()` and `stop_gateway` call in `run_protocol_test.sh`
