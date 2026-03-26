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
| `FERRUM_BACKEND_TLS_NO_VERIFY` | `true` | Accept self-signed certs |
| `FERRUM_ENABLE_HTTP3` | `true` | Enable QUIC listener (HTTP/3 test) |
| `FERRUM_PROXY_TLS_CERT_PATH` | `certs/cert.pem` | Gateway TLS cert |
| `FERRUM_DTLS_CERT_PATH` | `certs/cert.pem` | Gateway DTLS cert |

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
| HTTP/1.1 | 88,773 | 2.25ms | 2.18ms | 3.93ms | 54.37ms | 0 |
| HTTP/1.1+TLS | 85,210 | 2.34ms | 2.25ms | 4.24ms | 69.89ms | 0 |
| HTTP/2 (TLS) | 49,223 | 4.06ms | 3.87ms | 8.16ms | 34.30ms | 0 |
| HTTP/3 (QUIC) | 39,581 | 5.04ms | 4.60ms | 12.17ms | 105.28ms | 0 |
| WebSocket | 104,465 | 1.91ms | 1.82ms | 3.75ms | 73.41ms | 0 |
| gRPC | 34,470 | 5.80ms | 5.68ms | 9.81ms | 77.38ms | 0 |
| TCP | 108,332 | 1.84ms | 1.76ms | 3.60ms | 40.83ms | 0 |
| TCP+TLS | 112,152 | 1.78ms | 1.75ms | 2.92ms | 10.23ms | 0 |
| UDP | 79,029 | 2.53ms | 2.52ms | 3.38ms | 27.87ms | 0 |
| UDP+DTLS | 74,098 | 2.57ms | 2.53ms | 4.28ms | 99.33ms | 0 |

### Direct Backend (client → backend, no gateway)

| Protocol | Requests/sec | Avg Latency | P50 | P99 | Max |
|----------|-------------|-------------|------|------|------|
| HTTP/1.1 | 100,112 | 2.00ms | 2.07ms | 2.88ms | 11.29ms |
| HTTP/1.1+TLS | 98,935* | 2.02ms | 2.08ms | 3.17ms | 25.17ms |
| HTTP/2 (TLS) | 109,162 | 1.83ms | 1.91ms | 2.78ms | 8.06ms |
| HTTP/3 (QUIC) | 67,866 | 2.94ms | 2.80ms | 4.74ms | 79.17ms |
| WebSocket | 219,620 | 909μs | 881μs | 1.80ms | 7.34ms |
| gRPC | 118,650 | 1.68ms | 1.43ms | 5.62ms | 44.90ms |
| TCP | 215,646 | 926μs | 883μs | 1.97ms | 24.57ms |
| TCP+TLS | 221,520 | 901μs | 876μs | 1.75ms | 8.24ms |
| UDP | 228,705 | 873μs | 759μs | 2.05ms | 15.46ms |
| UDP+DTLS | —** | — | — | — | — |

*\*HTTP/1.1+TLS direct baseline uses plain HTTP since the backend has no TLS; the TLS overhead is entirely at the gateway.*
*\*\*UDP+DTLS direct backend cannot be tested at 200 connections due to webrtc\_dtls library limitation with concurrent DTLS handshakes. Gateway-proxied DTLS works fine (74K ops/sec) because the gateway terminates DTLS and forwards plain UDP.*

### Gateway Overhead

| Protocol | Gateway RPS | Direct RPS | Overhead | Notes |
|----------|------------|------------|----------|-------|
| HTTP/1.1 | 88,773 | 100,112 | ~11% | reqwest connection pool with keep-alive |
| HTTP/1.1+TLS | 85,210 | 98,935 | ~14% | TLS termination at gateway, plain HTTP to backend |
| HTTP/2 (TLS) | 49,223 | 109,162 | ~55% | reqwest H2; hyper-native pool planned |
| HTTP/3 (QUIC) | 39,581 | 67,866 | ~42% | QUIC proxy via quinn |
| WebSocket | 104,465 | 219,620 | ~52% | Upgrade overhead amortized over many messages |
| gRPC | 34,470 | 118,650 | ~71% | H2 multiplexing + protobuf passthrough |
| TCP | 108,332 | 215,646 | ~50% | Bidirectional copy, minimal per-byte overhead |
| TCP+TLS | 112,152 | 221,520 | ~49% | TLS termination + bidirectional copy |
| UDP | 79,029 | 228,705 | ~65% | Per-datagram session lookup + forwarding |
| UDP+DTLS | 74,098 | — | — | DTLS termination + plain UDP forwarding |

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
