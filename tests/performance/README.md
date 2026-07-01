# Ferrum Edge Performance Tests

This directory is the index for Ferrum Edge performance harnesses. Results are
suite-specific: throughput and latency depend on host hardware, operating
system, kernel/socket features, payload size, protocol, concurrency, duration,
build profile, enabled features, TLS mode, and load generator.

Do not treat one table as the global benchmark. When publishing or copying
numbers, cite the suite, date, environment, command shape, payload, concurrency,
duration, build profile, and comparison baseline.

## Suite Index

| Suite | Entry point | Measures | Result/provenance docs |
|---|---|---|---|
| HTTP wrk smoke | `./run_perf_test.sh` | Local HTTP/1.1 gateway overhead against a direct Hyper backend using `wrk`. Useful for quick development smoke tests. | This README. Raw wrk output and `performance_report.html` are generated per run. |
| CI HTTP overhead gate | `ci_overhead_bench.py` | Short HTTP overhead regression check used by `ci.yml`. | CI artifacts under `tests/performance/ci_results/`. |
| Multi-protocol matrix | [`multi_protocol/`](multi_protocol/) | HTTP/1.1, HTTPS, HTTP/2, HTTP/3, WebSocket, gRPC, TCP, TCP+TLS, UDP, and UDP+DTLS through Ferrum and direct backend baselines. Also includes Envoy comparison and connection saturation harnesses. | [`multi_protocol/README.md`](multi_protocol/README.md). |
| Payload-size matrix | [`payload_size/`](payload_size/) | Content-type and payload-size sweeps across HTTP, gRPC, WebSocket, TCP, UDP, and TLS variants. | [`payload_size/README.md`](payload_size/README.md). |
| Mesh hot-path microbenches | [`mesh/`](mesh/) | Criterion microbenches for mesh authorization, slice apply, and xDS translation hot/cold paths. | [`mesh/README.md`](mesh/README.md) and `mesh/baseline.md`. |
| Mesh DNS E2E | [`mesh-dns-e2e/`](mesh-dns-e2e/) | End-to-end transparent mesh DNS proxy latency/throughput over UDP and TCP. | [`mesh-dns-e2e/README.md`](mesh-dns-e2e/README.md). |
| Mesh HBONE E2E | [`mesh-hbone-e2e/`](mesh-hbone-e2e/) | Gateway-to-mesh HBONE outbound throughput over H2 CONNECT/mTLS. | [`mesh-hbone-e2e/README.md`](mesh-hbone-e2e/README.md). |

## Result Provenance Checklist

Every checked-in benchmark result should state:

- Date of the run.
- Host OS, kernel when relevant, CPU/architecture, and whether the run was local or CI.
- Ferrum commit or release, build profile, and enabled Cargo features.
- Benchmark command or workflow name.
- Protocols and comparison path: Ferrum gateway, direct backend, Envoy, or another gateway.
- Payload size, request shape, concurrency, duration, and warmup.
- Relevant tuning such as file descriptor limits, socket sysctls, H2/H3 flow control windows, pool warmup, and logging level.
- Artifact location when the run came from GitHub Actions.

If one of these fields is unknown, mark the result as historical or
directional instead of presenting it as a current headline number.

## Quick HTTP Smoke Test

The root `run_perf_test.sh` harness is still useful for local HTTP smoke tests:

```bash
cd tests/performance

# Requires wrk, Python 3, and a Rust toolchain.
./run_perf_test.sh
```

Environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `WRK_DURATION` | `30s` | Test duration for each wrk phase. |
| `WRK_THREADS` | `8` | Number of wrk worker threads. |
| `WRK_CONNECTIONS` | `100` | Concurrent wrk connections. |

The harness starts a direct Hyper backend, starts Ferrum Edge in file mode with
`perf_config.yaml`, runs wrk against gateway health/users endpoints and the
direct backend, then writes raw wrk output plus an optional
`performance_report.html`.

This smoke test intentionally covers a narrow HTTP/1.1 path. Use
`multi_protocol/` or `payload_size/` for headline protocol claims.

## Requirements

- `wrk` for `run_perf_test.sh`.
- Python 3 for report generation and CI overhead scripts.
- Rust toolchain and `protoc` for Rust benchmark binaries.
- Docker/kind only for suites that explicitly say they need them.

Install `wrk`:

```bash
# macOS
brew install wrk

# Ubuntu/Debian
sudo apt-get install wrk

# CentOS/RHEL
sudo yum install wrk
```

## CI and Manual Workflows

- `ci.yml` runs the short HTTP overhead regression gate when
  performance-sensitive paths change.
- `.github/workflows/perf-benchmark.yml` runs the multi-protocol benchmark on
  demand.
- `.github/workflows/payload-size-benchmark.yml` runs the payload-size matrix on
  demand.
- `.github/workflows/connection-saturation-benchmark.yml` runs the sustained
  connection-capacity harness with the host-level tuning needed for headline
  saturation numbers.
- `.github/workflows/gateways-protocol-benchmark.yml` runs the cross-gateway
  protocol benchmark on demand.

## Updating Published Numbers

1. Run the relevant suite from a clean checkout at the commit being reported.
2. Capture the provenance fields above in the suite-specific README or result
   artifact.
3. If copying a summary into the root README, link back to the suite README and
   include the date, payload size, concurrency, duration, and host class in the
   sentence immediately before the table.
4. Keep historical result tables labeled as historical when the current suite
   README has newer payloads or methodology.
