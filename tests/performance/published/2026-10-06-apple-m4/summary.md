# Ferrum Edge multi-protocol benchmark

- Date (UTC): 2026-10-06T23:17:56Z
- Commit: `e5c7616277549e81ed5cc8534cbb82764d01118c`
- Gateway: 0.9.13 — `cargo build --release`
- Host: Apple M4, 10 logical CPUs, 16.0 GiB, macOS 26.6.1 (arm64)
- Load average at start: [4.94, 9.48, 8.96]
- Runs per row: 3 (leg order alternates gateway-first / direct-first)
- Topology: proto_bench → ferrum-edge → proto_backend on one host over loopback; the direct leg is proto_bench → proto_backend with the same client protocol.

Values are medians across runs. `Overhead` is 1 − gateway RPS ÷ direct RPS on a shared host, where the gateway competes with the load generator and backend for the same cores. `Gateway CPU/req` is the gateway process's CPU time divided by the requests it served during the leg — the hardware-relative cost of the extra hop.

## throughput_64b

Concurrency 200, 15 s measured per leg.

| Protocol | Gateway RPS | Direct RPS | Overhead | Gateway p50 | Gateway p99 | Added p50 | Gateway CPU/req | RPS CV | Errors | Flags |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| HTTP/1.1 | 104,182 | 211,967 | 51% | 1.84 ms | 3.85 ms | 904 µs | 54 µs | 0.5% | 0 | — |
| HTTP/1.1 + TLS | 102,285 | 211,964 | 52% | 1.87 ms | 3.98 ms | 936 µs | 55 µs | 0.5% | 0 | — |
| HTTP/2 (TLS) | 46,987 | 274,902 | 83% | 4.30 ms | 5.66 ms | 3.68 ms | 96 µs | 0.4% | 0 | — |
| HTTP/3 (QUIC) | 59,801 | 105,272 | 43% | 3.33 ms | 4.99 ms | 1.44 ms | 80 µs | 0.4% | 0 | — |
| WebSocket | 108,566 | 211,876 | 49% | 1.82 ms | 2.58 ms | 891 µs | 36 µs | 0.5% | 0 | — |
| gRPC (h2c) | 79,694 | 213,170 | 62% | 2.36 ms | 5.54 ms | 1.56 ms | 49 µs | 0.8% | 0 | — |
| TCP | 108,970 | 210,983 | 48% | 1.82 ms | 2.45 ms | 883 µs | 35 µs | 0.1% | 0 | — |
| TCP + TLS | 108,169 | 211,378 | 49% | 1.82 ms | 2.57 ms | 894 µs | 36 µs | 0.4% | 0 | — |
| UDP | 81,918 | 261,483 | 69% | 2.50 ms | 2.89 ms | 1.74 ms | 59 µs | 0.1% | 0 | — |
| UDP + DTLS | 75,031 | 97,264 | 23% | 2.64 ms | 3.69 ms | 552 µs | 78 µs | 0.7% | 0 | — |

## throughput_10240b

Concurrency 200, 15 s measured per leg.

| Protocol | Gateway RPS | Direct RPS | Overhead | Gateway p50 | Gateway p99 | Added p50 | Gateway CPU/req | RPS CV | Errors | Flags |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| HTTP/1.1 | 96,609 | 210,533 | 54% | 1.99 ms | 4.14 ms | 1.04 ms | 59 µs | 0.3% | 0 | — |
| HTTP/1.1 + TLS | 84,744 | 178,335 | 52% | 2.25 ms | 4.97 ms | 1.20 ms | 67 µs | 0.6% | 0 | — |
| HTTP/2 (TLS) | 36,313 | 169,660 | 79% | 5.56 ms | 7.81 ms | 4.53 ms | 114 µs | 0.1% | 0 | — |
| HTTP/3 (QUIC) | 7,379 | 11,624 | 37% | 26.09 ms | 55.42 ms | 9.66 ms | 641 µs | 1.1% | 0 | — |
| WebSocket | 104,860 | 200,604 | 48% | 1.88 ms | 2.84 ms | 913 µs | 35 µs | 0.2% | 0 | — |
| gRPC (h2c) | 57,475 | 112,973 | 49% | 3.23 ms | 8.57 ms | 1.69 ms | 66 µs | 0.1% | 0 | — |
| TCP | 99,220 | 193,977 | 49% | 2.01 ms | 2.28 ms | 980 µs | 28 µs | 0.3% | 0 | — |
| TCP + TLS | 93,043 | 159,829 | 42% | 2.14 ms | 2.52 ms | 959 µs | 37 µs | 0.4% | 0 | — |
| UDP | 81,106 | 251,031 | 68% | 2.52 ms | 2.93 ms | 1.74 ms | 59 µs | 1.0% | 0 | — |
| UDP + DTLS | 74,926 | 95,677 | 22% | 2.64 ms | 3.62 ms | 516 µs | 77 µs | 0.2% | 0 | — |

## latency_64b

Concurrency 1, 10 s measured per leg.

One connection: RPS is bounded by round-trip latency, so read `Added p50` (the time the gateway hop adds) rather than `Overhead`.

| Protocol | Gateway RPS | Direct RPS | Overhead | Gateway p50 | Gateway p99 | Added p50 | Gateway CPU/req | RPS CV | Errors | Flags |
|---|---:|---:|---:|---:|---:|---:|---:|---:|---:|---|
| HTTP/1.1 | 19,408 | 50,656 | 62% | 49 µs | 73 µs | 30 µs | 39 µs | 0.7% | 0 | — |
| HTTP/1.1 + TLS | 18,886 | 48,797 | 61% | 51 µs | 74 µs | 32 µs | 40 µs | 0.8% | 0 | — |
| HTTP/2 (TLS) | 14,203 | 30,479 | 54% | 69 µs | 89 µs | 38 µs | 50 µs | 0.5% | 0 | — |
| HTTP/3 (QUIC) | 12,480 | 31,044 | 60% | 78 µs | 98 µs | 47 µs | 53 µs | 1.1% | 0 | — |
| WebSocket | 32,917 | 66,924 | 51% | 29 µs | 45 µs | 15 µs | 10 µs | 0.1% | 0 | — |
| gRPC (h2c) | 13,518 | 28,486 | 53% | 73 µs | 91 µs | 39 µs | 48 µs | 0.1% | 0 | — |
| TCP | 33,730 | 63,522 | 47% | 28 µs | 45 µs | 13 µs | 9 µs | 0.2% | 0 | — |
| TCP + TLS | 32,094 | 62,505 | 49% | 30 µs | 47 µs | 15 µs | 10 µs | 0.7% | 0 | — |
| UDP | 34,322 | 69,440 | 51% | 27 µs | 43 µs | 14 µs | 12 µs | 0.1% | 0 | — |
| UDP + DTLS | 29,874 | 56,321 | 47% | 32 µs | 47 µs | 15 µs | 14 µs | 0.4% | 0 | — |

