# Coverage

Ferrum Edge uses `cargo-llvm-cov` for Rust line coverage. The measured local
and CI scope is `--lib`, `--test unit_tests`, and `--test integration_tests`.
Functional tests, conformance tests, custom plugins, eBPF, vendored crates, and
performance workspaces are excluded from this baseline because they either
spawn subprocesses, use separate coverage reporters, or are not actionable for
the core proxy codebase.

## Running Locally

Install the tool once:

```bash
cargo install cargo-llvm-cov --locked
rustup component add llvm-tools-preview
```

Run the deterministic local coverage suite:

```bash
scripts/coverage.sh
```

The script prints a terminal summary and writes:

- HTML: `target/llvm-cov/html/index.html`
- LCOV: `target/llvm-cov/lcov.info`

Use a filter for targeted investigation:

```bash
scripts/coverage.sh -- plugins::cors
```

## CI Baseline

The scheduled `Coverage` workflow runs on pushes to `main`, manual dispatch,
and Sundays at 06:00 UTC. It publishes an HTML report and LCOV file as a
30-day GitHub Actions artifact. It also writes the overall coverage percentage
and lowest/highest-covered files to the workflow step summary.

Current overall coverage: **79.15% line coverage** (`143,848/181,736` lines),
captured locally on 2026-05-24 with `scripts/coverage.sh`. Replace this local
snapshot with the first successful `Coverage` workflow artifact value after the
workflow is merged to `main` if it differs.

## Lowest-Covered Modules

Measured from the local baseline run. Percentages are line coverage.

| Module | Coverage | Assessment |
| --- | ---: | --- |
| `src/main.rs` | 0.00% | Binary startup and process-exit paths are not exercised by lib/unit/integration coverage; keep most testing in CLI/startup helpers and functional smoke tests. |
| `src/http3/` | 23.69% | Protocol integration candidate; the server, WebSocket, and cross-protocol fallback paths need QUIC/H3 stream fixtures. |
| `src/bin/ferrum-cni.rs` | 49.64% | CLI-style binary path; targeted command parsing and error-path tests should be cheap. |
| `src/cli.rs` | 54.68% | Easy win; parser, path resolution, and health/version/reload branches are deterministic. |
| `src/runtime_metrics_tracing_layer.rs` | 58.33% | Easy win; small classification layer with bounded pure functions plus one untested event-recording path. |
| `src/health_check.rs` | 60.95% | Mixed candidate; passive health is unit-friendly, while active HTTP/gRPC probes need mocked backends. |
| `src/identity/` | 63.03% | Integration-test candidate; rotation and Workload API paths involve async CA/SPIFFE flows and long-running tasks. |
| `src/proxy/` | 64.81% | High-value integration candidate; hot-path protocol behavior needs focused fixtures rather than broad unit mocks. |
| `src/tls_offload.rs` | 75.71% | Targeted-test candidate for policy and offload edge cases. |
| `src/grpc/` | 77.34% | Protocol integration candidate; CP/DP and mesh gRPC failure paths are the likely remaining gaps. |

## Next Test Priorities

1. `src/http3/`: add a small H3 fixture layer for handshake, request body,
   WebSocket, and cross-protocol fallback error cases. This is the largest
   measured gap in core protocol code.
2. `src/health_check.rs`: cover passive-state transitions and active-probe
   formatting/error branches with mocked HTTP/gRPC backends. This gives good
   risk reduction without touching the proxy hot path.
3. `src/identity/`: add fake-CA and fake-Workload-API tests for SVID rotation,
   failed issuance, revision bumps, and trust-bundle refresh behavior.
4. `src/cli.rs` and `src/bin/ferrum-cni.rs`: add parser/error-path tests for
   command surfaces. These are quick wins and should not need external services.
5. `src/proxy/udp_proxy.rs` and `src/proxy/udp_batch.rs`: add narrow UDP
   fixture tests for batching, disconnect, and timeout/error accounting before
   expanding broader proxy coverage.
