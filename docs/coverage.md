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
- JSON summary: `target/llvm-cov/coverage.json`

Use a filter for targeted investigation:

```bash
scripts/coverage.sh -- plugins::cors
```

Run the heavier top-gap functional coverage pass when investigating the proxy,
HTTP/3, TCP/UDP, admin, and mode-level gaps:

```bash
scripts/coverage.sh --functional
```

This opt-in path builds Cargo's instrumented `ferrum-edge` binary and exports
its path through `FERRUM_EDGE_TEST_BIN` so subprocess-based functional tests
contribute to the same coverage report. MongoDB functional tests are included
in the filter list and skip gracefully when local MongoDB is not available.

## CI Baseline And Gates

The `Coverage` workflow runs on pull requests, pushes to `main`, manual
dispatch, and Sundays at 06:00 UTC. It publishes an HTML report, LCOV file, JSON
summary, and terminal summary as a 30-day GitHub Actions artifact named
`coverage-report`. It also writes the overall coverage percentage and
lowest/highest-covered files to the workflow step summary.

The PR gate is based on the latest completed default-branch coverage artifact
available when the gate was introduced on 2026-06-20:

| Scope | Remote baseline | Gate |
| --- | ---: | ---: |
| Overall line coverage | `210900/269397` lines, **78.29%** | **78.28%** |
| `src/plugins/` line coverage | `54957/64665` lines, **84.99%** | **84.98%** |
| Changed coverable `src/plugins/` lines on PRs | same plugin baseline | **84.98%** |

The thresholds are intentionally rounded down from the measured remote values
so presentation precision does not fail a run, while any real coverage drop in
overall or plugin coverage still fails CI. Changed-line coverage is enforced
only for coverable lines reported by LCOV; generated, ignored, or otherwise
non-coverable lines are ignored consistently with the main coverage report.

To inspect the same remote results without running coverage locally:

```bash
gh run list --repo ferrum-edge/ferrum-edge --workflow Coverage --branch main
gh run download <run-id> --repo ferrum-edge/ferrum-edge --name coverage-report --dir /tmp/ferrum-coverage
python3 scripts/check_coverage_thresholds.py \
  --coverage-json /tmp/ferrum-coverage/coverage.json \
  --lcov /tmp/ferrum-coverage/lcov.info \
  --min-overall-line 78.28 \
  --min-plugins-line 84.98 \
  --min-changed-plugins-line 84.98
```

The normal PR `CI` workflow also includes required plugin hardening regression
jobs:

- `Plugin Hardening Unit Regressions`: cache byte accounting and
  last-known-good plugin reload regressions.
- `Plugin Hardening Redis Regression`: multi-instance Redis request
  deduplication with `FERRUM_REDIS_REQUIRED=1`, so Redis startup failures cannot
  silently skip the regression.

Latest opt-in functional benchmark: **81.68% line coverage**
(`148,432/181,717` lines), captured locally on 2026-05-25 with
`rustc 1.95.0 (59807616e 2026-04-14)`. This is not the scheduled CI baseline
because functional coverage is heavier and depends on subprocess-based
fixtures, but it is the current top-gap benchmark for tracking progress toward
90%.

The 81.68% profile used:

- `scripts/coverage.sh --functional`
- `scripts/coverage.sh --functional-filter functional_cp_dp`
- `scripts/coverage.sh --functional-filter functional_cp_dp_resilience`
- `scripts/coverage.sh --functional-filter functional_grpc`
- `scripts/coverage.sh --functional-filter functional_load_balancer`

The default `--functional` filters include coverage-aware TCP/UDP/Mongo and
common-harness subprocess paths. Broad filters such as `h3`, and additional
legacy functional filters, can still select tests that under-report
child-process coverage until their local `kill()` cleanup paths are migrated to
the shared coverage-aware shutdown helper.

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
