---
paths:
  - "tests/**"
  - ".github/**"
  - "scripts/**"
  - "Cargo.toml"
  - "Cargo.lock"
  - "build.rs"
  - "rust-toolchain.toml"
  - ".cargo/**"
  - "docs/functional_testing*.md"
  - "docs/ci_cd.md"
  - "docs/connection_saturation_benchmark.md"
  - "docs/infrastructure_sizing.md"
  - "comparison/**"
---

# Testing Rules

## Local Testing Policy

- Test only what changed locally; CI is the full gate.
- Rust changes: `cargo fmt --all -- --check`, targeted clippy with `cargo clippy --lib --tests -p ferrum-edge -- -D warnings`, and targeted tests.
- Docs/comment-only changes: `git diff --check` and any relevant doc formatter/linter.
- Config/schema/spec/template changes: validate the changed surface, such as `ferrum-edge validate`, OpenAPI/schema checks, or targeted config/admin tests.
- Reserve `cargo clippy --all-targets -- -D warnings` for shared infrastructure, broad refactors, pre-release/pre-merge, or congested CI.

## Cargo Target Isolation

- Leave `CARGO_TARGET_DIR` unset across parallel worktrees. Cargo's default per-worktree `target/` avoids shared build locks.
- A stale inherited `CARGO_TARGET_DIR` causes `Blocking waiting for file lock on build directory`. Work around one command with `unset CARGO_TARGET_DIR && cargo ...`.
- Sharing `SCCACHE_DIR` is safe. The repo `.cargo/config.toml` already uses `sccache`.
- Within one workspace, run fmt, clippy, and tests sequentially because they share that workspace target dir.

## Test Placement

- Prefer external tests under `tests/` over new inline `#[cfg(test)] mod tests` in production source files.
- Do not add ad hoc test runners, manually invoked assertions, mock fixtures, or test-only runtime branches to main source modules.
- Existing inline tests may remain, but new coverage should use `tests/unit/<category>/<module>_tests.rs`, `tests/integration/`, `tests/functional/`, or `tests/conformance/` when possible.
- If private-only behavior cannot be tested externally without widening a runtime API, keep any inline test module minimal and do not add production-visible test helpers.
- Public API tests go in `tests/unit/<category>/<module>_tests.rs`.
- Component interaction tests go in `tests/integration/`.
- Full binary E2E tests go in `tests/functional/` with `#[ignore]` and require `cargo build --bin ferrum-edge`.
- Istio and xDS compatibility coverage goes in `tests/conformance/<category>.rs` with `register_feature!`.
- New `tests/unit/` files must be added to the appropriate `tests/unit/<category>/mod.rs`.

## Targeted Commands

- Existing inline source test: `cargo test --lib <module>::tests`
- Public API: `cargo test --test unit_tests <filter>`
- Cross-module behavior: `cargo test --test integration_tests <filter>`
- Proxy hot path: `cargo build --bin ferrum-edge && cargo test --test functional_tests <filter> -- --ignored`
- Multi-protocol perf: build once with `cargo build --release`, then `bash tests/performance/multi_protocol/run_protocol_test.sh {http1|http1-tls|http2|http3|ws|grpc|tcp|tcp-tls|udp|udp-dtls|all} [--duration N] [--concurrency N] [--skip-build]`

## Coverage

- Coverage is opt-in and not part of the normal local-test loop. Run when investigating untested code paths or after adding tests for a new module.
- Install: `cargo install cargo-llvm-cov --locked && rustup component add llvm-tools-preview`.
- Run: `scripts/coverage.sh` (lib + unit + integration). HTML report path is printed at the end.
- Narrow scope: `scripts/coverage.sh -- <filter>` forwards to `cargo llvm-cov`. Example: `scripts/coverage.sh -- plugins::cors`.
- Functional and conformance suites are intentionally excluded; they spawn subprocesses or use separate coverage reporters. Line coverage for lib/unit/integration runs in CI through `.github/workflows/coverage.yml`.
- Coverage outputs (`target/llvm-cov/`, `target/llvm-cov-target/`) are gitignored.

## Functional Test Rules

- Use `Stdio::null()` for gateway stdout/stderr unless the test reads the pipe. `Stdio::piped()` without reading can deadlock.
- Port allocation must retry. Bind-drop-rebind races with parallel tests.
- Use a struct harness with `try_new()` retry wrapper or a `start_gateway_with_retry()` helper.
- Every retry needs fresh ports and fresh temp dirs/DBs. Reusing killed SQLite can corrupt WAL.
- Backend/echo server should hold its listener. Do not drop+rebind; pass pre-bound `TcpListener` to `start_echo_server_on()`.
- `wait_for_health` returns `bool` or `Result`; it must not panic.
- `FERRUM_POOL_WARMUP_ENABLED=true` makes the gateway issue `HEAD /` to each backend at startup and shifts backend-hit assertions by one.
- Set `FERRUM_POOL_WARMUP_ENABLED=false` in tests that count backend hits.
- Keep warmup true when tests require the capability registry to have a `Supported` entry before traffic, such as native H3 or direct H2 routing.

## CI Expectations

- PR CI runs format, tests in parallel, lint, perf regression, and five build targets: Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64. The perf-regression job is path-gated on PRs (runs only for performance-sensitive changes) and always runs on pushes to `main` and on manual `workflow_dispatch`.
- Push to main overwrites the `latest` release and publishes multi-arch Docker images to Docker Hub and GHCR.
- Tags `v*` create versioned releases and Docker tags.
- Required secrets are `DOCKERHUB_USERNAME` and `DOCKERHUB_TOKEN`.
- GitHub Actions workflow permissions must be Read+Write for release automation.

## Test Structure

```text
tests/{unit_tests,integration_tests,functional_tests,conformance_tests}.rs
tests/unit/{config,plugins,admin,gateway_core,identity,secrets,tls,cli,notifications}/
tests/{integration,functional,performance,conformance}/
tests/scaffolding/
tests/common/
```

Functional tests are ignored by default. Conformance reporter emits `target/conformance/coverage.{json,md}`.

## Dependency Version Sync

- `tests/performance/multi_protocol/` is not a workspace member and has its own lockfile.
- Keep protocol deps aligned with root `Cargo.toml`. DTLS, H2, H3, QUIC, tonic, prost, rustls, and related crates can silently fail when versions drift.
- When bumping a shared dependency, update the multi-protocol manifest and run `cd tests/performance/multi_protocol && cargo update -p <crate>`.
- Preserve `# SYNC:` comments.
