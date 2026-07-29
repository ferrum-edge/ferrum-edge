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
  - "docs/protocol_perf_regression.md"
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

## Simulating A Server Going Away (tonic)

- `JoinHandle::abort()` on a task running `tonic::transport::Server::serve_with_incoming` does **not** disconnect existing clients. tonic spawns a detached `tokio::spawn` task per accepted connection, so aborting the accept loop only closes the listener; every established stream keeps being served.
- A long-lived server-streaming RPC (`ConfigSync.Subscribe`, `MeshSubscribe`, xDS ADS) therefore survives the "shutdown", and any assertion that depends on the client noticing — reconnect, CP/DP failover, stale-snapshot fencing — passes vacuously.
- `serve_with_incoming_shutdown` is not sufficient either: its signal triggers a *graceful* per-connection shutdown (GOAWAY), which never ends an infinite response stream.
- To genuinely sever the transport, own the server's runtime and shut it down (`tests/integration/cp_dp_grpc_tests.rs::SeverableTestCpServer`): dropping the runtime aborts the accept loop and every per-connection task, closing their sockets.
- Any failover test must additionally assert the client actually reached the fallback (e.g. `wait_for_cp_url`) before asserting what the fallback may or may not do. A negative-only assertion after a fake shutdown proves nothing.
- A `tokio::sync::broadcast` push to a CP that currently has no subscriber is silently dropped, so "the DP never applied X" can pass because X was never delivered. Assert delivery (`Sender::send` returns the receiver count) and a DP-side effect of the rejection (sticky `config_diverged` or its `config_divergence_recoveries_total`) rather than the absence alone.

## Functional Test Rules

- Use `Stdio::null()` for gateway stdout/stderr unless the test reads the pipe. `Stdio::piped()` without reading can deadlock.
- Port allocation must retry. Bind-drop-rebind races with parallel tests.
- Readiness is not identity — and that applies to bespoke spawners too, not just `TestGateway`. `functional_websocket_test.rs::wait_for_owned_gateway` reuses the exported `probe_gateway_identity` because a bare TCP accept let a foreign H2 fixture answer (and `PROTOCOL_ERROR`-reset) an RFC 8441 Extended CONNECT handshake (issue #3435).
- `TestGateway` mints a per-spawn-attempt admin JWT secret/issuer and `FERRUM_METRICS_BEARER_TOKEN`, and its spawn barrier requires the authenticated detail tier of `/health` plus `ready: true`; that combination is also the proof the child owns its proxy port, because `ready` flips only after every listener bind. Do not weaken it to an unauthenticated `/health` or a bare TCP accept, and do not add sleeps or test-level retries in its place.
- Use a struct harness with `try_new()` retry wrapper or a `start_gateway_with_retry()` helper.
- Every retry needs fresh ports and fresh temp dirs/DBs. Reusing killed SQLite can corrupt WAL.
- Backend/echo server should hold its listener. Do not drop+rebind; pass pre-bound `TcpListener` to `start_echo_server_on()`.
- `wait_for_health` returns `bool` or `Result`; it must not panic.
- **Readiness for a spawned gateway must be bound to THAT CHILD, not to "some process accepts this port"** (issue #2132). A reservation has to be released before the subprocess binds it, so a competing listener can take that port; the child then dies with `Address already in use` while a bare port probe keeps succeeding, and the driver reports the competitor's connection reset as a datapath failure. `functional_mesh_mode_test.rs` is the reference implementation: `wait_for_gateway_listener` polls `Child::try_wait()` before and after each probe, and a `ChildExited` outcome consumes the bounded attempt.
- **A fixture-owned server (control plane, echo backend) must not bind an ephemeral port already promised to a gateway subprocess.** Bind through a mesh-port-aware helper (`bind_fixture_listener`) that re-rolls, holding rejected listeners so the kernel cannot re-offer them. A `USED_MESH_PORTS`-style set alone only stops one reservation reusing another.
- **An attempt whose gateway died mid-run is VOID**: retry with fresh ports/dirs/control planes instead of returning the resulting transport error. Never retry an observation from a healthy fixture — authoritative protocol responses and fail-closed security assertions must be made exactly once.
- `FERRUM_POOL_WARMUP_ENABLED=true` makes the gateway issue `HEAD /` to each backend at startup and shifts backend-hit assertions by one.
- Set `FERRUM_POOL_WARMUP_ENABLED=false` in tests that count backend hits.
- Keep warmup true when tests require the capability registry to have a `Supported` entry before traffic, such as native H3 or direct H2 routing.

## CI Expectations

- Full-mode PR CI runs formatting and integration-shard coverage inside `ci-plan`, then runs consolidated test jobs (unit + inline lib, all secret backends, Consul + LDAP), two integration shards, three functional shards, lint, perf regression, and five build targets: Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64. The planner also emits trusted, fail-closed Helm/mesh/eBPF path gates so irrelevant jobs skip before runner allocation. Ordinary non-vendored documentation, license, and agent-instruction-only PRs stay on a lightweight diff-hygiene + `Tests` aggregate path; vendored Markdown and live-suite contract/runbook docs still select full mode. On full-mode PRs, the perf-regression job always runs lightweight protocol-perf static contracts (workflow/evaluator self-tests + scenario `py_compile`) after checkout; the expensive HTTP overhead benchmark runs only for shared runtime infrastructure (top-level `src/*.rs`), proxy/connection hot paths, file-mode startup and config, performance fixtures, or dependency/build-graph changes; plugin-internal, admin, secrets, and unrelated-mode changes skip the benchmark. It always runs on pushes to `main` and manual `workflow_dispatch`, and runs fail-closed when the PR diff cannot be computed.
- Branch protection must directly require `Tests`, `Merge Coverage`, `Gateway API Conformance`, `Mesh E2E Sidecar Live`, and `Multicluster Federation Live`. The dedicated workflows trigger on every PR and path-filter internally; do not add polling mirror jobs back to `ci.yml`.
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
