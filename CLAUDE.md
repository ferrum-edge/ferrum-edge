# CLAUDE.md - Ferrum Edge

Keep this root memory compact and always relevant. Subsystem details live in path-scoped `.claude/rules/*.md` files and should not be re-added here unless they apply across the whole repository. These rule files are intentionally not `@` imports; Claude Code loads them when matching files are opened/read, not at launch.

## Project Overview

Ferrum Edge is a high-performance Rust edge proxy for HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC, raw TCP, and UDP. It ships as one `ferrum-edge` binary with CLI subcommands, env/config-file configuration, load balancing, health checks, and 75+ plugins. Rust edition 2024, tokio, hyper 1.x. License: PolyForm Noncommercial 1.0.0 with dual commercial licensing.

## Build-Out Policy

Ferrum Edge is in active build-out. Do not add schema DB migrations for new schema changes; fold schema changes into the current baseline schema. Do not add or preserve legacy shims for old fields, env vars, config shapes, or database values unless explicitly requested. Custom plugin migrations under `custom_plugins/` are unaffected. Breaking changes are acceptable during this phase.

## Read Before Touching

- Mesh behavior: `docs/mesh.md`, `src/modes/mesh/`, `.claude/rules/mesh.md`
- HTTP/3, WebSocket, QUIC, TCP/UDP: `docs/http3.md`, `docs/tcp_udp_proxy.md`, `src/proxy/`, `src/http3/`, `.claude/rules/proxy-protocols.md`
- Plugin ordering/hooks: `docs/plugin_execution_order.md`, `src/plugins/mod.rs`, `.claude/rules/plugins.md`
- Config/env/database: `docs/configuration.md`, `ferrum.conf`, `src/config/env_config.rs`, `.claude/rules/config-database.md`
- Admin API/spec extraction: `docs/admin_api.md`, `docs/api_specs.md`, `openapi.yaml`, `.claude/rules/admin-api-specs.md`
- TLS/secrets/security: `docs/frontend_tls.md`, `docs/backend_mtls.md`, `src/tls/`, `src/secrets/`, `.claude/rules/tls-security.md`
- Tests and perf: `tests/`, `tests/performance/multi_protocol/`, `.claude/rules/testing.md`
- Coverage: `docs/coverage.md`, `.github/workflows/coverage.yml`, `scripts/coverage.sh`
- Dependencies/vendored patches: `deny.toml`, `vendor/`, `docs/dependency-policy.md`, `.claude/rules/dependencies.md`

## Core Commands

```bash
ferrum-edge run [OPTIONS]
ferrum-edge validate [OPTIONS]
ferrum-edge reload [--pid PID]
ferrum-edge version [--json]
ferrum-edge health [-p PORT] [--host H] [--tls] [--tls-no-verify] [--live]
```

`run`/`validate` flags: `-s/--settings <PATH>`, `-c/--spec <PATH>`, `-m/--mode <MODE>`, `-v/--verbose`. Precedence is CLI > env > conf file > smart defaults > hardcoded. CLI flags become env vars through `apply_run_overrides()` / `apply_validate_overrides()` before `CONF_FILE_CACHE` reads in `main.rs`.

```bash
cargo build
cargo build --release
cargo test --lib
cargo test --test unit_tests
cargo test --test integration_tests
cargo build --bin ferrum-edge && cargo test --test functional_tests -- --ignored
cargo fmt --all && cargo fmt --all -- --check
cargo clippy --lib --tests -p ferrum-edge -- -D warnings
```

Prerequisite: `protoc`; `build.rs` runs `tonic_build` on `proto/ferrum.proto`.

## Testing Policy

Test what changed and let CI run the full matrix. For Rust changes, run `cargo fmt --all -- --check`, targeted clippy, and relevant tests. Docs/comment-only changes usually need `git diff --check`. Config/schema/spec/template changes need validation of the changed surface and Rust checks only if Rust changed.

Target by scope: public APIs use `cargo test --test unit_tests <filter>`; cross-module behavior uses `cargo test --test integration_tests <filter>`; proxy hot-path changes use `cargo build --bin ferrum-edge && cargo test --test functional_tests <filter> -- --ignored`. Avoid adding new inline source tests; prefer external unit tests, integration tests, or focused test-only helpers under `tests/`.

Run the full local suite only for shared infrastructure, cross-module refactors, pre-release work, or when CI is congested. Leave `CARGO_TARGET_DIR` unset across parallel worktrees; inside one workspace, run fmt, clippy, and tests sequentially.

## Operating Modes

- `database`: R/W admin + proxy; PostgreSQL/MySQL/SQLite/MongoDB polling
- `file`: R/O admin + proxy; YAML/JSON and SIGHUP reload on Unix
- `cp`: R/W admin, no proxy; database + gRPC distribution
- `dp`: R/O admin + proxy; config from CP via gRPC with multi-CP failover
- `mesh`: R/O admin + proxy; service-mesh data plane consuming xDS or native MeshSubscribe
- `injector`: Kubernetes admission webhook for Ferrum mesh sidecars/init capture
- `node_agent`: per-node eBPF capture manager for ambient mesh; no proxy listeners
- `migrate`: runs DB migrations and exits

## Universal Engineering Rules

- No `.unwrap()` or `.expect()` in production paths without a documented invariant. Tests are exempt.
- Prefer `?`, explicit errors, and structured warnings. Avoid fallback helpers that hide config, parse, or I/O failures.
- No panics on the proxy request path. Return protocol-appropriate errors.
- Validate hostile input at the boundary, including path traversal, malformed headers, oversized bodies, and recursive/embedded credentials.
- Escape user-controlled input when interpolating JSON/XML response bodies.
- Always set `validation.validate_exp = true` for JWT verification.
- Do not log secrets, bearer tokens, cookies, private keys, or unredacted credential metadata.
- Admin API/OpenAPI parity is mandatory: endpoint, field, status-code, or plugin schema changes must update `openapi.yaml`.
- New `FERRUM_*` env vars require `docs/configuration.md` and `ferrum.conf` updates.
- Schema additions should use `#[serde(default, skip_serializing_if = "<pred>")]` when optional. Check `deny_unknown_fields` before adding fields.

## Hot-Path Invariants

- No avoidable locks on proxy hot paths: use `ArcSwap::load()` snapshots and precomputed caches; `DashMap` only for concurrent mutable maps.
- Avoid per-request allocations and `format!()` in hot loops. Use thread-local buffers and precomputed indexes.
- Rebuild `RouterCache`, `PluginCache`, `ConsumerIndex`, and `LoadBalancerCache` on reload, not per request.
- Atomic config reload uses `ArcSwap`: in-flight requests see old or new config, never partial state.
- Hot-path `DashMap` construction must use `crate::util::sharding::pool_shard_amount(env_config.pool_shard_amount)`.
- Pool keys use `|` as delimiter. Include every field that affects connection identity; exclude policy-only fields.
- Keep protocol correctness over shortcuts, especially HTTP/2/gRPC trailers, stream accounting, flow control, and WebSocket CONNECT behavior.

## Startup And Shutdown

Startup order: jemalloc on non-Windows, CLI parse/env overrides, rustls ring provider, external secret resolution on a single-threaded runtime, non-blocking tracing stdout, `validate` exit point, `overload::raise_fd_limit()`, `EnvConfig` parse, multi-threaded tokio, mode dispatch, SIGINT/SIGTERM via `watch::channel`.

Serving modes initialize TLS policy, frontend/admin TLS, DTLS, backend TLS validation, CP/DP gRPC TLS, stream port validation, stream listener binds, DNS warmup, optional pool warmup, and overload monitoring. Stream listener bind is fatal in database/file mode and non-fatal in DP.

Graceful shutdown: stop accept loops, set `OverloadState.draining=true`, add `Connection: close`, wait up to `FERRUM_SHUTDOWN_DRAIN_SECONDS` for active connections and requests, run 5s cleanup, exit. `RequestGuard` must live inside `ProxyBody` for H1/H2/gRPC so streaming requests are counted until their bodies finish; H3 uses a stack-local guard.

## Runtime And Admin Invariants

- Port `0` on proxy/admin HTTP ports or inside `FERRUM_CP_GRPC_LISTEN_ADDR` disables plaintext and is excluded from `reserved_gateway_ports()`.
- Admin API validates JWTs but never mints them. DB/CP require `FERRUM_ADMIN_JWT_SECRET` >= 32 chars; file mode generates a random read-only secret at startup.
- `FERRUM_ADMIN_REQUIRE_NAMESPACE_CLAIM=true` makes namespace-scoped admin routes require a JWT `ns` claim (same shapes as the CP/DP gRPC plane) authorizing the `X-Ferrum-Namespace` value; default off keeps the header a routing selector. Enforcement lives in `src/admin/mod.rs` (`is_namespace_scoped_route` + `enforce_namespace_claim`); malformed `ns` claims fail closed at authentication.
- Observability endpoints are tiered by default: `/live` is always unauthenticated and minimal (`{"status":"ok"}`); `/health`+`/status` return only `status`+`ready` unauthenticated and full diagnostics only when authenticated; `/overload` returns a coarse `{level}` unauthenticated and the full snapshot only when authenticated; `/metrics` returns `401` unless authenticated. "Authenticated" = valid admin JWT OR matching `FERRUM_METRICS_BEARER_TOKEN` OR a `FERRUM_METRICS_ALLOWED_CIDRS` source IP (`MetricsAuthPolicy` / `observability_detail_allowed` in `src/admin/mod.rs`). Do not regress these surfaces back to unauthenticated detail.
- `/health` DB check remains cached 15s via lock-free `ArcSwap`; refreshes are single-flight (`AdminState.db_health_refresh`, `cached_db_health_connected`) with a 5s probe timeout; do not expose the DB pool to unauthenticated floods.
- `/metrics/runtime` JSON remains JWT-authenticated and cached via lock-free `ArcSwap`.
- `GET /cluster` is JWT-authenticated: CP returns connected DPs; DP returns CP connection state.
- Overload manager uses atomic load-shedding flags, RED between thresholds, and `CachePadded` hot atomics. Do not collapse hot flags/counters onto shared cache lines.
- External secret suffixes resolve before config load: `_VAULT`, `_AWS`, `_AZURE`, `_GCP`, `_FILE`. Provider conflicts for one base key are errors.

## Source Layout

- `src/{main,cli,startup}.rs`: CLI, startup, mode dispatch, signals
- `src/admin/`: REST API, JWT, backup/audit, API specs
- `src/config/`: domain model, env config, file/db loaders, migrations, validation
- `src/modes/`: database/file/cp/dp/mesh/injector/node-agent/migrate runtimes
- `src/proxy/`, `src/http3/`, `src/dtls/`, `src/dns/`: proxy protocol paths
- `src/plugins/`, `custom_plugins/`: plugin trait, built-ins, custom plugin loading
- `src/grpc/`, `proto/`: CP/DP and mesh gRPC APIs
- `src/tls/`, `src/secrets/`, `src/identity/`: TLS, secret resolution, SPIFFE/SVID identity
- `src/{overload,load_balancer,health_check,circuit_breaker,retry,pool,connection_pool,router_cache,plugin_cache,consumer_index}.rs`: shared runtime infrastructure
- `tests/{unit,integration,functional,conformance,performance}/`: test suites and protocol benchmarks

## Environment References

Canonical env docs: `docs/configuration.md`. Runtime parsing: `src/config/env_config.rs`. Editable template: `ferrum.conf`. Load-bearing vars include `FERRUM_MODE`, `FERRUM_NAMESPACE`, `FERRUM_FILE_CONFIG_PATH`, `FERRUM_DB_TYPE`, `FERRUM_DB_URL`, `FERRUM_ADMIN_JWT_SECRET`, `FERRUM_CP_DP_GRPC_JWT_SECRET`, `FERRUM_DP_CP_GRPC_URLS`, TLS paths/flags, `FERRUM_POOL_WARMUP_ENABLED`, `FERRUM_CP_NAMESPACES`, and `FERRUM_CP_REQUIRE_NAMESPACE_CLAIM`.

## PR And Commit Workflow

When code changes are complete, targeted tests are green, and docs/specs are updated, push the branch and open a PR unless the user said otherwise or the work is intentionally local/exploratory. PRs need summary, changes, and test plan. Commit messages use concise imperative mood. Branch names conventionally use `feature/...`, `fix/...`, or `claude/...`; do not rename the current branch without explicit instruction.
