# CLAUDE.md — Ferrum Gateway

This file provides context for Claude Code when working on the Ferrum Gateway codebase.

## Project Overview

Ferrum Gateway is a high-performance API Gateway and reverse proxy built in Rust. It supports HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, and raw TCP/UDP stream proxying with a plugin architecture (20 built-in plugins), four operating modes, and load balancing with health checks.

- **Language**: Rust (edition 2024)
- **Async runtime**: tokio + hyper 1.0
- **Binary**: `ferrum-gateway` (single binary, mode selected via env var)
- **License**: PolyForm Noncommercial 1.0.0 (dual-licensed with paid commercial option)

## Quick Reference — Commands

### Build

```bash
cargo build                              # Debug build
cargo build --release                    # Release build (O3, thin LTO, strip)
```

**Prerequisite**: `protoc` (protobuf compiler) must be installed. `build.rs` runs `tonic_build` to compile `proto/ferrum.proto`.

### Test

```bash
# Unit tests (fast, no I/O)
cargo test --test unit_tests --all-features

# Integration tests (component interaction — mTLS, connection pool, gRPC, HTTP/3)
cargo test --test integration_tests --test admin_cached_config_tests --all-features

# Functional / end-to-end tests (start real gateway binary, test all modes)
# Requires: cargo build --bin ferrum-gateway (builds the binary first)
cargo test --test functional_tests --all-features -- --ignored

# All tests together
cargo test --all-features
cargo test --all-features -- --ignored   # includes E2E tests
```

### Lint

```bash
cargo clippy --all-targets --all-features -- -D warnings   # Zero warnings policy
cargo fmt --all -- --check                                  # Formatting check
cargo fmt                                                   # Auto-format
```

**CI enforces both clippy (zero warnings with `-D warnings`) and `cargo fmt --check`. Always run these before pushing.**

### CI Pipeline (GitHub Actions)

The CI workflow (`.github/workflows/ci.yml`) runs on push to `main` and PRs targeting `main`:

1. **Unit Tests** — `cargo test --test unit_tests --all-features`
2. **Functional Tests** (depends on unit tests) — integration tests + E2E tests with `--ignored` flag
3. **Lint** (parallel with unit tests) — clippy + fmt check
4. **Performance Regression** (depends on functional tests) — wrk-based load testing against baseline

All four jobs must pass for a PR to merge.

## Architecture

### Operating Modes (`FERRUM_MODE` env var)

| Mode | Description | Admin API | Proxy | Config Source |
|------|-------------|-----------|-------|---------------|
| `database` | Single-instance, DB-backed | Read/Write | Yes | PostgreSQL/MySQL/SQLite via polling |
| `file` | Single-instance, file-backed | Read-only | Yes | YAML/JSON file, SIGHUP reload |
| `cp` | Control Plane | Read/Write | **No** | Database + gRPC distribution |
| `dp` | Data Plane | Read-only | Yes | gRPC stream from CP |
| `migrate` | Schema migration utility | No | No | Runs DB migrations then exits |

### Core Design Principles

1. **Lock-free hot path**: All request-path reads use `ArcSwap::load()` or `DashMap` sharded locks. No `Mutex`/`RwLock` on the proxy path.
2. **Pre-computed indexes**: RouterCache, PluginCache, ConsumerIndex, and LoadBalancerCache are rebuilt on config reload, not per-request.
3. **Atomic config reload**: Config changes are loaded in background, validated, then swapped atomically via `ArcSwap`. Requests in-flight see old or new config — never partial.
4. **Resilience**: If the config source (DB/file/gRPC) is unavailable, the gateway continues serving with cached config.

### Source Layout

```
src/
├── main.rs                    # CLI parsing, mode dispatch, signal handling
├── lib.rs                     # Public API re-exports
├── admin/                     # Admin REST API (CRUD for proxies, consumers, upstreams, plugins)
│   ├── mod.rs                 # Routes, handlers, listener setup
│   └── jwt_auth.rs            # JWT middleware for admin endpoints
├── config/                    # Configuration loading & types
│   ├── types.rs               # Core domain model (Proxy, Consumer, Upstream, Plugin, etc.)
│   ├── env_config.rs          # Environment variable parsing (90+ vars)
│   ├── db_loader.rs           # Database config loader + polling
│   ├── file_loader.rs         # YAML/JSON file loader
│   ├── pool_config.rs         # Connection pool configuration
│   ├── config_migration.rs    # Config version migrations
│   └── migrations/            # SQL schema migrations (v001_initial_schema.rs)
├── modes/                     # Operating mode implementations
│   ├── database.rs            # Database mode entry point
│   ├── file.rs                # File mode entry point
│   ├── control_plane.rs       # CP mode (gRPC server + admin)
│   ├── data_plane.rs          # DP mode (gRPC client + proxy)
│   └── migrate.rs             # Migration mode
├── proxy/                     # Reverse proxy core
│   ├── mod.rs                 # ProxyState, handle_proxy_request, URL building
│   ├── handler.rs             # HTTP request/response processing, plugin lifecycle
│   ├── body.rs                # ProxyBody sum type (Full vs Tracked) with StreamingMetrics
│   ├── client_ip.rs           # Client IP resolution (trusted proxies, XFF)
│   ├── grpc_proxy.rs          # gRPC reverse proxy with HTTP/2 trailer support
│   ├── tcp_proxy.rs           # Raw TCP stream proxy with TLS termination/origination
│   ├── udp_proxy.rs           # UDP datagram proxy with per-client session tracking, DTLS frontend/backend
│   └── stream_listener.rs     # Stream listener lifecycle manager (reconcile on config reload)
├── plugins/                   # Plugin system (20 plugins)
│   ├── mod.rs                 # Plugin trait, registry, priority constants, lifecycle
│   └── [plugin_name].rs       # Individual plugin implementations
├── grpc/                      # CP/DP gRPC communication
│   ├── cp_server.rs           # Control Plane gRPC server (ConfigSync service)
│   └── dp_client.rs           # Data Plane gRPC client (subscribe + reconnect)
├── load_balancer.rs           # Load balancing algorithms + per-upstream cache
├── health_check.rs            # Active (HTTP/TCP/UDP probes) + passive health checking
├── circuit_breaker.rs         # Three-state circuit breaker
├── retry.rs                   # Retry logic with fixed/exponential backoff
├── connection_pool.rs         # HTTP client connection pooling with mTLS
├── router_cache.rs            # Pre-sorted route table with LPM path cache
├── plugin_cache.rs            # Plugin config cache (O(1) lookup by proxy_id)
├── consumer_index.rs          # Consumer lookup index (O(1) by credential type)
├── config_delta.rs            # Incremental config updates for CP/DP
├── dtls/                      # DTLS support (frontend termination, backend origination, cert helpers)
├── dns/                       # DNS resolution with caching
├── tls/                       # TLS/mTLS listener configuration
├── http3/                     # HTTP/3 (QUIC) support
└── custom_plugins/            # Custom/external plugin loading
```

### Domain Model (src/config/types.rs)

| Type | Description | Key Fields |
|------|-------------|------------|
| `GatewayConfig` | Top-level config container | proxies, consumers, upstreams, plugins |
| `Proxy` | A route + backend target | listen_path, backend_host/port/protocol, plugins, TLS/DNS/timeout overrides, pool_*, circuit_breaker, retry, response_body_mode |
| `Consumer` | An authenticated client identity | username, custom_id, credentials (HashMap), tags |
| `Upstream` | A load-balanced target group | targets (host/port/weight), algorithm, health_checks |
| `PluginConfig` | Plugin instance configuration | name, enabled, config (serde_json::Value) |

### Plugin System

Plugins execute in priority order (lower number = runs first). The lifecycle phases are:

1. `on_request_received` — Correlation ID, request transformer, bot detection
2. `authenticate` — Key auth, basic auth, JWT, HMAC, OAuth2
3. `authorize` — Access control (ACL), IP restriction
4. `before_proxy` — Rate limiting, body validation, request termination
5. `after_proxy` — Response transformer, CORS headers
6. `log` — Stdout logging, HTTP logging, Prometheus, OpenTelemetry

Plugin priority constants are defined in `src/plugins/mod.rs` (e.g., `priority::CORS = 100`, `priority::RATE_LIMITING = 1100`).

### Test Structure

```
tests/
├── unit_tests.rs              # Entry point → tests/unit/
├── integration_tests.rs       # Entry point → tests/integration/
├── functional_tests.rs        # Entry point → tests/functional/ (all #[ignored])
├── admin_cached_config_tests.rs
├── unit/
│   ├── config/                # Config parsing, env vars, TLS, pool config
│   ├── plugins/               # Per-plugin unit tests
│   ├── admin/                 # Admin API handler tests
│   └── gateway_core/          # Router, proxy, consumer index, DNS
├── integration/               # mTLS, connection pool, CP/DP gRPC, HTTP/3
├── functional/                # End-to-end per mode (file, DB, CP/DP, WebSocket, gRPC, LB)
└── performance/               # wrk-based load tests with baseline comparison
```

**Test conventions**:
- Unit tests: inline `#[cfg(test)]` modules for private functions, `tests/unit/` for public API
- Integration tests: test component interactions with real network I/O
- Functional tests: marked `#[ignore]` — start real gateway binary, test full request flow
- All test crates use `--all-features`

## Development Guidelines

### Before Every Commit

1. `cargo fmt` — format all code
2. `cargo clippy --all-targets --all-features -- -D warnings` — zero warnings
3. `cargo test --test unit_tests --all-features` — all unit tests pass
4. `cargo test --test integration_tests --test admin_cached_config_tests --all-features` — integration tests pass
5. If changing proxy behavior: `cargo build --bin ferrum-gateway && cargo test --test functional_tests --all-features -- --ignored` — E2E tests pass

### Code Quality Rules

- **No `.unwrap()` in production code** — use `?`, `.unwrap_or()`, `.unwrap_or_else()`, or match/if-let. `unwrap()` in tests is acceptable.
- **No `.expect()` in production code** — same as unwrap; use `anyhow::anyhow!()` + `?` for error propagation.
- **No panics on the hot path** — the proxy request path must never panic. Return errors gracefully.
- **Log errors, don't swallow them** — if using `.unwrap_or_default()`, consider logging a warning first.
- **Validate JWT expiration** — always set `validation.validate_exp = true` when verifying JWTs.
- **Escape user input in response bodies** — when interpolating user-provided strings into JSON/XML response bodies, escape special characters.

### Performance Rules

- **No allocations per-request when avoidable** — use pre-computed indexes (RouterCache, PluginCache, ConsumerIndex) instead of filtering/searching at request time. Static headers like Alt-Svc are pre-computed in `ProxyState` at startup.
- **No locks on the hot path** — use `ArcSwap::load()` for config reads, `DashMap` for concurrent maps. Never introduce `Mutex`/`RwLock` on the proxy path.
- **Pre-compute at config reload time** — when config changes, rebuild indexes, hash rings, lookup tables, and plugin metadata flags (e.g., `requires_response_body_buffering`). The request path should only do lookups.
- **Avoid `format!()` in hot loops** — pre-compute string keys at build time. Response headers like Alt-Svc are pre-formatted once, not per-request.
- **Use streaming responses by default** — only buffer when a plugin explicitly requires it. The buffering requirement is pre-computed per-proxy in `PluginCache` for O(1) lookup at request time.
- **Skip plugin phases when no plugins are configured** — guard plugin iteration loops with `plugins.is_empty()` to avoid iterator setup and async machinery overhead on the hot path.

### Adding a New Plugin

1. Create `src/plugins/my_plugin.rs` implementing the `Plugin` trait
2. Add a priority constant in `src/plugins/mod.rs` (`priority::MY_PLUGIN = N`)
3. Override `supported_protocols()` to declare which protocols the plugin supports (default is HTTP-only). Use the predefined constants: `ALL_PROTOCOLS`, `HTTP_FAMILY_PROTOCOLS`, `HTTP_GRPC_PROTOCOLS`, or `HTTP_ONLY_PROTOCOLS`
4. Register in the plugin registry (`create_plugin()` match arm in `mod.rs`)
5. Add unit tests in `tests/unit/plugins/my_plugin_tests.rs`
6. Add the module to `tests/unit/plugins/mod.rs`
7. Update `FEATURES.md`, `README.md`, and `docs/plugin_execution_order.md` (protocol matrix)

### Adding a New Config Field

1. Add the field to the appropriate struct in `src/config/types.rs` with `#[serde(default)]`
2. If env-var driven: add parsing in `src/config/env_config.rs`
3. If database-stored: update migration in `src/config/migrations/` and `db_loader.rs`
4. Add unit tests for deserialization in `tests/unit/config/`
5. Update `openapi.yaml` if the Admin API exposes it

### Database Considerations

- **Supported databases**: PostgreSQL, MySQL, SQLite (via sqlx)
- **Migrations**: Located in `src/config/migrations/`. Run via `FERRUM_MODE=migrate`.
- **Schema relationships**: Proxies reference upstreams via `upstream_id`. Plugins are associated with proxies via the `proxy_plugins` junction table. Consumers have credentials keyed by auth type.
- **Transactions**: All multi-step CRUD operations (create/update/delete proxy, delete plugin_config, delete upstream, cleanup orphaned upstream) are wrapped in `sqlx::Transaction` to prevent partial updates on crash or concurrent access.
- **Full proxy persistence**: All Proxy struct fields are persisted in the database, including `circuit_breaker` (JSON), `retry` (JSON), `response_body_mode`, and all `pool_*` override fields.
- **Incremental Polling**: Database mode polls for changes at `FERRUM_DB_POLL_INTERVAL_SECONDS` (default 30s) using a two-phase incremental strategy:
  1. **Startup**: Full `SELECT *` on all 4 tables to build the initial config and seed the poller's known ID sets.
  2. **Subsequent polls**: `load_incremental_config()` uses indexed `SELECT * FROM X WHERE updated_at > ?` queries (4 tables) to fetch only changed rows, plus lightweight `SELECT id FROM X` queries (4 tables) to detect deletions by diffing against the known ID set. A 1-second safety margin on the timestamp prevents missing boundary writes.
  3. **Fallback**: If the incremental poll fails for any reason, the loop automatically falls back to a full `load_full_config()` + `update_config()` cycle and re-seeds the known IDs.
  - The `updated_at` columns are indexed (`idx_proxies_updated_at`, `idx_consumers_updated_at`, `idx_plugin_configs_updated_at`, `idx_upstreams_updated_at`) so incremental queries use index scans, not full table scans.
  - Incremental results feed into `ProxyState::apply_incremental()` which patches the in-memory `GatewayConfig` and drives the same surgical cache updates (router, plugin, consumer, load balancer, circuit breaker, DNS warmup) as the full-reload path.

### PR Checklist

- [ ] `cargo fmt` — no formatting diffs
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — zero warnings
- [ ] `cargo test --test unit_tests --all-features` — unit tests pass
- [ ] `cargo test --test integration_tests --test admin_cached_config_tests --all-features` — integration tests pass
- [ ] New features have unit tests covering normal, edge, and error cases
- [ ] No `.unwrap()` or `.expect()` in production code paths
- [ ] No dead code (clippy enforces `-D dead-code`)
- [ ] PR description includes a summary, list of changes, and test plan
- [ ] Documentation updated if adding/changing features (FEATURES.md, README.md, docs/, openapi.yaml)

### Commit Message Style

Use imperative mood, concise subject lines:

```
Fix rate limiter to handle zero-window edge case
Add OAuth2 JWKS key rotation support
Reduce per-request allocations in plugin lookup
```

### Branch Naming

- `feature/<description>` — new features
- `fix/<description>` — bug fixes and corrections
- `claude/<generated-name>` — Claude-generated branches

## Key Environment Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_MODE` | (required) | `database`, `file`, `cp`, `dp`, `migrate` |
| `FERRUM_LOG_LEVEL` | `error` | `error`, `warn`, `info`, `debug`, `trace` |
| `FERRUM_PROXY_HTTP_PORT` | `8000` | Proxy HTTP listen port |
| `FERRUM_PROXY_HTTPS_PORT` | `8443` | Proxy HTTPS listen port |
| `FERRUM_ADMIN_HTTP_PORT` | `9000` | Admin API HTTP port |
| `FERRUM_ADMIN_HTTPS_PORT` | `9443` | Admin API HTTPS port |
| `FERRUM_ADMIN_JWT_SECRET` | (required for db/cp) | JWT secret for admin API auth |
| `FERRUM_FILE_CONFIG_PATH` | (required for file mode) | Path to YAML/JSON config file |
| `FERRUM_DB_TYPE` | (required for db mode) | `postgres`, `mysql`, `sqlite` |
| `FERRUM_DB_URL` | (required for db mode) | Database connection URL |
| `FERRUM_DB_CONFIG_BACKUP_PATH` | (none) | Path to externally provided JSON config backup for startup failover when DB is unreachable |
| `FERRUM_CP_GRPC_LISTEN_ADDR` | `0.0.0.0:50051` | CP gRPC server listen address |
| `FERRUM_DP_CP_GRPC_URL` | (required for dp mode) | CP gRPC URL for DP to connect to |
| `FERRUM_BACKEND_TLS_NO_VERIFY` | `false` | Skip backend TLS verification (testing only) |
| `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING` | `false` | Track streaming response total latency (adds per-stream overhead) |
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | (none) | HMAC-SHA256 server secret for basic_auth (~1μs vs ~100ms bcrypt) |
| `FERRUM_TRUSTED_PROXIES` | (empty) | Comma-separated CIDRs for XFF trust |
| `FERRUM_DTLS_CERT_PATH` | (none) | PEM cert for frontend DTLS termination (ECDSA P-256 / Ed25519) |
| `FERRUM_DTLS_KEY_PATH` | (none) | PEM key for frontend DTLS termination |
| `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | (none) | PEM CA cert for verifying DTLS client certs (frontend mTLS) |
| `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS` | `1000` | Threshold (ms) for warning-level logs on slow plugin HTTP calls |
| `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` | `100` | Max request body size (MiB) for `POST /restore` |

See `src/config/env_config.rs` for the full list of 90+ environment variables.

## Proto / gRPC

- Proto definition: `proto/ferrum.proto`
- Build script: `build.rs` compiles protos via `tonic_build`
- Service: `ConfigSync` with `Subscribe` (streaming) and `GetFullConfig` (unary)
- Auth: HS256 JWT in gRPC metadata (`authorization` key)

## Docker

- **Dockerfile**: Multi-stage build (rust:latest builder + debian:bookworm-slim runtime)
- **Exposed ports**: 8000, 8443 (proxy), 9000, 9443 (admin), 50051 (gRPC)
- **Health check**: `curl -f http://localhost:9000/health`
- **docker-compose.yml**: Profiles for `sqlite`, `postgres`, and `cp-dp` deployments

## Cargo Profiles

| Profile | Opt Level | LTO | Codegen Units | Use |
|---------|-----------|-----|---------------|-----|
| `dev` | 0 | No | 256 (incremental) | Local development |
| `release` | 3 | Thin | 16, strip=true | Production builds |
| `ci-release` | 2 | No | 256 | Fast CI builds |
