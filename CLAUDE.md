# CLAUDE.md — Ferrum Edge

This file provides context for Claude Code when working on the Ferrum Edge codebase.

## Project Overview

Ferrum Edge is a high-performance edge proxy built in Rust. It supports HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, and raw TCP/UDP stream proxying with a plugin architecture (28 built-in plugins including 4 AI/LLM-specific plugins), four operating modes, and load balancing with health checks.

- **Language**: Rust (edition 2024)
- **Async runtime**: tokio + hyper 1.0
- **Binary**: `ferrum-edge` (single binary, mode selected via env var)
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

# Integration tests (component interaction — mTLS, connection pool, gRPC, HTTP/3, admin API)
cargo test --test integration_tests --all-features

# Functional / end-to-end tests (start real gateway binary, test all modes)
# Requires: cargo build --bin ferrum-edge (builds the binary first)
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

1. **Format Check** — `cargo fmt --check` (instant, no compilation)
2. **Tests** (parallel with format check) — unit tests, integration tests, and E2E tests (`--ignored`) in a single job
3. **Lint** (depends on format check) — clippy with zero warnings
4. **Performance Regression** (depends on tests) — wrk-based load testing against baseline (built with `ci-release` profile)

All four jobs must pass for a PR to merge.

## Architecture

### Operating Modes (`FERRUM_MODE` env var)

| Mode | Description | Admin API | Proxy | Config Source |
|------|-------------|-----------|-------|---------------|
| `database` | Single-instance, DB-backed | Read/Write | Yes | PostgreSQL/MySQL/SQLite via polling |
| `file` | Single-instance, file-backed | Read-only | Yes | YAML/JSON file, SIGHUP reload (Unix only) |
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
├── plugins/                   # Plugin system (28 plugins, including 4 AI/LLM plugins)
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
├── router_cache.rs            # Pre-sorted route table with host+path routing, LPM path cache, and full-path-anchored regex routes
├── plugin_cache.rs            # Plugin config cache (O(1) lookup by proxy_id)
├── consumer_index.rs          # Consumer lookup index (O(1) by credential type)
├── config_delta.rs            # Incremental config updates for CP/DP
├── dtls/                      # DTLS support (frontend termination, backend origination, cert helpers)
├── dns/                       # DNS resolution with caching
├── service_discovery/         # Dynamic upstream discovery (DNS-SD, Kubernetes, Consul)
├── tls/                       # TLS/mTLS listener configuration
├── http3/                     # HTTP/3 (QUIC) support
└── custom_plugins/            # Drop-in custom plugins (auto-discovered by build.rs)
```

### Domain Model (src/config/types.rs)

| Type | Description | Key Fields |
|------|-------------|------------|
| `GatewayConfig` | Top-level config container | proxies, consumers, upstreams, plugins |
| `Proxy` | A route + backend target | listen_path, hosts, backend_host/port/protocol, plugins, TLS/DNS/timeout overrides, pool_*, circuit_breaker, retry, response_body_mode |
| `Consumer` | An authenticated client identity | username, custom_id, credentials (HashMap), tags |
| `Upstream` | A load-balanced target group | targets (host/port/weight/path), algorithm, health_checks |
| `PluginConfig` | Plugin instance configuration | name, enabled, config (serde_json::Value) |
| `ServiceDiscoveryConfig` | Dynamic upstream target discovery | provider (dns_sd/kubernetes/consul), poll_interval_seconds, provider-specific settings |

### Route Matching

Routes are matched in priority order within each host tier (exact host → wildcard host → catch-all):

1. **Prefix routes first** — longest-prefix match (pre-sorted by `listen_path.len()` descending)
2. **Regex routes second** — first match in config order wins

**Regex listen_path patterns** (prefixed with `~`) are **auto-anchored for full-path matching**: `^` is prepended and `$` is appended if not already present. This means `~/users/[^/]+` becomes `^/users/[^/]+$` and will only match `/users/42`, not `/users/42/profile`. Operators who need prefix-style regex matching can end their pattern with `.*` (e.g., `~/api/v[0-9]+/.*`). The shared helper `anchor_regex_pattern()` in `src/config/types.rs` is used by the router, validation, and admin endpoints.

### Plugin System

Plugins execute in priority order (lower number = runs first). The lifecycle phases are:

1. `on_request_received` — Correlation ID, request transformer, bot detection
2. `authenticate` — Key auth, basic auth, JWT, HMAC, JWKS
3. `authorize` — Access control (ACL), IP restriction
4. `before_proxy` — Rate limiting, AI prompt shield, body validation, AI request guard, request termination
5. `after_proxy` — Response transformer, CORS headers
6. `on_response_body` — AI token metrics, AI rate limiter (token counting)
7. `log` — Stdout logging, HTTP logging, Prometheus, OpenTelemetry

Plugin priority constants are defined in `src/plugins/mod.rs` (e.g., `priority::CORS = 100`, `priority::RATE_LIMITING = 2900`, `priority::AI_TOKEN_METRICS = 4100`).

### Test Structure

```
tests/
├── unit_tests.rs              # Entry point → tests/unit/
├── integration_tests.rs       # Entry point → tests/integration/
├── functional_tests.rs        # Entry point → tests/functional/ (all #[ignored])
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
- **Functional test subprocess rule**: When spawning the gateway binary in functional tests, use `Stdio::null()` for stdout/stderr unless the test explicitly reads the output (e.g., `functional_logging_test.rs`). Using `Stdio::piped()` without reading causes a pipe buffer deadlock — the OS buffer fills up from debug logs and the gateway blocks on writes, hanging the test.
- All test crates use `--all-features`

## Development Guidelines

### Before Every Commit

1. `cargo fmt` — format all code
2. `cargo clippy --all-targets --all-features -- -D warnings` — zero warnings
3. `cargo test --test unit_tests --all-features` — all unit tests pass
4. `cargo test --test integration_tests --all-features` — integration tests pass
5. If changing proxy behavior: `cargo build --bin ferrum-edge && cargo test --test functional_tests --all-features -- --ignored` — E2E tests pass

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

### Protocol-Specific Architecture

Each protocol has its own proxy path, connection pool, and backend dispatch. Understanding these paths is critical for performance work.

| Protocol | Frontend | Backend Client | Connection Pool | Streaming |
|----------|----------|---------------|-----------------|-----------|
| HTTP/1.1 | hyper server | reqwest | `ConnectionPool` (reqwest-managed) | Yes (default) |
| HTTP/2 | hyper server (ALPN) | reqwest or `Http2ConnectionPool` | Sharded H2 senders | Yes (default) |
| HTTP/3 | quinn/h3 server (`http3/server.rs`) | reqwest (via `connection_pool`) | reqwest auto-negotiates H2 via ALPN | Yes (coalescing buffer) |
| gRPC | hyper server (content-type detection) | `GrpcConnectionPool` (hyper H2 direct) | Sharded H2 senders | Yes (when no retry/body plugins) |
| WebSocket | hyper upgrade → tokio-tungstenite | Direct TCP upgrade | N/A (persistent connection) | Frame-by-frame forwarding |
| TCP | `TcpListener` per port | Direct `TcpStream::connect` | N/A (1:1 connection) | `copy_bidirectional` with idle timeout |
| UDP | `UdpSocket` per port | Per-session backend socket | N/A (session-keyed) | Datagram forwarding |

**Key dispatch points in `src/proxy/mod.rs`:**
- gRPC detection: `is_grpc_request()` checks `content-type: application/grpc` (line ~2530)
- H3 backend dispatch: `matches!(proxy.backend_protocol, BackendProtocol::H3)` (line ~3796)
- H2 pool dispatch: `matches!(proxy.backend_protocol, BackendProtocol::H2)` (line ~3828)
- Streaming vs buffered: controlled by `plugin_cache.requires_response_body_buffering()` and `proxy.retry.is_some()`

**HTTP/3 frontend architecture**: The H3 listener in `http3/server.rs` is a standalone QUIC server that handles its own request lifecycle (plugin phases, auth, route matching). For backend communication, it uses **reqwest** (not the `Http3ConnectionPool`). This is intentional — reqwest auto-negotiates HTTP/2 via ALPN which outperforms QUIC for small payloads due to lower per-request crypto overhead and more mature connection pooling. The `Http3ConnectionPool` in `http3/client.rs` is used only by the main hyper-based proxy path (`mod.rs`) for H3 backend targets.

**gRPC proxy architecture**: Uses hyper's HTTP/2 client directly (not reqwest) to preserve HTTP/2 trailers (`grpc-status`, `grpc-message`). The `GrpcConnectionPool` maintains sharded H2 connections with round-robin distribution. When `stream_response=true` (no retries, no body-buffering plugins), the response `Incoming` body is passed through as `ProxyBody::streaming_h2` — hyper forwards DATA and TRAILERS frames directly to the client without buffering.

### Performance Optimization Lessons

These are hard-won findings from profiling. Violating them causes measurable regressions.

**Allocation hot spots (most impactful):**
- **`HashMap::with_capacity()`** — always use `response.headers().keys_len()` when collecting response headers. Without it, the HashMap rehashes multiple times during header collection. This is a ~5-10% throughput impact.
- **Skip clones on streaming path** — when `stream_response=true` (no retries possible), move `method`/`headers`/`body_bytes` instead of cloning. Body clone for a 10KB payload = 10KB allocation wasted.
- **Conditional retry prep** — only build retry `HeaderMap` from `proxy_headers` when `proxy.retry.is_some()`. The common fast path (no retries) should do zero work. This was a +15% throughput fix for gRPC.
- **Pre-allocate body `Vec` from `content-length`** — parse the header to size the buffer, avoiding repeated reallocations during frame/chunk collection.

**Protocol-specific gotchas:**
- **Don't replace reqwest with H3 pool for HTTP/3 frontend→backend**: Tested and reverted. QUIC has higher per-request overhead than TCP/H2 for small payloads (~10x regression). reqwest's HTTP/2 pooling is highly optimized and auto-negotiates the best protocol via ALPN.
- **gRPC `Proxy.clone()` is expensive**: The full `Proxy` struct has many fields. Avoid cloning it per-request. Extract needed fields into lightweight param structs (see `TcpConnParams` pattern in `tcp_proxy.rs`).
- **H2 flow control tuning matters**: Default stream window (64KB) is too small for gRPC. The perf configs use 8MiB stream / 32MiB connection windows (`pool_http2_initial_stream_window_size`).
- **QUIC coalescing is critical**: Small QUIC frames kill performance. The H3 streaming path uses an 8-32KB coalescing buffer with time-based flush (2ms) to batch small chunks into larger QUIC frames.

**Resilience features per protocol:**

| Feature | HTTP/1.1 | HTTP/2 | HTTP/3 | gRPC | WebSocket | TCP | UDP |
|---------|----------|--------|--------|------|-----------|-----|-----|
| Load balancing | Full | Full | Full | Full | Full | Full | Full |
| Health checks | Full | Full | Full | Full (+ native gRPC) | HTTP probes | TCP SYN | UDP probe |
| Circuit breaker | Full | Full | Full | Full | Full | Connection-phase | Connection-phase |
| Retries | Full | Full | Full | Connection failures | Connection failures | Connection-phase | Connection-phase |
| Idle timeout | Pool-level | Pool-level | Pool-level | Pool-level | N/A | Configurable | Configurable |

### Known Protocol Gaps

Only two true gaps remain that cannot be solved without upstream library changes:

1. **No HTTP/2 WebSocket (RFC 8441)** — hyper's server doesn't support Extended CONNECT. Would require low-level h2 crate work to handle `:protocol = "websocket"` pseudo-headers.
2. **No DTLS 1.3** — No production Rust implementation exists (RFC 9147). `webrtc-dtls` only supports DTLS 1.2. QUIC (already supported) provides TLS 1.3 over UDP as an alternative.

### Multi-Protocol Performance Testing

Performance tests live in `tests/performance/multi_protocol/`. Run with:

```bash
# Build backend + gateway first
cd tests/performance/multi_protocol && cargo build --release

# Run specific protocol (http1, http1-tls, http2, http3, ws, grpc, tcp, tcp-tls, udp, udp-dtls, all)
bash run_protocol_test.sh grpc --duration 30 --concurrency 200

# Skip rebuild
bash run_protocol_test.sh all --skip-build --duration 30 --concurrency 100
```

Each test runs a gateway with protocol-specific config (`configs/*.yaml`) and a multi-protocol backend, measuring throughput via `wrk` or protocol-specific load tools. Both "via gateway" and "direct backend" are measured to calculate proxy overhead.

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
  1. **Startup**: Full `SELECT *` on all 4 tables to build the initial config and seed the poller's known ID sets. The `loaded_at` timestamp is captured **before** queries execute so the safety margin covers the full load duration.
  2. **Subsequent polls**: `load_incremental_config()` uses indexed `SELECT * FROM X WHERE updated_at > ?` queries (4 tables) to fetch only changed rows, plus lightweight `SELECT id FROM X` queries (4 tables) to detect deletions by diffing against the known ID set. A 1-second safety margin on the timestamp prevents missing boundary writes.
  3. **Validation**: Incremental results are validated (hosts, regex listen_paths, unique listen_paths, stream proxies, upstream references) before being applied — same as the full-load path. Invalid incremental configs are rejected and the previous valid config remains in effect.
  4. **Consistency**: The poller's known ID sets are only updated **after** `apply_incremental()` succeeds. If validation rejects the config, known IDs stay unchanged so the next poll re-fetches the same changes.
  5. **Fallback**: If the incremental poll fails for any reason, the loop automatically falls back to a full `load_full_config()` + `update_config()` cycle and re-seeds the known IDs.
  - The `updated_at` columns are indexed (`idx_proxies_updated_at`, `idx_consumers_updated_at`, `idx_plugin_configs_updated_at`, `idx_upstreams_updated_at`) so incremental queries use index scans, not full table scans.
  - Incremental results feed into `ProxyState::apply_incremental()` which patches the in-memory `GatewayConfig` and drives the same surgical cache updates (router, plugin, consumer, load balancer, circuit breaker, DNS warmup) as the full-reload path.
  - **CP mode** uses the same incremental polling strategy. Deltas are serialized and broadcast to DPs as `DELTA` updates (update_type=1) via gRPC. DPs apply them via `apply_incremental()`. On incremental poll failure, the CP falls back to a full reload and broadcasts a `FULL_SNAPSHOT`.
- **Multi-URL Failover**: `FERRUM_DB_FAILOVER_URLS` accepts comma-separated fallback database URLs. On startup, if the primary `FERRUM_DB_URL` is unreachable, failover URLs are tried in order. During polling, if both incremental and full reload fail, the gateway attempts to reconnect via failover URLs before marking the DB as unavailable. All failover URLs must use the same `FERRUM_DB_TYPE` and share TLS settings.
- **Read Replica**: `FERRUM_DB_READ_REPLICA_URL` offloads config polling reads to a read replica. The polling loop (both full and incremental) queries the replica, while Admin API writes always go to the primary. If the replica is unreachable at startup, polling transparently falls back to the primary. DNS re-resolution is performed independently for both primary and replica hostnames.

### PR Checklist

- [ ] `cargo fmt` — no formatting diffs
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` — zero warnings
- [ ] `cargo test --test unit_tests --all-features` — unit tests pass
- [ ] `cargo test --test integration_tests --all-features` — integration tests pass
- [ ] New features have unit tests covering normal, edge, and error cases
- [ ] No `.unwrap()` or `.expect()` in production code paths
- [ ] No dead code (clippy enforces `-D dead-code`)
- [ ] PR description includes a summary, list of changes, and test plan
- [ ] Documentation updated if adding/changing features (FEATURES.md, README.md, docs/, openapi.yaml)

### Commit Message Style

Use imperative mood, concise subject lines:

```
Fix rate limiter to handle zero-window edge case
Add JWKS multi-provider auth support
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
| `FERRUM_PROXY_BIND_ADDRESS` | `0.0.0.0` | Bind address for proxy listeners. Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_ADMIN_HTTP_PORT` | `9000` | Admin API HTTP port |
| `FERRUM_ADMIN_HTTPS_PORT` | `9443` | Admin API HTTPS port |
| `FERRUM_ADMIN_BIND_ADDRESS` | `0.0.0.0` | Bind address for admin listeners. Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_ADMIN_JWT_SECRET` | (required for db/cp) | JWT secret for admin API auth |
| `FERRUM_FILE_CONFIG_PATH` | (required for file mode) | Path to YAML/JSON config file |
| `FERRUM_DB_TYPE` | (required for db mode) | `postgres`, `mysql`, `sqlite` |
| `FERRUM_DB_URL` | (required for db mode) | Database connection URL |
| `FERRUM_DB_CONFIG_BACKUP_PATH` | (none) | Path to externally provided JSON config backup for startup failover when DB is unreachable |
| `FERRUM_DB_FAILOVER_URLS` | (empty) | Comma-separated failover database URLs (tried in order when primary is unreachable) |
| `FERRUM_DB_READ_REPLICA_URL` | (none) | Read replica URL for config polling (reduces primary load, falls back to primary) |
| `FERRUM_CP_GRPC_LISTEN_ADDR` | `0.0.0.0:50051` | CP gRPC server listen address |
| `FERRUM_CP_GRPC_TLS_CERT_PATH` | (none) | PEM cert for CP gRPC TLS |
| `FERRUM_CP_GRPC_TLS_KEY_PATH` | (none) | PEM key for CP gRPC TLS |
| `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` | (none) | PEM CA for verifying DP client certs (mTLS) |
| `FERRUM_DP_CP_GRPC_URL` | (required for dp mode) | CP gRPC URL for DP to connect to (`http://` or `https://`) |
| `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | (none) | PEM CA cert for verifying CP server cert |
| `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` | (none) | PEM client cert for DP-to-CP mTLS |
| `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH` | (none) | PEM client key for DP-to-CP mTLS |
| `FERRUM_DP_GRPC_TLS_NO_VERIFY` | `false` | Skip gRPC TLS cert verification (testing only) |
| `FERRUM_TLS_NO_VERIFY` | `false` | Skip outbound TLS verification for all connections (testing only) |
| `FERRUM_TLS_CA_BUNDLE_PATH` | (none) | Path to PEM CA bundle for outbound TLS verification (internal CAs) |
| `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING` | `false` | Track streaming response total latency (adds per-stream overhead) |
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | (none) | HMAC-SHA256 server secret for basic_auth (~1μs vs ~100ms bcrypt) |
| `FERRUM_TRUSTED_PROXIES` | (empty) | Comma-separated CIDRs for XFF trust |
| `FERRUM_DTLS_CERT_PATH` | (none) | PEM cert for frontend DTLS termination (ECDSA P-256 / Ed25519) |
| `FERRUM_DTLS_KEY_PATH` | (none) | PEM key for frontend DTLS termination |
| `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | (none) | PEM CA cert for verifying DTLS client certs (frontend mTLS) |
| `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS` | `1000` | Threshold (ms) for warning-level logs on slow plugin HTTP calls |
| `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` | `100` | Max request body size (MiB) for `POST /restore` |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | `4` | QUIC connections per HTTP/3 backend (distributes frame processing) |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | HTTP/3 connection pool idle eviction timeout |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | `30` | Cleanup sweep interval for HTTP, gRPC, HTTP/2, HTTP/3 pools |
| `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` | `300` | Default TCP idle timeout (5 min). Per-proxy `tcp_idle_timeout_seconds` overrides. 0 = disabled |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Maximum concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | UDP session cleanup sweep interval |
| `FERRUM_WORKER_THREADS` | (CPU cores) | Tokio worker threads (maps to `runtime::Builder::worker_threads`) |
| `FERRUM_BLOCKING_THREADS` | `512` | Tokio max blocking threads |
| `FERRUM_MAX_CONNECTIONS` | `100000` | Max concurrent proxy connections (semaphore-bounded; 0 = unlimited) |
| `FERRUM_TCP_LISTEN_BACKLOG` | `2048` | TCP listen backlog size (min 128) |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | `250` | Server-side HTTP/2 max concurrent streams per inbound connection |

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
