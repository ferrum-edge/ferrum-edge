# CLAUDE.md — Ferrum Edge

This file provides context for Claude Code when working on the Ferrum Edge codebase.

## Project Overview

Ferrum Edge is a high-performance edge proxy built in Rust. It supports HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, and raw TCP/UDP stream proxying with a plugin architecture (54 built-in plugins including 5 AI/LLM-specific plugins, 1 serverless function plugin, 1 response mock plugin, 1 spec expose plugin, 1 compression plugin, 1 SSE stream handler plugin, 3 gRPC-specific plugins, 3 WebSocket frame-level plugins, 1 WebSocket logging plugin, 1 UDP datagram-level plugin, 1 Loki logging plugin, 1 UDP logging plugin, 1 Kafka logging plugin, 1 SOAP WS-Security plugin, 1 load testing plugin, and 1 API chargeback plugin), four operating modes, and load balancing with health checks.

- **Language**: Rust (edition 2024)
- **Async runtime**: tokio + hyper 1.0
- **Binary**: `ferrum-edge` (single binary, CLI subcommands + env var config)
- **License**: PolyForm Noncommercial 1.0.0 (dual-licensed with paid commercial option)

## Quick Reference — Commands

### CLI Subcommands

```bash
ferrum-edge run [OPTIONS]                # Start gateway in foreground
ferrum-edge validate [OPTIONS]           # Validate config without starting
ferrum-edge reload [--pid PID]           # Send SIGHUP to running instance (Unix)
ferrum-edge version [--json]             # Print version info
ferrum-edge health [-p PORT] [--host H] [--tls] [--tls-no-verify]  # Health check (for distroless Docker HEALTHCHECK)
ferrum-edge                              # No args = legacy env-var-only mode
```

**`run` options**: `-s/--settings <PATH>` (ferrum.conf), `-c/--spec <PATH>` (resources YAML/JSON), `-m/--mode <MODE>`, `-v/--verbose` (repeatable).

**`validate` options**: `-s/--settings <PATH>`, `-c/--spec <PATH>`.

**Precedence**: CLI flag > env var > conf file > smart path defaults > hardcoded defaults.

**Smart defaults**: When `--settings`/`--spec` are omitted and env vars are unset, the CLI searches `./ferrum.conf`, `./config/ferrum.conf`, `/etc/ferrum/ferrum.conf` for settings and `./resources.yaml`, `./resources.json`, `./config/resources.yaml`, `./config/resources.json`, `/etc/ferrum/config.yaml`, `/etc/ferrum/config.json` for spec.

**Mode inference**: When `--spec` is provided and no mode is configured, `FERRUM_MODE=file` is set automatically.

**Backwards compatibility**: `ferrum-edge` with no args skips CLI parsing entirely and runs the existing env-var-only startup path. All Docker/systemd/CI deployments continue unchanged.

**Implementation**: `src/cli.rs` defines clap derive structs. `apply_run_overrides()` / `apply_validate_overrides()` translate CLI flags into env vars via `unsafe { std::env::set_var() }` before the `CONF_FILE_CACHE` OnceLock is triggered. This ordering is critical — see the comment in `main.rs`.

### Build

```bash
cargo build                              # Debug build
cargo build --release                    # Release build (O3, thin LTO, strip)
```

**Prerequisite**: `protoc` (protobuf compiler) must be installed. `build.rs` runs `tonic_build` to compile `proto/ferrum.proto`.

### Test

```bash
# Unit tests (fast, no I/O)
cargo test --test unit_tests
# Integration tests (component interaction — mTLS, connection pool, gRPC, HTTP/3, admin API)
cargo test --test integration_tests
# Functional / end-to-end tests (start real gateway binary, test all modes)
# Requires: cargo build --bin ferrum-edge (builds the binary first)
cargo test --test functional_tests -- --ignored

# All tests together
cargo test
cargo test -- --ignored   # includes E2E tests
```

### Lint

```bash
cargo clippy --all-targets -- -D warnings   # Zero warnings policy
cargo fmt --all -- --check                                  # Formatting check
cargo fmt                                                   # Auto-format
```

**CI enforces both clippy (zero warnings with `-D warnings`) and `cargo fmt --check`. Always run these before pushing.**

**MANDATORY: Before every `git commit`, run `cargo fmt --all` and then `cargo fmt --all -- --check` to verify zero diffs. CI will reject unformatted code. This is the #1 cause of CI failures — never skip it.**

### CI Pipeline (GitHub Actions)

The CI workflow (`.github/workflows/ci.yml`) runs on push to `main` and PRs targeting `main`:

1. **Format Check** — `cargo fmt --check` (instant, no compilation)
2. **Tests** (parallel with format check) — unit tests, integration tests, and E2E tests (`--ignored`) in a single job
3. **Lint** (depends on format check) — clippy with zero warnings
4. **Performance Regression** (depends on tests) — wrk-based load testing against baseline (built with `ci-release` profile)

All four jobs must pass for a PR to merge.

5. **Build Binaries** (depends on tests + lint) — release builds for 5 targets: Linux x86_64, Linux ARM64 (via `cross`), macOS x86_64, macOS ARM64, Windows x86_64. Runs on both PRs and main pushes to catch cross-platform build failures before merge.

On push to `main` only (after build binaries pass), additional jobs run:

6. **Latest Release** — overwrites a `latest` prerelease GitHub Release with all binaries and SHA256 checksums
7. **Docker** — builds per-platform images from pre-built binaries using `Dockerfile.release`, then creates a multi-arch manifest (linux/amd64 + linux/arm64) pushed to both Docker Hub (`ferrumedge/ferrum-edge:latest`) and GHCR (`ghcr.io/ferrum-edge/ferrum-edge:latest`)

### Release Pipeline (GitHub Actions)

The release workflow (`.github/workflows/release.yml`) runs on tag pushes matching `v*` (e.g., `v0.9.0`):

1. **Build Release Binaries** — same 5 targets as CI
2. **Create GitHub Release** — versioned, non-prerelease GitHub Release with binaries and checksums
3. **Docker** — multi-arch Docker images tagged with version variants (`v0.9.0`, `0.9.0`, `0.9`) pushed to Docker Hub and GHCR

### Required GitHub Actions Secrets

| Secret | Purpose |
|--------|---------|
| `DOCKERHUB_USERNAME` | Docker Hub username (e.g., `ferrumedge`) |
| `DOCKERHUB_TOKEN` | Docker Hub access token (Account Settings > Security > Access Tokens, Read & Write) |

GHCR uses the built-in `GITHUB_TOKEN` — no additional secret needed. Ensure repo **Settings > Actions > General > Workflow permissions** is set to **Read and write permissions**.

## Architecture

### Operating Modes (`FERRUM_MODE` env var)

| Mode | Description | Admin API | Proxy | Config Source |
|------|-------------|-----------|-------|---------------|
| `database` | Single-instance, DB-backed | Read/Write | Yes | PostgreSQL/MySQL/SQLite via polling |
| `file` | Single-instance, file-backed | Read-only | Yes | YAML/JSON file, SIGHUP reload (Unix only) |
| `cp` | Control Plane | Read/Write | **No** | Database + gRPC distribution |
| `dp` | Data Plane | Read-only | Yes | gRPC stream from CP |
| `migrate` | Schema migration utility | No | No | Runs DB migrations then exits |

**Disabling plaintext listeners (TLS-only operation)**: Setting `FERRUM_PROXY_HTTP_PORT=0` disables the plaintext HTTP proxy listener, `FERRUM_ADMIN_HTTP_PORT=0` disables the plaintext admin HTTP listener, and setting the port to `0` in `FERRUM_CP_GRPC_LISTEN_ADDR` (e.g., `0.0.0.0:0`) disables the gRPC listener. Disabled ports are excluded from `reserved_gateway_ports()` so stream proxy port conflict checks are unaffected. The gateway warns at startup if a plaintext port is disabled but no TLS is configured for that surface (which would leave no listeners active). The `ferrum-edge health` CLI subcommand auto-detects `FERRUM_ADMIN_HTTP_PORT=0` and switches to TLS mode (port 9443), or accepts `--tls` / `--tls-no-verify` flags explicitly.

**Admin JWT secret handling is intentionally per-mode**: Database and CP modes **require** `FERRUM_ADMIN_JWT_SECRET` (hard failure if unset) because their read-write admin API issues tokens via `POST /auth` that must survive restarts and be valid across instances sharing the same secret. File mode has a **read-only** admin API that never issues tokens, so it generates a random secret as a convenience — all externally-crafted tokens are rejected since no one can predict the secret. This asymmetry is by design, not an inconsistency.

**`/health` DB check is intentionally cached (15s TTL)**: The `/health` and `/status` endpoints are unauthenticated (by design — load balancer probes need them). Without caching, each call runs `SELECT 1` (SQL) or `ping` (MongoDB), which an attacker with admin port access could flood to exhaust the DB connection pool (`FERRUM_DB_POOL_MAX_CONNECTIONS`, default 10), starving config polling and admin writes. The `CachedDbHealthResult` in `AdminState` caches the boolean result for 15 seconds via lock-free `ArcSwap`. Do not remove this cache or make `/health` call `db.health_check()` directly on every request.

### Core Design Principles

1. **Lock-free hot path**: All request-path reads use `ArcSwap::load()` or `DashMap` sharded locks. No `Mutex`/`RwLock` on the proxy path.
2. **Zero-allocation hot path**: Connection pool keys use thread-local buffers (no `String` allocation on cache hits). Load balancer selections return `Arc<UpstreamTarget>` (pointer bump, not struct clone). Response header collection avoids allocating key strings for existing headers. Status code counters are pre-populated so the hot path uses DashMap read locks, not write locks.
3. **Pre-computed indexes**: RouterCache, PluginCache, ConsumerIndex, and LoadBalancerCache are rebuilt on config reload, not per-request.
4. **Atomic config reload**: Config changes are loaded in background, validated, then swapped atomically via `ArcSwap`. Requests in-flight see old or new config — never partial.
5. **Resilience**: If the config source (DB/file/gRPC) is unavailable, the gateway continues serving with cached config.

### Startup Sequence

1. **jemalloc** — Global allocator on non-Windows (reduces fragmentation under high concurrency)
2. **CLI parsing** — clap parses subcommands and flags. Early-exit commands (`version`, `reload`) return immediately. `run`/`validate` apply env var overrides via `apply_run_overrides()`/`apply_validate_overrides()`. No subcommand = legacy env-var-only mode (skips CLI overrides). **Must run before step 4** because the `CONF_FILE_CACHE` OnceLock captures `FERRUM_CONF_PATH` on first access
3. **rustls crypto provider** — Install ring as the TLS backend (must be first)
4. **Logging** — JSON structured logging via `tracing-subscriber` with a non-blocking stdout writer (`tracing-appender`). Buffer capacity is tunable via `FERRUM_LOG_BUFFER_CAPACITY`
5. **Validate exit** — If `validate` subcommand, loads config, validates, prints result, and exits (skips steps 6-9)
6. **Secret resolution** — Single-threaded tokio runtime resolves `FERRUM_*_SECRET_*` env vars from Vault/AWS/Azure/GCP/file backends. Uses single-threaded runtime because `std::env::set_var` is unsafe with concurrent threads
7. **EnvConfig parsing** — 90+ env vars parsed into `EnvConfig` (now includes resolved secrets)
8. **Multi-threaded runtime** — tokio `new_multi_thread()` with configurable worker/blocking threads
9. **Mode dispatch** — Runs the selected operating mode (database/file/cp/dp/migrate)
10. **Signal handling** — SIGINT/SIGTERM trigger graceful shutdown via `watch::channel`

Within each mode (database/file/dp), after config is loaded:

9. **TLS policy** — `TlsPolicy::from_env_config()` builds the cipher suite, protocol version, and key exchange group constraints from `FERRUM_TLS_*` env vars
10. **Frontend TLS** — Loads `FERRUM_FRONTEND_TLS_CERT_PATH` / `FERRUM_FRONTEND_TLS_KEY_PATH` into a rustls `ServerConfig` for HTTPS, gRPC, and WebSocket listeners. Optionally loads `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` for frontend mTLS. The gateway hard-fails if configured paths are invalid (no silent fallback to plaintext).
11. **Admin TLS** — Loads `FERRUM_ADMIN_TLS_CERT_PATH` / `FERRUM_ADMIN_TLS_KEY_PATH` for the admin API HTTPS listener (same validation rules as frontend TLS)
12. **DTLS certs** — Loads `FERRUM_DTLS_CERT_PATH` / `FERRUM_DTLS_KEY_PATH` for UDP proxy frontend DTLS termination (ECDSA P-256 / Ed25519)
13. **Backend TLS** — Per-proxy `backend_tls_client_cert_path`, `backend_tls_client_key_path`, and `backend_tls_server_ca_cert_path` are validated at config load time (startup and each reload). Invalid paths reject the config — no silent degradation.
14. **CP/DP gRPC TLS** — CP loads `FERRUM_CP_GRPC_TLS_CERT_PATH` / key / client CA for the gRPC server. DP loads `FERRUM_DP_GRPC_TLS_*` certs for the gRPC client connection to CP.
15. **Stream proxy port validation** — Validates that stream proxy `listen_port` values do not conflict with gateway reserved ports (`FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`, `FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`, CP gRPC port). Ports set to `0` (disabled) are excluded from conflict checks. Conflicts are fatal in database/file modes.
16. **Stream listener bind** — `initial_reconcile_stream_listeners()` binds TCP/UDP stream proxy ports. In database/file modes, bind failure is fatal (gateway exits). In DP mode, bind failures are logged as errors but non-fatal — the DP continues serving HTTP traffic and retries when the CP pushes corrected config.
17. **DNS warmup** — All backend hostnames (proxy backends, upstream targets, plugin endpoints) are resolved concurrently before accepting traffic.
18. **Connection pool warmup** — When `FERRUM_POOL_WARMUP_ENABLED=true` (default), pre-establishes backend connections for HTTP-family pools (reqwest, gRPC, HTTP/2 direct, HTTP/3) after DNS warmup. TCP/UDP stream proxies are skipped (no persistent pools). Upstream targets are expanded so each target gets a warmed connection. Failures are logged as warnings but never block startup.
19. **Overload monitor** — Background task started in all proxy-serving modes (database/file/dp). Monitors FD usage, active connection count, and event loop latency at `FERRUM_OVERLOAD_CHECK_INTERVAL_MS` intervals (default: 1s). Sets atomic action flags (`disable_keepalive`, `reject_new_connections`) when thresholds are breached. See `src/overload.rs`.

### Graceful Shutdown & Connection Draining

On SIGTERM/SIGINT the gateway performs a graceful drain:

1. **Accept loops exit** — all listeners stop accepting new connections
2. **Drain phase** — `OverloadState.draining` is set to `true`, causing `Connection: close` on all HTTP/1.1 responses. The gateway waits up to `FERRUM_SHUTDOWN_DRAIN_SECONDS` (default: 30) for the `active_connections` counter (maintained by `ConnectionGuard` RAII) to reach zero.
3. **Background cleanup** — DNS refresh, config polling, overload monitor get 5s timeout
4. **Exit** — process exits cleanly

**Connection tracking**: Every accepted connection (HTTP/1.1, H2, H3, gRPC) creates a `ConnectionGuard` in the accept loop that increments `OverloadState.active_connections` on creation and decrements on drop. When the last guard drops during drain, `Notify::notify_one()` wakes the drain waiter. Cost: one `AtomicU64::fetch_add(Relaxed)` per connection (~5ns).

**`FERRUM_SHUTDOWN_DRAIN_SECONDS=0`** disables draining — the gateway exits immediately after accept loops close, matching pre-drain behavior.

### Overload Manager

The overload manager (`src/overload.rs`) provides progressive load shedding based on resource pressure signals. It is always enabled.

**Resource monitors** (run in a single background tokio task):
- **File descriptors**: `count_open_fds()` / `get_fd_limit()` — prevents EMFILE cliff
- **Connections**: `OverloadState.active_connections` / `FERRUM_MAX_CONNECTIONS`
- **Event loop latency**: `tokio::task::yield_now()` scheduling delay — detects thread starvation

**Progressive actions** (each signal triggers independently):

| Threshold | Action | Hot Path Cost |
|-----------|--------|---------------|
| FD ≥ 80% or Conn ≥ 85% | `disable_keepalive` → `Connection: close` on responses | 1 `AtomicBool::load(Relaxed)` per response |
| FD ≥ 95% or Conn ≥ 95% or Loop ≥ 500ms | `reject_new_connections` → accept+drop (HTTP) / refuse (H3) | 1 `AtomicBool::load(Relaxed)` per accept |

**Admin endpoint**: `GET /overload` (unauthenticated) returns JSON with pressure ratios and active actions. Returns 503 when `level` is `critical`.

**State transitions are logged**: `warn` when entering overload, `info` when recovering. No log spam — only logs on transitions.

### External Secret Resolution

The gateway resolves secrets from external providers at startup, before any config is loaded. Env vars with provider-specific suffixes are resolved and the base env var is set:

| Suffix | Provider | Example |
|--------|----------|---------|
| `_VAULT` | HashiCorp Vault | `FERRUM_DB_URL_VAULT=secret/data/db#url` |
| `_AWS` | AWS Secrets Manager | `FERRUM_DB_URL_AWS=my-secret#password` |
| `_AZURE` | Azure Key Vault | `FERRUM_DB_URL_AZURE=https://vault.azure.net/secrets/db-url` |
| `_GCP` | GCP Secret Manager | `FERRUM_DB_URL_GCP=projects/P/secrets/S/versions/latest` |
| `_FILE` | File on disk | `FERRUM_DB_URL_FILE=/run/secrets/db_url` |
| `_ENV` | Another env var | `FERRUM_DB_URL_ENV=DATABASE_URL` |

Backends are grouped so a single client is created per provider type (avoids repeated credential initialization). Conflict detection prevents two providers from setting the same base key.

### Source Layout

```
src/
├── main.rs                    # CLI parsing, mode dispatch, signal handling
├── cli.rs                     # CLI subcommand definitions (clap derive), path resolution, env var injection
├── lib.rs                     # Public API re-exports
├── admin/                     # Admin REST API (CRUD for proxies, consumers, upstreams, plugins)
│   ├── mod.rs                 # Routes, handlers, listener setup
│   └── jwt_auth.rs            # JWT middleware for admin endpoints
├── config/                    # Configuration loading & types
│   ├── types.rs               # Core domain model (Proxy, Consumer, Upstream, Plugin, etc.)
│   ├── env_config.rs          # Environment variable parsing (90+ vars)
│   ├── db_backend.rs          # DatabaseBackend trait (shared interface for sqlx + MongoDB)
│   ├── db_loader.rs           # SQL config loader + polling (sqlx: PostgreSQL, MySQL, SQLite)
│   ├── mongo_store.rs         # MongoDB config store
│   ├── file_loader.rs         # YAML/JSON file loader
│   ├── pool_config.rs         # Connection pool configuration
│   ├── config_migration.rs    # Config version migrations
│   └── migrations/            # SQL schema migrations (v001_initial_schema.rs) + CustomPluginMigration support
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
│   ├── http2_pool.rs          # HTTP/2 direct connection pool (hyper H2, sharded senders)
│   ├── sni.rs                 # SNI extraction from TLS/DTLS ClientHello (used by passthrough mode)
│   ├── tcp_proxy.rs           # Raw TCP stream proxy with TLS termination/origination/passthrough
│   ├── udp_batch.rs           # Batched UDP recv via recvmmsg(2) on Linux (reduces syscall overhead)
│   ├── udp_proxy.rs           # UDP datagram proxy with per-client session tracking, DTLS frontend/backend/passthrough
│   └── stream_listener.rs     # Stream listener lifecycle manager (reconcile on config reload, port pre-bind check)
├── plugins/                   # Plugin system (54 plugins, including 5 AI/LLM, 1 AI federation, 1 serverless, 1 response mock, 1 spec expose, 1 compression, 1 SSE, 3 gRPC, 3 WS frame, 1 WS logging, 1 UDP datagram, 1 Loki logging, 1 UDP logging, 1 Kafka logging, 1 SOAP WS-Security plugin, 1 load testing plugin, and 1 API chargeback plugin)
│   ├── mod.rs                 # Plugin trait, registry, priority constants, lifecycle
│   ├── [plugin_name].rs       # Individual plugin implementations
│   └── utils/                 # Shared plugin infrastructure
│       ├── http_client.rs     # Shared HTTP client for plugin outbound calls
│       └── redis_rate_limiter.rs  # Shared Redis client for centralized rate limiting
├── grpc/                      # CP/DP gRPC communication
│   ├── cp_server.rs           # Control Plane gRPC server (ConfigSync service, broadcast channel)
│   └── dp_client.rs           # Data Plane gRPC client (subscribe + exponential backoff reconnect)
├── overload.rs                # Overload manager: resource monitors, progressive load shedding, graceful drain
├── load_balancer.rs           # Load balancing algorithms + per-upstream cache (Arc<UpstreamTarget> for zero-cost selection) + HealthContext for dual-map health filtering
├── health_check.rs            # Active (shared per-upstream probes) + passive (isolated per-proxy) health checking with two-level index
├── circuit_breaker.rs         # Three-state circuit breaker (connection errors vs status code failures tracked independently via trip_on_connection_errors)
├── retry.rs                   # Retry logic with fixed/exponential backoff
├── connection_pool.rs         # HTTP client connection pooling with mTLS (thread-local pool keys for zero-alloc cache hits)
├── router_cache.rs            # Pre-sorted route table with host+path routing, LPM path cache, and full-path-anchored regex routes
├── plugin_cache.rs            # Plugin config cache (O(1) lookup by proxy_id)
├── consumer_index.rs          # Consumer lookup index (O(1) by credential type, multi-credential aware)
├── config_delta.rs            # Incremental config updates for CP/DP
├── dtls/                      # DTLS support (frontend termination, backend origination, cert helpers)
├── dns/                       # DNS resolution with caching, stale-while-revalidate, background refresh
├── service_discovery/         # Dynamic upstream discovery (DNS-SD, Kubernetes, Consul)
├── secrets/                   # External secret resolution (Vault, AWS, Azure, GCP, env, file)
│   ├── mod.rs                 # Secret backend registry + conflict detection
│   ├── vault.rs               # HashiCorp Vault KV v2
│   ├── aws.rs                 # AWS Secrets Manager
│   ├── azure.rs               # Azure Key Vault
│   ├── gcp.rs                 # Google Cloud Secret Manager
│   ├── env.rs                 # Environment variable references
│   └── file.rs                # File-based secrets (Docker Swarm, K8s volume mounts)
├── tls/                       # TLS/mTLS listener configuration
├── http3/                     # HTTP/3 (QUIC) support
└── custom_plugins/            # Drop-in custom plugins (auto-discovered by build.rs, supports plugin_migrations())
```

### Domain Model (src/config/types.rs)

| Type | Description | Key Fields |
|------|-------------|------------|
| `GatewayConfig` | Top-level config container | proxies, consumers, upstreams, plugins |
| `Proxy` | A route + backend target | namespace, listen_path, hosts, backend_host/port/protocol, plugins, TLS/DNS/timeout overrides, pool_*, circuit_breaker, retry, response_body_mode, allowed_ws_origins, udp_max_response_amplification_factor, passthrough |
| `Consumer` | An authenticated client identity | namespace, username, custom_id, credentials (HashMap — each type maps to a single JSON object or an array of objects for multi-credential rotation), acl_groups (Vec), tags |
| `Upstream` | A load-balanced target group | namespace, targets (host/port/weight/path), algorithm, health_checks |
| `PluginConfig` | Plugin instance configuration | namespace, name, enabled, config (serde_json::Value), priority_override (Option<u16>) |
| `ServiceDiscoveryConfig` | Dynamic upstream target discovery | provider (dns_sd/kubernetes/consul), poll_interval_seconds, provider-specific settings |

**Namespace isolation**: Every resource (`Proxy`, `Consumer`, `Upstream`, `PluginConfig`) has a `namespace` field (default `"ferrum"`). The gateway instance's `FERRUM_NAMESPACE` env var controls which namespace it loads and proxies. In database mode, all queries filter by namespace. In file mode, resources are filtered post-deserialization. The Admin API uses an `X-Ferrum-Namespace` header (defaults to `"ferrum"` if omitted) to scope all CRUD operations — this allows a CP to manage resources across all namespaces. `GET /namespaces` returns all distinct namespaces in the config/database. Uniqueness constraints (listen_path, proxy name, consumer identity, upstream name, listen_port) are all scoped per-namespace. Different namespaces run on different gateway instances, so the same `listen_port` can be safely reused across namespaces — the OS-level bind at startup catches real conflicts on the actual machine. In the CP/DP gRPC protocol, the DP sends its namespace in `SubscribeRequest` for observability logging.

**Hostname normalization**: All hostnames are normalized to ASCII-lowercase at the admission layer via `normalize_fields()` — this includes `Proxy.hosts`, `Proxy.backend_host`, and `UpstreamTarget.host`. Normalization runs at every entry point: admin API (create/update/batch/restore), file loader, DB loader (full and incremental), DP gRPC client, and config backup restore. Downstream consumers (DNS cache, connection pool keys, health check keys, LB keys) rely on this invariant and do NOT re-lowercase. Do not add per-lookup lowercasing in those paths — it is unnecessary and adds hot-path overhead.

### Route Matching

Routes are matched in priority order within each host tier (exact host → wildcard host → catch-all):

1. **Prefix routes first** — longest-prefix match via HashMap index (O(path_depth), typically 2-5 lookups)
2. **Regex routes second** — first match via RegexSet (O(path_length) single DFA pass, independent of pattern count)

**Prefix route matching uses `IndexedPrefixRoutes`** — a HashMap that maps each `listen_path` to its proxy, built at config-load time. On a cache miss, the router walks the request path backwards through `/` segment boundaries doing O(1) HashMap lookups at each step. This is **O(path_depth)** regardless of how many proxies are configured, replacing the previous O(n) linear scan that degraded throughput by 30-46% as proxy count grew from 50 to 500+. **Do not replace this with a linear scan or any algorithm whose per-request cost scales with total proxy count.** The HashMap index is applied to all three host tiers (exact, wildcard, catch-all). The `IndexedPrefixRoutes` struct in `src/router_cache.rs` bundles the sorted `Vec<RouteEntry>` (for `apply_delta` retain scans) with the `HashMap<String, Arc<Proxy>>` index.

**Regex route matching uses `IndexedRegexRoutes`** — a `RegexSet` that compiles all patterns for a host tier into a single DFA, built at config-load time. On a cache miss, `RegexSet::matches()` evaluates all patterns in one pass (O(path_length), independent of how many regex patterns exist), then only the winning pattern's individual `Regex` runs `captures()` to extract named groups. When multiple patterns match, the lowest index wins (preserving first-match-wins / config-order semantics). **Do not replace this with sequential per-pattern matching — that is O(n_patterns) per cache miss and degrades at scale.** The `IndexedRegexRoutes` struct in `src/router_cache.rs` bundles `Vec<RegexRouteEntry>` with the `RegexSet`.

**Router lookup cache** (`DashMap` in `RouterCache`) caches `(host, path) → proxy` results for O(1) repeated lookups. Cache size is controlled by `FERRUM_ROUTER_CACHE_MAX_ENTRIES` (default: auto-scales as `max(10_000, proxies × 3)`). Both prefix and regex matches have separate cache partitions to prevent high-cardinality regex paths from evicting prefix entries. Negative lookups (no route matched) are also cached to prevent repeated scans from scanner traffic.

**Regex listen_path patterns** (prefixed with `~`) are **auto-anchored for full-path matching**: `^` is prepended and `$` is appended if not already present. This means `~/users/[^/]+` becomes `^/users/[^/]+$` and will only match `/users/42`, not `/users/42/profile`. Operators who need prefix-style regex matching can end their pattern with `.*` (e.g., `~/api/v[0-9]+/.*`). The shared helper `anchor_regex_pattern()` in `src/config/types.rs` is used by the router, validation, and admin endpoints.

### Protocol-Level Request Validation

The gateway validates protocol-level constraints before routing to block smuggling, desync, and framing attacks. These checks run on every inbound request in `handle_proxy_request()` (HTTP/1.1, HTTP/2) and `handle_h3_request()` (HTTP/3) via the shared `check_protocol_headers()` helper in `src/proxy/mod.rs`.

| Check | HTTP/1.x | HTTP/2 | HTTP/3 | Response |
|-------|----------|--------|--------|----------|
| **HTTP/1.0 + TE** (no chunked in 1.0) | Reject 400 | N/A | N/A | `{"error":"HTTP/1.0 does not support Transfer-Encoding"}` |
| **CL + TE conflict** (request smuggling) | Reject 400 | N/A (no TE) | N/A (no TE) | `{"error":"Request contains both Content-Length and Transfer-Encoding headers"}` |
| **Multiple Content-Length** (mismatched values) | Reject 400 | Reject 400 | Reject 400 | `{"error":"Multiple Content-Length headers with conflicting values"}` |
| **Multiple Host headers** | Reject 400 | N/A (:authority) | N/A (:authority) | `{"error":"Request contains multiple Host headers"}` |
| **TE header value** | Any allowed | Only "trailers" | N/A | `{"error":"HTTP/2 TE header must be 'trailers' or absent"}` |
| **Content-Length non-numeric** | Reject 400 | Reject 400 | Reject 400 | `{"error":"Content-Length header contains invalid non-numeric value"}` |
| **TRACE method** | Reject 405 | Reject 405 | Reject 405 | `{"error":"TRACE method is not allowed"}` |
| **gRPC non-POST method** | Reject (gRPC error) | Reject (gRPC error) | N/A | gRPC trailers-only error |
| **WebSocket Sec-WebSocket-Key** | Format validated | N/A | N/A | Treated as non-WS request |
| **WebSocket Origin** | Per-proxy | N/A | N/A | Reject 403 when `allowed_ws_origins` is set and Origin doesn't match |

**CL + TE conflict** is the most critical check — it prevents HTTP request smuggling attacks that exploit parsing disagreements between the proxy and backend about message boundaries (RFC 9112 §6.1).

**Content-Length non-numeric validation**: RFC 9110 §8.6 specifies Content-Length MUST be a non-negative integer (ASCII digits only). Values like `-1`, `1.5`, `0x10`, or `abc` are rejected before routing. This check is integrated into the existing CL conflict detection loop in `check_protocol_headers()`.

**TRACE method blocking**: TRACE is blocked globally before routing to prevent Cross-Site Tracing (XST) attacks, where TRACE echoes request headers (including cookies and auth tokens) in the response body.

**WebSocket Origin validation**: When a proxy's `allowed_ws_origins` is non-empty, WebSocket upgrade requests must include an `Origin` header matching one of the allowed values (case-insensitive). This protects against Cross-Site WebSocket Hijacking (CSWSH) per RFC 6455 §10.2. The check runs after authentication/authorization plugins, before the upgrade handshake.

**WebSocket Sec-WebSocket-Key validation**: RFC 6455 §4.1 requires the key to be a base64-encoded 16-byte nonce. The `is_valid_websocket_key()` helper validates this; requests with malformed keys are not treated as WebSocket upgrades, falling through to regular HTTP handling.

**HTTP/1.1 Transfer-Encoding values** (intentionally not validated): The gateway accepts any TE value on HTTP/1.1 (e.g., `gzip`, `deflate`, `trailers`) because RFC 9110 §10.1.4 permits them. TE is stripped as a hop-by-hop header before forwarding to backends, so unknown values cannot cause parsing disagreements. The real danger (CL+TE smuggling) is caught by the conflict check. HTTP/1.0 + TE is rejected since HTTP/1.0 has no chunked encoding.

**H2.CL downgrade smuggling** (verified safe): When proxying HTTP/2 requests to HTTP/1.1 backends, the gateway strips `Content-Length` as a hop-by-hop header at all proxy dispatch paths (reqwest first attempt, retries, and HTTP/3). Reqwest then recalculates `Content-Length` from the actual body bytes via `req_builder.body()`. An attacker cannot smuggle a mismatched CL from HTTP/2 to HTTP/1.1.

**TE.TE obfuscation** (verified safe): Transfer-Encoding obfuscation variants (e.g., `"Chunked"`, `" chunked"`, `"chunked, identity"`) cannot reach backends because: (1) HTTP/1.0 rejects all TE outright, (2) HTTP/1.1 strips TE as hop-by-hop before forwarding, (3) HTTP/2 validates TE must be exactly `"trailers"` (case-insensitive with whitespace trim), (4) hyper normalizes header names to lowercase preventing name-case obfuscation. Tested with 10+ TE obfuscation variants in `protocol_validation_tests.rs`.

**What hyper/h2/quinn already validate** (no additional checks needed):
- HTTP method token syntax (RFC 7230)
- Header name/value syntax
- Header name normalization to lowercase (prevents header name case obfuscation)
- HTTP/2 pseudo-header presence and ordering (`:method`, `:path`, `:scheme`, `:authority`)
- HTTP/2 frame format, stream state machine, flow control
- HTTP/2 stream abuse detection (`max_pending_accept_reset_streams`, `max_local_error_reset_streams`)
- HTTP/3 QUIC packet format, TLS 1.3 handshake, stream state transitions
- WebSocket frame format, masking, close frame validation (tokio-tungstenite)

### TLS/DTLS Passthrough Mode

When `passthrough: true` is set on a stream proxy, the gateway forwards encrypted client bytes directly to the backend without terminating TLS (TCP) or DTLS (UDP). The proxy peeks at the TLS/DTLS ClientHello to extract SNI for logging but never decrypts application data.

**Implementation details:**
- **TCP passthrough** (`src/proxy/tcp_proxy.rs`): Uses `TcpStream::peek()` to read the ClientHello without consuming bytes, then `bidirectional_copy` forwards the entire encrypted stream to the backend as plain TCP.
- **UDP passthrough** (`src/proxy/udp_proxy.rs`): Parses the first DTLS ClientHello datagram for SNI, then creates a plain UDP backend socket (skips DTLS origination). All datagrams pass through unmodified.
- **SNI extraction** (`src/proxy/sni.rs`): Hand-written TLS/DTLS ClientHello parser that extracts the server_name extension (type 0x0000) per RFC 6066 §3. Handles both TLS 1.2/1.3 and DTLS 1.2 ClientHello formats. SNI hostnames are normalized to lowercase.
- **Stream listener** (`src/proxy/stream_listener.rs`): When `passthrough` is true, frontend TLS/DTLS config is skipped — the listener accepts raw TCP/UDP connections.

**Validation rules** (in `Proxy::validate_fields_inner()`):
- `passthrough` only valid on stream proxies (`is_stream_proxy()`)
- Mutually exclusive with `frontend_tls` (can't terminate and pass through simultaneously)
- Backend TLS fields (`backend_tls_client_cert_path`, `backend_tls_client_key_path`, `backend_tls_server_ca_cert_path`) are rejected — the proxy doesn't originate backend TLS in passthrough mode

**Logging:** `StreamConnectionContext.sni_hostname` and `StreamTransactionSummary.sni_hostname` carry the extracted SNI to connection-lifecycle plugins (`on_stream_connect`, `on_stream_disconnect`).

### Stream Proxy Port Validation

TCP/UDP stream proxies bind dedicated ports via `listen_port`. Port conflicts are detected at multiple levels:

**Config validation** (`validate_stream_proxies()` + `validate_stream_proxy_port_conflicts()`):
- `listen_port` required for stream proxies, forbidden for HTTP proxies
- Unique across all stream proxies (in-memory check)
- Must not collide with gateway reserved ports — collected by `EnvConfig::reserved_gateway_ports()` (proxy HTTP/HTTPS, admin HTTP/HTTPS, CP gRPC)

**Admin API** (database/CP modes only):
- Port uniqueness via DB query (`check_listen_port_unique()`)
- Gateway reserved port conflict check (skipped in CP mode — proxies run on remote DPs)
- OS-level port availability probe via `check_port_available()` — probes only the matching transport (TCP or UDP) then drops (skipped in CP mode)

**Startup reconcile** (`initial_reconcile_stream_listeners()`):
- Pre-binds each port before spawning the listener task; bind failures are collected
- In database/file modes: bind failure is **fatal** — gateway exits with a clear error
- In DP mode: bind failure is **non-fatal** — error logged, DP continues. This prevents a bad port pushed by the CP from permanently bricking the DP on restart. The DP retries when the CP pushes corrected config.

**Runtime reconcile** (config reload / incremental update):
- Bind failures are logged as errors but never crash the gateway
- Failed listeners are skipped; existing working listeners continue unaffected

**DP port conflict validation — intentionally deferred to bind time**: The DP does NOT run `validate_stream_proxy_port_conflicts()` when receiving full config snapshots or incremental deltas from the CP. This is by design — the CP manages proxies for many heterogeneous DPs, each with different reserved ports, so the CP cannot know which ports conflict on each DP. Rejecting the entire config would prevent all valid proxies from running. Instead, port conflicts are detected at bind time during listener reconciliation, where only the conflicting proxy is skipped and all others proceed normally.

### Plugin System

Plugins execute in priority order (lower number = runs first). Multiple instances of the same plugin type are supported on a single proxy (e.g., two `http_logging` instances for Splunk and Datadog). Each instance has its own `id`, `config`, and optional `priority_override` to control relative execution order. When a proxy-scoped plugin has the same `plugin_name` as a global plugin, the global instance is replaced — but multiple proxy-scoped instances of the same type coexist.

The lifecycle phases are:

1. `on_request_received` — OTel tracing (25), correlation ID (50), CORS preflight (100), request termination (125), IP restriction (150), bot detection (200), spec expose (210), SSE validation (250), gRPC-Web translation (260), gRPC method router (275)
2. `authenticate` — mTLS auth (950), JWKS auth (1000), JWT auth (1100), key auth (1200), basic auth (1300), HMAC auth (1400)
3. `authorize` — Access control / ACL (2000), TCP connection throttle (2050). Supports consumer username and ACL group allow/deny lists, plus `allow_authenticated_identity` for external JWKS/OIDC identities without consumer mapping
4. `before_proxy` — SSE request shaping (250), SOAP WS-Security (1500), Request size limiting (2800), GraphQL (2850), rate limiting (2900), AI prompt shield (2925), body validator (2950), AI request guard (2975), AI federation (2985), request transformer (3000), serverless function (3025), response mock (3030), gRPC deadline (3050), compression (4050)
5. `on_final_request_body` — Post-transform request body validation. Request size limiting re-checks after request_transformer rewrites. Body validator validates gRPC protobuf requests against descriptors (unary RPCs only, with gzip decompression for compressed frames) and re-checks JSON/XML after request_transformer rewrites
6. `after_proxy` — SSE response headers (250), Response size limiting (3490), response caching (3500), response transformer (4000), compression (4050), CORS headers (100). Rejects are now enforced on the response path across HTTP, HTTP/3, and gRPC
7. `on_final_response_body` — Post-transform response body hooks. Response size limiting, response caching, and response-side body validator operate on the final client-visible body (after response_transformer), not the raw backend body
8. `on_response_body` — AI token metrics (4100), AI rate limiter (4200)
9. `log` — Stdout logging (9000), StatsD logging (9075), HTTP logging (9100), TCP logging (9125), Kafka logging (9150), Loki logging (9155), UDP logging (9160), WebSocket logging (9175), transaction debugger (9200, `tracing::debug` on `transaction_debug` target), Prometheus (9300), API chargeback (9350), OTel tracing (25)
10. `on_ws_frame` — WebSocket frame-level hooks: ws_message_size_limiting (2810), ws_rate_limiting (2910), ws_frame_logging (9050)
11. `on_stream_connect` / `on_stream_disconnect` — TCP/UDP stream lifecycle hooks for auth (mTLS), authz (ACL), throttling (tcp_connection_throttle), rate limiting, logging, metrics, and tracing plugins. For TCP+TLS proxies, `on_stream_connect` runs after the frontend TLS handshake so client cert data is available. For UDP+DTLS proxies, `on_stream_connect` runs after the DTLS handshake completes, with client certificate DER bytes available in `StreamConnectionContext` for mTLS authentication
12. `on_udp_datagram` — Per-datagram UDP hooks fired in both directions (client→backend and backend→client). `UdpDatagramContext.direction` distinguishes the two. udp_rate_limiting (2915) uses this for datagram/byte rate limiting. Zero overhead when no plugin opts in via `requires_udp_datagram_hooks()`. Backend→client hooks run before each response datagram is relayed to the client, enabling response-side rate limiting and filtering

**Multi-auth**: `AuthMode::Multi` recognizes both `ctx.identified_consumer` (consumer-backed auth) and `ctx.authenticated_identity` (external JWKS/OIDC identity) as successful authentication. First-success-wins semantics apply.

**Multi-credential rotation**: Each credential type in a consumer's `credentials` HashMap can be either a single JSON object (backward compatible) or an array of objects. This enables zero-downtime credential rotation — e.g., two API keys or two JWT secrets active simultaneously. The helper `Consumer::credential_entries(cred_type)` normalizes both formats. For index-based lookups (keyauth, mtls_auth), all entries are inserted into the ConsumerIndex HashMap — hot-path lookup remains O(1). For secret-based verification (jwt, basicauth, hmac_auth), the plugin iterates entries after the O(1) consumer lookup (typically 1-2 entries). The max entries per type is configurable via `FERRUM_MAX_CREDENTIALS_PER_TYPE` (default 2). Admin API provides `POST /consumers/:id/credentials/:type` (append) and `DELETE /consumers/:id/credentials/:type/:index` (remove by index) for credential lifecycle management.

**gRPC rejection normalization**: Plugin rejects for `application/grpc` requests are converted to trailers-only gRPC errors (`HTTP 200` + `grpc-status` / `grpc-message`) rather than raw HTTP error responses. This includes pre-proxy rejects, response-path rejects, route misses, and method filtering.

**Request body buffering**: Two-tier system — config-time upper bound (`requires_request_body_buffering()`) determines if a proxy _may_ need buffering, then request-time check (`should_buffer_request_body()`) decides per-request. Only plugins that read the body (graphql, body_validator, ai_request_guard, ai_prompt_shield, ai_federation) trigger buffering; transform-only plugins do not force early prebuffering.

**External identity support**: `ctx.authenticated_identity` (set by JWKS/OIDC) is treated as a first-class principal across rate-limit keys, cache keys, log summaries, and backend identity-header injection on all protocol paths (HTTP, HTTP/3, gRPC, WebSocket).

**HTTP logging custom headers**: The `http_logging` plugin supports a `custom_headers` config field (JSON object of header name → value pairs) that are sent with every batch POST request. This enables integration with services that require non-standard authentication headers (e.g., `DD-API-KEY` for Datadog, `Api-Key` for New Relic, `X-Sumo-Category` for Sumo Logic). See `docs/plugins.md` for the full service integration quick reference table covering Splunk, Datadog, New Relic, Sumo Logic, Elastic, Loki, Azure Monitor, AWS CloudWatch, Google Cloud Logging, Logtail, Axiom, and Mezmo.

**Response mock path scoping**: The `response_mock` plugin matches rule paths **relative to the proxy's `listen_path`**, not the full incoming request path. The plugin strips the proxy's prefix listen_path from `ctx.path` before matching rules. For example, proxy with `listen_path: /api/v1` + request to `/api/v1/users` → mock rule path should be `/users`. A request to exactly the listen_path matches as `/`. For root listen_path (`/`) or regex listen_paths (`~` prefix), no stripping occurs and rules match the full path. This ensures mock rules are scoped to the proxy they are configured on.

Plugin priority constants are defined in `src/plugins/mod.rs` (e.g., `priority::CORS = 100`, `priority::REQUEST_TERMINATION = 125`, `priority::TCP_CONNECTION_THROTTLE = 2050`, `priority::RATE_LIMITING = 2900`, `priority::RESPONSE_SIZE_LIMITING = 3490`, `priority::COMPRESSION = 4050`). Per-instance `priority_override` (on `PluginConfig`) can override these built-in constants via the `PriorityOverridePlugin` wrapper in `plugin_cache.rs`.

### DNS Cache (`src/dns/mod.rs`)

All gateway components share a single `DnsCache` instance:

- **Pre-warmed at startup**: Backend hostnames, plugin target hostnames, and upstream targets are resolved before traffic starts flowing
- **TTL-based expiration**: Cache entries expire based on configurable TTL (default from `FERRUM_DNS_CACHE_TTL_SECONDS`)
- **Stale-while-revalidate**: Serves the old IP while refreshing in the background, avoiding DNS latency on the hot path
- **Background refresh**: A dedicated task refreshes entries before they expire, keeping the cache warm
- **`DnsCacheResolver`**: Implements `reqwest::dns::Resolve` — plugged into every `reqwest::Client` for automatic cache integration
- **Custom nameservers**: Supports `FERRUM_DNS_NAMESERVERS` for internal DNS (e.g., Consul DNS, CoreDNS) and DNS-over-TLS via `FERRUM_DNS_TLS_NAMESERVERS`
- **Record type optimization**: Remembers whether A or AAAA succeeded last for each hostname, querying that type first on refresh

### Centralized Rate Limiting (Redis)

All three rate limiting plugins (`rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`) support centralized mode via `sync_mode: "redis"` in their plugin config. When enabled, rate limit counters are stored in Redis instead of in-memory DashMaps, allowing multiple gateway instances (e.g., multiple data planes) to enforce a single shared rate limit.

**Architecture:**
- **Shared client**: `src/plugins/utils/redis_rate_limiter.rs` provides `RedisRateLimitClient` — a shared Redis client with lazy connection, auto-reconnect via `ConnectionManager`, and background health checking.
- **Algorithm**: Two-window weighted approximation using native Redis commands (`INCR`, `GET`, `EXPIRE` pipelined in a single round-trip). No Lua scripts. `effective_count = prev_window * (1 - elapsed_fraction) + current_count`.
- **Key design**: Keys are prefixed with `{redis_key_prefix}:{rate_key}:{window_index}` where `window_index = epoch_seconds / window_seconds`. All instances share the same window boundaries via system epoch clock.
- **Resilience**: If Redis goes down, plugins automatically fall back to local in-memory DashMap state and log a warning. A background tokio task pings Redis every N seconds (configurable via `redis_health_check_interval_seconds`) and switches back when connectivity is restored.
- **TLS**: Supports `rediss://` URLs. CA verification and skip-verify use gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY`.
- **Protocol compatibility**: Uses the standard RESP protocol, so works with **Redis, Valkey, DragonflyDB, KeyDB, or Garnet** — any RESP-compatible server.
- **Per-plugin isolation**: Each plugin instance has its own Redis connection and key prefix. Different proxies can use different Redis instances.
- **No DB schema changes**: Plugin config is stored as opaque JSON (`serde_json::Value`) in the `plugin_configs` table, so new config fields are backward-compatible.

**Config fields** (same for all three plugins):
- `sync_mode`: `"local"` (default) or `"redis"`
- `redis_url`: Connection URL (required when `sync_mode: "redis"`)
- `redis_tls`: Enable TLS (CA verification and skip-verify use gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY`)
- `redis_key_prefix`: Key namespace (defaults to `ferrum:{plugin_name}`)
- `redis_pool_size`, `redis_connect_timeout_seconds`, `redis_health_check_interval_seconds`: Connection tuning
- `redis_username`, `redis_password`: Authentication

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

**Test placement rules** — follow these exactly; do not place tests in the wrong location:

| What to test | Where to put it | Why |
|---|---|---|
| Private functions / private structs | `#[cfg(test)] mod tests` **inline** in the source file | Rust visibility: `tests/` is a separate crate and cannot see non-`pub` items |
| Public API of a module | `tests/unit/<category>/<module>_tests.rs` | Keeps source files focused; runs as part of `cargo test --test unit_tests` |
| Component interactions (real I/O) | `tests/integration/` | Separate from unit; may need network/TLS setup |
| Full gateway binary (E2E) | `tests/functional/` with `#[ignore]` | Requires `cargo build --bin ferrum-edge` first |

**Adding a new test file** to `tests/unit/`: create the file and add `mod <name>;` to the relevant `tests/unit/<category>/mod.rs`.

**Inline `#[cfg(test)]` blocks are correct and intentional** for any test that calls a private function — do not move them to `tests/unit/` and do not make functions `pub` just to enable external testing.

**Functional test subprocess rule**: Use `Stdio::null()` for the gateway's stdout/stderr unless the test explicitly reads the output. `Stdio::piped()` without reading causes a pipe-buffer deadlock (OS buffer fills from debug logs → gateway blocks on writes → test hangs).

## Development Guidelines

### Before Every Commit

**CRITICAL: Steps 1-2 are non-negotiable. Run them before every single `git commit`, no exceptions.**

1. `cargo fmt --all` — format all code
2. `cargo fmt --all -- --check` — **verify** no formatting diffs remain (CI rejects unformatted code immediately)
3. `cargo clippy --all-targets -- -D warnings` — zero warnings
4. `cargo test --test unit_tests` — all unit tests pass
5. `cargo test --test integration_tests` — integration tests pass
6. If changing proxy behavior: `cargo build --bin ferrum-edge && cargo test --test functional_tests -- --ignored` — E2E tests pass

**All steps (1-5) must pass locally before pushing. Do not skip step 2 — `cargo fmt` can miss files that `cargo fmt --all -- --check` catches.**

### Code Quality Rules

- **No `.unwrap()` in production code** — use `?`, `.unwrap_or()`, `.unwrap_or_else()`, or match/if-let. `unwrap()` in tests is acceptable.
- **No `.expect()` in production code** — same as unwrap; use `anyhow::anyhow!()` + `?` for error propagation.
- **No panics on the hot path** — the proxy request path must never panic. Return errors gracefully.
- **Log errors, don't swallow them** — if using `.unwrap_or_default()`, consider logging a warning first.
- **Validate JWT expiration** — always set `validation.validate_exp = true` when verifying JWTs.
- **Escape user input in response bodies** — when interpolating user-provided strings into JSON/XML response bodies, escape special characters.

### TLS Architecture

**Backend CA Trust Chain** — all protocol paths follow this resolution order:

1. **Proxy-specific CA** (`backend_tls_server_ca_cert_path`) — verify with **only** that CA (webpki/system roots are excluded)
2. **Global CA bundle** (`FERRUM_TLS_CA_BUNDLE_PATH`) — verify with **only** the global CA (webpki/system roots are excluded)
3. **Neither set** — verify with webpki/system roots (secure default)
4. **Explicit opt-out** — `backend_tls_verify_server_cert: false` per-proxy or `FERRUM_TLS_NO_VERIFY=true` globally skips verification

**CA exclusivity**: When a custom CA is configured (proxy or global), it is the **sole** trust anchor. Webpki/system roots are not added. This prevents backends with internal CAs from being MITMed via any public CA. Webpki roots are only used as a convenience fallback when no CA is explicitly configured.

**Startup validation**: Per-proxy TLS file paths (`backend_tls_client_cert_path`, `backend_tls_client_key_path`, `backend_tls_server_ca_cert_path`) are validated at config load time. The gateway refuses to start (or rejects the config reload) if configured paths cannot be read or parsed. There is no silent fallback to unauthenticated or unverified connections.

**TLS path deduplication**: Multiple proxies sharing the same cert file paths result in each unique file being parsed only once during validation.

**Cert/key pairing**: Client cert and key must be configured as a pair. CA is independent — you can set just a CA to verify a server without presenting client identity.

**No silent fallbacks**: All protocol paths hard-error on cert load failure. No degradation to unauthenticated connections.

**Certificate expiration checking**: All TLS surfaces (frontend, admin, DTLS, CP/DP gRPC, per-proxy backend certs, CA bundles) check X.509 `notBefore`/`notAfter` at load time. Expired certificates are rejected (hard failure). Certificates expiring within `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS` (default 30) emit a warning log. Set to 0 to disable near-expiry warnings. The `check_cert_expiry()` helper in `src/tls/mod.rs` is shared across all surfaces.

**Certificate revocation (CRL)**: When `FERRUM_TLS_CRL_FILE_PATH` is set, all TLS/DTLS surfaces reject certificates listed in the CRL. The CRL file is PEM-encoded and may contain multiple `-----BEGIN X509 CRL-----` blocks (e.g., one per issuing CA). Loaded once at startup via `tls::load_crls()` and shared across all surfaces via `Arc`. Policy: `allow_unknown_revocation_status()` (certs not covered by any CRL are accepted — avoids breaking public CA backends) + `only_check_end_entity_revocation()` (checks leaf cert only, not intermediates). Applied to: frontend mTLS (`WebPkiClientVerifier`), all 6 backend paths (`WebPkiServerVerifier` via `build_server_verifier_with_crls()`), DTLS frontend mTLS, DTLS backend. Not applied to DP→CP gRPC client (tonic manages TLS internally). Requires restart to reload — no hot-reload (consistent with all other TLS surfaces).

**No hot reload for any TLS surface**: Updating a cert file on disk has no effect until restart (or config reload for per-proxy paths, which creates new pool entries but does not re-read files for existing ones). This applies to frontend, backend, admin, DTLS, and gRPC TLS surfaces. See `docs/frontend_tls.md` for the complete list.

**Pool-per-cert-path**: For reqwest-based paths (HTTP/1.1, H2 via reqwest, H3 frontend-to-backend), different cert paths create different `reqwest::Client` pool entries. For rustls-based paths (gRPC pool, H2 direct pool), TLS config is built per-connection.

**Protocol TLS coverage** — all 8 backend protocol paths follow the CA trust chain:

| Protocol Path | TLS Library | Pool Isolation |
|---------------|-------------|----------------|
| HTTP/1.1 (`ConnectionPool`) | reqwest/rustls | Per `reqwest::Client` keyed by cert paths |
| HTTP/2 via reqwest (`ConnectionPool`) | reqwest/rustls | Same as HTTP/1.1 |
| HTTP/2 direct (`Http2ConnectionPool`) | rustls | Per-connection TLS config |
| HTTP/3 backend (`Http3ConnectionPool`) | rustls/quinn | Per-endpoint TLS config |
| H3 frontend-to-backend (reqwest) | reqwest/rustls | Same as HTTP/1.1 |
| gRPC (`GrpcConnectionPool`) | rustls/hyper-h2 | Per-connection TLS config |
| WebSocket (wss://) | rustls | Per-connection (no persistent pool) |
| TCP/TLS | rustls | Per-listener lifecycle |

See `docs/backend_mtls.md` and `docs/frontend_tls.md` for full details.

**Non-rustls TLS paths** — some plugins use external libraries with their own TLS stacks:

| Plugin | TLS Library | Gateway Integration |
|--------|-------------|-------------------|
| `kafka_logging` | librdkafka/OpenSSL | `FERRUM_TLS_CA_BUNDLE_PATH` → `ssl.ca.location`, `FERRUM_TLS_NO_VERIFY` → `enable.ssl.certificate.verification=false`. Plugin-level fields override. CRL not applied (use `producer_config` → `ssl.crl.location`). |
| `redis` (rate limiting) | rustls via redis crate | `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY` applied via `PluginHttpClient` accessors. |

These paths use the gateway's global TLS settings as defaults but cannot follow the full CA trust chain (proxy-specific CA, CA exclusivity, CRL) because TLS is managed by the external library rather than rustls.

**When adding new protocol paths**: Must follow the same CA trust chain (proxy CA -> global CA -> webpki roots) with CA exclusivity (custom CA = sole trust anchor, no webpki mixing). For reqwest paths use `.tls_built_in_root_certs(false)` when adding a custom CA. For rustls paths use `RootCertStore::empty()` when a custom CA is present. For non-rustls paths (external libraries like librdkafka), integrate `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY` as defaults via `PluginHttpClient` accessors. Must validate cert paths at config load time. Must hard-error on cert load failure with no silent fallback.

### Performance Rules

- **No allocations per-request when avoidable** — use pre-computed indexes (RouterCache, PluginCache, ConsumerIndex) instead of filtering/searching at request time. Static headers like Alt-Svc are pre-computed in `ProxyState` at startup.
- **No locks on the hot path** — use `ArcSwap::load()` for config reads, `DashMap` for concurrent maps. Never introduce `Mutex`/`RwLock` on the proxy path.
- **Pre-compute at config reload time** — when config changes, rebuild indexes, hash rings, lookup tables, and plugin metadata flags (e.g., `requires_response_body_buffering`). The request path should only do lookups.
- **Avoid `format!()` in hot loops** — pre-compute string keys at build time. Response headers like Alt-Svc are pre-formatted once, not per-request. Connection pool keys use `write!()` into thread-local `String` buffers to avoid heap allocation on cache hits.
- **Use `Arc` for shared read-only data returned per-request** — `LoadBalancer` stores `Vec<Arc<UpstreamTarget>>` so that target selection returns a cheap `Arc::clone()` instead of cloning the full struct. Apply the same pattern when adding new data that is created at config-reload time and returned by reference on the hot path.
- **Use streaming responses by default** — only buffer when a plugin explicitly requires it. The buffering requirement is pre-computed per-proxy in `PluginCache` for O(1) lookup at request time.
- **Skip plugin phases when no plugins are configured** — guard plugin iteration loops with `plugins.is_empty()` to avoid iterator setup and async machinery overhead on the hot path.
- **Always use the shared DNS cache for `reqwest::Client`** — every `reqwest::Client::builder()` call must include `.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())))`. This ensures all HTTP clients (connection pool, health probes, fallback clients, plugin HTTP clients) share the gateway's pre-warmed DNS cache with TTL, stale-while-revalidate, and background refresh. Never create a `reqwest::Client` that falls back to system DNS resolution in production code paths.

### Protocol-Specific Architecture

Each protocol has its own proxy path, connection pool, and backend dispatch. Understanding these paths is critical for performance work.

| Protocol | Frontend | Backend Client | Connection Pool | Streaming |
|----------|----------|---------------|-----------------|-----------|
| HTTP/1.1 | hyper server | reqwest | `ConnectionPool` (reqwest-managed) | Yes (default) |
| HTTP/2 | hyper server (ALPN) | reqwest or `Http2ConnectionPool` | Sharded H2 senders | Yes (default) |
| HTTP/3 | quinn/h3 server (`http3/server.rs`) | reqwest (via `connection_pool`) | reqwest auto-negotiates H2 via ALPN | Yes (coalescing buffer) |
| gRPC | hyper server (content-type detection) | `GrpcConnectionPool` (hyper H2 direct) | Sharded H2 senders | Yes (when no retry/body plugins) |
| WebSocket | hyper upgrade (H1 101) or H2 Extended CONNECT (RFC 8441 200 OK) → tokio-tungstenite | Direct TCP upgrade | N/A (persistent connection) | Frame-by-frame forwarding |
| TCP | `TcpListener` per port | Direct `TcpStream::connect` | N/A (1:1 connection) | `copy_bidirectional` with idle timeout |
| UDP | `UdpSocket` per port | Per-session backend socket | N/A (session-keyed) | Datagram forwarding |

**Key dispatch points in `src/proxy/mod.rs`:**
- gRPC detection: `is_grpc_request()` checks `content-type: application/grpc` (line ~2530)
- H3 backend dispatch: `matches!(proxy.backend_protocol, BackendProtocol::H3)` (line ~3796)
- H2 pool dispatch: `matches!(proxy.backend_protocol, BackendProtocol::H2)` (line ~3828)
- Streaming vs buffered: controlled by `plugin_cache.requires_response_body_buffering()` and `proxy.retry.is_some()`

**HTTP/3 frontend architecture**: The H3 listener in `http3/server.rs` is a standalone QUIC server that handles its own request lifecycle (plugin phases, auth, route matching). For backend communication, it uses **reqwest** (not the `Http3ConnectionPool`). This is intentional — reqwest auto-negotiates HTTP/2 via ALPN which outperforms QUIC for small payloads due to lower per-request crypto overhead and more mature connection pooling. The `Http3ConnectionPool` in `http3/client.rs` is used only by the main hyper-based proxy path (`mod.rs`) for H3 backend targets. The H3 listener enforces its own per-header and total-header size limits (`FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` / `FERRUM_MAX_HEADER_SIZE_BYTES`) since it does not use hyper's built-in header validation — the host header extracted for routing is a substring of an already-validated header, so separate host-length validation is unnecessary.

**QUIC connection migration awareness**: The H3 connection loop in `http3/server.rs` detects QUIC connection migration (RFC 9000 §9) by comparing `quinn::Connection::remote_address()` against a cached `SocketAddr` before each request dispatch. The comparison is two integer fields (IP + port) — zero allocation. The formatted IP string (`Arc<str>`) is only re-created when the address actually changes (rare — mobile network handoff). This ensures IP-based rate-limit keys and access logs reflect the client's current IP after migration, not the stale IP from connection establishment. Do not revert this to a once-per-connection cache — it was added to fix a security issue where migrated clients bypassed per-IP rate limits.

**gRPC proxy architecture**: Uses hyper's HTTP/2 client directly (not reqwest) to preserve HTTP/2 trailers (`grpc-status`, `grpc-message`). The `GrpcConnectionPool` maintains sharded H2 connections with round-robin distribution. When `stream_response=true` (no retries, no body-buffering plugins), the response `Incoming` body is passed through as `ProxyBody::streaming_h2` — hyper forwards DATA and TRAILERS frames directly to the client without buffering.

**Connection pool keys**: Each pool uses a string key to decide whether two proxies can share a pooled connection. The key must include every field that affects connection *identity* — destination, TLS trust, client credentials, and DNS routing. Missing a field allows two proxies with different configs to share a connection (pool poisoning); adding unnecessary fields causes fragmentation and P95 regressions. All keys use `|` as the field delimiter because `:` appears in IPv6 addresses and would create ambiguous key boundaries.

| Pool | File | Key Format | Sharding | Notes |
|------|------|-----------|----------|-------|
| HTTP | `connection_pool.rs` | `{dest}\|{proto}\|{dns_override}\|{ca_path}\|{mtls_cert}\|{verify}` | No (reqwest internal) | `dest` is `u={upstream_id}` or `d={host}:{port}` to prevent namespace collisions. `verify` is the effective flag (proxy AND global). |
| gRPC | `proxy/grpc_proxy.rs` | `{host}\|{port}\|{tls}\|{dns_override}\|{ca_path}\|{mtls_cert}\|{verify}` | `#N` suffix | `tls` is bool from `BackendProtocol::Grpcs`. Shard key reuses a pre-allocated buffer. |
| HTTP/2 | `proxy/http2_pool.rs` | `{host}\|{port}\|{dns_override}\|{ca_path}\|{mtls_cert}\|{verify}` | `#N` suffix | Always TLS (no tls flag needed). |
| HTTP/3 | `http3/client.rs` | `{host}\|{port}\|{index}\|{ca_path}\|{mtls_cert}\|{verify}` | Index in key | `index` distributes across `connections_per_backend` QUIC connections. Target-path keys use `{host}\|{port}\|{index}` only (TLS inherited from proxy). |

**Rules for modifying pool keys:**
- **Every field that affects `create_connection()` output must be in the key.** If two proxies with different values for a field would get different TLS configs, different resolved IPs, or different client identities, that field must be in the key.
- **Never add fields that only affect policy** (timeouts, pool sizes, keepalive intervals). These don't change connection identity and adding them causes fragmentation.
- **Empty/default values are free** — most proxies won't set per-proxy mTLS or dns_override, so these fields are empty strings and all proxies sharing a backend still share one pool entry.
- **Keep the `|` delimiter** — do not switch to `:` or any character that can appear in hostnames, IPv6 addresses, or file paths.

### Health Check Architecture

Health checking uses a **two-layer design** to prevent cross-proxy contamination while keeping shared state where appropriate:

**Active health checks** (periodic probes) are shared per-upstream in `HealthChecker.active_unhealthy_targets: DashMap<"upstream_id::host:port", u64>`. When a TCP/HTTP/UDP/gRPC probe fails, the target is marked unhealthy for ALL proxies using that upstream — correct because the target is genuinely unreachable regardless of which proxy routes through it. Active probe state uses a separate `active_target_states` DashMap with the same key format.

**Passive health checks** (traffic-based failure counting) are isolated per-proxy via a two-level index: `HealthChecker.passive_health: DashMap<proxy_id, Arc<ProxyHealthState>>`. Each `ProxyHealthState` contains:
- `unhealthy: DashMap<"host:port", u64>` — targets this proxy considers unhealthy
- `states: DashMap<"host:port", Arc<TargetHealth>>` — failure/success counters for this proxy

This means proxy A sending large payloads that trigger 500s will only mark targets unhealthy in proxy A's own `ProxyHealthState`. Proxy B (sending small payloads that succeed) maintains an independent healthy view of the same targets, even when both proxies share the same upstream.

**Target selection** checks both layers via `HealthContext`:
```rust
pub struct HealthContext<'a> {
    pub active_unhealthy: &'a DashMap<String, u64>,
    pub proxy_passive: Option<Arc<ProxyHealthState>>,
}
```

The `proxy_passive` is resolved once per request via `passive_health.get(proxy_id)` (one outer DashMap lookup, `Arc::clone` ~5ns), then reused for all targets in `healthy_targets()`. Each target check is two O(1) DashMap lookups using pre-computed keys:
1. `active_unhealthy.contains_key(&target_keys[i])` — pre-computed `upstream_id::host:port`
2. `proxy_passive.unhealthy.contains_key(&host_port_keys[i])` — pre-computed `host:port`

No composite key construction, no thread-local buffers, no string formatting on the hot path.

**Key design rules:**
- **Never merge active and passive state into a single map.** Active probes are proxy-agnostic (same ping for everyone). Passive failures are proxy-specific (different payloads → different outcomes). Merging them causes cross-proxy contamination.
- **Never key passive state by `upstream_id`.** Two proxies sharing the same upstream must have independent passive health state. The isolation boundary is the proxy, not the upstream.
- **The `ProxyHealthState` inner maps use plain `host:port` keys** (not `upstream_id::host:port`). Since a proxy has at most one `upstream_id`, the proxy_id partition already provides uniqueness.
- **`report_response()` takes `proxy_id`** (not `upstream_id`). The proxy is the isolation boundary for passive health.
- **`remove_stale_targets()` cleans both layers**: active entries by exact `upstream_id::host:port` match, passive entries by iterating each proxy's inner map and retaining only current `host:port` targets.
- **Passive recovery timer** iterates all proxies' inner maps, checking `host:port` suffix matches against the upstream's targets. Runs in a background task (not hot path).

### Performance Optimization Lessons

These are hard-won findings from profiling. Violating them causes measurable regressions.

**Allocation hot spots (most impactful):**
- **`HashMap::with_capacity()`** — always use `response.headers().keys_len()` when collecting response headers. Without it, the HashMap rehashes multiple times during header collection. This is a ~5-10% throughput impact.
- **Skip clones on streaming path** — when `stream_response=true` (no retries possible), move `method`/`headers`/`body_bytes` instead of cloning. Body clone for a 10KB payload = 10KB allocation wasted.
- **Conditional retry prep** — only build retry `HeaderMap` from `proxy_headers` when `proxy.retry.is_some()`. The common fast path (no retries) should do zero work. This was a +15% throughput fix for gRPC.
- **Pre-allocate body `Vec` from `content-length`** — parse the header to size the buffer, avoiding repeated reallocations during frame/chunk collection.
- **Thread-local pool key buffers** — connection pool key generation uses `thread_local!` `String` buffers reused across requests on the same tokio worker. The DashMap lookup happens while borrowing the buffer, so cache hits (99%+ of requests) allocate zero heap memory. Only the cold path (first request per unique proxy config) allocates a `String` for DashMap insertion. Applied to reqwest (`connection_pool.rs`) and HTTP/3 (`http3/client.rs`) pools.
- **`Arc<UpstreamTarget>` in load balancer** — `LoadBalancer.targets` stores `Vec<Arc<UpstreamTarget>>` and `TargetSelection.target` is `Arc<UpstreamTarget>`. Every LB selection is a single atomic increment (~5ns) instead of cloning the full struct (String host + HashMap tags + Option path, ~200-500ns). All 7 selection algorithms (round-robin, WRR, least-connections, least-latency, consistent-hashing, random, fallback) return `Arc::clone()`.
- **Response header `get_mut()` pattern** — `collect_response_headers()` and `collect_hyper_response_headers()` use `get_mut(k.as_str())` to check for existing headers before allocating the key `String`. For multi-valued headers (common with `set-cookie`), this avoids allocating a key that already exists in the map. The `set-cookie` vs comma separator is determined via zero-cost `HeaderName` comparison before any allocation.
- **Pre-populated status code DashMap** — Common HTTP status codes (200, 201, 204, 301, 302, 304, 400, 401, 403, 404, 405, 408, 429, 500, 502, 503, 504) are inserted into `ProxyState.status_counts` at construction. The hot path uses `DashMap::get()` (shared read lock) for virtually all requests instead of `entry()` (write lock).

**Route matching (critical for scale):**
- **NEVER use O(n) linear scan for prefix route matching** where n = total proxy count. The router previously scanned ALL routes in a host tier on every cache miss, causing 30-46% throughput degradation at 50→500 proxies. The `IndexedPrefixRoutes` HashMap index in `router_cache.rs` replaced this with O(path_depth) lookups (typically 2-5, independent of proxy count). Any future changes to route matching MUST preserve this O(path_depth) guarantee — do not introduce loops over all routes on the request path.
- **NEVER use sequential per-pattern regex matching** — the `IndexedRegexRoutes` `RegexSet` in `router_cache.rs` evaluates all regex patterns for a host tier in a single DFA pass (O(path_length), independent of pattern count). The previous approach tested each `Regex` sequentially which was O(n_patterns). Do not replace `find_regex_match_indexed()` with a loop over individual patterns.
- **Router cache size must scale with proxy count** — a fixed-size cache with thousands of proxies causes eviction thrashing (constant cache misses → expensive lookups + DashMap `retain()` lock contention). The auto-scaling default (`proxies × 3`, min 10K) prevents this. `FERRUM_ROUTER_CACHE_MAX_ENTRIES` overrides for memory-constrained deployments.

**Protocol-specific gotchas:**
- **Don't replace reqwest with H3 pool for HTTP/3 frontend→backend**: Tested and reverted. QUIC has higher per-request overhead than TCP/H2 for small payloads (~10x regression). reqwest's HTTP/2 pooling is highly optimized and auto-negotiates the best protocol via ALPN.
- **gRPC `Proxy.clone()` is expensive**: The full `Proxy` struct has many fields. Avoid cloning it per-request. Extract needed fields into lightweight param structs (see `TcpConnParams` pattern in `tcp_proxy.rs`).
- **H2 flow control tuning matters**: Default stream window (64KB) is too small for gRPC. The perf configs use 8MiB stream / 32MiB connection windows (`pool_http2_initial_stream_window_size`).
- **UDP frontend recv uses `recvmmsg` on Linux**: The drain loop after each `recv_from` wakeup uses `recvmmsg(2)` to batch up to 64 datagrams per syscall (configurable via `FERRUM_UDP_RECVMMSG_BATCH_SIZE`). This reduces kernel crossing overhead from 1-per-datagram to 1-per-batch, matching Envoy's GRO-based approach. The `RecvMmsgBatch` in `src/proxy/udp_batch.rs` pre-allocates buffers at listener startup. On non-Linux, falls back to `try_recv_from`. Reply handlers (backend→client) intentionally skip `recvmmsg` — each session has its own backend socket with much lower per-socket throughput, and per-session batch buffer allocation (64 × 65KB = 4MB) would be prohibitive at scale.
- **QUIC coalescing is critical**: Small QUIC frames kill performance. The H3 streaming path uses an 8-32KB coalescing buffer with time-based flush (2ms) to batch small chunks into larger QUIC frames.

**Resilience features per protocol:**

| Feature | HTTP/1.1 | HTTP/2 | HTTP/3 | gRPC | WebSocket | TCP | UDP |
|---------|----------|--------|--------|------|-----------|-----|-----|
| Load balancing | Full | Full | Full | Full | Full | Full | Full |
| Health checks | Full | Full | Full | Full (+ native gRPC) | HTTP probes | TCP SYN | UDP probe |
| Circuit breaker | Full | Full | Full | Full | Full | Connection-phase | Connection-phase |
| Retries | Full | Full | Full | Connection failures | Connection failures | Connection-phase | Connection-phase |
| Idle timeout | Pool-level | Pool-level | Pool-level | Pool-level | N/A | Configurable | Configurable |

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
2. **Constructor must return `Result<Self, String>`** — every plugin's `new()` must validate its config and return `Err` with a clear message if the config is invalid. See the "Plugin Config Validation" section below for rules.
3. Add a priority constant in `src/plugins/mod.rs` (`priority::MY_PLUGIN = N`)
4. Override `supported_protocols()` to declare which protocols the plugin supports (default is HTTP-only). Use the predefined constants: `ALL_PROTOCOLS`, `HTTP_FAMILY_PROTOCOLS`, `HTTP_GRPC_PROTOCOLS`, `HTTP_FAMILY_AND_TCP_PROTOCOLS`, `HTTP_FAMILY_AND_STREAM_PROTOCOLS`, `HTTP_ONLY_PROTOCOLS`, `GRPC_ONLY_PROTOCOLS`, `TCP_ONLY_PROTOCOLS`, or `UDP_ONLY_PROTOCOLS`
5. Register in the plugin registry (`create_plugin_with_http_client()` match arm in `mod.rs`) — use `?` on the `new()` call (e.g., `Ok(Some(Arc::new(my_plugin::MyPlugin::new(config)?)))`)
6. Add the plugin name to `available_plugins()` in `mod.rs`
7. Add unit tests in `tests/unit/plugins/my_plugin_tests.rs` — include tests for both valid configs (`.unwrap()`) and invalid configs (`.is_err()` / `.err().unwrap()`)
8. Add the module to `tests/unit/plugins/mod.rs`
9. Update `FEATURES.md`, `README.md`, and `docs/plugin_execution_order.md` (protocol matrix)

**CRITICAL: `before_proxy` header parameter**: In `before_proxy(&self, ctx: &mut RequestContext, headers: &mut HashMap<String, String>)`, always read request headers from the `headers` parameter, **never from `ctx.headers`**. When no plugin in the chain modifies request headers (`modifies_request_headers() == false`), the handler moves headers out of `ctx.headers` via `std::mem::take()` as a zero-clone optimization (see `src/proxy/mod.rs` ~line 4168). During `before_proxy` execution, `ctx.headers` is an empty HashMap in this fast path. The `headers` parameter always contains the actual request headers regardless of which optimization path the handler takes. This applies to reading headers directly (`headers.get("content-type")`) and to any helper methods called from `before_proxy` — pass the `headers` parameter through rather than accessing `ctx.headers` in the helper. Other phases (`on_request_received`, `authenticate`, `authorize`) are not affected — only `before_proxy` uses this optimization.

### Plugin Config Validation

All plugin constructors **must** return `Result<Self, String>`. Config validation is enforced at three levels:

1. **Admin API** — `validate_plugin_config_definition()` instantiates the plugin via `create_plugin()` at create/update time. Invalid configs are rejected with HTTP 400.
2. **File mode** — `file_loader.rs` calls `plugins::validate_plugin_config()` for each enabled plugin at startup. Invalid configs **fail startup**.
3. **Database mode** — `db_loader.rs` calls `plugins::validate_plugin_config()` for each enabled plugin at load time. Invalid configs are **warned** (data already exists in DB).

**Validation rules for `new()` constructors:**

- **Return `Err` when the plugin would have no effect** — if the config is missing required fields that make the plugin a no-op (e.g., rate limiter with no rate windows, size limiter with `max_bytes=0`, transformer with no rules), return an error. Do not silently default to a no-op.
- **Return `Err` for invalid values** — reject malformed regexes, unknown enum variants, out-of-range numbers, and other parse failures. Do not silently skip or default.
- **Sensible defaults are fine** — optional fields with reasonable defaults (e.g., `limit_by` defaulting to `"ip"`) should use `.unwrap_or()` without an error. Only require explicit config for fields where there is no safe default.
- **Never `warn!()` for something that should be an `Err`** — if you would have logged a warning saying "plugin will have no effect", that should be an `Err` instead.
- **Use `Ok(Self { ... })` for the success path** — wrap the struct construction in `Ok()`.

**The shared validation entry point** is `plugins::validate_plugin_config(name, config) -> Result<(), String>` which wraps `create_plugin()`. File/DB loaders call this; the admin API calls `validate_plugin_config_definition()` which does the same thing plus scope checks.

### Adding a Custom Plugin with Database Migrations

Custom plugins that need their own database tables can declare migrations via a `plugin_migrations()` function alongside their `create_plugin()` factory. The build script auto-discovers plugins that export `plugin_migrations()` and generates a collector function.

1. Create `custom_plugins/my_plugin.rs` with `create_plugin()` (standard custom plugin convention)
2. Export a `plugin_migrations()` function returning `Vec<CustomPluginMigration>` from `crate::config::migrations`
3. Each migration has: `version` (scoped per-plugin), `name`, `checksum`, `sql` (default), optional `sql_postgres`/`sql_mysql` overrides
4. Prefix table names with the plugin name to avoid collisions with core tables
5. Multi-statement SQL is supported (semicolon-separated)
6. Run `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` to apply — plugin migrations are tracked separately in `_ferrum_plugin_migrations` with composite PK `(plugin_name, version)`
7. See `custom_plugins/example_audit_plugin.rs` for a complete working example and `CUSTOM_PLUGINS.md` for the full guide

### Adding a New Config Field

1. Add the field to the appropriate struct in `src/config/types.rs` with `#[serde(default)]`
2. If env-var driven: add parsing in `src/config/env_config.rs`
3. **Update `ferrum.conf`** — every new `FERRUM_*` env var must also be added to `ferrum.conf` with a commented-out default and descriptive comment. The conf file and env vars must stay in sync.
4. If database-stored (SQL backends): add a migration in `src/config/migrations/` (ALTER TABLE / new column) and update row parsing in `db_loader.rs`
5. **MongoDB gets the field automatically** — `MongoStore` serializes domain types via `bson::to_document`/`from_document` using serde, so new fields on `Proxy`, `Consumer`, `Upstream`, or `PluginConfig` are persisted without any MongoDB-specific migration. New indexes (if the field needs to be queried) should be added to `MongoStore::run_migrations()`.
6. Add unit tests for deserialization in `tests/unit/config/`
7. Update `openapi.yaml` if the Admin API exposes it

**Schema centralization**: The domain types in `src/config/types.rs` (`Proxy`, `Consumer`, `Upstream`, `PluginConfig`) are the single source of truth for schema. MongoDB uses serde-based BSON serialization so new fields propagate automatically. SQL backends require explicit migrations (ALTER TABLE) and manual row parsing in `db_loader.rs`. This asymmetry is by design — centralizing SQL DDL generation from the Rust types would add significant complexity for marginal benefit, and the SQL backends need fine-grained control over column types, indexes, and cross-database dialect differences.

### Database Considerations

- **Supported databases**: PostgreSQL, MySQL, SQLite (via sqlx), MongoDB (via `mongodb` crate)
- **Database backend abstraction**: The `DatabaseBackend` trait in `src/config/db_backend.rs` abstracts all database operations. `DatabaseStore` (sqlx) and `MongoStore` (mongodb) both implement this trait. The admin API and operating modes use `Arc<dyn DatabaseBackend>` for polymorphic dispatch.
- **MongoDB support**: Uses BSON document storage with domain types serialized directly via serde. No junction tables — plugin associations are embedded in proxy documents. Indexes replace SQL migrations (idempotent `createIndex`). Incremental polling uses `updated_at` timestamp queries (same strategy as SQL). MongoDB-specific env vars: `FERRUM_MONGO_DATABASE`, `FERRUM_MONGO_APP_NAME`, `FERRUM_MONGO_REPLICA_SET`, `FERRUM_MONGO_AUTH_MECHANISM`, `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS`, `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS`.
- **Migrations**: Core gateway migrations in `src/config/migrations/` (SQL). For MongoDB, `run_migrations()` creates indexes instead. Custom plugin migrations declared via `plugin_migrations()` in plugin files and tracked in `_ferrum_plugin_migrations`. Both run via `FERRUM_MODE=migrate`.
- **Schema relationships (SQL)**: Proxies reference upstreams via `upstream_id`. Plugins are associated with proxies via the `proxy_plugins` junction table. Consumers have credentials keyed by auth type and an `acl_groups` JSON array for group-based access control.
- **Schema relationships (MongoDB)**: Same domain model, different storage. Proxy documents embed plugin associations directly (no junction collection). Upstream references use `upstream_id` field with an index. Credentials and acl_groups are nested BSON objects/arrays. The `_id` field maps to the resource's `id`.
- **Transactions (SQL)**: All multi-step CRUD operations (create/update/delete proxy, delete plugin_config, delete upstream, cleanup orphaned upstream) are wrapped in `sqlx::Transaction` to prevent partial updates on crash or concurrent access.
- **Transactions (MongoDB)**: Single-document operations are atomic by default. Multi-document operations (e.g., delete proxy + associated plugin_configs) are not transactional unless a replica set is configured (`FERRUM_MONGO_REPLICA_SET`). Without a replica set, operations are designed to be idempotent — partial failures are detected and cleaned up on the next poll cycle.
- **Custom plugin migrations (SQL)**: `CustomPluginMigration` structs with `sql`, `sql_postgres`, `sql_mysql` fields. Tracked in `_ferrum_plugin_migrations`.
- **Custom plugin migrations (MongoDB)**: The SQL-based `CustomPluginMigration` system is **SQL-only**. Custom plugins needing MongoDB collections/indexes should create them in their `create_plugin()` initialization or provide a separate setup function. The `sql` field in `CustomPluginMigration` is skipped when `FERRUM_DB_TYPE=mongodb`.
- **Full proxy persistence**: All Proxy struct fields are persisted in the database, including `circuit_breaker` (JSON), `retry` (JSON), `response_body_mode`, and all `pool_*` override fields.
- **Incremental Polling**: Database mode polls for changes at `FERRUM_DB_POLL_INTERVAL_SECONDS` (default 30s) using a two-phase incremental strategy:
  1. **Startup**: Full `SELECT *` on all 4 tables to build the initial config and seed the poller's known ID sets. The `loaded_at` timestamp is captured **before** queries execute so the safety margin covers the full load duration.
  2. **Subsequent polls**: `load_incremental_config()` uses indexed `SELECT * FROM X WHERE updated_at > ?` queries (4 tables) to fetch only changed rows, plus lightweight `SELECT id FROM X` queries (4 tables) to detect deletions by diffing against the known ID set. A 1-second safety margin on the timestamp prevents missing boundary writes.
  3. **Validation**: Incremental results are validated (field-level constraints, hosts, regex listen_paths, unique listen_paths, stream proxies, stream proxy gateway port conflicts, upstream references, plugin references) before being applied — same as the full-load path. Invalid incremental configs are rejected and the previous valid config remains in effect.
  4. **Consistency**: The poller's known ID sets are only updated **after** `apply_incremental()` succeeds. If validation rejects the config, known IDs stay unchanged so the next poll re-fetches the same changes.
  5. **Fallback**: If the incremental poll fails for any reason, the loop automatically falls back to a full `load_full_config()` + `update_config()` cycle and re-seeds the known IDs.
  - The `updated_at` columns are indexed (`idx_proxies_updated_at`, `idx_consumers_updated_at`, `idx_plugin_configs_updated_at`, `idx_upstreams_updated_at`) so incremental queries use index scans, not full table scans.
  - Incremental results feed into `ProxyState::apply_incremental()` which patches the in-memory `GatewayConfig` and drives the same surgical cache updates (router, plugin, consumer, load balancer, circuit breaker, DNS warmup) as the full-reload path.
  - **CP mode** uses the same incremental polling strategy. Deltas are serialized and broadcast to DPs as `DELTA` updates (update_type=1) via a tokio `broadcast` channel (capacity configurable via `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`, default 128). DPs apply them via `apply_incremental()`. On incremental poll failure, the CP falls back to a full reload and broadcasts a `FULL_SNAPSHOT`. If a DP lags behind by more than the channel capacity, it automatically receives a fresh full snapshot instead of the missed deltas (self-healing). The broadcast is lock-free — `tx.send()` writes once to a ring buffer that all receivers share; it never blocks on slow DPs.
- **Multi-URL Failover**: `FERRUM_DB_FAILOVER_URLS` accepts comma-separated fallback database URLs. On startup, if the primary `FERRUM_DB_URL` is unreachable, failover URLs are tried in order. During polling, if both incremental and full reload fail, the gateway attempts to reconnect via failover URLs before marking the DB as unavailable. All failover URLs must use the same `FERRUM_DB_TYPE` and share TLS settings.
- **Read Replica**: `FERRUM_DB_READ_REPLICA_URL` offloads config polling reads to a read replica. The polling loop (both full and incremental) queries the replica, while Admin API writes always go to the primary. If the replica is unreachable at startup, polling transparently falls back to the primary. DNS re-resolution is performed independently for both primary and replica hostnames.
- **MongoDB-specific deployment nuances**: See `docs/mongodb.md` for the full deployment guide. Key differences from SQL backends:
  - **Read preference**: MongoDB uses `readPreference` in the connection string (e.g., `?readPreference=secondaryPreferred`) instead of `FERRUM_DB_READ_REPLICA_URL`. The driver routes reads to secondaries and writes to the primary automatically through a single connection string.
  - **Failover**: MongoDB replica sets handle failover natively — list all members in `FERRUM_DB_URL` (e.g., `mongodb://m1,m2,m3/ferrum?replicaSet=rs0`). `FERRUM_DB_FAILOVER_URLS` is only needed for standalone (non-replica-set) MongoDB deployments.
  - **Connection pool**: The MongoDB driver manages its own pool internally. `FERRUM_DB_POOL_*` settings are SQL-only and ignored for MongoDB. Use connection string options (`maxPoolSize`, `minPoolSize`) for MongoDB pool tuning.
  - **Transactions**: Single-document operations are always atomic. Multi-document ACID transactions require a replica set (`FERRUM_MONGO_REPLICA_SET`). Without one, multi-document operations are idempotent with cleanup on the next poll cycle.

### PR Checklist

- [ ] `cargo fmt` — no formatting diffs
- [ ] `cargo clippy --all-targets -- -D warnings` — zero warnings
- [ ] `cargo test --test unit_tests` — unit tests pass
- [ ] `cargo test --test integration_tests` — integration tests pass
- [ ] New features have unit tests covering normal, edge, and error cases
- [ ] No `.unwrap()` or `.expect()` in production code paths
- [ ] No dead code (clippy enforces `-D dead-code`)
- [ ] PR description includes a summary, list of changes, and test plan
- [ ] Documentation updated if adding/changing features (FEATURES.md, README.md, docs/, openapi.yaml)
- [ ] New `FERRUM_*` env vars added to `ferrum.conf` with commented defaults

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
| `FERRUM_NAMESPACE` | `ferrum` | Namespace this gateway instance loads and manages. Resources from other namespaces are ignored. Enables multi-tenant resource isolation |
| `FERRUM_LOG_LEVEL` | `error` | `error`, `warn`, `info`, `debug`, `trace` |
| `FERRUM_LOG_BUFFER_CAPACITY` | `128000` | Max buffered log lines in the non-blocking writer channel. When full, new events are dropped (lossy) to avoid backpressure |
| `FERRUM_PROXY_HTTP_PORT` | `8000` | Proxy HTTP listen port. `0` = disabled (TLS-only) |
| `FERRUM_PROXY_HTTPS_PORT` | `8443` | Proxy HTTPS listen port |
| `FERRUM_PROXY_BIND_ADDRESS` | `0.0.0.0` | Bind address for proxy listeners. Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_FRONTEND_TLS_CERT_PATH` | (none) | PEM certificate the gateway presents to incoming clients (HTTPS, WebSocket, gRPC, TCP/TLS) |
| `FERRUM_FRONTEND_TLS_KEY_PATH` | (none) | PEM private key for the gateway's frontend TLS certificate |
| `FERRUM_ADMIN_HTTP_PORT` | `9000` | Admin API HTTP port. `0` = disabled (TLS-only) |
| `FERRUM_ADMIN_HTTPS_PORT` | `9443` | Admin API HTTPS port |
| `FERRUM_ADMIN_BIND_ADDRESS` | `0.0.0.0` | Bind address for admin listeners. Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_ADMIN_JWT_SECRET` | (required for db/cp) | JWT secret for admin API auth |
| `FERRUM_ADMIN_JWT_ISSUER` | `ferrum-edge` | JWT issuer claim (iss) for admin API tokens |
| `FERRUM_ADMIN_JWT_MAX_TTL` | `3600` | Maximum TTL in seconds for admin API JWT tokens |
| `FERRUM_FILE_CONFIG_PATH` | (required for file mode) | Path to YAML/JSON config file |
| `FERRUM_DB_TYPE` | (required for db mode) | `postgres`, `mysql`, `sqlite`, `mongodb` |
| `FERRUM_DB_URL` | (required for db mode) | Database connection URL |
| `FERRUM_DB_CONFIG_BACKUP_PATH` | (none) | Path to externally provided JSON config backup for startup failover when DB is unreachable |
| `FERRUM_DB_FAILOVER_URLS` | (empty) | Comma-separated failover database URLs (tried in order when primary is unreachable) |
| `FERRUM_DB_READ_REPLICA_URL` | (none) | Read replica URL for config polling (reduces primary load, falls back to primary) |
| `FERRUM_DB_POOL_MAX_CONNECTIONS` | `10` | Max connections in the database pool. Increase for CP mode with many DPs |
| `FERRUM_DB_POOL_MIN_CONNECTIONS` | `1` | Min idle connections maintained in the pool (eager warming) |
| `FERRUM_DB_POOL_ACQUIRE_TIMEOUT_SECONDS` | `30` | Max seconds to wait for a pool connection before error |
| `FERRUM_DB_POOL_IDLE_TIMEOUT_SECONDS` | `600` | Max seconds a connection can sit idle before eviction |
| `FERRUM_DB_POOL_MAX_LIFETIME_SECONDS` | `300` | Max lifetime of a connection (forces DNS re-resolution) |
| `FERRUM_DB_POOL_CONNECT_TIMEOUT_SECONDS` | `10` | Max seconds to wait for a new TCP connection to the database. 0 = disabled |
| `FERRUM_DB_POOL_STATEMENT_TIMEOUT_SECONDS` | `30` | Max execution time per SQL statement (PG/MySQL only). 0 = disabled |
| `FERRUM_DB_SLOW_QUERY_THRESHOLD_MS` | (none) | Threshold (ms) for warning-level logs on slow DB queries |
| `FERRUM_MONGO_DATABASE` | `ferrum` | MongoDB database name (when `FERRUM_DB_TYPE=mongodb`) |
| `FERRUM_MONGO_APP_NAME` | (none) | MongoDB app name for server-side connection tracking |
| `FERRUM_MONGO_REPLICA_SET` | (none) | MongoDB replica set name (required for change streams/transactions) |
| `FERRUM_MONGO_AUTH_MECHANISM` | (auto) | MongoDB auth mechanism override (e.g. `SCRAM-SHA-256`, `MONGODB-X509`) |
| `FERRUM_MONGO_SERVER_SELECTION_TIMEOUT_SECONDS` | `30` | MongoDB server selection timeout |
| `FERRUM_MONGO_CONNECT_TIMEOUT_SECONDS` | `10` | MongoDB TCP connection timeout |
| `FERRUM_CP_GRPC_LISTEN_ADDR` | `0.0.0.0:50051` | CP gRPC server listen address |
| `FERRUM_CP_GRPC_TLS_CERT_PATH` | (none) | PEM cert for CP gRPC TLS |
| `FERRUM_CP_GRPC_TLS_KEY_PATH` | (none) | PEM key for CP gRPC TLS |
| `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` | (none) | PEM CA for verifying DP client certs (mTLS) |
| `FERRUM_CP_DP_GRPC_JWT_SECRET` | (required in cp and dp modes) | Shared JWT secret for CP/DP gRPC auth (required in cp and dp modes) |
| `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY` | `128` | Broadcast channel capacity for CP-to-DP delta fan-out. DPs that lag behind by more than this many updates receive a full snapshot instead. Increase for high config churn |
| `FERRUM_DP_CP_GRPC_URL` | (required for dp mode) | CP gRPC URL for DP to connect to (`http://` or `https://`) |
| `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | (none) | PEM CA cert for verifying CP server cert |
| `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` | (none) | PEM client cert for DP-to-CP mTLS |
| `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH` | (none) | PEM client key for DP-to-CP mTLS |
| `FERRUM_DP_GRPC_TLS_NO_VERIFY` | `false` | Skip gRPC TLS cert verification (testing only) |
| `FERRUM_TLS_NO_VERIFY` | `false` | Skip outbound TLS verification for all connections (testing only) |
| `FERRUM_TLS_CA_BUNDLE_PATH` | (none) | Path to PEM CA bundle for outbound TLS verification (internal CAs) |
| `FERRUM_TLS_CRL_FILE_PATH` | (none) | Path to PEM CRL file for certificate revocation checking across all TLS/DTLS surfaces |
| `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS` | `30` | Days before cert expiration to warn. Expired certs are always rejected. 0 = disable warnings |
| `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING` | `false` | Track streaming response total latency (adds per-stream overhead) |
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | `ferrum-edge-change-me-in-production` | HMAC-SHA256 server secret for basic_auth (~1μs vs ~100ms bcrypt). **Must be changed in production.** |
| `FERRUM_TRUSTED_PROXIES` | (empty) | Comma-separated CIDRs for XFF trust |
| `FERRUM_DTLS_CERT_PATH` | (none) | PEM cert for frontend DTLS termination (ECDSA P-256 / P-384) |
| `FERRUM_DTLS_KEY_PATH` | (none) | PEM key for frontend DTLS termination |
| `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | (none) | PEM CA cert for verifying DTLS client certs (frontend mTLS) |
| `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS` | `1000` | Threshold (ms) for warning-level logs on slow plugin HTTP calls |
| `FERRUM_PLUGIN_HTTP_MAX_RETRIES` | `0` | Retry count for safe plugin HTTP calls (GET/HEAD/OPTIONS) on transport failures |
| `FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS` | `100` | Delay (ms) between plugin HTTP transport retries |
| `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` | `100` | Max request body size (MiB) for `POST /restore` |
| `FERRUM_HTTP3_CONNECTIONS_PER_BACKEND` | `4` | QUIC connections per HTTP/3 backend (distributes frame processing) |
| `FERRUM_HTTP3_POOL_IDLE_TIMEOUT_SECONDS` | `120` | HTTP/3 connection pool idle eviction timeout |
| `FERRUM_POOL_WARMUP_ENABLED` | `true` | Pre-establish backend connections at startup after DNS warmup. Skipped for TCP/UDP |
| `FERRUM_POOL_WARMUP_CONCURRENCY` | `500` | Maximum concurrent connection warmup attempts at startup |
| `FERRUM_POOL_CLEANUP_INTERVAL_SECONDS` | `30` | Cleanup sweep interval for HTTP, gRPC, HTTP/2, HTTP/3 pools |
| `FERRUM_ROUTER_CACHE_MAX_ENTRIES` | `0` (auto) | Router prefix/negative lookup cache size. 0 = auto-scale as `max(10_000, proxies × 3)`. Set explicit value to cap memory. Min: 1,000, Max: 10,000,000 |
| `FERRUM_TCP_IDLE_TIMEOUT_SECONDS` | `300` | Default TCP idle timeout (5 min). Per-proxy `tcp_idle_timeout_seconds` overrides. 0 = disabled |
| `FERRUM_UDP_MAX_SESSIONS` | `10000` | Maximum concurrent UDP sessions per proxy |
| `FERRUM_UDP_CLEANUP_INTERVAL_SECONDS` | `10` | UDP session cleanup sweep interval |
| `FERRUM_UDP_RECVMMSG_BATCH_SIZE` | `64` | Datagrams per `recvmmsg` syscall on Linux (1-1024). Reduces syscall overhead for high-throughput UDP. Ignored on non-Linux |
| `FERRUM_UDP_RECV_BATCH_LIMIT` | `6000` | Max datagrams drained per recv wakeup before yielding. Higher = better burst throughput, lower = better fairness |
| `FERRUM_WORKER_THREADS` | (CPU cores) | Tokio worker threads (maps to `runtime::Builder::worker_threads`) |
| `FERRUM_BLOCKING_THREADS` | `512` | Tokio max blocking threads |
| `FERRUM_MAX_CONNECTIONS` | `100000` | Max concurrent proxy connections (semaphore-bounded; 0 = unlimited) |
| `FERRUM_TCP_LISTEN_BACKLOG` | `2048` | TCP listen backlog size (min 128) |
| `FERRUM_ACCEPT_THREADS` | `0` (auto-detect) | Parallel accept() loops per proxy listener port via SO_REUSEPORT. `0` = CPU cores. `1` = single listener. Parallelizes kernel-level connection intake independently of `FERRUM_WORKER_THREADS` |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | `1000` | Server-side HTTP/2 max concurrent streams per inbound connection |
| `FERRUM_SERVER_HTTP2_MAX_PENDING_ACCEPT_RESET_STREAMS` | `64` | Server-side HTTP/2 pending reset-stream threshold before GOAWAY |
| `FERRUM_SERVER_HTTP2_MAX_LOCAL_ERROR_RESET_STREAMS` | `256` | Server-side HTTP/2 local reset-stream threshold before GOAWAY |
| `FERRUM_WEBSOCKET_MAX_CONNECTIONS` | `20000` | Max concurrently upgraded WebSocket connections (`0` = disabled) |
| `FERRUM_MAX_HEADER_COUNT` | `100` | Max number of request headers allowed. `0` = unlimited |
| `FERRUM_MAX_URL_LENGTH_BYTES` | `8192` | Max URL length in bytes (path + query string). `0` = unlimited |
| `FERRUM_MAX_QUERY_PARAMS` | `100` | Max number of query parameters allowed. `0` = unlimited |
| `FERRUM_MAX_GRPC_RECV_SIZE_BYTES` | `4194304` | Max total received gRPC payload size in bytes (4 MiB). `0` = unlimited |
| `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` | `16777216` | Max WebSocket frame size in bytes (16 MiB). Also sets max message size to 4x frame size |
| `FERRUM_WEBSOCKET_WRITE_BUFFER_SIZE` | `131072` | WebSocket write buffer size in bytes (128 KB). Controls data buffered before flushing to transport. Increase to 4194304 for workloads with large WS frames (1 MB+). Only applies when frame-level plugins are active |
| `FERRUM_WEBSOCKET_TUNNEL_MODE` | `false` | When true and no frame-level plugins are configured, bypass WebSocket frame parsing and use raw TCP bidirectional copy. Improves large-payload throughput significantly. Trade-off: `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` not enforced (no DoS risk — fixed-size copy buffer) |
| `FERRUM_MAX_CREDENTIALS_PER_TYPE` | `2` | Max credential entries per type per consumer. Enables zero-downtime rotation by allowing multiple active credentials simultaneously |
| `FERRUM_HTTP_HEADER_READ_TIMEOUT_SECONDS` | `10` | HTTP/1.1 header read timeout in seconds. Protects against slowloris attacks. `0` = disabled |
| `FERRUM_BACKEND_ALLOW_IPS` | `both` | Backend IP allowlist policy: `private` (only RFC 1918/loopback/link-local/CGNAT), `public` (only non-private), `both` (no restriction) |
| `FERRUM_MAX_CONCURRENT_REQUESTS_PER_IP` | `0` | Max concurrent proxy requests per resolved client IP. `0` = disabled. Uses trusted proxy XFF resolution |
| `FERRUM_ADMIN_ALLOWED_CIDRS` | (empty) | Comma-separated CIDRs/IPs allowed to connect to admin API. Empty = all allowed |
| `FERRUM_ADD_VIA_HEADER` | `true` | Add Via header (RFC 9110 §7.6.3) on request and response paths |
| `FERRUM_VIA_PSEUDONYM` | `ferrum-edge` | Pseudonym in the Via header (e.g., `1.1 ferrum-edge`) |
| `FERRUM_ADD_FORWARDED_HEADER` | `false` | Add Forwarded header (RFC 7239) alongside X-Forwarded-* headers |
| `FERRUM_OVERLOAD_CHECK_INTERVAL_MS` | `1000` | Overload monitor check interval in milliseconds (min: 100) |
| `FERRUM_OVERLOAD_FD_PRESSURE_THRESHOLD` | `0.80` | FD usage ratio to disable keepalive (0.0-1.0) |
| `FERRUM_OVERLOAD_FD_CRITICAL_THRESHOLD` | `0.95` | FD usage ratio to reject new connections (0.0-1.0) |
| `FERRUM_OVERLOAD_CONN_PRESSURE_THRESHOLD` | `0.85` | Connection usage ratio to disable keepalive (0.0-1.0) |
| `FERRUM_OVERLOAD_CONN_CRITICAL_THRESHOLD` | `0.95` | Connection usage ratio to reject new connections (0.0-1.0) |
| `FERRUM_OVERLOAD_LOOP_WARN_US` | `10000` | Event loop latency (μs) for warning log |
| `FERRUM_OVERLOAD_LOOP_CRITICAL_US` | `500000` | Event loop latency (μs) to reject new connections |
| `FERRUM_SHUTDOWN_DRAIN_SECONDS` | `30` | Seconds to wait for in-flight connections to drain on shutdown. `0` = immediate |

See `src/config/env_config.rs` for the full list of 90+ environment variables.

## Proto / gRPC

- Proto definition: `proto/ferrum.proto`
- Build script: `build.rs` compiles protos via `tonic_build`
- Service: `ConfigSync` with `Subscribe` (streaming) and `GetFullConfig` (unary)
- Auth: HS256 JWT in gRPC metadata (`authorization` key)
- **CP broadcast**: `CpGrpcServer::with_channel_capacity()` creates the tokio broadcast channel. `CpGrpcServer::new()` is a convenience wrapper that defaults to capacity 128 (used by tests). Production code in `control_plane.rs` calls `with_channel_capacity()` passing `env_config.cp_broadcast_channel_capacity`.
- **DP reconnect**: `start_dp_client_with_shutdown_and_startup_ready()` uses exponential backoff with jitter (1s → 2s → 4s → … → 30s cap, ±25% jitter) to prevent thundering-herd reconnection storms when many DPs restart simultaneously. Backoff resets to 1s on clean stream disconnect (CP graceful shutdown). The single-shot `connect_and_subscribe()` has no retry loop (used by tests and one-off callers).

## Docker

- **Dockerfile**: Multi-stage build (rust:latest builder + distroless runtime) — for local `docker build .`
- **Dockerfile.release**: Distroless runtime image (`gcr.io/distroless/cc-debian13:nonroot`) using pre-built binaries with `TARGETARCH` for multi-arch CI builds — used by CI/CD workflows only
- **Distroless**: No shell, no package manager, no OS CVEs. OpenSSL is vendored (statically linked) so `libssl` is not needed. CA certificates are included in `distroless/cc`. Runs as UID 65532 (`nonroot`)
- **Exposed ports**: 8000, 8443 (proxy), 9000, 9443 (admin), 50051 (gRPC)
- **Health check**: `ferrum-edge health` CLI subcommand (no curl needed in distroless)
- **docker-compose.yml**: Profiles for `sqlite`, `postgres`, and `cp-dp` deployments
- **Docker Hub**: `ferrumedge/ferrum-edge` — `:latest` (main), `:v0.9.0` / `:0.9.0` / `:0.9` (tagged releases)
- **GHCR**: `ghcr.io/ferrum-edge/ferrum-edge` — same tag scheme as Docker Hub

## Cargo Profiles

| Profile | Opt Level | LTO | Codegen Units | Use |
|---------|-----------|-----|---------------|-----|
| `dev` | 0 | No | 256 (incremental) | Local development |
| `release` | 3 | Thin | 16, strip=true | Production builds |
| `ci-release` | 2 | No | 256 | Fast CI builds |
