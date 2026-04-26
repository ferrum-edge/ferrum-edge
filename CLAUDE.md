# CLAUDE.md — Ferrum Edge

## Project Overview

High-performance Rust edge proxy (HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC, raw TCP/UDP) with 58+ plugins, four operating modes, LB + health checks. Rust (edition 2024) on tokio + hyper 1.0. Single binary `ferrum-edge` (CLI subcommands + env config). License: PolyForm Noncommercial 1.0.0 (dual-licensed commercial).

## Commands

### CLI

```bash
ferrum-edge run [OPTIONS]       # Start gateway
ferrum-edge validate [OPTIONS]  # Validate config without starting
ferrum-edge reload [--pid PID]  # SIGHUP to running instance (Unix)
ferrum-edge version [--json]
ferrum-edge health [-p PORT] [--host H] [--tls] [--tls-no-verify]
ferrum-edge                     # No args = legacy env-var-only mode (backcompat)
```

`run`/`validate` flags: `-s/--settings <PATH>`, `-c/--spec <PATH>`, `-m/--mode <MODE>`, `-v/--verbose`. **Precedence**: CLI > env > conf file > smart defaults > hardcoded. Smart defaults search `./ferrum.conf`, `./config/ferrum.conf`, `/etc/ferrum/ferrum.conf` and `./resources.{yaml,json}`, `./config/resources.{yaml,json}`, `/etc/ferrum/config.{yaml,json}`. CLI flags translate to env vars via `apply_run_overrides()` **before** `CONF_FILE_CACHE` reads — see `main.rs`.

### Build / Test / Lint

```bash
cargo build                               # Debug
cargo build --release                     # O3, thin LTO, strip
cargo test --test unit_tests              # Fast, no I/O
cargo test --test integration_tests       # Component interaction
cargo build --bin ferrum-edge && cargo test --test functional_tests -- --ignored  # E2E
cargo clippy --all-targets -- -D warnings
cargo fmt --all && cargo fmt --all -- --check
```

**Prerequisite**: `protoc`. `build.rs` runs `tonic_build` on `proto/ferrum.proto`.

### Before Every Commit — MANDATORY

**Steps 1-3 are non-negotiable. CI rejects unformatted code immediately — #1 cause of CI failures.**

0. `rustup update stable` — CI uses `dtolnay/rust-toolchain@stable`; new clippy lints will fail CI if you're behind
1. `cargo fmt --all` then `cargo fmt --all -- --check` (fmt can miss files that --check catches)
2. `cargo clippy --all-targets -- -D warnings`
3. `cargo test --test unit_tests && cargo test --test integration_tests`
4. If proxy behavior changed: `cargo build --bin ferrum-edge && cargo test --test functional_tests -- --ignored`

### CI (GitHub Actions)

PRs: format check → tests (parallel) → lint → perf regression → build 5 targets (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64). All must pass to merge. Push to main: build → overwrite `latest` release → multi-arch Docker to Docker Hub + GHCR. Tag `v*`: versioned release + Docker tags (`v0.9.0`/`0.9.0`/`0.9`). Required secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`. GHCR uses `GITHUB_TOKEN`. Repo **Settings > Actions > Workflow permissions** must be Read+Write.

## Architecture

### Operating Modes (`FERRUM_MODE`)

- `database` — R/W admin + proxy; PostgreSQL/MySQL/SQLite/MongoDB polling
- `file` — R/O admin + proxy; YAML/JSON, SIGHUP reload (Unix)
- `cp` (Control Plane) — R/W admin, **no proxy**, database + gRPC distribution
- `dp` (Data Plane) — R/O admin + proxy; gRPC from CP (multi-CP failover via `FERRUM_DP_CP_GRPC_URLS`)
- `migrate` — runs DB migrations, exits

**TLS-only listeners**: port `0` on `FERRUM_PROXY_HTTP_PORT`/`FERRUM_ADMIN_HTTP_PORT`/inside `FERRUM_CP_GRPC_LISTEN_ADDR` disables plaintext. Excluded from `reserved_gateway_ports()`. Gateway warns if plaintext disabled and no TLS configured.

**Admin JWT asymmetry (intentional)**: the admin API only *validates* JWTs — it never mints them (operators pre-sign tokens externally). DB/CP require `FERRUM_ADMIN_JWT_SECRET` (≥32 chars) because their R/W admin API needs a stable, known secret so operator-minted tokens stay valid across instances and restarts. File mode is read-only, so it generates a random secret at startup — externally crafted tokens can never validate.

**`/health` DB check cached 15s via lock-free `ArcSwap`** (`AdminState.CachedDbHealthResult`). Endpoints unauthenticated; without caching an attacker could flood `SELECT 1` and exhaust `FERRUM_DB_POOL_MAX_CONNECTIONS` (default 10). Do not remove. Response includes `database.pool` stats when connected.

**`GET /cluster`** (JWT-auth): CP returns connected DPs (from `DpNodeRegistry`, auto-removed on stream drop via `TrackedStream`); DP returns CP connection state (from `DpCpConnectionState`, primary vs fallback, `last_config_received_at`).

### Core Design Principles

1. **Lock-free hot path** — `ArcSwap::load()` + `DashMap`. No `Mutex`/`RwLock` on proxy path.
2. **Zero-allocation hot path** — thread-local pool key buffers; `Arc<UpstreamTarget>` LB selection; response header `get_mut()` before key alloc; pre-populated status code DashMap.
3. **Pre-computed indexes** — `RouterCache`, `PluginCache`, `ConsumerIndex`, `LoadBalancerCache` rebuilt on reload, not per-request.
4. **Atomic config reload** — `ArcSwap` swap; in-flight requests see old or new, never partial.
5. **Resilience** — if config source unavailable, keep serving cached config.

### Startup

jemalloc (non-Windows) → CLI parse + env overrides (before `CONF_FILE_CACHE`) → rustls ring provider → tracing-subscriber non-blocking stdout → `validate` exits here → secret resolution (single-threaded rt, `std::env::set_var` is unsafe with concurrent threads) → `EnvConfig` parse → multi-threaded tokio → mode dispatch → SIGINT/SIGTERM via `watch::channel`.

Per serving mode: TLS policy → frontend TLS → admin TLS → DTLS → backend TLS validation → CP/DP gRPC TLS → stream port validation → stream listener bind (fatal in db/file, non-fatal in dp) → DNS warmup → connection pool warmup (if `FERRUM_POOL_WARMUP_ENABLED`) → overload monitor.

### TLS Rotation

All file-based TLS materials are **static operational inputs**. Cert changes on disk are NOT picked up live (K8s Secrets, sidecar volumes, etc.). Rotation = **gateway restart / rolling redeploy**.

### Graceful Shutdown

SIGTERM/SIGINT → accept loops exit → drain (`OverloadState.draining=true`, `Connection: close` on responses, wait up to `FERRUM_SHUTDOWN_DRAIN_SECONDS` for `active_connections` + `active_requests` to reach zero via RAII guards; `Notify::notify_one()` on last drop) → 5s background cleanup → exit.

`RequestGuard` is embedded into `ProxyBody` via `with_request_guard()` on H1/H2/gRPC paths so it lives as long as hyper streams — critical for H2/gRPC streaming. H3 uses stack local. Tracks the real concurrency driver (1 H2 conn with 1000 streams = 1 conn + up to 1000 requests). `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` disables drain.

### Overload Manager (`src/overload.rs`)

Progressive load shedding via atomic flags (`disable_keepalive`, `reject_new_connections`, `reject_new_requests`). Monitors FD, connections, requests, event-loop latency. Thresholds: FD ≥ 80% / Conn ≥ 85% / Req ≥ 85% → disable keepalive. FD ≥ 95% / Conn ≥ 95% / Loop ≥ 500ms → reject new connections. Req ≥ 95% → reject new requests (503 / gRPC UNAVAILABLE). `GET /overload` (unauth) returns pressure + `port_exhaustion_events`; 503 at critical. State transitions logged (warn enter, info recover) — no spam. RED probabilistic shedding between thresholds via golden-ratio hashing.

### External Secret Resolution

At startup, before config load. Env var suffixes resolve the base name: `_VAULT` (HashiCorp Vault KV v2), `_AWS` (Secrets Manager), `_AZURE` (Key Vault), `_GCP` (Secret Manager), `_FILE` (disk), `_ENV` (another env var). Backends grouped per provider (one client). Conflict detection prevents two providers setting the same base key. See `src/secrets/`.

### Source Layout (pointers)

- `src/{main,cli}.rs` — CLI, mode dispatch, signals
- `src/admin/` — REST API + JWT middleware
- `src/config/` — `types.rs` (domain model), `env_config.rs` (90+ vars), `db_backend.rs` trait + `db_loader.rs`/`mongo_store.rs`, `file_loader.rs`, `migrations/`
- `src/modes/` — database/file/control_plane/data_plane/migrate
- `src/proxy/` — `mod.rs` (handle_proxy_request), `handler.rs`, `body.rs` (ProxyBody + Coalescing adapters), `grpc_proxy.rs`, `http2_pool.rs`, `tcp_proxy.rs`, `udp_proxy.rs`, `udp_batch.rs`, `sni.rs`, `stream_listener.rs`, `client_ip.rs`
- `src/plugins/` — `mod.rs` (trait + priorities), `utils/`, per-plugin files
- `src/grpc/` — `cp_server.rs`, `dp_client.rs`; `src/http3/` — QUIC server + `Http3ConnectionPool`
- `src/{dtls,dns,secrets,tls,service_discovery}/`
- Top-level utilities: `overload.rs`, `load_balancer.rs`, `health_check.rs`, `circuit_breaker.rs`, `retry.rs`, `pool/`, `connection_pool.rs`, `router_cache.rs`, `plugin_cache.rs`, `consumer_index.rs`, `config_delta.rs`, `date_cache.rs`, `lazy_timeout.rs`, `socket_opts.rs`, `tls_offload.rs`
- `custom_plugins/` — auto-discovered by `build.rs`; supports `plugin_migrations()`

### Domain Model (`src/config/types.rs`)

`GatewayConfig` → `Proxy`, `Consumer`, `Upstream`, `PluginConfig`. Each has `namespace` (default `"ferrum"`).

**Namespace isolation**: `FERRUM_NAMESPACE` controls what a gateway loads. DB queries filter by namespace; file mode filters post-deserialize. Admin API uses `X-Ferrum-Namespace` header. Uniqueness constraints (listen_path, proxy name, consumer identity, upstream name, listen_port) are per-namespace — same `listen_port` is safe across namespaces (OS bind catches real conflicts).

**Hostname normalization**: ASCII-lowercase at admission via `normalize_fields()` — `Proxy.hosts`, `Proxy.backend_host`, `UpstreamTarget.host`. Applied in every entry point (admin API, loaders, DP gRPC, restore). Downstream consumers rely on this — **do not re-lowercase** in DNS/pool/health/LB keys.

### Route Matching

Per host tier (exact host → wildcard → catch-all): prefix routes first (O(path_depth) via `IndexedPrefixRoutes` HashMap), regex routes second (O(path_length) via `IndexedRegexRoutes` `RegexSet` — single DFA pass regardless of pattern count), host-only fallback (`listen_path: None` + `hosts` set; never applies to catch-all tier).

**NEVER** replace prefix matching with O(n) linear scan; **NEVER** replace regex matching with sequential per-pattern — both caused 30-46% throughput degradation at scale. Router cache (`DashMap`) sized by `FERRUM_ROUTER_CACHE_MAX_ENTRIES` (default auto = `max(10_000, proxies × 3)`). Negative lookups cached to repel scanners.

Regex listen_paths (`~` prefix) auto-anchored full-path (`^...$`). For prefix-style, end with `.*`. Helper: `anchor_regex_pattern()` in `src/config/types.rs`.

### Proxy `hosts`/`listen_path`/`listen_port` contract

- **HTTP-family** (`http`/`https`/`ws`/`wss`/`grpc`/`grpcs`/`h3`): route on hosts + listen_path. At least one of `hosts`/`listen_path` required. `listen_port` MUST be `None`.
- **Stream-family** (`tcp`/`tcp_tls`/`udp`/`dtls`): route on `listen_port`. `listen_path` MUST be `None` (hard error).

Host-only HTTP proxy matches all paths under its hosts; `strip_listen_path: true` is a no-op there. `hosts: []` + `listen_path: None` is rejected. Uniqueness: two HTTP proxies conflict iff same `listen_path` + overlapping `hosts` (empty hosts = catch-all, overlaps all). Host-only and path-carrying on same host coexist (different match tiers). See `DatabaseBackend::check_listen_path_unique()` in `src/config/db_backend.rs`.

**`backend_scheme` + runtime flavor**: HTTP-family proxies accept `http`/`https` and `backend_scheme` is optional (defaults to `https`). Stream-family (`tcp`/`tcps`/`udp`/`dtls`) requires an explicit scheme. gRPC and WebSocket are NOT schemes — they are runtime flavors classified per-request via `backend_dispatch::detect_http_flavor()` (one header lookup, zero allocation). A single `https` proxy serves Plain/gRPC/WebSocket traffic uniformly. HTTPS backends are classified out of band into the usable plain-HTTP buckets (`h1`, `h2_tls`, `h3`) plus the gRPC transport buckets (`h2_tls`, `h2c`).

**HTTP/3 is decoupled from the backend.** An H3 client can hit any `https` backend; the gateway dispatches Plain/gRPC via reqwest / H2 pool just like H1/H2 clients do and only uses the native H3 backend pool when the startup capability registry has already proved the concrete backend target supports H3. WebSocket over H3 returns 501 (RFC 9220 not broadly supported). See [docs/http3.md](docs/http3.md) for the cross-protocol bridge, buffering policy, and rationale.

### Protocol-Level Request Validation

`check_protocol_headers()` in `src/proxy/mod.rs` runs on every inbound request. Rejects (400 unless noted): HTTP/1.0+TE, **CL+TE conflict** (RFC 9112 §6.1 smuggling), multiple CL/mismatched, multiple Host, HTTP/2 TE not `"trailers"`, non-numeric Content-Length, TRACE (405 XST defense), non-WS CONNECT (405). Host trailing dot stripped pre-routing. gRPC non-POST → gRPC error trailers. Invalid Sec-WebSocket-Key falls through as non-WS. WS Origin rejected 403 when `allowed_ws_origins` set.

CONNECT: H2 Extended CONNECT (RFC 8441) with `:protocol=websocket` is the only allowed variant. Response hop-by-hop filtering (RFC 9110 §7.6.1) strips `connection`/`keep-alive`/`proxy-authenticate`/`proxy-connection`/`te`/`trailer`/`transfer-encoding`/`upgrade` across all response paths. Smuggling verified safe: H2.CL downgrade (CL stripped, reqwest recalculates); TE.TE obfuscation (H1.0 rejects, H1.1 strips, H2 validates `"trailers"`, hyper lowercases). See `protocol_validation_tests.rs`. hyper/h2/quinn already validate: method/header syntax, pseudo-header ordering, H2 frame/stream state, reset-stream abuse, QUIC packet format, WS frame/masking/close.

### TLS/DTLS Passthrough

`passthrough: true` on stream proxies forwards encrypted bytes to backend without TLS/DTLS termination. Peeks at ClientHello for SNI (`src/proxy/sni.rs`). TCP: `TcpStream::peek()` then `bidirectional_copy`. UDP: parse first DTLS ClientHello for SNI; backend is plain UDP. Validation: stream proxies only, mutually exclusive with `frontend_tls`, backend TLS fields rejected. `StreamConnectionContext.sni_hostname` + `consumer_username` (from `effective_identity()`) flow to stream lifecycle plugins.

### TCP Bidirectional-Relay Modes (`src/proxy/tcp_proxy.rs`)

Splice/kTLS-splice/io_uring paths use the syscall fast path; userspace runs only when splice unavailable (non-Linux, TLS w/o kTLS, backend TLS-terminated).

Userspace modes: **fast path** (both `FERRUM_TCP_IDLE_TIMEOUT_SECONDS=0` AND `FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS=0`) delegates to `copy_bidirectional_with_sizes` — best throughput, no BiLock overhead, but no idle watchdog (OS keepalive ~2h), no half-close cap, `disconnect_direction: unknown` on error. **Direction-tracking** (default, either timeout non-zero) gives idle timeout + half-close cap + per-direction byte counters + first-failure attribution at ~5ns BiLock per r/w + two 4-64 KB buffers per conn. Pick fast path when upstream L4 LB enforces timeouts and throughput matters; stay on direction-tracking when self-hosted or dashboards consume `disconnect_direction`.

**`backend_read_timeout_ms` / `backend_write_timeout_ms`** on TCP relays: per-direction inactivity watermarks (`Arc<AtomicU64>`) refreshed on read progress (b2c) or partial-write progress (c2b). Phase 1 watchdog polls 1/sec. Chunked write loop refreshes on each partial progress — slow-but-progressing backends NOT misclassified. Schema allows `0` to disable for long-lived workloads (DB keepalives, SSH, IMAP). Splice/kTLS/io_uring paths rely only on `tcp_idle_timeout_seconds`.

### Stream Proxy Port Validation

Validation levels: config (`validate_stream_proxies()` + `validate_stream_proxy_port_conflicts()`); admin API (DB uniqueness + port probe, skipped in CP); startup reconcile (pre-bind; fatal in db/file, **non-fatal in DP** — prevents bad config from bricking DPs); runtime reconcile (never crashes). DP does NOT re-validate port conflicts on CP-pushed config (CP can't know each DP's reserved ports). Conflicts are detected at bind time — only the conflicting proxy is skipped.

### Plugin System

Priority order, lower = first. Multiple instances per proxy allowed. Each has `id`, `config`, optional `priority_override`. Scopes: `global` (all proxies), `proxy` (one, independent instance), `proxy_group` (subset via association list, **single shared instance** — stateful plugins like rate_limiting share counters; cascade-delete when no proxies remain). A proxy/group-scoped plugin replaces a same-named global; multiple scoped instances of the same type coexist.

**Lifecycle phases** (see `src/plugins/mod.rs` for `priority::*` constants, `docs/plugin_execution_order.md` for the protocol matrix):

1. `on_request_received` — tracing/CORS/termination/IP+geo/bot/spec_expose/SSE validate/gRPC-Web/size+rate/tx_debug
2. `authenticate` — mTLS (950), JWKS (1000), JWT (1100), keyauth (1200), LDAP (1250), basicauth (1300), HMAC (1400)
3. `authorize` — ACL (2000), rate_limiting (2900)
4. `before_proxy` — SOAP WS-Security, AI cache/dedup/guards/federation, request_transformer, serverless, response_mock, gRPC deadline, mirror, load_testing, response_caching, compression, ai_rate_limiter
5. `on_final_request_body` — body_validator (gRPC protobuf + JSON/XML after transformer), gRPC-Web validation
6. `after_proxy` — counterpart to before_proxy; rejects enforced on response path across HTTP/H3/gRPC
7. `on_final_response_body` — dedup + semantic cache store, size limiting, response_caching LRU uncacheable predictor
8. `on_response_body` — AI response guard, AI token metrics
9. `log` — stdout, statsd, http, tcp, kafka, loki, udp, ws, tx_debug, prometheus, chargeback
10. `on_ws_frame` — ws_message_size_limiting, ws_rate_limit, ws_frame_logging
11. `on_stream_connect`/`on_stream_disconnect` — TCP+TLS runs after handshake (client cert available); UDP+DTLS after DTLS handshake
12. `on_udp_datagram` — bidirectional hooks; zero overhead unless `requires_udp_datagram_hooks()`

**Multi-auth**: `AuthMode::Multi` accepts `ctx.identified_consumer` OR `ctx.authenticated_identity` (JWKS/OIDC). First-success-wins. Empty chain → reject.

**Multi-credential rotation**: Each credential type can be single object or array. `Consumer::credential_entries(cred_type)` normalizes. Index-based (keyauth, mtls) inserts all in `ConsumerIndex` (O(1)); secret-based (jwt, basicauth, hmac) iterates (typically 1-2). `FERRUM_MAX_CREDENTIALS_PER_TYPE` (default 2). Admin: `POST /consumers/:id/credentials/:type` + `DELETE .../:index`.

**gRPC rejection normalization**: Plugin rejects for `application/grpc` → trailers-only gRPC errors.

**Body buffering**: Two-tier — `PluginCache.requires_request/response_body_buffering()` (O(1) upper bound) then per-request `should_buffer_*_body(&RequestContext)`. gRPC: `GrpcBody::Streaming(Incoming)` when no body plugins + no retries; `Buffered(Full<Bytes>)` otherwise.

**CRITICAL — `before_proxy(ctx, headers)`**: always read headers from the `headers` parameter, NEVER from `ctx.headers`. When no plugin sets `modifies_request_headers() == true`, the handler `std::mem::take()`s headers out of `ctx.headers` — `ctx.headers` is empty during this phase. Only this phase has this quirk.

**External identity**: `ctx.authenticated_identity` is first-class across rate-limit/cache keys, log summaries, backend identity-header injection. **Response mock path scoping**: `response_mock` strips the proxy's `listen_path` prefix before rule matching (no stripping for root/regex listen_paths).

### Transaction Summary Fields

`TransactionSummary` (HTTP/gRPC/WS) and `StreamTransactionSummary` (TCP/UDP) in `src/plugins/mod.rs`. HTTP path has body-streaming fields (`body_error_class`, `body_completed`, `bytes_streamed_to_client`) — populated fully only after a forthcoming `DeferredTransactionLogger`. Stream path has disconnect-attribution fields (`disconnect_direction`: `ClientToBackend`/`BackendToClient`/`Unknown`; `disconnect_cause`: `IdleTimeout`/`RecvError`/`BackendError`/`GracefulShutdown`). Error classifiers: `classify_reqwest_error`, `classify_grpc_proxy_error`, `classify_boxed_error`, `classify_http2_pool_error`, `classify_http3_error`.

### DNS Cache (`src/dns/mod.rs`)

Shared singleton; pre-warmed. Native TTL by default, floored by `FERRUM_DNS_MIN_TTL_SECONDS`. Stale-while-revalidate + background refresh at `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT` of TTL (90%). Priority: per-proxy `dns_cache_ttl_seconds` > `FERRUM_DNS_TTL_OVERRIDE_SECONDS` > native. Failed retries via background task. TCP fallback for truncated UDP. Concurrent nameserver races (`FERRUM_DNS_NUM_CONCURRENT_REQS`). **`DnsCacheResolver` must be plugged into every `reqwest::Client` in production.**

### Centralized Rate Limiting (Redis)

Four rate plugins (`rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`, `udp_rate_limiting`) support `sync_mode: "redis"`. Shared client in `src/plugins/utils/redis_rate_limiter.rs`. Algorithm: two-window weighted via pipelined `INCR`/`GET`/`EXPIRE` — no Lua. Keys `{prefix}:{rate_key}:{window_index}`; default prefix `{FERRUM_NAMESPACE}:{plugin_name}` prevents cross-gateway collisions. Auto-fallback to in-memory on outage + background reconnect. TLS via `rediss://` uses global `FERRUM_TLS_*`. Works with Redis/Valkey/DragonflyDB/KeyDB/Garnet.

## Test Structure

```
tests/{unit_tests,integration_tests,functional_tests}.rs   # Entry points
tests/unit/{config,plugins,admin,gateway_core}/
tests/{integration,functional,performance}/                # functional tests are #[ignore]
```

### Test Placement — follow exactly

- Private fns/structs → `#[cfg(test)] mod tests` **inline** in source (tests/ is separate crate, can't see non-`pub`)
- Public API → `tests/unit/<category>/<module>_tests.rs`
- Component interaction → `tests/integration/`
- Full binary E2E → `tests/functional/` with `#[ignore]`; requires `cargo build --bin ferrum-edge`

Inline `#[cfg(test)]` modules are intentional — do NOT promote fns to `pub` to enable external tests. Files with inline tests: `adaptive_buffer.rs`, `overload.rs`, `load_balancer.rs`, `router_cache.rs`, `config/mongo_store.rs`, `grpc/cp_server.rs`, `proxy/udp_proxy.rs`, `secrets/{env,file,mod}.rs`, `service_discovery/{consul,kubernetes}.rs`.

New test file in `tests/unit/`: create file + add `mod <name>;` to `tests/unit/<category>/mod.rs`.

### Functional Test Rules

- **`Stdio::null()` for gateway stdout/stderr** unless read. `Stdio::piped()` without reading deadlocks on buffer fill.
- **Port allocation MUST retry**: bind-drop-rebind races with other parallel tests that can steal the port between drop and gateway bind (gateway fails silently with `Stdio::null()`).
- **Pool warmup vs backend-hit assertions** — `FERRUM_POOL_WARMUP_ENABLED=true` (production default) makes the gateway issue a `HEAD /` to every backend at startup, which throws off `received_requests().len()` / `accepted_connections()` assertions by exactly one. Set `FERRUM_POOL_WARMUP_ENABLED=false` in any test that counts backend hits. Conversely, tests that depend on the capability registry having a `Supported` entry before traffic flows (H3 native pool, direct H2 pool routing) REQUIRE warmup `true` — without it the first request lands while the registry is still empty. See `tests/scaffolding/harness.rs` rustdoc for the full rule of thumb.

Use struct harness with `try_new()` retry wrapper (killing gateway on `wait_for_health` failure) OR a `start_gateway_with_retry()` helper. Rules: fresh ports + fresh temp dirs/DBs every retry (reusing killed SQLite can corrupt WAL); backend/echo server holds listener — don't drop+rebind, pass pre-bound `TcpListener` to `start_echo_server_on()`; `wait_for_health` returns `bool`/`Result`, never panic.

## Development Guidelines

### Code Quality Rules

- **No `.unwrap()` or `.expect()` in production code** — use `?`, `.unwrap_or()`, `.unwrap_or_else()`, match/if-let. OK in tests.
- **No panics on hot path** — proxy request path must never panic. Return errors.
- Don't silently swallow errors — log warnings before `.unwrap_or_default()` when appropriate.
- **Always `validation.validate_exp = true`** on JWT verification.
- Escape user input when interpolating into JSON/XML response bodies.

### TLS Architecture

**Backend CA trust chain**: proxy `backend_tls_server_ca_cert_path` → global `FERRUM_TLS_CA_BUNDLE_PATH` → webpki/system roots. Opt-out via `backend_tls_verify_server_cert: false` or `FERRUM_TLS_NO_VERIFY=true`.

**CA exclusivity**: custom CA = sole trust anchor (no webpki mixing). When adding new paths with custom CA: reqwest → `.tls_built_in_root_certs(false)`; rustls → `RootCertStore::empty()`.

**Startup validation**: per-proxy TLS paths validated by `validate_all_fields_with_ip_policy()` at config load. File = refuse to start; DB = warn; DP = reject update, keep cached. No silent fallback.

**Cert expiration** (`check_cert_expiry()` in `src/tls/mod.rs`): all surfaces check `notBefore`/`notAfter`. Expired = hard failure. Warning within `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS` (default 30).

**CRL** (`FERRUM_TLS_CRL_FILE_PATH`): PEM (multiple blocks OK), loaded once, `Arc`-shared. Policy: `allow_unknown_revocation_status` + `only_check_end_entity_revocation`. Applied to frontend mTLS, all 6 rustls backend paths, DTLS. NOT applied to DP→CP gRPC (tonic-managed). Restart to reload. No hot reload for any TLS surface.

**Pool-per-cert-path**: reqwest paths (HTTP/1.1, H2 via reqwest, H3 frontend→backend) → distinct `reqwest::Client`. rustls paths (gRPC pool, H2 direct) → per-connection.

**Non-rustls paths**: `kafka_logging` (librdkafka/OpenSSL) — `FERRUM_TLS_CA_BUNDLE_PATH`→`ssl.ca.location`, `FERRUM_TLS_NO_VERIFY`→`enable.ssl.certificate.verification=false` (plugin fields override; CRL via `producer_config.ssl.crl.location`). `redis` applies global flags via `PluginHttpClient` accessors.

**`PluginHttpClient` limits**: plugins bypassing proxy dispatch (`ai_federation` "terminate and respond") use shared `PluginHttpClient` with global TLS only — no per-proxy CA/CRL/cipher. For private endpoints, add internal CAs to global bundle (include public roots too since CA exclusivity disables webpki).

### Performance Rules

- No per-request allocations when avoidable — use pre-computed indexes. Static headers (Alt-Svc) pre-computed in `ProxyState`.
- No locks on hot path — `ArcSwap::load()` + `DashMap` only.
- Pre-compute at config reload (indexes, hash rings, plugin metadata flags like `requires_response_body_buffering`).
- No `format!()` in hot loops — pool keys use `write!()` into thread-local `String` buffers (zero-alloc on cache hits, 99%+).
- `Arc` shared read-only data — `LoadBalancer.targets: Vec<Arc<UpstreamTarget>>`, selection = atomic increment (~5ns) not clone (~200-500ns).
- Streaming by default — buffer only when a plugin requires it. Small-response eager buffer via `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` (64 KiB) when CL known — single `bytes().await` beats coalescing adapter for JSON. SSE always streams. `SizeLimitedStreamingResponse` enforces limit frame-by-frame when CL absent.
- Skip plugin phases when empty — guard with `plugins.is_empty()`.
- **Every `reqwest::Client::builder()` must call `.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())))`**. No production path should fall back to system DNS.

### Protocol Paths

- **HTTP/1.1**: hyper → reqwest via `ConnectionPool`. Streaming default.
- **HTTP/2**: hyper (ALPN) → reqwest or `Http2ConnectionPool` (sharded H2 senders). Streaming default.
- **HTTP/3**: quinn/h3 → `Http3ConnectionPool`. Streaming via `CoalescingH3Body`/`DirectH3Body`.
- **gRPC**: hyper (content-type) → `GrpcConnectionPool` (sharded H2). Request + response streaming via `CoalescingH2Body`.
- **WebSocket**: hyper upgrade or H2 Ext CONNECT → direct TCP upgrade; persistent, frame-by-frame.
- **TCP**: `TcpListener` → `TcpStream::connect`; 1:1. `splice(2)` on Linux (plain + kTLS) else `copy_bidirectional`.
- **UDP**: `UdpSocket` → per-session socket, session-keyed. GSO-batched send on Linux.

Dispatch in `src/proxy/mod.rs`: `detect_http_flavor(&req) -> HttpFlavor::{Plain, Grpc, WebSocket}` classifies the request once (shared with the H3 frontend). Backend selection uses `Proxy.dispatch_kind: DispatchKind` (pre-computed at config load via `GatewayConfig::resolve_dispatch_kind()` — variants: `HttpPool`, `HttpsPool`, `TcpRaw`, `TcpTls`, `UdpRaw`, `UdpDtls`) plus the backend capability registry keyed by real backend target identity. Plain HTTPS requests prefer native H3 when the target is classified as `h3`, else the direct H2 pool when classified as `h2_tls`, else reqwest. Streaming vs buffered: two-tier check + `proxy.retry.is_some()`.

**H3 frontend architecture** (`http3/server.rs`, standalone QUIC server). Backend dispatch branches on `(backend capability, http_flavor)`:
- `Plain + backend classified as h3` — native H3 fast path via `Http3ConnectionPool` (quinn/h3), fully streamed.
- Everything else — cross-protocol bridge `http3::cross_protocol::run` reuses `state.connection_pool` (reqwest) / `state.grpc_pool`, so one `https` proxy serves H1/H2/H3 clients uniformly. WebSocket-over-H3 returns 501.
- Cross-protocol buffering: request body buffered (`&mut RequestStream` can't be captured by reqwest's `'static` body), response streamed with the same coalesce window as the native H3 writer. gRPC trailers forwarded via `send_trailers` on both buffered and streaming responses.

**QUIC connection migration**: `http3/server.rs` compares `remote_address()` per request (zero-alloc integer compare). `Arc<str>` re-created only on actual change. Fixes a security issue where migrated clients bypassed per-IP rate limits — do NOT revert to once-per-connection cache.

**gRPC proxy**: hyper H2 direct (not reqwest) to preserve trailers. `GrpcBody::Buffered | Streaming` sum type; streaming forwards `Incoming` frame-by-frame when no body plugins + no retries, bounded by H2 window. Response in `CoalescingH2Body` (128 KB, trailer-safe) when streaming — up to +35% at 5MB.

### Connection Pool Keys

Shared shell in `src/pool/mod.rs`; per-pool key formats below. Key must include every field affecting connection identity (destination, TLS trust, client credentials, DNS routing). Missing field = pool poisoning; extra = fragmentation. `|` delimiter (IPv6 colons would be ambiguous).

- **HTTP** (`connection_pool.rs`): `{dest}|{proto}|{dns_override}|{ca}|{mtls_cert}|{verify}` — `dest` is `u={upstream_id}` or `d={host}:{port}`
- **gRPC** (`proxy/grpc_proxy.rs`): `{host}|{port}|{tls}|{dns_override}|{ca}|{mtls_cert}|{verify}` + shard `#N` — `tls` from `matches!(backend_scheme, Some(BackendScheme::Https))`; gRPC pool entered at runtime by content-type, not by scheme
- **HTTP/2** (`proxy/http2_pool.rs`): `{host}|{port}|{dns_override}|{ca}|{mtls_cert}|{verify}` + shard `#N` (always TLS)
- **HTTP/3** (`http3/client.rs`): `{host}|{port}|{index}|{dns_override}|{ca}|{mtls_cert}|{mtls_key}|{verify}` — matches `backend_capabilities::capability_key` so probe classification and QUIC reuse stay aligned. `pool_key_for_target(proxy, host, port, idx)` takes `&Proxy` for the same reason.

Rules: never add policy fields (timeouts, pool sizes, keepalives); empty/default strings are free; keep `|` delimiter.

**Policy cross-proxy sharing**: Because pool keys exclude policy fields, proxies resolving to the same entry share policy baked into the client (first-wins). `backend_read_timeout_ms` not observable (applied per-request via `RequestBuilder::timeout()`). `backend_connect_timeout_ms` IS observable (reqwest has no per-request override). Force separation via distinct `dns_override`. Upstream fix tracked: seanmonstar/reqwest#3017.

### Backend Capability Registry (`src/proxy/backend_capabilities.rs`)

Out-of-band protocol classifier that decides whether a plain HTTPS request uses native H3, the direct H2 pool, or reqwest — keyed by deduplicated backend target identity (scheme + host + port + `dns_override` + CA + mTLS cert + mTLS key + verify). The key format matches `Http3ConnectionPool::pool_key` so the classification and QUIC reuse stay aligned.

**Lifecycle**:
- `warmup_connection_pools()` (file/db with `FERRUM_POOL_WARMUP_ENABLED=true`) awaits a full probe pass before traffic.
- `start_backend_capability_refresh_task(run_initial_refresh, shutdown)`: spawns the periodic probe every `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS` (default 86400 = 24h). Callers pass `true` when warmup was skipped (warmup-off or DP with non-empty initial config) so the registry populates before the first periodic tick — otherwise HTTPS dispatch falls back to reqwest until the 24h mark. DP passes `false` because its startup config is empty; first CP config push triggers `spawn_backend_capability_refresh` via `apply_incremental`/`update_config`.
- Config reload (`apply_incremental` / `update_config`) calls `spawn_backend_capability_refresh` — the `RefreshCoalescer` guarantees at most one in-flight task plus one queued re-run via a `try_finish` handoff that re-checks `pending` after releasing the runner role, so late config changes are never orphaned.

**Probe parallelism**:
- Cross-target: `for_each_concurrent(pool_warmup_concurrency)` (default 500), matching the DNS warmup pattern.
- Intra-target (HTTPS only): `tokio::join!` runs the H2 probe (`probe_h2_tls` borrows `&mut record`) and the H3 probe (`probe_h3` returns `H3ProbeOutcome` to avoid aliasing the mutable record borrow) in parallel, halving worst-case per-target wall-clock.
- Probe timeouts clamp to `BACKEND_CAPABILITY_PROBE_TIMEOUT_MS_CAP` (5 s) so slow QUIC discovery never holds startup readiness.

**Hot-path lookup**:
- `BackendCapabilityRegistry::get(proxy, target)` builds the key in a thread-local `RefCell<String>` buffer — zero per-request allocation on repeat calls (mirrors `HTTP2_POOL_KEY_BUF`).
- `supports_native_http3_backend(state, proxy, target)` and `supports_direct_http2_backend` are two boolean checks on the returned record. `Unknown` / `Unsupported` both route via reqwest, so an empty registry degrades gracefully.

**Stale-cache invalidation**: `mark_h3_unsupported(proxy, target)` and `mark_h2_tls_unsupported(proxy, target)` Arc-swap the cached record to downgrade the relevant bucket with an operator-visible `last_probe_error`.

- H3 downgrade gated by `is_h3_transport_error_class` (ConnectionRefused/Timeout/Reset/Closed/TlsError/ProtocolError/DnsLookupError/PortExhaustion/ConnectionPoolError/ReadWriteTimeout — NOT ClientDisconnect or payload-size errors) via `is_h3_transport_failure`, which inspects `error_class` ONLY. `classify_h3_error` flags GOAWAY / stream reset / non-connect read timeouts with `connection_error=false`; they are still transport failures and must downgrade. Hit sites: `proxy_to_backend`, `proxy_to_backend_http3_retry` (H1/H2 frontend → H3 backend), plus `http3/server.rs` streaming-body / streaming-response / buffered paths (H3 frontend → H3 backend).
- H2/TLS downgrade fires on `Http2PoolError::BackendSelectedHttp1` in the direct-H2 dispatch branch — the old per-pool-key ALPN learning cache was removed when the capability registry took over, so without this downgrade every subsequent request would repeat the failed H2 handshake + ALPN fallback until the 24 h refresh. The gRPC `h2_tls` bucket is downgraded in lockstep because the same ALPN observation applies. `plain_http.h1` is set to `Supported` to record that the backend still speaks HTTPS — just over HTTP/1.1.

The next periodic refresh re-probes and restores `Supported` if the backend recovers.

**Per-target dispatch contract**: The retry loop in `proxy_to_backend_inner` captures `current_dispatch_h3 = supports_native_http3_backend(...)` for the target being attempted and threads it into the dispatch call (as `dispatch_h3` to `proxy_to_backend`, or as the H3-vs-reqwest branch selector for retries) — re-reading the registry inside `proxy_to_backend` would race the async DNS resolve against a concurrent `mark_h3_unsupported` / refresh and split a single attempt's dispatch decision in half. Two scopes:

- **Same target across attempts** → keep the snapshot. Cross-protocol replay against the same backend would bypass `proxy.retry.retry_on_methods` (the failed transport attempt may have flushed headers/body before the error surfaced) and risk duplicating non-idempotent requests on the same backend instance. Same-protocol H3 retries do replay the retained body (the outer retry loop's job, gated by `retry_on_methods`); the prohibition is on protocol switching, not on replay itself.
- **Load-balancer rotation to a different target** → recompute `current_dispatch_h3` for the new target. Different target → different backend → no same-target partial-write replay risk, so the new target's actual capability classification (mixed-capability upstreams are real: target A speaks H3, target B speaks H1) wins. Without recompute, an H3-supported initial target locks `dispatch_h3 = true` for every retry and forces `proxy_to_backend_http3_retry` against an H1-only B → 502 forever. Per-target lookup is O(1) (`DashMap` + thread-local key buffer); `Unknown` and `Unsupported` both gracefully fall to reqwest.

Capability downgrade still fires on every transport-class H3 failure but only affects the next attempt's dispatch decision (or the next request, if no rotation happens). This matches industry practice (Envoy, NGINX, HAProxy, Cloudflare, GFE): cross-protocol fallback happens at connection establishment (happy-eyeballs) or via the next-attempt's per-target classification, never silently mid-attempt against the same backend.

**Probe outcomes for expected-unsupported cases** (h2c on plaintext HTTP, H3 on most HTTPS backends): classified as `Unsupported` with a `debug!` log — not appended to `last_probe_error`. Only genuine connection/TLS-config failures on HTTPS backends populate the error string so operators don't chase phantom errors every refresh cycle.

**Admin introspection** (JWT-authenticated, always exposed): `GET /backend-capabilities` returns the full registry snapshot (`BackendCapabilityRegistry::snapshot()`); `POST /backend-capabilities/refresh` forces a synchronous classification pass. Operators use these for routing-decision debugging, protocol-rollout monitoring, and post-incident recovery (force-refresh after a live downgrade). Payloads carry only classifications + probe timestamps — no credentials or request bodies — so they're safe to leave permanently enabled. See [docs/admin_api.md](docs/admin_api.md#backend-capability-registry) + `openapi.yaml` for the full schema; Phase-3 scripted-backend tests assert on these endpoints.

### Connection-Error Classification Boundary

`BackendResponse::connection_error: bool` has exactly one meaning: **"the request body never reached the backend's application layer."** When `true`, the gateway-level retry loop fires `retry_on_connect_failure` regardless of HTTP method, because replaying a request that never went on the wire is idempotent by construction. When `false`, retries must respect `retry_on_methods` / `retryable_status_codes`.

Every protocol classifier (reqwest, direct H2 pool, gRPC pool, native H3 pool, H3 cross-protocol bridge, recv-side body classifier) funnels its `ErrorClass` through one helper:

```rust
retry::request_reached_wire(error_class) -> bool
// connection_error = !request_reached_wire(error_class)
```

`request_reached_wire` returns `false` only for pre-wire transport classes: `ConnectionRefused`, `ConnectionTimeout`, `DnsLookupError`, `TlsError`, `PortExhaustion`, `ConnectionPoolError`. Everything else (`ConnectionReset`, `ConnectionClosed`, `ProtocolError`, `ReadWriteTimeout`, `RequestBodyTooLarge`, `ResponseBodyTooLarge`, `ClientDisconnect`, `RequestError`) is post-wire.

**Per-classifier `connection_error: bool` fields are intentionally absent.** Earlier code derived the boolean separately at every dispatch site (`e.is_connect() || e.is_timeout()` for reqwest; an `is_conn_error` tuple element for H3) and the implementations disagreed. Concretely the H3 string-heuristic classifier matched `"reset"` BEFORE specific h3 / QUIC tokens, so a stream-level `RESET_STREAM` (an application-layer abort) classified as `ConnectionReset` with `connection_error=true` and an `ApplicationClose` (genuinely transport-class) classified as `ProtocolError` with `connection_error=false`. The H3 classifier in `proxy/mod.rs::classify_h3_error` is now a thin wrapper over `http3::client::classify_http3_error` so both paths agree byte-for-byte; the bare `"stream"` substring (which used to false-match `"upstream"` in load-balancer messages) is gone.

**`retry::error_class_log_kind(class)`** centralizes the short label every dispatcher emits as the `error_kind` field on `tracing::error!` log lines. Operators grep one stable token per failure mode across all protocol logs.

**H3 pool body-on-wire signal.** [`Http3ConnectionPool`](src/http3/client.rs) returns a typed [`H3PoolError`](src/http3/client.rs) instead of `anyhow::Error`. `H3PoolError::request_on_wire()` is `true` once the H3 stream has been opened on ANY internal attempt (cached → fallback → fresh-connect chain). Once the body has been (at least partially) committed, `with_request_on_wire(true)` promotes the final returned error to `request_on_wire=true` so a subsequent connect-class failure CANNOT mask the earlier wire commitment. Gateway H3 sites combine this with the classifier:

```rust
let request_on_wire = e.request_on_wire();
let (error_kind, error_class) = classify_h3_error(e.as_ref());
let is_conn_error = !request_on_wire && !retry::request_reached_wire(error_class);
```

This protects against the race where the H3 pool's first internal attempt sent the body on a stale cached connection (post-wire) and a fallback-attempt connect failure surfaces last (pre-wire-looking). Without the sticky promotion, the gateway would conclude `connection_error=true` and replay a non-idempotent request the backend may already have processed.

**Out of scope (P9 follow-up).** The H3 pool still does internal `body.clone()` retries across cached/fallback indices; an attempt that committed the body and then died mid-stream causes a non-idempotent replay on the next internal index, regardless of `retry_on_methods`. The body-on-wire signal makes the OUTER gateway retry safe; tightening the INNER pool replay to honor `retry_on_methods` is a separate correctness fix.

**`mark_h3_unsupported` is unrelated.** Capability downgrade uses `is_h3_transport_error_class(error_class)` — broader than `request_reached_wire` (it includes `ConnectionReset` / `ConnectionClosed` / `ProtocolError` / `ReadWriteTimeout` because a backend that resets H3 streams or times out reads is still failing the H3 transport, even if the request reached the wire). The two predicates intentionally diverge.

### Health Check Architecture (two-layer)

- **Active probes** (periodic): shared per-upstream in `HealthChecker.active_unhealthy_targets: DashMap<"upstream_id::host:port", u64>`. Failure marks unhealthy for ALL proxies using that upstream (target is genuinely down).
- **Passive** (traffic-based): isolated per-proxy in `HealthChecker.passive_health: DashMap<proxy_id, Arc<ProxyHealthState>>`. Inner maps keyed by plain `host:port`. Proxy A's failures do NOT affect proxy B even on the same upstream.

Selection via `HealthContext { active_unhealthy, proxy_passive }`. `compute_health_bitset()` snapshots into stack `u128` bitset via two O(1) DashMap lookups per target (pre-computed keys); algorithms use free bit tests. >128 targets → Vec fallback. Consistent hash ring uses O(1) bitset check.

Rules: never merge active+passive maps (cross-proxy contamination); never key passive by `upstream_id` (proxy is the isolation boundary); `report_response()` takes `proxy_id`; `remove_stale_targets()` cleans both layers.

### Key Performance Lessons (do not violate)

**Allocation**: `HashMap::with_capacity(headers().keys_len())` when collecting; move (not clone) on streaming path; build retry `HeaderMap` only when `proxy.retry.is_some()` (+15% gRPC); pre-alloc body `Vec` from content-length; `Arc<UpstreamTarget>` for LB; response header `get_mut()` before key alloc; pre-populated status code DashMap (read lock not write).

**Routing**: NEVER O(n) linear scan for prefix routes; NEVER sequential per-pattern regex; router cache must scale with proxy count.

**Protocol gotchas**: don't replace reqwest with H3 pool for H3 frontend→backend (~10x regression on small payloads); gRPC `Proxy.clone()` is expensive — extract fields into param structs (see `TcpConnParams`); H2 flow control 8 MiB stream / 32 MiB conn for gRPC; `recvmmsg` for UDP frontend recv (reply handlers skip it intentionally); QUIC coalesce 8-32 KB + 2ms flush; `CoalescingH2Body` 128 KB chunks (+35% gRPC at large payloads) — trailer-safe, do NOT revert; Linux `splice(2)` for TCP plain-to-plain via `bidirectional_splice()`; **NEVER splice TLS without kTLS**.

**Active Pingora-inspired optimizations**: frequency-aware router cache eviction (Count-Min Sketch); `IP_BIND_ADDRESS_NO_PORT`; `TCP_FASTOPEN`; thread-local Date header cache; TLS handshake offload runtime; RED probabilistic shedding; UDP jitter-adaptive buffers; `lazy_timeout`; cacheability predictor LRU; `TCP_INFO` BDP sizing; **kTLS** (per-cipher probe, `zeroize` on drop — never consume TLS stream before confirming kernel install); **io_uring splice** (Linux 5.6+, warns if `FERRUM_BLOCKING_THREADS < 1024`); **UDP GSO** (GRO infra-only, needs recvmmsg-primary rewrite); `IP(v6)_PKTINFO` reply-source selection (GSO-combined `sendmsg`, pins `UdpSession.local_addr` via `OnceLock`); `SO_BUSY_POLL`; `HealthBitset` zero-alloc LB selection with FxHash-style hashing.

### Multi-Protocol Performance Testing

Tests in `tests/performance/multi_protocol/`. Build once with `cargo build --release`, then `bash run_protocol_test.sh {http1|http1-tls|http2|http3|ws|grpc|tcp|tcp-tls|udp|udp-dtls|all} [--duration N] [--concurrency N] [--skip-build]`. Measures gateway overhead vs direct backend.

### Adding a New Plugin

1. `src/plugins/my_plugin.rs` implements `Plugin` trait; constructor returns `Result<Self, String>`
2. Priority constant in `src/plugins/mod.rs` (`priority::MY_PLUGIN = N`)
3. Override `supported_protocols()` (default HTTP only). Constants: `ALL_PROTOCOLS`, `HTTP_FAMILY_PROTOCOLS`, `HTTP_GRPC_PROTOCOLS`, `HTTP_FAMILY_AND_STREAM_PROTOCOLS`, `HTTP_ONLY_PROTOCOLS`, `GRPC_ONLY_PROTOCOLS`, `TCP_ONLY_PROTOCOLS`, `UDP_ONLY_PROTOCOLS`
4. Register in `create_plugin_with_http_client()` match arm (use `?` on `new()`) + add name to `available_plugins()`
5. Unit tests in `tests/unit/plugins/my_plugin_tests.rs` (valid AND invalid configs) + add to `tests/unit/plugins/mod.rs`
6. Update `FEATURES.md`, `README.md`, `docs/plugin_execution_order.md`

### Plugin Config Validation

All `new()` return `Result<Self, String>`. Enforced at: (1) Admin API via `validate_plugin_config_definition()` → HTTP 400; (2) file mode via `plugins::validate_plugin_config()` → fails startup; (3) DB mode → **warn** (data already in DB).

Rules: return `Err` when plugin would be a no-op (rate limiter with no windows, size limiter with 0, transformer with no rules); return `Err` for invalid values (bad regex, bad enum, out-of-range); sensible defaults are fine; never `warn!()` for what should be `Err`. Shared entry: `plugins::validate_plugin_config(name, config) -> Result<(), String>` wraps `create_plugin()`.

### File Dependency Validation (Isolated Tolerance)

Files (TLS certs, MaxMind `.mmdb`) exist on DP nodes, not CP. Per-mode behavior so one bad file doesn't reject the whole config:

- **Backend TLS certs** (`validate_all_fields_with_ip_policy()`): file = fatal, DB/CP admin = warn, DP = reject update, keep old config.
- **Plugin `.mmdb`** (`validate_plugin_file_dependencies()` — separate from the above): file = fatal, DB = warn, CP admin + DP = skip (constructor tolerates; plugin degrades at request time via configured `on_lookup_failure` policy).

Graceful degradation pattern (`geo_restriction` example): constructor logs `warn!` + stores `reader: None`, applies policy at request time. New plugins with file deps: tolerate missing files in constructor; add check to `GatewayConfig::validate_plugin_file_dependencies()`; do NOT add to `validate_all_fields_with_ip_policy()` (which gates whole config on DP). Frontend TLS cert failure is ALWAYS fatal.

### Adding a Custom Plugin with DB Migrations

`custom_plugins/my_plugin.rs` with `create_plugin()` + exported `plugin_migrations() -> Vec<CustomPluginMigration>`. Fields: `version` (per-plugin), `name`, `checksum`, `sql` + optional `sql_postgres`/`sql_mysql`. Prefix tables with plugin name. Multi-statement supported. Run with `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up`; tracked in `_ferrum_plugin_migrations` with `(plugin_name, version)` PK. See `custom_plugins/example_audit_plugin.rs` + `CUSTOM_PLUGINS.md`. **MongoDB**: `CustomPluginMigration` is SQL-only; create MongoDB collections/indexes in `create_plugin()`.

### Adding a New Config Field

1. Struct in `src/config/types.rs` with `#[serde(default)]`
2. Env-driven → `src/config/env_config.rs`
3. **Update `ferrum.conf`** — every new `FERRUM_*` needs commented default + comment. Conf and env vars MUST stay in sync.
4. SQL storage → migration in `src/config/migrations/` + row parsing in `db_loader.rs`
5. MongoDB auto-persists via serde BSON — only add indexes in `MongoStore::run_migrations()` if queried
6. Unit tests in `tests/unit/config/`; update `openapi.yaml` if admin-exposed

SQL requires explicit migrations (control over types/indexes/dialects); MongoDB is serde-driven. Intentional asymmetry.

### Database

PostgreSQL/MySQL/SQLite (sqlx), MongoDB. SQLite uses `PRAGMA journal_mode=WAL`/`busy_timeout=5000`/`foreign_keys=ON` via `after_connect`.

`DatabaseBackend` trait in `src/config/db_backend.rs`; `DatabaseStore` (sqlx) + `MongoStore` both impl. Admin + modes use `Arc<dyn DatabaseBackend>`.

**Transactions**: SQL wraps multi-step CRUD in `sqlx::Transaction`. MongoDB: single-doc atomic; multi-doc requires replica set (`FERRUM_MONGO_REPLICA_SET`), else idempotent with poll-cycle cleanup.

**Incremental polling** (`FERRUM_DB_POLL_INTERVAL_SECONDS`, default 30s): startup = full `SELECT *`; subsequent = indexed `updated_at > ?` + lightweight `SELECT id` deletion diff. 1s safety margin. Validated before apply; known IDs unchanged on reject. Auto-fallback to full reload on failure. **CP broadcasts deltas** via tokio `broadcast` (capacity = `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`); lagging DPs auto-get a full snapshot.

**Failover**: `FERRUM_DB_FAILOVER_URLS` (same `FERRUM_DB_TYPE`); `FERRUM_DB_READ_REPLICA_URL` offloads polling (writes always primary). **MongoDB** (`docs/mongodb.md`): `readPreference` in URL replaces read-replica var; replica sets handle failover natively (list members in `FERRUM_DB_URL`); pool via driver (`maxPoolSize`/`minPoolSize` in URL) — `FERRUM_DB_POOL_*` ignored.

### PR Checklist

`cargo fmt` clean; `cargo clippy --all-targets -- -D warnings`; unit + integration tests pass; new features have normal/edge/error tests; no `.unwrap()`/`.expect()` in prod; no dead code (`-D dead-code`); PR description with summary + changes + test plan; docs updated (FEATURES.md, README.md, docs/, openapi.yaml); new `FERRUM_*` env vars in `ferrum.conf` with commented defaults.

### Commit Style / Branch Naming

Imperative mood, concise (e.g., `Fix rate limiter to handle zero-window edge case`). Branches: `feature/...`, `fix/...`, `claude/...`.

## Key Environment Variables

Full list: 90+ vars in `src/config/env_config.rs` and `ferrum.conf`. Most-common essentials below.

- `FERRUM_MODE` (required): `database`/`file`/`cp`/`dp`/`migrate`
- `FERRUM_NAMESPACE` (`ferrum`): which namespace this instance loads
- `FERRUM_LOG_LEVEL` (`error`)
- `FERRUM_PROXY_HTTP_PORT`/`HTTPS_PORT` (8000/8443); `FERRUM_ADMIN_HTTP_PORT`/`HTTPS_PORT` (9000/9443) — `0` disables plaintext
- `FERRUM_ADMIN_JWT_SECRET` (required db/cp, ≥32 chars)
- `FERRUM_FRONTEND_TLS_CERT_PATH`/`KEY_PATH`
- `FERRUM_TLS_CA_BUNDLE_PATH` (global backend CA, exclusive); `FERRUM_TLS_NO_VERIFY` (**testing only**); `FERRUM_TLS_CRL_FILE_PATH`
- `FERRUM_FILE_CONFIG_PATH` (required file mode)
- `FERRUM_DB_TYPE`/`DB_URL` (required db); `FERRUM_DB_FAILOVER_URLS`, `FERRUM_DB_READ_REPLICA_URL`; `FERRUM_DB_POOL_MAX_CONNECTIONS` (10, bump for CP)
- `FERRUM_CP_GRPC_LISTEN_ADDR` (`0.0.0.0:50051`; port `0` disables)
- `FERRUM_CP_DP_GRPC_JWT_SECRET` (required cp/dp, ≥32 chars)
- `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY` (128; lagging DPs auto-snapshot)
- `FERRUM_DP_CP_GRPC_URL`/`URLS` (required dp); `FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS` (300)
- `FERRUM_MAX_CONNECTIONS` (100000)/`MAX_REQUESTS` (0 = unlimited)
- `FERRUM_SHUTDOWN_DRAIN_SECONDS` (30; `0` immediate)
- `FERRUM_WORKER_THREADS` (CPU cores); `FERRUM_BLOCKING_THREADS` (512; **bump to ≥1024 with io_uring splice at scale**)
- `FERRUM_ACCEPT_THREADS` (0 = CPU cores; SO_REUSEPORT)
- `FERRUM_TCP_IDLE_TIMEOUT_SECONDS`/`HALF_CLOSE_MAX_WAIT_SECONDS` (300/300; both `0` → TCP fast path)
- `FERRUM_UDP_MAX_SESSIONS` (10000); `FERRUM_UDP_RECVMMSG_BATCH_SIZE` (64)
- `FERRUM_WEBSOCKET_MAX_CONNECTIONS` (20000; 0 = disabled)
- `FERRUM_WEBSOCKET_TUNNEL_MODE` (`false`) — raw TCP copy; **frame-loss risk for server-push** (stock tickers, Socket.IO) where backend writes in same TCP segment as 101
- `FERRUM_MAX_CREDENTIALS_PER_TYPE` (2); `FERRUM_BASIC_AUTH_HMAC_SECRET` (**change in production**)
- `FERRUM_TRUSTED_PROXIES` (XFF CIDRs); `FERRUM_BACKEND_ALLOW_IPS` (`both`/`private`/`public`)
- `FERRUM_ROUTER_CACHE_MAX_ENTRIES` (0 = auto `max(10K, proxies × 3)`)
- `FERRUM_POOL_WARMUP_ENABLED` (`true`); `FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE` (8 MiB), `FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE` (32 MiB) — gRPC tuning
- `FERRUM_BACKEND_CAPABILITY_REFRESH_INTERVAL_SECS` (86400 = 24h) — background re-classification interval for the backend capability registry (H1/H2/H3 + h2c). Tune down during backend protocol rollouts so H3-upgrade / rollback detection latency shrinks; startup + H3 failure downgrade are the main triggers the rest of the time.
- `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` (65536; eager buffer when CL ≤ this; `0` always stream)
- `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` (32; bounded mpsc for H3→non-H3 cross-protocol request-body bridge; ~512 KiB pipeline depth per upload)
- `FERRUM_KTLS_ENABLED`/`IO_URING_SPLICE_ENABLED`/`UDP_GSO_ENABLED`/`UDP_PKTINFO_ENABLED`/`UDP_GRO_ENABLED`/`TCP_FASTOPEN_ENABLED` (all `auto` on Linux)
- `FERRUM_DNS_MIN_TTL_SECONDS` (5); `FERRUM_DNS_TTL_OVERRIDE_SECONDS` (0)
- `FERRUM_ADD_VIA_HEADER`/`VIA_PSEUDONYM` (`true`/`ferrum-edge`)

## Proto / gRPC (CP/DP)

`proto/ferrum.proto` compiled by `build.rs` via `tonic_build`. Service `ConfigSync` with `Subscribe` (streaming) + `GetFullConfig` (unary). HS256 JWT in `authorization` metadata. CP broadcast: `CpGrpcServer::with_channel_capacity()` in prod (passes `env_config.cp_broadcast_channel_capacity`); `new()` defaults to 128 for tests. DP reconnect: priority-ordered URLs with per-URL exponential backoff (1s→2s→4s→…30s, ±25% jitter). On fallback CP, `tokio::select!` races stream against primary-retry timer (`FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`). `FERRUM_DP_CP_GRPC_URLS` takes precedence over `_URL`.

## Docker

`Dockerfile` (multi-stage → distroless `gcr.io/distroless/cc-debian13:nonroot`) for local; `Dockerfile.release` for CI. No shell, OpenSSL vendored, UID 65532. Ports 8000/8443/9000/9443/50051. Healthcheck: `ferrum-edge health`. `docker-compose.yml` profiles: `sqlite`/`postgres`/`cp-dp`. Images: `ferrumedge/ferrum-edge` (Docker Hub), `ghcr.io/ferrum-edge/ferrum-edge`.

## Cargo Profiles

- `dev` — opt 0, no LTO, 256 codegen units (incremental)
- `release` — opt 3, thin LTO, 16 codegen units, strip
- `ci-release` — opt 2, no LTO, 256 codegen units (fast CI)
