# CLAUDE.md — Ferrum Edge

## Project Overview

High-performance Rust edge proxy (HTTP/1.1, HTTP/2, HTTP/3, WebSocket, gRPC, raw TCP/UDP) with 58+ plugins, four operating modes, LB + health checks. Rust (edition 2024) on tokio + hyper 1.0. Single binary `ferrum-edge` (CLI subcommands + env config). License: PolyForm Noncommercial 1.0.0 (dual-licensed commercial).

## Build-Out Compatibility Policy

Ferrum Edge is in active build-out. Do not add schema DB migrations for new schema changes; fold schema changes into the current baseline schema instead. Do not add or preserve legacy compatibility shims for old fields, environment variables, config shapes, or database values unless explicitly requested. Breaking changes are acceptable in this phase.

## Read Before Touching

- Mesh behavior → [docs/mesh.md](docs/mesh.md) + `src/modes/mesh/` + mesh plugin injection notes below
- HTTP/3 / WebSocket / QUIC → [docs/http3.md](docs/http3.md) + `src/http3/` + Backend Capability Registry below
- API spec extraction → [docs/api_specs.md](docs/api_specs.md) + `src/admin/api_specs/`
- Config/env changes → [docs/configuration.md](docs/configuration.md) + `ferrum.conf` + `src/config/env_config.rs`
- Plugin ordering or hooks → [docs/plugin_execution_order.md](docs/plugin_execution_order.md) + `src/plugins/mod.rs`
- Upstream protocol dependencies → Dependency Version Sync below + `tests/performance/multi_protocol/`

## Commands

### CLI

```bash
ferrum-edge run [OPTIONS]       # Start gateway
ferrum-edge validate [OPTIONS]  # Validate config without starting
ferrum-edge reload [--pid PID]  # SIGHUP to running instance (Unix)
ferrum-edge version [--json]
ferrum-edge health [-p PORT] [--host H] [--tls] [--tls-no-verify]
```

`run`/`validate` flags: `-s/--settings <PATH>`, `-c/--spec <PATH>`, `-m/--mode <MODE>`, `-v/--verbose`. **Precedence**: CLI > env > conf file > smart defaults > hardcoded. Smart defaults search `./ferrum.conf`, `./config/ferrum.conf`, `/etc/ferrum/ferrum.conf` and `./resources.{yaml,json}`, `./config/resources.{yaml,json}`, `/etc/ferrum/config.{yaml,json}`. CLI flags translate to env vars via `apply_run_overrides()` **before** `CONF_FILE_CACHE` reads — see `main.rs`.

### Command Reference

Use these as building blocks; the local testing policy below decides which subset to run.

```bash
cargo build                               # Debug
cargo build --release                     # O3, thin LTO, strip
cargo test --test unit_tests              # Fast, no I/O
cargo test --lib                          # Inline #[cfg(test)] mod tests in src/ (private fns)
cargo test --test integration_tests       # Component interaction
cargo build --bin ferrum-edge && cargo test --test functional_tests -- --ignored  # E2E
cargo clippy --all-targets -- -D warnings
cargo fmt --all && cargo fmt --all -- --check
```

**Prerequisite**: `protoc`. `build.rs` runs `tonic_build` on `proto/ferrum.proto`.

### Cargo target-dir isolation across parallel checkouts

If two git worktrees or clones of this repo share a single `CARGO_TARGET_DIR`, concurrent `cargo build`/`test`/`clippy` invocations across them stall on the shared target-dir lock — symptom is `Blocking waiting for file lock on build directory`, or a cargo invocation that hangs with no output. With no `CARGO_TARGET_DIR` override, Cargo's default puts artifacts in `<worktree>/target/` and each checkout gets its own isolated target dir for free. **Fix at the shell-profile level: leave `CARGO_TARGET_DIR` unset.** Env vars beat `.cargo/config.toml`, and the tracked config can't carry a per-worktree absolute path, so this is the only place to fix it.

`SCCACHE_DIR` (if set) is safe to share — sccache is concurrency-safe and amortizes dependency builds across worktrees. The repo's `.cargo/config.toml` wires `rustc-wrapper = "sccache"` already, so a shared sccache dir gives you compile reuse without the target-dir contention.

Within a single workspace, still run `fmt` → `clippy` → `test` sequentially (not via `&` / parallel shells) — they share *that* workspace's target dir and will lock each other.

If a shell inherited a stale `CARGO_TARGET_DIR`, `env | grep CARGO_TARGET_DIR` confirms it; `unset CARGO_TARGET_DIR` in the same invocation as the `cargo` command works around it for that one call (agent shells are typically fresh per command, so the `unset` and `cargo` must share the call).

### Local testing — targeted, not exhaustive

CI runs the full matrix on every PR (format, clippy, all test crates, perf regression, 5 build targets). Locally, test only what you changed and let CI catch the rest — don't run the whole suite after every iteration.

**Before pushing, choose by change type:**
- Rust changes → `cargo fmt --all -- --check` + targeted clippy (`cargo clippy --lib --tests -p ferrum-edge -- -D warnings`) + the targeted tests below. Reserve `cargo clippy --all-targets -- -D warnings` for the "full suite" trigger conditions below — `--all-targets` pulls in benches and every test crate, i.e. a near-full build, and is what most often clashes with concurrent agents.
- Docs/comment-only → `git diff --check` plus any relevant doc formatter/linter if one exists
- Config/schema/spec/template changes → validate the changed surface (`ferrum-edge validate`, OpenAPI/schema checks, or targeted config/admin tests) and run Rust fmt/clippy only if Rust files changed

**Targeted by change scope:**
- Private fn in `src/` → `cargo test --lib <module>::tests`
- Public API → `cargo test --test unit_tests <filter>`
- Cross-module behavior → `cargo test --test integration_tests <filter>`
- Proxy hot-path change → `cargo build --bin ferrum-edge && cargo test --test functional_tests <filter> -- --ignored`

**Run the full suite locally only when:**
- Touching shared infrastructure (config types, plugin trait, pool, router, hot path)
- Refactoring across modules
- Pre-release / pre-merge if CI is congested

Otherwise: push and let CI's parallel matrix do the wide pass. CI is the gate, not the local machine.

### CI (GitHub Actions)

PRs: format → tests (parallel) → lint → perf regression → build 5 targets (Linux x86_64/ARM64, macOS x86_64/ARM64, Windows x86_64). All must pass to merge. Push to main: overwrite `latest` release + multi-arch Docker (Docker Hub + GHCR). Tag `v*`: versioned release + Docker tags. Required secrets: `DOCKERHUB_USERNAME`, `DOCKERHUB_TOKEN`. Repo Settings > Actions > Workflow permissions must be Read+Write.

## Architecture

### Operating Modes (`FERRUM_MODE`)

- `database` — R/W admin + proxy; PostgreSQL/MySQL/SQLite/MongoDB polling
- `file` — R/O admin + proxy; YAML/JSON, SIGHUP reload (Unix)
- `cp` (Control Plane) — R/W admin, **no proxy**, database + gRPC distribution
- `dp` (Data Plane) — R/O admin + proxy; gRPC from CP (multi-CP failover via `FERRUM_DP_CP_GRPC_URLS`)
- `mesh` — R/O admin + proxy; service-mesh data plane consuming xDS or native MeshSubscribe
- `injector` — Kubernetes admission webhook; emits JSON patches that add Ferrum mesh sidecars/init capture
- `node_agent` — per-node eBPF capture manager for ambient mesh; no proxy listeners
- `migrate` — runs DB migrations, exits

**TLS-only listeners**: port `0` on `FERRUM_PROXY_HTTP_PORT`/`FERRUM_ADMIN_HTTP_PORT`/inside `FERRUM_CP_GRPC_LISTEN_ADDR` disables plaintext. Excluded from `reserved_gateway_ports()`. Gateway warns if plaintext disabled and no TLS configured.

**Admin JWT asymmetry (intentional)**: the admin API only *validates* JWTs — it never mints them (operators pre-sign tokens externally). DB/CP require `FERRUM_ADMIN_JWT_SECRET` (≥32 chars) because their R/W admin API needs a stable, known secret so operator-minted tokens stay valid across instances and restarts. File mode is read-only, so it generates a random secret at startup — externally crafted tokens can never validate.

**`/health` DB check cached 15s via lock-free `ArcSwap`** (`AdminState.CachedDbHealthResult`). Endpoints unauthenticated; without caching an attacker could flood `SELECT 1` and exhaust `FERRUM_DB_POOL_MAX_CONNECTIONS` (default 32). Do not remove. Response includes `database.pool` stats when connected.

**`/metrics/runtime` JSON response cached via lock-free `ArcSwap`** (`runtime_metrics_cache()`). Endpoint is JWT-authenticated; without caching, aggressive polling would amplify system sampling and serialization work. Do not remove.

**`GET /cluster`** (JWT-auth): CP returns connected DPs (from `DpNodeRegistry`, auto-removed on stream drop via `TrackedStream`); DP returns CP connection state (from `DpCpConnectionState`, primary vs fallback, `last_config_received_at`).

### Core Design Principles

1. **Lock-free hot path** — `ArcSwap::load()` + `DashMap`. No `Mutex`/`RwLock` on proxy path.
2. **Zero-allocation hot path** — thread-local pool key buffers; `Arc<UpstreamTarget>` LB selection; response header `get_mut()` before key alloc; pre-populated status code DashMap.
3. **Pre-computed indexes** — `RouterCache`, `PluginCache`, `ConsumerIndex`, `LoadBalancerCache` rebuilt on reload, not per-request.
4. **Atomic config reload** — `ArcSwap` swap; in-flight requests see old or new, never partial.
5. **Resilience** — if config source unavailable, keep serving cached config.

### Startup

jemalloc (non-Windows) → CLI parse + env overrides (before `CONF_FILE_CACHE`) → rustls ring provider → tracing-subscriber non-blocking stdout → `validate` exits here → secret resolution (single-threaded rt, `std::env::set_var` is unsafe with concurrent threads) → `overload::raise_fd_limit()` (Unix only; raises `RLIMIT_NOFILE.rlim_cur` to `rlim_max`, never asks for privileges we don't have, no-op when denied) → `EnvConfig` parse → multi-threaded tokio → mode dispatch → SIGINT/SIGTERM via `watch::channel`.

**FD soft-cap raise**: `raise_fd_limit()` runs once after logging is up so the result reaches stderr/structured logs. We never attempt to raise the *hard* cap (it requires `CAP_SYS_RESOURCE`) — operators set the hard cap via `LimitNOFILE=` (systemd), `--ulimit nofile=` (Docker), or `/etc/security/limits.conf`. When the effective soft cap after startup is below `FD_HARD_LIMIT_PRODUCTION_FLOOR` (65,536), startup emits a single structured `warn!` with the suggested remediation and continues. Below the floor the gateway will still serve, but its 95% FD-critical threshold trips earlier under load.

Per serving mode: TLS policy → frontend TLS → admin TLS → DTLS → backend TLS validation → CP/DP gRPC TLS → stream port validation → stream listener bind (fatal in db/file, non-fatal in dp) → DNS warmup → connection pool warmup (if `FERRUM_POOL_WARMUP_ENABLED`) → overload monitor.

### TLS Rotation

Most file-based TLS materials are **static operational inputs**. Cert/key changes on disk are NOT picked up live (K8s Secrets, sidecar volumes, etc.). Rotation = **gateway restart / rolling redeploy**, except for the narrow cases below.

Narrow carve-out: when `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, mesh inbound `PeerAuthentication` mode changes and the frontend client CA verifier may be rebuilt on mesh slice apply for mesh HTTP/HBONE termination listeners AND mesh-shared TCP+TLS / UDP+DTLS stream listeners. TCP+TLS listeners snapshot the shared `rustls::ServerConfig` slot per accept; UDP+DTLS listeners hot-swap the per-server `FrontendDtlsConfig` on every active `DtlsServer`. Existing handshake-complete sessions keep their material until they end (rustls/dimpl consult the config only at handshake).

Narrow frontend cert/key carve-out: when `FERRUM_FRONTEND_TLS_LIVE_RELOAD_ENABLED=true`, the proxy HTTPS / H2 / HTTP/3 and admin HTTPS listeners watch their `FERRUM_FRONTEND_TLS_CERT_PATH` / `FERRUM_FRONTEND_TLS_KEY_PATH` and `FERRUM_ADMIN_TLS_CERT_PATH` / `FERRUM_ADMIN_TLS_KEY_PATH` files at a poll interval (`FERRUM_FRONTEND_TLS_WATCH_INTERVAL_SECONDS`, default 30s). On a validated change the watcher rebuilds the `rustls::ServerConfig` (re-running `enable_early_data` / `enable_secret_extraction_for_ktls` for the proxy frontend) and atomically swaps it into the listener's `SharedFrontendTls` `ArcSwap` slot; the H3 listener subscribes to a revision watch channel and re-applies a fresh `quinn::ServerConfig` via `Endpoint::set_server_config`. Rebuild failures (parse / expired / not-yet-valid / key mismatch) keep the previous config and emit a `warn!` — the gateway never serves a known-bad TLS config. In-flight TLS sessions keep their original `ServerConfig` (rustls reads it only during the handshake; swapping does not tear down live sessions). The DTLS frontend and operator-supplied per-proxy backend TLS paths remain static (restart required) under this flag; pre-bound listener tests (file-mode in-process harness) also stay on the startup config. Default is `false` — historic restart-required behavior is preserved.

Narrow backend carve-out: the `FERRUM_GATEWAY_SVID_CERT_PATH` / `_KEY_PATH` / `_TRUST_BUNDLE_PATH` files are watched for backend client SVID rotation. A validated reload updates the gateway SVID slot, preserves any CP-delivered trust-bundle override, bumps the backend `|svidg=<generation>` marker, drains old backend TLS config caches, restarts active HTTP health probes, and optionally force-drains old-generation pool entries after `FERRUM_MESH_SVID_ROTATION_DRAIN_SECONDS`. Lower-level in-memory producers (`RotationConfig.revision_tx` for Ferrum-as-issuer, `SvidFetchHandle::with_revision_tx` for SPIRE-agent workload-API) may also bind to `ProxyState.backend_svid_rotation_tx` in future flows. Backend CA bundles and ordinary operator-supplied backend client cert/key paths remain static startup inputs.

### Graceful Shutdown

SIGTERM/SIGINT → accept loops exit → drain (`OverloadState.draining=true`, `Connection: close` on responses, wait up to `FERRUM_SHUTDOWN_DRAIN_SECONDS` for `active_connections` + `active_requests` to reach zero via RAII guards; `Notify::notify_one()` on last drop) → 5s background cleanup → exit.

`RequestGuard` is embedded into `ProxyBody` via `with_request_guard()` on H1/H2/gRPC paths so it lives as long as hyper streams — critical for H2/gRPC streaming. H3 uses stack local. Tracks the real concurrency driver (1 H2 conn with 1000 streams = 1 conn + up to 1000 requests). `FERRUM_SHUTDOWN_DRAIN_SECONDS=0` disables drain.

### Overload Manager (`src/overload.rs`)

Progressive load shedding via atomic flags (`disable_keepalive`, `reject_new_connections`, `reject_new_requests`). Monitors FD, connections, requests, event-loop latency. Thresholds: FD ≥ 80% / Conn ≥ 85% / Req ≥ 85% → disable keepalive. FD ≥ 95% / Conn ≥ 95% / Loop ≥ 500ms → reject new connections. Req ≥ 95% → reject new requests (503 / gRPC UNAVAILABLE). `GET /overload` (unauth) returns pressure + `port_exhaustion_events`; 503 at critical. State transitions logged (warn enter, info recover) — no spam. RED probabilistic shedding between thresholds via golden-ratio hashing.

Hot atomics on `OverloadState` (`disable_keepalive`, `reject_new_connections`, `reject_new_requests`, `active_connections`, `active_requests`, `red_drop_probability`, `red_request_counter`) are wrapped in `crossbeam_utils::CachePadded` so the read-mostly action flags don't share a cache line with the `fetch_add`/`fetch_sub` counters — at multi-core accept rates this prevents coherence-traffic stalls on the hot accept path. Snapshot fields (`fd_current`, `conn_current`, etc.), `port_exhaustion_events`, and `draining` are NOT padded (written ≤ 1 Hz or only on rare events). `CachePadded<T>` derefs to `T`, so all `.load()` / `.fetch_add()` call sites compile unchanged — do not unwrap or re-shape these fields.

### External Secret Resolution

At startup, before config load. Env var suffixes resolve the base name: `_VAULT` (HashiCorp Vault KV v2), `_AWS` (Secrets Manager), `_AZURE` (Key Vault), `_GCP` (Secret Manager), `_FILE` (disk). Backends grouped per provider (one client). Conflict detection prevents two providers setting the same base key. See `src/secrets/`.

### Source Layout (pointers)

- `src/{main,cli}.rs` — CLI, mode dispatch, signals
- `src/admin/` — REST API + JWT middleware; `api_specs/` (extractor + handlers), `spec_codec.rs` (gzip + sha256)
- `src/config/` — `types.rs` (domain model), `env_config.rs` (90+ vars), `db_backend.rs` trait + `db_loader.rs`/`mongo_store.rs`, `file_loader.rs`, `migrations/`
- `src/modes/` — database/file/control_plane/data_plane/migrate; `src/modes/mesh/` — mesh mode (`mod.rs` runtime + plugin injection + materialization, `config.rs` data model, `slice.rs` per-node filtering, `policy.rs` authz evaluation, `hbone.rs` identity parsing, `dns_proxy.rs` transparent DNS, `runtime.rs` ArcSwap state, `config_consumer/` native + xDS clients); `src/modes/injector.rs` — K8s admission webhook
- `src/proxy/` — `mod.rs` (handle_proxy_request), `hbone_proxy.rs` (HBONE transport handler), `handler.rs`, `body.rs` (ProxyBody + Coalescing adapters), `grpc_proxy.rs`, `http2_pool.rs`, `tcp_proxy.rs`, `udp_proxy.rs`, `udp_batch.rs`, `sni.rs`, `stream_listener.rs`, `client_ip.rs`
- `src/plugins/` — `mod.rs` (trait + priorities), `utils/`, per-plugin files; `src/plugins/mesh/` — mesh plugins (authz, spiffe_identity, workload_metrics, Prometheus/OTel helpers)
- `src/grpc/` — `cp_server.rs`, `dp_client.rs`, `mesh_server.rs`, `mesh_registry.rs`; `src/http3/` — QUIC server + `Http3ConnectionPool`
- `src/{dtls,dns,notifications,secrets,tls,service_discovery}/` — `notifications/` is a reusable, plugin-agnostic notification layer (Slack/Teams/Discord/webhook channels + `${var}` templating + bounded-concurrency dispatch). Used by `src/plugins/proxy_alerts/`; reusable from non-plugin callers (overload manager, mesh policy enforcement, custom plugins) without depending on `proxy_alerts`. Schema: [docs/notifications.md](docs/notifications.md).
- Top-level utilities: `overload.rs`, `load_balancer.rs`, `health_check.rs`, `circuit_breaker.rs`, `retry.rs`, `pool/`, `connection_pool.rs`, `router_cache.rs`, `plugin_cache.rs`, `consumer_index.rs`, `config_delta.rs`, `date_cache.rs`, `lazy_timeout.rs`, `socket_opts.rs`, `tls_offload.rs`
- `custom_plugins/` — auto-discovered by `build.rs`; supports `plugin_migrations()`

### Mesh Mode Architecture (`src/modes/mesh/`)

Full docs: [docs/mesh.md](docs/mesh.md). Engineering invariants only below.

**Topologies** (`MeshTopology`): `Sidecar` (inbound 15006 mTLS + outbound 15001 capture), `Ambient` (HBONE 15008 + outbound 15001), `EastWestGateway` (SNI-routed passthrough on 15443), `EgressGateway` (mTLS inbound 15090 → external ServiceEntry backends). Topology drives which listeners spawn; all share the same proxy/plugin chain.

**Runtime state**: `ArcSwap<Option<MeshSlice>>` in `runtime.rs` — lock-free hot-swap, same pattern as `GatewayConfig`. `wait_for_first_slice()` blocks startup until the first valid slice arrives.

**Config consumption** (`config_consumer/`): `FERRUM_MESH_CONFIG_PROTOCOL=native` uses `MeshConfigSync.MeshSubscribe` gRPC; `xds` uses a standard ADS client (CDS/EDS/LDS/RDS/SDS, 25ms debounce). Both: jittered exponential backoff (1s→30s, ±25%), multi-CP failover via `FERRUM_DP_CP_GRPC_URLS`, JWT auth in metadata.

**PolicyScope filtering**: scope-aware mesh resources are filtered against workload namespace + labels via shared helpers (`policy_scope_applies_to_workload` / `scope_applies_to_workload`); do NOT fork those predicates. Single-winner precedence (`WorkloadSelector` > `Namespace` > `MeshWide`) applies only where the runtime resolves one effective setting, such as `PeerAuthentication` and `MeshProxyConfig`. `MeshPolicy` and `MeshRequestAuthentication` are additive after filtering, and `MeshTelemetryResource` merges per section.

**Mesh plugin injection** (`mod.rs::inject_mesh_global_plugins()`): auto-injects reserved-ID global plugins at slice-apply time: `__mesh_spiffe_identity` (940), `__mesh_authz` (2075), `__mesh_workload_metrics`, `__mesh_request_auth` (only when JWT rules present), `__mesh_access_log`. Operator-managed globals of the same type override mesh-injected ones.

**HBONE trust-domain gating** (`hbone.rs` + `mesh_authz`): HTTP/2 CONNECT over mTLS on port 15008. Baggage `source.principal` is rewritten onto the authz principal only when (a) the authenticated peer is on `mesh_authz`'s `trusted_hbone_assertors` allow-list AND (b) the baggage identity's trust domain matches the peer cert's or appears in `FERRUM_MESH_TRUST_DOMAIN_ALIASES`. Authenticated peers that are NOT trusted assertors keep their own peer-cert identity even when they carry baggage; the dropped baggage is surfaced as `mesh_authz.ignored_baggage.untrusted_assertor=true` in transaction logs (and contributes `mesh_authz.deny_policy=untrusted_assertor` when policy denies the resulting request). Trust-domain mismatches behave the same way with the existing `trust_domain_mismatch` reason. The trusted-assertor list defaults to the Istio ambient ztunnel/waypoint SAs (`["ztunnel", "waypoint"]`); operators with custom waypoint SA names (Gateway-managed waypoints often use `<gateway-name>` or `<gateway-name>-istio`) override via `FERRUM_MESH_TRUSTED_HBONE_ASSERTORS` (comma-separated; each entry is a bare service-account name OR a full `spiffe://...` id for exact-identity pinning). Configuring a `mesh_authz` global plugin with an explicit empty `trusted_hbone_assertors: []` disables baggage rewriting entirely. Fallback baggage key aliases enumerated in `HboneIdentity::from_headers()`.

**PeerAuthentication inbound mTLS**: by default, resolved once at startup from the initial slice. With `FERRUM_MESH_PEER_AUTH_LIVE_RELOAD_ENABLED=true`, only the resolved mTLS mode and frontend client CA verifier may hot-swap on slice apply; frontend cert/key paths remain static restart-required inputs. Coverage includes mesh HTTP/HBONE termination listeners AND mesh-shared TCP+TLS / UDP+DTLS stream listeners — `apply_mesh_inbound_tls_reload` publishes the swapped `ServerConfig` into the HBONE slot, the shared stream-listener TLS slot, and then walks every active `DtlsServer` to rebuild the `FrontendDtlsConfig`. A failed rebuild on any path keeps the previous config there and logs a warning (no rejection of the whole slice). `Disable` is rejected for Ambient and EgressGateway slice updates and keeps the last good config. See [docs/mesh.md](docs/mesh.md#peerauthentication).

**Authorization evaluation** (`policy.rs`): DENY rules first (first match wins). Any ALLOW rule + no match → implicit deny (Istio semantics). `RequestMatch` supports Istio-style conjunctive negative-match fields (`not_methods`/`not_paths`/`not_hosts`/`not_ports`) — a rule with `methods=[GET]` AND `not_paths=[/admin]` forms a single AND-block; do NOT split into separate DENY policies.

**Istio empty-rule semantics**: K8s translation must preserve `AuthorizationPolicy` action semantics. `ALLOW` with no `rules` is allow-nothing (emit a never-matching rule); `DENY`/`AUDIT` with no `rules` are no-ops. Do not collapse all empty-rule policies to the same representation.

**DestinationRule port-level settings**: `connectionPool.tcp.connectTimeout` lands on `Upstream.port_overrides[port].connect_timeout_ms` and is enforced by HTTP/H2/H3, gRPC, TCP, and HBONE dispatch. Per-port `loadBalancer` and `outlierDetection` land on the same slot and are enforced by HTTP-family / gRPC / WebSocket / HBONE dispatch via isolated per-port LB counters/hash rings and passive thresholds. `connectionPool.http.{maxRequestsPerConnection, idleTimeout, http2MaxRequests}` lands on `Upstream.port_overrides[port].{http_max_requests_per_connection, http_idle_timeout_ms, h2_max_concurrent_streams}` (top-level fan-out applies to every target port; per-port `portLevelSettings` overrides per-port). At dispatch, `resolve_effective_proxy_for_target` projects them onto `Proxy.pool_max_requests_per_connection`, `Proxy.pool_idle_timeout_seconds`, and `Proxy.pool_http2_max_concurrent_streams` on the owned clone; the direct H2 (`http2_pool.rs`) and gRPC (`grpc_proxy.rs`) builders consume the H2 cap via both `max_concurrent_streams` and `initial_max_send_streams`. `http_max_requests_per_connection` is wire-projected end-to-end but currently inert at runtime — hyper does not yet expose a close-after-N-requests builder knob. `connectionPool.tcp.maxConnections` and `connectionPool.tcp.tcpKeepalive` (`time`/`interval`/`probes`) land on `Upstream.port_overrides[port].max_connections` and `.tcp_keepalive`; top-level fan-out applies to every target port, per-port `portLevelSettings` overrides per-port. Both are enforced only on TCP / TCP+TLS / TCP-passthrough dispatch today — HTTP-family enforcement is a follow-on PR. `maxConnections` exhaustion returns `StreamSetupKind::BackendMaxConnectionsExceeded`; `tcpKeepalive` failures from `setsockopt` are logged and continue (best-effort). TCP/UDP/DTLS stream proxies enforce only `connect_timeout_ms`, `max_connections`, and `tcp_keepalive` per-port and use upstream-level LB/passive policy. Phantom ports (DR entries whose port isn't on any target) are skipped with a warning. Admin-API POST/PUT setting `Upstream.port_overrides` is rejected — canonical surface is a DestinationRule.

**Mesh materialization**: `materialize_east_west_gateway_proxies()` creates SNI-passthrough TCP proxies (east-west topology only). `materialize_egress_gateway_proxies()` creates HTTP-family proxies from ServiceEntries with `location: mesh_external` (egress topology only).

**Injector mode** (`src/modes/injector.rs`): K8s admission webhook (`POST /mutate`). Sidecar `runAsUser=PROXY_UID`, optional iptables init container (NET_ADMIN). IPv4/IPv6 capture CIDRs are partitioned into `iptables`/`ip6tables` blocks; `FERRUM_MESH_IP6TABLES_ENABLED=auto|true|false` controls IPv6 fan-out, and cleanup scripts must stay best-effort even when `ip6tables` is missing. SPIFFE ID: `spiffe://{trust_domain}/ns/{namespace}/sa/{service_account}`. JWT secret via `SecretKeyRef` (never plaintext). Opt-in: `ferrum.io/inject=true` or `ferrum.io/mesh=enabled`. Opt-out: `sidecar.istio.io/inject=false` or `ferrum.io/inject=false`.

### Domain Model (`src/config/types.rs`)

`GatewayConfig` → `Proxy`, `Consumer`, `Upstream`, `PluginConfig`. Each has `namespace` (default `"ferrum"`).

**Namespace isolation**: `FERRUM_NAMESPACE` controls what a gateway loads. DB queries filter by namespace; file mode filters post-deserialize. Admin API uses `X-Ferrum-Namespace` header. Uniqueness constraints (listen_path, proxy name, consumer identity, upstream name, listen_port) are per-namespace — same `listen_port` is safe across namespaces (OS bind catches real conflicts).

**Hostname normalization**: ASCII-lowercase at admission via `normalize_fields()` — `Proxy.hosts`, `Proxy.backend_host`, `UpstreamTarget.host`. Applied in every entry point (admin API, loaders, DP gRPC, restore). Downstream consumers rely on this — **do not re-lowercase** in DNS/pool/health/LB keys.

**`ApiSpec` is intentionally not in `GatewayConfig`** — it is admin-only metadata (one row per `(namespace, proxy_id)`), accessed via the `DatabaseBackend` trait surface from admin handlers only. `Proxy`/`Upstream`/`PluginConfig` carry an optional `api_spec_id: Option<String>` ownership tag (NULL for resources created via direct admin endpoints; set when extracted from a spec). PUT-replace and DELETE semantics depend on this tag — see "API Spec Management" below.

### Route Matching

Per host tier (exact host → wildcard → catch-all): exact-path routes first (`=/path`, O(1) HashMap lookup), prefix routes second (O(path_depth) via `IndexedPrefixRoutes` HashMap), regex routes third (O(path_length) via `IndexedRegexRoutes` `RegexSet` — single DFA pass regardless of pattern count), host-only fallback (`listen_path: None` + `hosts` set; never applies to catch-all tier).

**NEVER** replace prefix matching with O(n) linear scan; **NEVER** replace regex matching with sequential per-pattern — both caused 30-46% throughput degradation at scale. Router cache (`DashMap`) sized by `FERRUM_ROUTER_CACHE_MAX_ENTRIES` (default auto = `max(10_000, proxies × 3)`). Negative lookups cached to repel scanners.

Exact listen_paths (`=` prefix) match the whole path after query stripping. Regex listen_paths (`~` prefix) auto-anchored full-path (`^...$`). For prefix-style regex, end with `.*`. Helper: `anchor_regex_pattern()` in `src/config/types.rs`.

### Proxy `hosts`/`listen_path`/`listen_port` contract

- **HTTP-family** (`http`/`https`/`ws`/`wss`/`grpc`/`grpcs`/`h3`): route on hosts + listen_path. At least one of `hosts`/`listen_path` required. `listen_port` MUST be `None`.
- **Stream-family** (`tcp`/`tcp_tls`/`udp`/`dtls`): route on `listen_port`. `listen_path` MUST be `None` (hard error).

Host-only HTTP proxy matches all paths under its hosts; `strip_listen_path: true` is a no-op there. Exact listen_paths use `=/path`; prefix listen_paths use `/path`; regex listen_paths use `~pattern`. `hosts: []` + `listen_path: None` is rejected. Uniqueness: two HTTP proxies conflict iff same `listen_path` + overlapping `hosts` (empty hosts = catch-all, overlaps all). Host-only and path-carrying on same host coexist (different match tiers). See `DatabaseBackend::check_listen_path_unique()` in `src/config/db_backend.rs`.

**`backend_scheme` + runtime flavor**: HTTP-family proxies accept `http`/`https` and `backend_scheme` is optional (defaults to `https`). Stream-family (`tcp`/`tcps`/`udp`/`dtls`) requires an explicit scheme. gRPC and WebSocket are NOT schemes — they are runtime flavors classified per-request via `backend_dispatch::detect_http_flavor()` (one header lookup, zero allocation). A single `https` proxy serves Plain/gRPC/WebSocket traffic uniformly. HTTPS backends are classified out of band into the usable plain-HTTP buckets (`h1`, `h2_tls`, `h3`) plus the gRPC transport buckets (`h2_tls`, `h2c`).

**HTTP/3 frontend invariant**:
- Invariant: an H3 client can hit any `https` backend; native H3 backend dispatch is used only when the capability registry proves the concrete target supports H3.
- Touch points: `src/http3/`, `src/proxy/backend_capabilities.rs`, [docs/http3.md](docs/http3.md).
- Regression guard: H3 WebSocket (RFC 9220 Extended CONNECT) bridges to the same backend WebSocket transport and frame-plugin pipeline as H1/H2; the H3 frontend never speaks WebSocket directly to a backend. Gated by `FERRUM_HTTP3_WEBSOCKET_ENABLED`.

### Protocol-Level Request Validation

`check_protocol_headers()` in `src/proxy/mod.rs` runs on every inbound request. Rejects (400 unless noted): HTTP/1.0+TE, **CL+TE conflict** (RFC 9112 §6.1 smuggling), multiple CL/mismatched/empty-list-token Content-Length, multiple Host on H1/H2/H3, HTTP/2 and HTTP/3 TE values other than exactly non-empty `"trailers"` list members, non-numeric Content-Length, TRACE (405 XST defense), non-WS CONNECT (405). `check_host_authority_consistency()` rejects H2/H3 Host vs `:authority` disagreement before routing after scheme-default port normalization (`http`/`ws`: 80, `https`/`wss`: 443). Host/authority routing normalization strips valid ports for route lookup, preserves bracketed IPv6 literals, rejects unbracketed IPv6 literals, strips trailing dots, and lowercases ASCII. gRPC non-POST → gRPC error trailers. Invalid Sec-WebSocket-Key falls through as non-WS. WS Origin rejected 403 when `allowed_ws_origins` set.

CONNECT: H2 Extended CONNECT (RFC 8441) and H3 Extended CONNECT (RFC 9220), both with `:protocol=websocket`, are the only allowed CONNECT variants. Other Extended CONNECT protocols (`:protocol=connect-udp`, `:protocol=webtransport`, etc.) are rejected with 405. RFC 9220 §5 specifies that WebSocket frames over H3 MUST be unmasked (unlike RFC 6455 / RFC 8441 which mandate masked client-to-server frames); the gateway accepts unmasked H3 client frames and only emits unmasked frames on the H3 path — strict closing on a masked H3 frame (RFC 9220 §5 says SHOULD close with 1002) is a future-work follow-up. Response hop-by-hop filtering (RFC 9110 §7.6.1) strips `connection`/`keep-alive`/`proxy-authenticate`/`proxy-connection`/`te`/`trailer`/`transfer-encoding`/`upgrade` across all response paths. Smuggling verified safe: H2.CL downgrade (CL stripped, reqwest recalculates); TE.TE obfuscation (H1.0 rejects, H1.1 strips, H2/H3 validate non-empty `"trailers"` tokens, hyper lowercases); CL parser differentials (`42,`, `,42`, `4,,2`) reject before dispatch. See `protocol_validation_tests.rs`. hyper/h2/quinn already validate: method/header syntax, pseudo-header ordering, H2 frame/stream state, reset-stream abuse, QUIC packet format, WS frame/masking/close.

Frontend TLS/DTLS handshakes are bounded by `FERRUM_FRONTEND_TLS_HANDSHAKE_TIMEOUT_SECONDS` (default 10s, 0 disables) before HTTP header timers can start. Backend TLS/H2/gRPC/H3 handshakes are bounded by the per-proxy `backend_connect_timeout_ms` budget; this is an end-to-end connect budget, not only the TCP SYN phase. Frontend DTLS demux state is capped before allocating per-peer channels/tasks and released on handshake timeout; `/overload.stream_listeners.dtls_demux_sessions` exposes an eventually consistent pre-handshake diagnostic count for triage.

**Frontend TLS-before-backend invariant**:
- Invariant: every TLS/DTLS-terminating client-facing protocol completes frontend crypto/admission before backend dispatch.
- Touch points: HTTPS/H2/gRPC/WSS route only after TLS; normal H3 after QUIC/TLS; TCP+TLS after `on_stream_connect`; UDP+DTLS after `on_stream_connect`.
- Regression guard: frontend handshake failures and plugin rejects do not dial backend and do not trip backend circuit breakers.
- Exception: operator-enabled HTTP/3 0-RTT (`FERRUM_TLS_EARLY_DATA_METHODS`) is disabled by default, method-gated, and forwarded with `Early-Data: 1`.

### TLS/DTLS Passthrough

`passthrough: true` on stream proxies forwards encrypted bytes to backend without TLS/DTLS termination. Peeks at ClientHello for SNI (`src/proxy/sni.rs`). TCP: `TcpStream::peek()` then `bidirectional_copy`. UDP: parse first DTLS ClientHello for SNI; backend is plain UDP. Validation: stream proxies only, mutually exclusive with `frontend_tls`, backend TLS fields rejected. `StreamConnectionContext.sni_hostname` + `consumer_username` (from `effective_identity()`) flow to stream lifecycle plugins.

Plain TCP server-first protocols and passthrough may require different upstream timing; do not move terminating TLS/DTLS frontend paths to backend-first ordering without preserving the frontend-before-backend invariant and tests.

### TCP Bidirectional-Relay Modes (`src/proxy/tcp_proxy.rs`)

Splice/kTLS-splice/io_uring paths use the syscall fast path; userspace runs only when splice unavailable (non-Linux, TLS w/o kTLS, backend TLS-terminated).

Userspace modes: **fast path** (all relay bounds disabled: `FERRUM_TCP_IDLE_TIMEOUT_SECONDS=0`, `FERRUM_TCP_HALF_CLOSE_MAX_WAIT_SECONDS=0`, and per-proxy `backend_read_timeout_ms=0` / `backend_write_timeout_ms=0`) delegates to `copy_bidirectional_with_sizes` — best throughput, no BiLock overhead, but no idle/per-direction watchdog, no half-close cap, `disconnect_direction: unknown` on error. **Direction-tracking** (default, any bound non-zero) gives idle timeout + half-close cap + per-direction byte counters + first-failure attribution at ~5ns BiLock per r/w + two 4-64 KB buffers per conn. Pick fast path when upstream L4 LB enforces timeouts and throughput matters; stay on direction-tracking when self-hosted, enforcing backend inactivity, or dashboards consume `disconnect_direction`.

**`backend_read_timeout_ms` / `backend_write_timeout_ms`** on TCP relays: per-direction inactivity watermarks refreshed on read progress (b2c) or partial-write progress (c2b). The watchdog ticks every 1s when the shortest active timeout is below 30s, and every 5s when all active timeouts are 30s or longer, so the default 30,000 ms backend timeouts fire within ~35s. Chunked write loop refreshes on each partial progress — slow-but-progressing backends NOT misclassified. Schema allows `0` to disable for long-lived workloads (DB keepalives, SSH, IMAP). Splice/kTLS/io_uring paths rely only on `tcp_idle_timeout_seconds`.

### Stream Proxy Port Validation

Validation levels: config (`validate_stream_proxies()` + `validate_stream_proxy_port_conflicts()`); admin API (DB uniqueness + port probe, skipped in CP); startup reconcile (pre-bind; fatal in db/file, **non-fatal in DP** — prevents bad config from bricking DPs); runtime reconcile (never crashes). DP does NOT re-validate port conflicts on CP-pushed config (CP can't know each DP's reserved ports). Conflicts are detected at bind time — only the conflicting proxy is skipped.

### Plugin System

Priority order, lower = first. Multiple instances per proxy allowed. Each has `id`, `config`, optional `priority_override`. Scopes: `global` (all proxies), `proxy` (one, independent instance), `proxy_group` (subset via association list, **single shared instance** — stateful plugins like rate_limiting share counters; cascade-delete when no proxies remain). A proxy/group-scoped plugin replaces a same-named global; multiple scoped instances of the same type coexist.

**Lifecycle phases** (see `src/plugins/mod.rs` for `priority::*` constants, `docs/plugin_execution_order.md` for the protocol matrix):

1. `on_request_received` — tracing/CORS/termination/IP+geo/bot/spec_expose/spiffe_identity (940)/SSE validate/gRPC-Web/size+rate/tx_debug
2. `authenticate` — mTLS (950), JWKS (1000), JWT (1100), keyauth (1200), LDAP (1250), basicauth (1300), HMAC (1400)
3. `authorize` — ACL (2000), mesh_authz (2075), rate_limiting (2900)
4. `before_proxy` — SOAP WS-Security, AI cache/dedup/guards/federation, workload_metrics, request_transformer, serverless, response_mock, gRPC deadline, mirror, load_testing, response_caching, compression, ai_rate_limiter
5. `on_final_request_body` — body_validator (gRPC protobuf + JSON/XML after transformer), gRPC-Web validation
6. `after_proxy` — counterpart to before_proxy; rejects enforced on response path across HTTP/H3/gRPC
7. `on_final_response_body` — dedup + semantic cache store, size limiting, response_caching LRU uncacheable predictor
8. `on_response_body` — AI response guard, AI token metrics
9. `log` — stdout, statsd, http, tcp, kafka, loki, udp, ws, tx_debug, prometheus, chargeback, access_log
10. `on_ws_frame` — ws_message_size_limiting, ws_rate_limit, ws_frame_logging
11. `on_stream_connect`/`on_stream_disconnect` — TCP+TLS runs after handshake (client cert available); UDP+DTLS after DTLS handshake; mesh_authz and workload_metrics use SPIFFE/HBONE identity metadata here
12. `on_udp_datagram` — bidirectional hooks; zero overhead unless `requires_udp_datagram_hooks()`

**`mesh_authz` PolicyScope enforcement**: every `MeshPolicy` carries a `PolicyScope` — `MeshWide` / `Namespace { namespace }` / `WorkloadSelector { selector }`. In sidecar / ambient / east-west / egress-gateway topologies the plugin filters `slice.mesh_policies` at construction time (cold path) using `crate::modes::mesh::config::policy_scope_applies_to_workload(policy, proxy_namespace, proxy_labels)`; the request hot path then evaluates only the applicable subset. Without this filter, a namespace-scoped DENY in namespace `A` denies traffic for workloads in `B`, and a namespace- or workload-scoped ALLOW raises `saw_allow` for unrelated proxies and triggers implicit-deny on traffic other namespaces' policies already permit. Proxy identity (`namespace` + `labels`) flows in through one of: (1) the embedded `mesh_slice.namespace` / `mesh_slice.labels` (mesh-mode global plugin injection — the fields are pre-populated by `MeshSlice::from_gateway_config` from `MeshRuntimeConfig.namespace` + `FERRUM_MESH_WORKLOAD_LABELS`), (2) explicit `namespace` / `labels` JSON config keys on the plugin (direct configuration / tests), or (3) both, with explicit fields overriding the slice. The same `policy_scope_applies_to_workload` helper is used by `MeshSlice::from_gateway_config` so xDS / native MeshSubscribe slice construction and the plugin filter cannot drift. Empty `WorkloadSelector` (`labels: {}`, `namespace: None`) intentionally matches any workload. **Node-waypoint topology is the exception**: one listener serves many pods, so a single proxy identity does not fit the slice-level filter. `inject_mesh_global_plugins` sets `per_pod_policy_scoping: true` on the mesh_authz instance and the construction-time filter is skipped; the request path instead reads `ctx.node_waypoint_policy_scope` (an `Arc<PolicyScopeCache>` stamped by the connection admit path alongside `ctx.node_waypoint_pod_uid` from `NodeWaypointIdentityResolver`) and filters policies via `PolicyScopeCache::policy_applies`, which delegates to the same canonical helper so semantics stay identical. Missing scope retains mesh-wide policies only — namespace/selector-scoped policies are withheld until the resolver has the pod's workload metadata, and the fallback emits `ctx.metadata["mesh_authz.scope_missing"] = "true"` so transaction logs surface the race window. Slice apply stages the workload SPIFFE scope index before config validation, publishes it only after `proxy_state.update_config` accepts the matching plugin cache, and recomputes the pod UID map from current identities while holding the scope-update lock so rejected slices and concurrent identity churn stay side-effect free.

**Istio empty-rule semantics**: Kubernetes translation must preserve `AuthorizationPolicy` action semantics. `ALLOW` with no `rules` is allow-nothing (emit a never-matching rule so the authz engine's implicit deny applies); `DENY`/`AUDIT` with no `rules` are no-ops. Do not collapse all empty-rule policies to the same representation.

**Multi-auth**: `AuthMode::Multi` accepts `ctx.identified_consumer` OR `ctx.authenticated_identity` (JWKS/OIDC). First-success-wins. Empty chain → reject.

**`auth_method` tracking**: `ctx.auth_method` (`Option<&'static str>`) is set by `run_auth_impl()` on the first successful auth plugin (e.g., `"jwt_auth"`, `"key_auth"`, `"mtls_auth"`). Stream protocols set it in `mtls_auth::on_stream_connect()`. Flows to `TransactionSummary.auth_method` and `StreamTransactionSummary.auth_method` across all protocols (HTTP/1.1, H2, H3, gRPC, WebSocket, TCP, UDP/DTLS). `&'static str` avoids allocation — all values are compiled-in literals from `AuthMechanism::mechanism_name()`. Serialized with `skip_serializing_if = "Option::is_none"` so unauthenticated requests don't bloat logs.

**Multi-credential rotation**: Each credential type is stored as an array. `Consumer::credential_entries(cred_type)` returns object entries from that array. Index-based (keyauth, mtls) inserts all in `ConsumerIndex` (O(1)); secret-based (jwt, basicauth, hmac) iterates (typically 1-2). `FERRUM_MAX_CREDENTIALS_PER_TYPE` (default 2). Admin: `PUT /consumers/:id/credentials/:type` replaces the array; `POST /consumers/:id/credentials/:type` appends one entry; `DELETE .../:index` removes one entry.

**gRPC rejection normalization**: Plugin rejects for `application/grpc` → trailers-only gRPC errors.

**Body buffering**: Two-tier — `PluginCache.requires_request/response_body_buffering()` (O(1) upper bound) then per-request `should_buffer_*_body(&RequestContext)`. gRPC: `GrpcBody::Streaming(Incoming)` when no body plugins + no retries; `Buffered(Full<Bytes>)` otherwise.

**CRITICAL — `before_proxy(ctx, headers)`**: always read headers from the `headers` parameter, NEVER from `ctx.headers`. When no plugin sets `modifies_request_headers() == true`, the handler `std::mem::take()`s headers out of `ctx.headers` — `ctx.headers` is empty during this phase. Only this phase has this quirk.

**External identity**: `ctx.authenticated_identity` is first-class across rate-limit/cache keys, log summaries, backend identity-header injection. **Response mock path scoping**: `response_mock` strips the proxy's prefix `listen_path` before rule matching (no stripping for root/regex/exact listen_paths).

### Transaction Summary Fields

`TransactionSummary` (HTTP/gRPC/WS) and `StreamTransactionSummary` (TCP/UDP) in `src/plugins/mod.rs`. Both carry `auth_method: Option<&'static str>` identifying which authentication mechanism succeeded (e.g., `"jwt_auth"`, `"key_auth"`, `"mtls_auth"`, `"basic_auth"`, `"hmac_auth"`, `"ldap_auth"`, `"jwks_auth"`). `None` for unauthenticated requests. `WsDisconnectContext` also carries `auth_method` for WebSocket lifecycle plugins. HTTP path has body-streaming fields (`body_error_class`, `body_completed`, `bytes_streamed`) — populated fully only after a forthcoming `DeferredTransactionLogger`. Stream path has disconnect-attribution fields (`disconnect_direction`: `ClientToBackend`/`BackendToClient`/`Unknown`; `disconnect_cause`: `IdleTimeout`/`RecvError`/`BackendError`/`GracefulShutdown`). Error classifiers: `classify_reqwest_error`, `classify_grpc_proxy_error`, `classify_boxed_error`, `classify_http2_pool_error`, `classify_http3_error`.

**Metadata redaction**: Both summaries' `metadata: HashMap<String, String>` fields are sanitized at serialize time via `plugins::utils::metadata_redaction::serialize_redacted_metadata` (wired through `#[serde(serialize_with = ...)]`). Any key whose lowercased form contains a substring from `DEFAULT_SENSITIVE_METADATA_KEYS` (`authorization`, `cookie`, `set-cookie`, `x-api-key`, `x-auth-token`, `x-csrf-token`, `bearer`, `password`, `secret`, `token`) — or any operator-supplied substring from `FERRUM_LOG_REDACT_METADATA_KEYS` (comma-separated) — has its value replaced with `[REDACTED]` before going to any logger sink (stdout, http, tcp, kafka, loki, udp, ws, statsd). The in-memory map is untouched, so other plugin phases still see the original. New loggers do NOT need to redact themselves — they get redaction for free as long as they serialize `TransactionSummary` / `StreamTransactionSummary` through serde. Custom plugins that stash credentials, session IDs, or correlation tokens in `ctx.metadata` therefore cannot accidentally leak them through transaction logs.

**Customizable output schema** (`src/plugins/utils/log_schema/`): operators can shape the JSON / line-protocol output of every logging plugin via a per-plugin `schema:` block (or `schema_ref:` against a named `transaction_log_schema` plugin). Supports rename, omit, reorder, static fields, derived fields (`status_class`, `backend_host`, `summary_kind`, `outcome`), metadata flatten/omit, and timestamp format conversion. Implemented as a `serde::Serialize` wrapper (`SchemaView<'a, T: SchemaSerializable>`) — zero allocation when no schema is configured, byte-for-byte identical to native serialization on the default path. Metadata redaction always applies, on every path (rename of `metadata`, flatten with prefix, etc.). `transaction_log_schema` is restricted to `PluginScope::Global` and is constructed first during plugin-cache rebuild so subsequent plugins can resolve `schema_ref:` against the new state. Non-shipping plugins (`prometheus_metrics`, `api_chargeback`, `transaction_debugger`) reject `schema:` / `schema_ref:` at construction. Field-registry drift is caught by `tests/integration/log_schema_registry_tests.rs`. Full reference: [docs/log_schema.md](docs/log_schema.md).

### DNS Cache (`src/dns/mod.rs`)

Shared singleton; pre-warmed. Native TTL by default, floored by `FERRUM_DNS_MIN_TTL_SECONDS`. Stale-while-revalidate + background refresh at `FERRUM_DNS_REFRESH_THRESHOLD_PERCENT` of TTL (90%). Priority: per-proxy `dns_cache_ttl_seconds` > `FERRUM_DNS_TTL_OVERRIDE_SECONDS` > native. Failed retries via background task. TCP fallback for truncated UDP. Concurrent nameserver races (`FERRUM_DNS_NUM_CONCURRENT_REQS`). **`DnsCacheResolver` must be plugged into every `reqwest::Client` in production.**

### Centralized Rate Limiting (Redis)

Four rate plugins (`rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`, `udp_rate_limiting`) support `sync_mode: "redis"`. Shared client in `src/plugins/utils/redis_rate_limiter.rs`. Algorithm: two-window weighted via pipelined `INCR`/`GET`/`EXPIRE` — no Lua. Keys `{prefix}:{rate_key}:{window_index}`; default prefix `{FERRUM_NAMESPACE}:{plugin_name}` prevents cross-gateway collisions. Auto-fallback to in-memory on outage + background reconnect. TLS via `rediss://` uses global `FERRUM_TLS_*`. Works with Redis/Valkey/DragonflyDB/KeyDB/Garnet.

**ACL credentials**: `redis_username` / `redis_password` plugin fields are honored on both plain and TLS code paths — they are injected into the parsed `redis::ConnectionInfo` (via `set_username` / `set_password`) before the client connects, and used by both the main connection and the background health-check pinger. Explicit fields override any user-info embedded in `redis_url`; with both unset, URL-embedded credentials flow through unchanged.

### API Spec Management (admin-only metadata)

Full docs: [docs/api_specs.md](docs/api_specs.md). Operators submit OpenAPI 2.0/3.0.x/3.1.x/3.2.x docs (JSON/YAML) with `x-ferrum-proxy` (required), `x-ferrum-upstream`, `x-ferrum-plugins` extensions. Handler extracts native Ferrum resources, validates, persists transactionally, stores original gzip-compressed. Endpoints: `POST/PUT/GET/DELETE /api-specs[/{id}]`, `GET /api-specs/by-proxy/{proxy_id}`, `GET /api-specs`. Mode behavior: db/cp = read+write; dp/file = both endpoints reject.

**Hot-path invariant — `api_specs` is admin-only metadata, NEVER loaded by gateway runtime.** Required guards:
- Not a `GatewayConfig` field — would put 25 MiB+ blobs through `ArcSwap` and polling loop
- Not in `src/config/db_loader.rs` `load_*` / poll path
- Not in `src/grpc/cp_server.rs` `broadcast_update` — DPs never see specs
- Not added to any periodic refresh, snapshot, or runtime cache

Specs are admin-API on-demand only. Adding them to any runtime path is a regression. Integration test: `tests/integration/admin_db_api_specs_tests.rs`.

**Validation reuse — do NOT fork the admit path.** Spec-extracted resources go through identical validators to direct admin POSTs (`Proxy::normalize_fields()`, `validate_fields()`, `plugins::validate_plugin_config()`, uniqueness checks). See `extract_and_validate()` in `src/admin/api_specs/handlers.rs`.

**Ownership model**: nullable `api_spec_id` column on `proxies`/`upstreams`/`plugin_configs`. PUT `/api-specs/{id}` deletes spec-owned resources (`WHERE api_spec_id = {id}`) and re-inserts; hand-added resources (api_spec_id NULL) survive. DELETE cascades via FK on proxy; spec-owned upstream cleaned manually (no FK on back-link by design).

**Forbidden in specs** (rejected in `src/admin/api_specs/extractor.rs`): `x-ferrum-consumers` (use `POST /consumers`), plugin `scope != proxy`, plugin `proxy_id != spec proxy.id`, embedded credential keys (recursive walk on `config` value, NOT the plugin name — a `jwt` plugin with normal config is fine).

**Idempotent PUT**: `replace_api_spec_bundle` compares `resource_hash` (sha256 of resource fields, excluding `api_spec_id`/`created_at`/`updated_at`). On match, only the `api_specs` row updates; `updated_at` on `proxies`/`upstreams`/`plugin_configs` does NOT advance — polling cycle does not trigger router/plugin cache rebuild, pool warmup, capability refresh, or DP broadcast. When changing the hash function, update `replace_api_spec_bundle` in `db_loader.rs` and `mongo_store.rs` together.

**Storage caps**: body submit cap is `FERRUM_ADMIN_SPEC_MAX_BODY_SIZE_MIB` (default 25). MongoDB additionally bounded by BSON 16 MB doc limit — operators with >~14 MiB compressed specs should use a SQL backend. MongoDB multi-doc atomicity requires `FERRUM_MONGO_REPLICA_SET`.

## Test Structure

```
tests/{unit_tests,integration_tests,functional_tests,conformance_tests}.rs   # Entry points
tests/unit/{config,plugins,admin,gateway_core}/
tests/{integration,functional,performance,conformance}/    # functional tests are #[ignore]
```

### Test Placement — follow exactly

- Private fns/structs → `#[cfg(test)] mod tests` **inline** in source (tests/ is separate crate, can't see non-`pub`)
- Public API → `tests/unit/<category>/<module>_tests.rs`
- Component interaction → `tests/integration/`
- Full binary E2E → `tests/functional/` with `#[ignore]`; requires `cargo build --bin ferrum-edge`
- Istio + xDS compatibility matrix coverage → `tests/conformance/<category>.rs` (registers `(category, feature, status)` via `register_feature!`; the end-of-suite reporter emits `target/conformance/coverage.{json,md}`). See [CONFORMANCE.md](CONFORMANCE.md#istio--xds-conformance-suite).

Inline `#[cfg(test)]` modules are intentional — do NOT promote fns to `pub` to enable external tests. Files with inline tests: `adaptive_buffer.rs`, `overload.rs`, `load_balancer.rs`, `router_cache.rs`, `config/mongo_store.rs`, `grpc/cp_server.rs`, `proxy/udp_proxy.rs`, `secrets/{env,file,mod}.rs`, `service_discovery/{consul,kubernetes}.rs`.

New test file in `tests/unit/`: create file + add `mod <name>;` to `tests/unit/<category>/mod.rs`.

### Functional Test Rules

- **`Stdio::null()` for gateway stdout/stderr** unless read. `Stdio::piped()` without reading deadlocks on buffer fill.
- **Port allocation MUST retry**: bind-drop-rebind races with other parallel tests that can steal the port between drop and gateway bind (gateway fails silently with `Stdio::null()`).
- **Pool warmup vs backend-hit assertions** — `FERRUM_POOL_WARMUP_ENABLED=true` (production default) makes the gateway issue a `HEAD /` to every backend at startup, which throws off `received_requests().len()` / `accepted_connections()` assertions by exactly one. Set `FERRUM_POOL_WARMUP_ENABLED=false` in any test that counts backend hits. Conversely, tests that depend on the capability registry having a `Supported` entry before traffic flows (H3 native pool, direct H2 pool routing) REQUIRE warmup `true` — without it the first request lands while the registry is still empty. See `tests/scaffolding/harness.rs` rustdoc for the full rule of thumb.

Use struct harness with `try_new()` retry wrapper (killing gateway on `wait_for_health` failure) OR a `start_gateway_with_retry()` helper. Rules: fresh ports + fresh temp dirs/DBs every retry (reusing killed SQLite can corrupt WAL); backend/echo server holds listener — don't drop+rebind, pass pre-bound `TcpListener` to `start_echo_server_on()`; `wait_for_health` returns `bool`/`Result`, never panic.

## Development Guidelines

### Code Quality Rules

**Production Rust:**
- No `.unwrap()` / `.expect()` in production code. Tests are exempt. Prefer `?`, explicit error handling, or documented invariants.
- Avoid `unwrap_or`-style fallbacks when they could hide real configuration, parsing, or I/O failures — log a `warn!` before `.unwrap_or_default()` when a fallback is genuinely desired.
- No panics on the proxy request path. Return errors.

**Hot path:**
- No `format!()` or avoidable allocation in hot loops.
- No global `Mutex` / `RwLock` on the proxy hot path.
- Prefer `ArcSwap` snapshots for read-mostly state.
- Use `DashMap` only for concurrent mutable maps.
- New hot-path `DashMap` construction must go through `crate::util::sharding::pool_shard_amount(env_config.pool_shard_amount)`.

**Schemas:**
- Backward-compatible optional field additions must use `#[serde(default, skip_serializing_if = "<pred>")]`.
- Required new fields need a migration/versioning plan.
- Check parent structs for `#[serde(deny_unknown_fields)]` before adding fields.

**Configuration:**
- New `FERRUM_*` env vars require updates to `docs/configuration.md` and `ferrum.conf`.
- Update config tests/examples where applicable.

**Pool keys:**
- Use `|` as the delimiter, never `:`.
- Ensure key components cannot contain `|`, or escape/encode them before joining.

**Admin API / OpenAPI parity:**
- Admin API request/response changes (new endpoints, fields, status codes) and any new plugin must be reflected in `openapi.yaml`. UI integrations consume that spec — drift silently breaks downstream tooling.

**Injector / Kubernetes admission:**
- Changes touching `src/modes/injector.rs` require review for webhook body-size limits, SSRF exposure, Kubernetes `AdmissionReview` shape, UID echoing, `status` / `allowed` behavior, and JSONPatch correctness.

**Security:**
- Always set `validation.validate_exp = true` on JWT verification.
- Escape user input when interpolating into JSON/XML response bodies.

### TLS Architecture

**Backend CA trust chain**: proxy `backend_tls_server_ca_cert_path` → global `FERRUM_TLS_CA_BUNDLE_PATH` → webpki/system roots. Opt-out via `backend_tls_verify_server_cert: false` or `FERRUM_TLS_NO_VERIFY=true`. The proxy backend path always passes a fully-built `rustls::ClientConfig` to reqwest via `use_preconfigured_tls(...)`, so the trust store is constructed in-house from `RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS)` regardless of platform.

**CA exclusivity**: custom CA = sole trust anchor (no webpki mixing). When adding new paths with custom CA: reqwest → `.tls_certs_only([cert])` (replaces the trust store wholesale; sole API since reqwest 0.13 — older `.tls_built_in_root_certs(false) + .add_root_certificate(cert)` was removed); rustls → `RootCertStore::empty()`.

**reqwest "rustls" feature trust roots (no-custom-CA paths only)**: since reqwest 0.13 the bundled `rustls` feature ships `rustls-platform-verifier` instead of `webpki-roots`. Verifier resolution: macOS keychain → Windows cert store → webpki bundled fallback on Linux. This affects only the *helper* clients that don't preconfigure TLS — `health_check.rs`, `plugins/utils/http_client.rs`, `plugins/spec_expose.rs` — and only when no `FERRUM_TLS_CA_BUNDLE_PATH` / per-plugin CA is configured. Production deploys (Linux containers) see no behaviour change. macOS/Windows operators running the gateway locally will pick up roots from their OS keychain on those paths.

**Startup validation**: per-proxy TLS paths validated by `validate_all_fields_with_ip_policy()` at config load. File = refuse to start; DB = warn; DP = reject update, keep cached. No silent fallback.

**Cert expiration** (`check_cert_expiry()` in `src/tls/mod.rs`): all surfaces check `notBefore`/`notAfter`. Expired = hard failure. Warning within `FERRUM_TLS_CERT_EXPIRY_WARNING_DAYS` (default 30).

**CRL** (`FERRUM_TLS_CRL_FILE_PATH`): PEM, loaded once, `Arc`-shared. Applied to frontend mTLS (H1/H2/H3/DTLS), all 6 rustls backend paths, and rustls-based logging sinks (`tcp_logging` TLS, `ws_logging` wss, `udp_logging` DTLS). NOT applied to DP→CP gRPC (tonic-managed) or reqwest-based plugin paths (reqwest exposes no CRL config). Restart to reload — no hot reload for any TLS surface.

**Pool-per-cert-path**: reqwest paths (HTTP/1.1, H2 via reqwest, H3 frontend→backend) → distinct `reqwest::Client`. rustls paths (gRPC pool, H2 direct) → per-connection.

**Non-rustls paths**: `kafka_logging` (librdkafka/OpenSSL) — `FERRUM_TLS_CA_BUNDLE_PATH`→`ssl.ca.location`, `FERRUM_TLS_NO_VERIFY`→`enable.ssl.certificate.verification=false` (plugin fields override; CRL via `producer_config.ssl.crl.location`). `redis` applies global flags via `PluginHttpClient` accessors. Logging sinks built on rustls (`tcp_logging` TLS, `ws_logging` wss, `udp_logging` DTLS) now apply the gateway CRL list via `PluginHttpClient::tls_crls()` → `build_server_verifier_with_crls`.

**`PluginHttpClient` limits**: plugins bypassing proxy dispatch (`ai_federation` "terminate and respond") use shared `PluginHttpClient` with global TLS only — no per-proxy CA/CRL/cipher. For private endpoints, add internal CAs to global bundle (include public roots too since CA exclusivity disables webpki).

### Performance Rules

- No per-request allocations when avoidable — use pre-computed indexes. Static headers (Alt-Svc) pre-computed in `ProxyState`.
- No locks on hot path — `ArcSwap::load()` + `DashMap` only.
- Pre-compute at config reload (indexes, hash rings, plugin metadata flags like `requires_response_body_buffering`).
- No `format!()` in hot loops — pool keys use `write!()` into thread-local `String` buffers (zero-alloc on cache hits, 99%+).
- `Arc` shared read-only data — `LoadBalancer.targets: Vec<Arc<UpstreamTarget>>`, selection = atomic increment (~5ns) not clone (~200-500ns).
- Streaming by default — buffer only when a plugin requires it. Small-response eager buffer via `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` (64 KiB) when CL known — single `bytes().await` beats coalescing adapter for JSON. SSE always streams. `SizeLimitedStreamingResponse` enforces limit frame-by-frame when CL absent.
- `ProxyBody`-backed response coalescing uses one generic `Coalescing<S: FrameSource>` adapter in `src/proxy/body.rs` with three pluggable sources (`ReqwestFrameSource` for H1/H2-via-reqwest, `Incoming` for direct H2 / gRPC pool, `H3FrameSource` for native H3). Each path calls a thin builder (`coalescing_body`, `coalescing_h2_body`, `coalescing_h3_body`) over the shared adapter — there is no separate H1/H2/H3 `ProxyBody` coalescer to keep in sync. The H3 frontend cross-protocol bridge is separate (`src/http3/cross_protocol.rs`) because it writes directly to QUIC streams, but it shares the H3 coalescing knobs. Per-protocol bounds differ because native frame sizes differ: `FERRUM_HTTP3_COALESCE_MIN/MAX_BYTES` clamp to `[H3_COALESCE_MIN_FLOOR=1 KiB, H3_COALESCE_MAX_CAP=1 MiB]` (H3 framing is QUIC-packet-sized), `FERRUM_H2_COALESCE_TARGET_BYTES` clamps to `[16 KiB, 1 MiB]` (matches RFC 9113 default frame size). Latency-tracked H1/H2 paths inherit the same coalescing by composing `base_body.into_tracked(baseline)` over the regular streaming dispatch — no parallel "tracked" body builders.
- Skip plugin phases when empty — guard with `plugins.is_empty()`.
- **Every `reqwest::Client::builder()` must call `.dns_resolver(Arc::new(DnsCacheResolver::new(dns_cache.clone())))`**. No production path should fall back to system DNS.
- **Hot atomics use `CachePadded`** — see "Overload Manager" above. Co-locating a read-mostly action flag with a write-heavy counter on the same cache line forces inter-core coherence traffic on every load, turning a free atomic read into a pipeline stall under sustained load. Apply the same treatment to any new accept/dispatch-path atomic that is read concurrently with a hot writer.

### Protocol Paths

- **HTTP/1.1**: hyper → reqwest via `ConnectionPool`. Streaming default.
- **HTTP/2**: hyper (ALPN) → reqwest or `Http2ConnectionPool` (sharded H2 senders). Streaming default.
- **HTTP/3**: quinn/h3 → `Http3ConnectionPool`. Streaming via `coalescing_h3_body` (shared `Coalescing<H3FrameSource>`) / `direct_streaming_h3_body`.
- **gRPC**: hyper (content-type) → `GrpcConnectionPool` (sharded H2). Request + response streaming via `coalescing_h2_body` (shared `Coalescing<Incoming>`).
- **WebSocket**: hyper upgrade or H2 Ext CONNECT → direct TCP upgrade; persistent, frame-by-frame.
- **TCP**: `TcpListener` → `TcpStream::connect`; 1:1. `splice(2)` on Linux (plain + kTLS) else `copy_bidirectional`.
- **UDP**: `UdpSocket` → per-session socket, session-keyed. GSO-batched send on Linux.

Dispatch in `src/proxy/mod.rs`: `detect_http_flavor(&req) -> HttpFlavor::{Plain, Grpc, WebSocket}` classifies the request once (shared with the H3 frontend). Backend selection uses `Proxy.dispatch_kind: DispatchKind` (pre-computed at config load via `GatewayConfig::resolve_dispatch_kind()` — variants: `HttpPool`, `HttpsPool`, `TcpRaw`, `TcpTls`, `UdpRaw`, `UdpDtls`) plus the backend capability registry keyed by real backend target identity. Plain HTTPS requests prefer native H3 when the target is classified as `h3`, else the direct H2 pool when classified as `h2_tls`, else reqwest. Streaming vs buffered: two-tier check + `proxy.retry.is_some()`.

**H3 frontend architecture** (`http3/server.rs`, standalone QUIC server). Backend dispatch branches on `(backend capability, http_flavor)`:
- `Plain + backend classified as h3` — native H3 fast path via `Http3ConnectionPool` (quinn/h3), fully streamed.
- `WebSocket` — RFC 9220 Extended CONNECT bridge (`http3::websocket::handle_h3_websocket`) to the same backend WebSocket transport and frame-plugin pipeline as H1/H2.
- Everything else — cross-protocol bridge `http3::cross_protocol::run` reuses `state.connection_pool` (reqwest) / `state.grpc_pool`, so one `https` proxy serves H1/H2/H3 clients uniformly.
- Cross-protocol buffering: request body buffered (`&mut RequestStream` can't be captured by reqwest's `'static` body), response streamed with the same coalesce window as the native H3 writer. gRPC trailers forwarded via `send_trailers` on both buffered and streaming responses.
- **RFC 8470 0-RTT signalling**: when a request arrives via TLS 1.3 0-RTT (quinn `into_0rtt()`, `ctx.is_early_data == true`) the gateway strips any client-supplied `Early-Data` header from the inbound request and re-injects `Early-Data: 1` on the outbound backend request — `build_h3_backend_headers` (native H3 backend), `build_plain_request_builder` / the gRPC bridge `HeaderMap` (cross-protocol), and the H3 WebSocket bridge all preserve this contract. The gateway already gates 0-RTT acceptance via `state.early_data_methods`; the header lets the origin server apply its own replay-safety policy on top.

**QUIC connection migration**: `http3/server.rs` compares `remote_address()` per request (zero-alloc integer compare). `Arc<str>` re-created only on actual change. Fixes a security issue where migrated clients bypassed per-IP rate limits — do NOT revert to once-per-connection cache.

**gRPC proxy**: hyper H2 direct (not reqwest) to preserve trailers. `GrpcBody::Buffered | Streaming` sum type; streaming forwards `Incoming` frame-by-frame when no body plugins + no retries, bounded by H2 window. Response wrapped in `coalescing_h2_body` (`Coalescing<Incoming>`, 128 KB target, trailer-safe — stashes gRPC trailers while flushing buffered data) when streaming — up to +35% at 5MB.

### Connection Pool Keys

Shared shell in `src/pool/mod.rs`; per-pool key formats below. Key must include every field affecting connection identity (destination, TLS trust, client credentials, DNS routing). Missing field = pool poisoning; extra = fragmentation. `|` delimiter (IPv6 colons would be ambiguous).

- **HTTP** (`connection_pool.rs`): `{dest}|{proto}|{dns_override}|{subset}|{ca}|{mtls_cert}|{mtls_key}|{sni}|{san_digest}|{verify}|{svid_generation}` — `dest` is `u={upstream_id}` or `d={host}:{port}`; `subset` is `proxy.upstream_subset` (empty when unset)
- **gRPC** (`proxy/grpc_proxy.rs`): `{host}|{port}|{tls}|{dns_override}|{subset}|{ca}|{mtls_cert}|{mtls_key}|{sni}|{san_digest}|{verify}|{svid_generation}` + shard `#N` — `tls` from `matches!(backend_scheme, Some(BackendScheme::Https))`; gRPC pool entered at runtime by content-type, not by scheme
- **HTTP/2** (`proxy/http2_pool.rs`): `{host}|{port}|{dns_override}|{subset}|{ca}|{mtls_cert}|{mtls_key}|{sni}|{san_digest}|{verify}|{svid_generation}` + shard `#N` (always TLS)
- **HTTP/3** (`http3/client.rs`): `{host}|{port}|{index}|{dns_override}|{subset}|{ca}|{mtls_cert}|{mtls_key}|{sni}|{san_digest}|{verify}|{svid_generation}`. `pool_key_for_target(proxy, host, port, idx)` takes `&Proxy` so retry/probe paths include the same backend identity fields. Backend capability keys remain a protocol-classification key and use the static SVID-generation marker; rotation is handled by pool-key partitioning.

The `subset` field partitions backend pools by DestinationRule subset so two proxies that share `(host, port, dns_override)` but select different subsets (each carrying distinct `trafficPolicy.tls`) cannot share a connection even when their TLS material happens to be byte-identical. Subset-level TLS overlay is projected onto `Proxy.resolved_tls` by `GatewayConfig::resolve_upstream_tls` from each upstream's `resolved_subset_tls` map; the `subset` key field is a defense-in-depth backstop on top of that TLS partitioning.

Rules: never add policy fields (timeouts, pool sizes, keepalives); empty/default strings are free; keep `|` delimiter.

**Pool DashMap shard sizing**: every pool's hot-path `DashMap` (entries, pending_creations, rr_counters, DNS cache, `per_ip_request_counts`, router prefix/regex cache) is built via `DashMap::with_shard_amount()` resolved through `crate::util::sharding::pool_shard_amount(env_config.pool_shard_amount)` — default auto-derives `next_power_of_two(max(64, num_cpus * 16))`. DashMap's default of `4 * num_cpus` starves writes at high cardinality. New hot-path `DashMap::new()` callers must mirror this; low-cardinality maps (`health_check`, `circuit_breaker`, plugin-internal) stay at the default.

**Policy cross-proxy sharing**: Because pool keys exclude policy fields, proxies resolving to the same entry share the underlying `reqwest::Client`. Both `backend_connect_timeout_ms` and `backend_read_timeout_ms` are applied per-request on the dispatch side (`RequestBuilder::connect_timeout()` and `RequestBuilder::timeout()`), so two proxies with different timeouts on the same pool entry get independent per-request timeouts — no cross-proxy leakage, no need for a `dns_override` work-around. The `connect_timeout` per-request override comes from a vendored copy of reqwest 0.13.3 with PR seanmonstar/reqwest#3017 applied; see `vendor/reqwest-0.13.3-ferrum-patched/` and `docs/upstream-reqwest-patches/001-per-request-connect-timeout/` for the lifecycle and retirement plan.

One nuance: hyper coalesces concurrent cold-pool connects, so simultaneous requests from sibling proxies racing the same shared client over a cold/saturated pool entry all wait on a single in-flight handshake — whichever poller wins the connect dictates the effective connect timeout for the coalesced group. The same coalescing happened with the old client-level connect timeout; it's not a regression. Steady-state dispatches reuse warm idle connections and skip the window. If strict per-proxy isolation including the cold-connect race is required, fragment the pool via distinct `dns_override` values.

### Backend Capability Registry (`src/proxy/backend_capabilities.rs`)

**Invariant**: plain HTTPS backend dispatch chooses native H3, direct H2, or reqwest from a per-target capability record keyed the same way as `Http3ConnectionPool::pool_key`. `Unknown` / `Unsupported` route via reqwest, so an empty registry degrades gracefully.

**Touch points**: populated by `warmup_connection_pools()` when `FERRUM_POOL_WARMUP_ENABLED=true`; otherwise `start_backend_capability_refresh_task(run_initial_refresh=true, ...)` runs the first probe pass. Config reload calls `spawn_backend_capability_refresh`; `RefreshCoalescer` guarantees at most one in-flight task + one queued re-run. Hot lookup uses a thread-local key buffer.

**Regression guards**:
- Stale-cache invalidation uses `mark_h3_unsupported` / `mark_h2_tls_unsupported`; H3 downgrade is gated by `is_h3_transport_error_class` and excludes `ClientDisconnect`, payload-size errors, and `GracefulRemoteClose`.
- `H3_NO_ERROR` ApplicationClose / GOAWAY at `recv_response` is `ErrorClass::GracefulRemoteClose`, not a capability failure. Upstream h3-crate fix is vendored at `vendor/h3-0.0.8-ferrum-patched`; lifecycle in [docs/upstream-h3-patches/](docs/upstream-h3-patches/).
- `proxy_to_backend_inner` captures `current_dispatch_h3 = supports_native_http3_backend(...)` once per attempt. Keep the snapshot for the same target; recompute after LB rotation to a different target so mixed-capability upstreams work.

**Admin introspection** (JWT-auth): `GET /backend-capabilities` snapshot, `POST /backend-capabilities/refresh` forces classification pass. Payloads carry only classifications + probe timestamps — safe to leave permanently enabled. See [docs/admin_api.md](docs/admin_api.md#backend-capability-registry).

### Connection-Error Classification Boundary

**Invariant**: `BackendResponse::connection_error: bool` means exactly "the request body never reached the backend's application layer." When `true`, `retry_on_connect_failure` can replay regardless of HTTP method; when `false`, retries must respect `retry_on_methods` / `retryable_status_codes`.

**Touch points**: every protocol classifier funnels `ErrorClass` through `retry::request_reached_wire(error_class) -> bool`, which returns `false` only for pre-wire classes: `ConnectionRefused`, `ConnectionTimeout`, `DnsLookupError`, `TlsError`, `PortExhaustion`, `ConnectionPoolError`. Per-classifier `connection_error: bool` fields are intentionally absent.

**H3 regression guard**: [`Http3ConnectionPool`](src/http3/client.rs) returns typed `H3PoolError`; `H3PoolError::request_on_wire()` is authoritative once `send_request().await` has succeeded on any internal attempt. Gateway H3 sites use the pool signal **exclusively** for `connection_error`:

```rust
let is_conn_error = !e.request_on_wire();
let (error_kind, error_class) = classify_h3_error(e.as_ref()); // labels + downgrade gating only
```

Do NOT AND with `!request_reached_wire(error_class)` for H3 — the class is a label and can disagree with the typed signal. The fresh-connect setup path MUST preserve the sticky flag with `H3PoolError::pre_wire(e).promote_on_wire_if(any_request_on_wire)`.

**Connect-phase RST guard**: a SYN that gets RST'd is equivalent to ECONNREFUSED. `classify_reqwest_error` collapses connect-phase `"refused"` / `"reset"` into `ConnectionRefused`; `classify_http2_pool_error::classify_io_error` treats the H2 pool as connect-only; H3 relies on `request_on_wire`.

**Capability-downgrade note**: `mark_h3_unsupported` intentionally uses `is_h3_transport_error_class`, which is broader than `request_reached_wire` because mid-stream resets/closes/protocol errors still fail the H3 transport.

### Health Check Architecture (two-layer)

- **Active probes** (periodic): shared per-upstream in `HealthChecker.active_unhealthy_targets: DashMap<"upstream_id::host:port", u64>`. Failure marks unhealthy for ALL proxies using that upstream (target is genuinely down).
- **Passive** (traffic-based): isolated per-proxy in `HealthChecker.passive_health: DashMap<proxy_id, Arc<ProxyHealthState>>`. Inner maps keyed by plain `host:port`. Proxy A's failures do NOT affect proxy B even on the same upstream.

Selection via `HealthContext { active_unhealthy, proxy_passive }`. `compute_health_bitset()` snapshots into stack `u128` bitset via two O(1) DashMap lookups per target (pre-computed keys); algorithms use free bit tests. >128 targets → Vec fallback. Consistent hash ring uses O(1) bitset check.

Rules: never merge active+passive maps (cross-proxy contamination); never key passive by `upstream_id` (proxy is the isolation boundary); `report_response()` takes `proxy_id`; `remove_stale_targets()` cleans both layers.

### Key Performance Lessons (do not violate)

**Allocation**: `HashMap::with_capacity(headers().keys_len())` when collecting; move (not clone) on streaming path; build retry `HeaderMap` only when `proxy.retry.is_some()` (+15% gRPC); pre-alloc body `Vec` from content-length; `Arc<UpstreamTarget>` for LB; response header `get_mut()` before key alloc; pre-populated status code DashMap (read lock not write).

**Routing**: NEVER O(n) linear scan for prefix routes; NEVER sequential per-pattern regex; router cache must scale with proxy count.

**Protocol gotchas**: don't replace reqwest with H3 pool for H3 frontend→backend (~10x regression on small payloads); keep hyper HTTP/1 `.writev(true)` on BOTH cleartext and TLS server builders (H1-TLS bulk local bench +3-5% RPS); gRPC `Proxy.clone()` is expensive — extract fields into param structs (see `TcpConnParams`); H2 flow control 8 MiB stream / 32 MiB conn for gRPC; `recvmmsg` for UDP frontend recv (reply handlers skip it intentionally); QUIC coalesce 8-32 KB + 2ms flush; gRPC response coalescer (`coalescing_h2_body` over the shared `Coalescing<Incoming>`) keeps 128 KB chunks (+35% gRPC at large payloads) — trailer-safe, do NOT revert; direct-H2 plain responses bypass `coalescing_h2_body` (use `direct_streaming_h2_body`) only when `Content-Length` is known, within the max response limit, and >= 512 KiB; small/mid-sized and unknown-size responses stay coalesced; Linux `splice(2)` for TCP plain-to-plain via `bidirectional_splice()`; **NEVER splice TLS without kTLS**.

**Active Pingora-inspired optimizations**: frequency-aware router cache eviction (Count-Min Sketch); `IP_BIND_ADDRESS_NO_PORT`; `TCP_FASTOPEN`; thread-local Date header cache; TLS handshake offload runtime; RED probabilistic shedding; UDP jitter-adaptive buffers; `lazy_timeout`; cacheability predictor LRU; `TCP_INFO` BDP sizing; **kTLS** (per-cipher probe, `zeroize` on drop — never consume TLS stream before confirming kernel install); **io_uring splice** (Linux 5.6+, warns if `FERRUM_BLOCKING_THREADS < 1024`); **UDP GSO** (GRO infra-only, needs recvmmsg-primary rewrite); `IP(v6)_PKTINFO` reply-source selection (GSO-combined `sendmsg`, pins `UdpSession.local_addr` via `OnceLock`); `SO_BUSY_POLL`; `HealthBitset` zero-alloc LB selection with FxHash-style hashing.

### Multi-Protocol Performance Testing

Tests in `tests/performance/multi_protocol/`. Build once with `cargo build --release`, then `bash run_protocol_test.sh {http1|http1-tls|http2|http3|ws|grpc|tcp|tcp-tls|udp|udp-dtls|all} [--duration N] [--concurrency N] [--skip-build]`. Measures gateway overhead vs direct backend.

### Adding a New Plugin

1. `src/plugins/my_plugin.rs` implements `Plugin` trait; constructor returns `Result<Self, String>`
2. Priority constant in `src/plugins/mod.rs` (`priority::MY_PLUGIN = N`)
3. Override `supported_protocols()` (default HTTP only). Constants: `ALL_PROTOCOLS`, `HTTP_FAMILY_PROTOCOLS`, `HTTP_GRPC_PROTOCOLS`, `HTTP_FAMILY_AND_STREAM_PROTOCOLS`, `HTTP_ONLY_PROTOCOLS`, `GRPC_ONLY_PROTOCOLS`, `TCP_ONLY_PROTOCOLS`, `UDP_ONLY_PROTOCOLS`
4. Register in `create_plugin_with_http_client()` match arm (use `?` on `new()`) + add name to `available_plugins()`
5. Unit tests in `tests/unit/plugins/my_plugin_tests.rs` (valid AND invalid configs) + add to `tests/unit/plugins/mod.rs`
6. Update `FEATURES.md`, `README.md`, `docs/plugin_execution_order.md`, and `openapi.yaml` (plugin schema for UI parity)

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

**Startup behavior** (`database` and `cp` modes): on boot, after core schema migrations (`run_pending`), the gateway calls `db.pending_plugin_migrations()` and:

- If any are pending and `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=false` (default), emits a `warn!` listing them — the gateway does NOT auto-mutate the schema. Operators must run `FERRUM_MODE=migrate FERRUM_MIGRATE_ACTION=up` explicitly before serving traffic that depends on the new schema. This preserves the contract that schema changes never run silently at boot.
- If `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS=true`, applies pending plugin migrations via `db.apply_plugin_migrations()` before `load_full_config`. A failed migration in this path is fatal — better to refuse startup than to come up with an inconsistent schema. Useful for embedded deployments (e.g., SQLite where the binary owns the database) that want a single binary upgrade to bring plugin schema up to date.

The trait methods `pending_plugin_migrations` / `apply_plugin_migrations` default to no-op for backends that don't support SQL plugin migrations (e.g., MongoDB). The `database` and `cp` startup paths share `crate::modes::handle_startup_plugin_migrations()`. The standalone `migrate` mode is unchanged — it always applies plugin migrations regardless of this flag.

### Adding a New Config Field

1. Struct in `src/config/types.rs` with `#[serde(default)]`
2. Env-driven → `src/config/env_config.rs`
3. **Update config docs** — `docs/configuration.md` is the canonical human-readable `FERRUM_*` reference; `ferrum.conf` is the editable operator template. Every new `FERRUM_*` needs a table entry in `docs/configuration.md` and a concise commented default in `ferrum.conf`; both MUST stay in sync with `env_config.rs`.
4. SQL storage → migration in `src/config/migrations/` + row parsing in `db_loader.rs`
5. MongoDB auto-persists via serde BSON — only add indexes in `MongoStore::run_migrations()` if queried
6. Unit tests in `tests/unit/config/`; update `openapi.yaml` if admin-exposed

SQL requires explicit migrations (control over types/indexes/dialects); MongoDB is serde-driven. Intentional asymmetry.

### Database

PostgreSQL/MySQL/SQLite (sqlx), MongoDB. SQLite uses `PRAGMA journal_mode=WAL`/`busy_timeout=5000`/`foreign_keys=ON` via `after_connect`.

`DatabaseBackend` trait in `src/config/db_backend.rs`; `DatabaseStore` (sqlx) + `MongoStore` both impl. Admin + modes use `Arc<dyn DatabaseBackend>`.

**Transactions**: SQL wraps multi-step CRUD in `sqlx::Transaction`. MongoDB: single-doc atomic; multi-doc requires replica set (`FERRUM_MONGO_REPLICA_SET`), else idempotent with poll-cycle cleanup.

**Incremental polling** (`FERRUM_DB_POLL_INTERVAL`, default 30s): startup = full `SELECT *`; subsequent = indexed `updated_at > ?` + lightweight `SELECT id` deletion diff. 1s safety margin. Validated before apply; known IDs unchanged on reject. Auto-fallback to full reload on failure. **CP broadcasts deltas** via tokio `broadcast` (capacity = `FERRUM_CP_BROADCAST_CHANNEL_CAPACITY`); lagging DPs auto-get a full snapshot.

**Failover**: `FERRUM_DB_FAILOVER_URLS` (same `FERRUM_DB_TYPE`); `FERRUM_DB_READ_REPLICA_URL` offloads polling (writes always primary). **Database TLS**: canonical envs are `FERRUM_DB_TLS_MODE` (`disable`/`allow`/`prefer`/`require`/`verify-ca`/`verify-full`) plus `FERRUM_DB_TLS_CA_CERT_PATH`, `FERRUM_DB_TLS_CLIENT_CERT_PATH`, and `FERRUM_DB_TLS_CLIENT_KEY_PATH`; MySQL rejects `allow`, MongoDB env mode supports only `disable`/`require`/`verify-full`, and SQLite accepts only `disable` as a no-op while rejecting cert paths and other TLS modes. **MongoDB** (`docs/mongodb.md`): `readPreference` in URL replaces read-replica var; replica sets handle failover natively (list members in `FERRUM_DB_URL`); pool via driver (`maxPoolSize`/`minPoolSize` in URL) — `FERRUM_DB_POOL_*` ignored.

### Dependency Version Sync

`tests/performance/multi_protocol/` is a standalone crate (not a workspace member) with its own `Cargo.toml` and `Cargo.lock`. Protocol-level dependencies shared with the root crate **must stay version-aligned** — cross-version wire incompatibilities cause silent failures (e.g., dimpl 0.5 ↔ 0.6 DTLS handshakes hang). When bumping any of these deps in the root `Cargo.toml`, also bump the matching line in `tests/performance/multi_protocol/Cargo.toml` and run `cd tests/performance/multi_protocol && cargo update -p <crate>`. Look for `# SYNC:` comments in both files.

### PR Checklist

When a task is complete (changes made, targeted tests green, docs updated), push the branch and open the PR without waiting for explicit instruction — opening the PR is part of finishing the work, not a separate ask. Skip only if the user said otherwise, the work is genuinely incomplete, or the change is purely exploratory/local.

Use "Local testing" above for validation and record what ran in the PR. New features need normal/edge/error coverage. No `.unwrap()`/`.expect()` in prod, no dead code, and no silent behavior changes. PR description must include summary + changes + test plan. Docs updated when behavior changes (`FEATURES.md`, `README.md`, `docs/`, `openapi.yaml`); new `FERRUM_*` vars need `docs/configuration.md` + `ferrum.conf` commented defaults.

### Commit Style / Branch Naming

Imperative mood, concise (e.g., `Fix rate limiter to handle zero-window edge case`). Branches: `feature/...`, `fix/...`, `claude/...`.

## Key Environment Variables

**Canonical reference**: [docs/configuration.md](docs/configuration.md). **Runtime parsing**: `src/config/env_config.rs`. **Editable template**: `ferrum.conf`. Only the load-bearing ones are listed here — for the full list (90+ vars), use the docs.

**Required by mode:**
- `FERRUM_MODE` (`database`/`file`/`cp`/`dp`/`mesh`/`injector`/`node_agent`/`migrate`)
- `FERRUM_NAMESPACE` (`ferrum`) — which namespace this instance loads
- `FERRUM_FILE_CONFIG_PATH` (required `file`)
- `FERRUM_DB_TYPE` + `FERRUM_DB_URL` (required `database`/`cp`)
- `FERRUM_ADMIN_JWT_SECRET` (required `db`/`cp`, ≥32 chars)
- `FERRUM_CP_DP_GRPC_JWT_SECRET` (required `cp`/`dp`, ≥32 chars)
- `FERRUM_DP_CP_GRPC_URLS` (required `dp`)

**Surfaces that change gateway behavior in non-obvious ways:**
- `FERRUM_PROXY_HTTP_PORT`/`HTTPS_PORT`, `FERRUM_ADMIN_HTTP_PORT`/`HTTPS_PORT`, port inside `FERRUM_CP_GRPC_LISTEN_ADDR` — port `0` disables plaintext (TLS-only listener)
- `FERRUM_TLS_CA_BUNDLE_PATH` (global backend CA, **exclusive** — disables webpki when set); `FERRUM_TLS_NO_VERIFY` (testing only); `FERRUM_TLS_CRL_FILE_PATH`
- `FERRUM_POOL_WARMUP_ENABLED` (`true`) — disabling skews backend-hit assertions and delays capability registry population
- `FERRUM_AUTO_APPLY_PLUGIN_MIGRATIONS` (`false`) — opt-in auto-apply at startup; default warns but doesn't auto-mutate schema
- `FERRUM_WEBSOCKET_TUNNEL_MODE` (`false`) — raw TCP copy; **frame-loss risk for server-push** (stock tickers, Socket.IO)
- `FERRUM_BLOCKING_THREADS` (512) — **bump to ≥1024 with io_uring splice at scale**
- `FERRUM_LOG_REDACT_METADATA_KEYS` (empty) — extra substrings to redact from transaction logs beyond built-ins (`authorization`/`cookie`/`set-cookie`/`x-api-key`/`x-auth-token`/`x-csrf-token`/`bearer`/`password`/`secret`/`token`)

**Mesh-specific** (only relevant in `mesh`/`injector` modes): see [docs/mesh.md](docs/mesh.md). Topology/listeners/SPIFFE/DNS proxy vars all live in `ferrum.conf` under `FERRUM_MESH_*`.

## Proto / gRPC (CP/DP)

`proto/ferrum.proto` compiled by `build.rs` via `tonic_build`. Service `ConfigSync` with `Subscribe` (streaming) + `GetFullConfig` (unary). HS256 JWT in `authorization` metadata. CP broadcast: `CpGrpcServer::with_channel_capacity()` in prod (passes `env_config.cp_broadcast_channel_capacity`); `new()` defaults to 128 for tests. DP reconnect: priority-ordered URLs with per-URL exponential backoff (1s→2s→4s→…30s, ±25% jitter). On fallback CP, `tokio::select!` races stream against primary-retry timer (`FERRUM_DP_CP_FAILOVER_PRIMARY_RETRY_SECS`).

## Docker

`Dockerfile` (multi-stage → distroless `gcr.io/distroless/cc-debian13:nonroot`) for local; `Dockerfile.release` for CI. No shell, OpenSSL vendored, UID 65532. Ports 8000/8443/9000/9443/50051. Healthcheck: `ferrum-edge health`. `docker-compose.yml` profiles: `sqlite`/`postgres`/`cp-dp`. Images: `ferrumedge/ferrum-edge` (Docker Hub), `ghcr.io/ferrum-edge/ferrum-edge`.

## Cargo Profiles

- `dev` — opt 0, no LTO, 256 codegen units (incremental)
- `release` — opt 3, thin LTO, 16 codegen units, strip
- `ci-release` — opt 2, no LTO, 256 codegen units (fast CI)
