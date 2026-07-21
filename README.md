<p align="center">
  <img src="assets/ferrum_edge.png" alt="Ferrum Edge" width="300">
</p>

<h1 align="center">Ferrum Edge</h1>

<p align="center">A high-performance edge proxy built in Rust</p>

<p align="center">
  <a href="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/ci.yml"><img src="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/ci.yml/badge.svg?branch=main" alt="CI"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/coverage.yml"><img src="https://github.com/ferrum-edge/ferrum-edge/actions/workflows/coverage.yml/badge.svg?branch=main" alt="Coverage"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/releases/latest"><img src="https://img.shields.io/github/v/release/ferrum-edge/ferrum-edge" alt="Release"></a>
  <a href="https://github.com/ferrum-edge/ferrum-edge/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue" alt="License"></a>
  <a href="https://hub.docker.com/r/ferrumedge/ferrum-edge"><img src="https://img.shields.io/docker/pulls/ferrumedge/ferrum-edge" alt="Docker Pulls"></a>
</p>

## Overview

Ferrum Edge is a lightweight, extensible edge proxy designed for modern microservice architectures. It provides dynamic routing, multi-protocol support, a robust plugin system, and multiple deployment topologies — from single-node file-based setups to distributed Control Plane / Data Plane architectures.

**Key highlights:**

- **Multi-protocol**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, raw TCP/UDP with TLS/DTLS
- **Built-in plugin system**: Authentication, authorization, OPA policy decisions, adaptive concurrency, WAF content threat detection, OpenAPI contract validation, rate limiting, fault injection, compression, response security headers, SSE stream handling, transformation, response mocking, spec exposure, serverless functions, AI/LLM-specific plugins (including AI federation for multi-provider routing), MCP / Agent Tool Gateway routing, A2A agent gateway observability/policy, load testing, API chargeback, and observability
- **Eight operating modes**: Database, File, Control Plane, Data Plane, Mesh, Injector, Node Agent, and Migrate
- **Lock-free hot path**: All request-path reads use `ArcSwap` or `DashMap` — no mutexes on the proxy path
- **Zero-downtime config reloads**: Atomic config swap via DB polling, SIGHUP, or CP push
- **Service mesh**: Six topologies (sidecar, ambient, node waypoint, service waypoint, east-west gateway, egress), native MeshSubscribe, xDS ADS, or localized file config consumption, SPIFFE identity, HBONE, transparent DNS proxy, mesh authorization, REGISTRY_ONLY outbound policy, and Istio/GAMMA RED metrics. See [docs/mesh.md](docs/mesh.md)
- **Runtime observability**: JWT-gated `/metrics/runtime` JSON snapshot with system/process state, HTTP status windows, error classes, DNS outcomes, backend pool churn, TCP resets, log counters, and overload state
- **Kubernetes mesh translation**: Gateway API and Istio VirtualService route splits, Istio AuthorizationPolicy/RequestAuthentication/PeerAuthentication, and sidecar injection webhook

For the full feature list, see [FEATURES.md](FEATURES.md).

## Operating Modes

| Mode | Env Var | Description | Admin API | Proxy |
|------|---------|-------------|-----------|-------|
| **Database** | `FERRUM_MODE=database` | Single-instance, DB-backed (PostgreSQL/MySQL/SQLite/MongoDB) | Read/Write | Yes |
| **File** | `FERRUM_MODE=file` | Single-instance, YAML/JSON config, SIGHUP reload | Read-only | Yes |
| **Control Plane** | `FERRUM_MODE=cp` | Centralized config authority, gRPC distribution to DPs | Read/Write | No |
| **Data Plane** | `FERRUM_MODE=dp` | Horizontally scalable traffic processing nodes | Read-only | Yes |
| **Mesh** | `FERRUM_MODE=mesh` | Service-mesh data plane consuming native MeshSubscribe, xDS ADS, or a localized config file with six topologies | Read-only | Yes |
| **Injector** | `FERRUM_MODE=injector` | Kubernetes admission webhook that injects Ferrum mesh sidecars/init capture | No | No |
| **Node Agent** | `FERRUM_MODE=node_agent` | Per-node eBPF capture manager for ambient mesh; no proxy listeners. See [docs/node_agent.md](docs/node_agent.md) | Optional (read-only) | No |
| **Migrate** | `FERRUM_MODE=migrate` | Runs DB schema migrations then exits (explicit CLI / external K8s Job; not a Helm chart mode) | No | No |

See [docs/cp_dp_mode.md](docs/cp_dp_mode.md) for distributed deployment details.
On Kubernetes, map each mode to its chart or external contract in
[docs/kubernetes_deployment.md](docs/kubernetes_deployment.md#binary-operating-mode-kubernetes-contract).

## Prerequisites

- **Rust** toolchain — latest stable (the repo pins `channel = "stable"` via `rust-toolchain.toml`; rustup will auto-install on first `cargo` invocation). CI runs clippy with `-D warnings` against the current stable, so local toolchains MUST be at parity.
- **protoc** (Protocol Buffers compiler) for gRPC code generation
- **Database** (optional): PostgreSQL, MySQL, SQLite, or MongoDB (for database and CP modes)

## Installation

### From Source

```bash
git clone https://github.com/ferrum-edge/ferrum-edge.git
cd ferrum-edge
cargo build --release

# Install to PATH
sudo cp target/release/ferrum-edge /usr/local/bin/
ferrum-edge version
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/ferrum-edge/ferrum-edge/releases) for Linux x86_64/ARM64 and macOS x86_64/ARM64.

```bash
# Example: Linux x86_64
curl -LO https://github.com/ferrum-edge/ferrum-edge/releases/latest/download/ferrum-edge-x86_64-unknown-linux-gnu.tar.gz
tar xzf ferrum-edge-x86_64-unknown-linux-gnu.tar.gz
sudo mv ferrum-edge /usr/local/bin/
ferrum-edge version
```

### Docker

```bash
docker pull ghcr.io/ferrum-edge/ferrum-edge:latest

docker run -d --name ferrum-edge \
  -p 8000:8000 \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=sqlite \
  -e FERRUM_DB_URL="sqlite:////data/ferrum.db?mode=rwc" \
  -e FERRUM_ADMIN_JWT_SECRET="please-change-me-to-a-32+character-secret" \
  -e FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
  -v ferrum_data:/data \
  ghcr.io/ferrum-edge/ferrum-edge:latest
```

> **Admin API exposure.** The admin API is a management plane. Both admin
> listeners (HTTP and HTTPS) bind to loopback (`127.0.0.1`) by default, so the
> example does **not** publish port 9000 and admin is not reachable from the
> network. In the writable `database`/`cp` modes the gateway **refuses to start**
> if the plaintext admin listener is bound to a non-loopback address (`0.0.0.0`,
> a public IP, or a private/VPC interface IP) with no `FERRUM_ADMIN_ALLOWED_CIDRS`
> allowlist. To make admin reachable from outside the container you must set
> `FERRUM_ADMIN_BIND_ADDRESS=0.0.0.0` (or `::`) — loopback alone is not reachable
> through a published port. Then either: (a) serve it over TLS
> (`FERRUM_ADMIN_TLS_CERT_PATH`/`FERRUM_ADMIN_TLS_KEY_PATH`, publish `9443`, set
> `FERRUM_ADMIN_HTTP_PORT=0` to disable plaintext) and/or set
> `FERRUM_ADMIN_ALLOWED_CIDRS`; or (b) for throwaway local testing only, set
> `FERRUM_ALLOW_INSECURE_ADMIN_HTTP=true` and publish `127.0.0.1:9000:9000`.

See [docs/docker.md](docs/docker.md) for Docker Compose examples and production deployment.

## Getting Started

### File Mode (quickest start)

```bash
# Using the CLI (recommended)
ferrum-edge run --spec tests/config.yaml -v

# Using environment variables
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH=tests/config.yaml \
FERRUM_LOG_LEVEL=info \
cargo run --release -- run
```

With smart defaults, if `./ferrum.conf` and `./resources.yaml` exist in the current directory:

```bash
ferrum-edge run
```

See [docs/cli.md](docs/cli.md) for the full CLI reference.

### Database Mode (SQLite)

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
FERRUM_LOG_LEVEL=info \
cargo run --release -- run
```

### Database Mode (PostgreSQL)

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL="postgres://user:pass@localhost/ferrum" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
cargo run --release -- run
```

### Database Mode (MongoDB)

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=mongodb \
FERRUM_DB_URL="mongodb://user:pass@localhost:27017/ferrum?authSource=admin" \
FERRUM_MONGO_DATABASE=ferrum \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_ADMIN_BIND_ADDRESS=127.0.0.1 \
cargo run --release -- run
```

### Control Plane + Data Plane (local development)

The CP→DP gRPC channel carries Data Plane authentication JWTs and the full
gateway configuration, so it is **TLS-first and secure-by-default**: the CP
refuses to bind a plaintext gRPC listener on a non-loopback address, and the DP
refuses a non-loopback `http://` CP URL, unless TLS is configured (or plaintext
is explicitly permitted — see below). The loopback quickstart below runs as-is;
any networked deployment must use TLS.

```bash
# Control Plane (loopback + plaintext — local development only; secrets must be 32+ chars)
FERRUM_MODE=cp \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="change-me-dev-admin-secret-min-32-chars" \
FERRUM_CP_GRPC_LISTEN_ADDR="127.0.0.1:50051" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run

# Data Plane (single CP, loopback — local development only)
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS="http://localhost:50051" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run

# Data Plane (multi-CP failover over TLS — production shape)
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URLS="https://cp1:50051,https://cp2:50051,https://cp3:50051" \
FERRUM_DP_GRPC_TLS_CA_CERT_PATH="/certs/ca.pem" \
FERRUM_CP_DP_GRPC_JWT_SECRET="change-me-dev-cp-dp-secret-min-32-chars" \
cargo run --release -- run
```

For production CP/DP with TLS/mTLS, see [docs/cp_dp_mode.md](docs/cp_dp_mode.md#transport-security-tlsmtls). To intentionally run plaintext config sync on a networked address (trusted network, with compensating controls), set `FERRUM_CP_DP_GRPC_ALLOW_PLAINTEXT=true` on both the CP and the DP. For multi-region high availability, see [docs/multi_region_ha.md](docs/multi_region_ha.md).

## Default Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| `8000` | HTTP | Proxy traffic |
| `8443` | HTTPS | Proxy traffic (TLS) |
| `9000` | HTTP | Admin API |
| `9443` | HTTPS | Admin API (TLS) |
| `50051` | gRPC | Control Plane → Data Plane sync |

All ports are configurable via environment variables (`FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`, `FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`, `FERRUM_CP_GRPC_LISTEN_ADDR`). Set any plaintext port to `0` to disable its listener entirely for TLS-only deployments.

## Configuration

Ferrum Edge is configured through environment variables, with an optional `ferrum.conf` file for defaults. Environment variables take precedence.

### Essential Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MODE` | **Yes** | — | `database`, `file`, `cp`, `dp`, `mesh`, `injector`, `node_agent`, `migrate` |
| `FERRUM_LOG_LEVEL` | No | `warn` | `error`, `warn`, `info`, `debug`, `trace` |
| `FERRUM_LOG_BUFFER_CAPACITY` | No | `4096` | Per-sink hard record limit; aggregate bytes are separately bounded by `FERRUM_LOG_BUFFER_BYTES` |
| `FERRUM_PROXY_HTTP_PORT` | No | `8000` | HTTP proxy port (`0` = disabled) |
| `FERRUM_PROXY_HTTPS_PORT` | No | `8443` | HTTPS proxy port |
| `FERRUM_ACCEPT_THREADS` | No | `0` (auto-detect) | Parallel accept loops via SO_REUSEPORT (0 = CPU cores; Unix only, non-Unix falls back to one loop) |
| `FERRUM_ADMIN_HTTP_PORT` | No | `9000` | Admin API HTTP port (`0` = disabled) |
| `FERRUM_ADMIN_JWT_SECRET` | DB/CP | — | HS256 secret for Admin API (min 32 chars) |
| `FERRUM_DB_TYPE` | DB/CP | — | `postgres`, `mysql`, `sqlite`, `mongodb` |
| `FERRUM_DB_URL` | DB/CP | — | Database connection string |
| `FERRUM_FILE_CONFIG_PATH` | File mode | — | Path to YAML/JSON config file |

For the full list of 300+ environment variables, see [docs/configuration.md](docs/configuration.md).

Operational note: all logging flows through bounded **non-blocking writers** (fixed record and byte admission → dedicated background threads → stdout/stderr), so log calls never block request-processing threads. Keep application logs on `stdout`/`stderr` by default. In containers, let the container runtime or platform collect and rotate the stream. On VMs, prefer running Ferrum Edge under `systemd` or another supervisor and let `journald`, `rsyslog`, `logrotate`, or a host log agent handle retention and rotation. Only add application-level file logging if you have a specific requirement for local log files. Under extreme throughput, size `FERRUM_LOG_BUFFER_CAPACITY` and `FERRUM_LOG_BUFFER_BYTES` together; increasing the record limit alone cannot increase admission when the byte budget is already full. New events are dropped and counted when either bound is reached so collector backpressure cannot stall the gateway.

### File Mode Config Format

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api/v1"
    backend_scheme: http
    backend_host: "backend-service"
    backend_port: 3000
    strip_listen_path: true
    plugins:
      - plugin_config_id: "log-plugin"

consumers:
  - id: "user-1"
    username: "alice"
    credentials:
      keyauth:
        - key: "alice-api-key"
    acl_groups:
      - "engineering"

plugin_configs:
  - id: "log-plugin"
    plugin_name: "stdout_logging"
    config: {}
    scope: global
    enabled: true
```

See [docs/configuration.md](docs/configuration.md) for stream proxy config, service discovery, and the `ferrum.conf` reference.

## Admin API

JWT-protected REST API for managing proxies, consumers, plugins, and upstreams at runtime.

> The examples below use `http://localhost:9000`, matching the local quick-start
> (admin bound to loopback, plaintext). In production, serve the admin API over
> **HTTPS** (`FERRUM_ADMIN_TLS_CERT_PATH`/`FERRUM_ADMIN_TLS_KEY_PATH`, then
> `https://host:9443`) and disable plaintext with `FERRUM_ADMIN_HTTP_PORT=0`, or
> restrict callers with `FERRUM_ADMIN_ALLOWED_CIDRS`. Bearer tokens sent over
> plaintext `http://` traverse the network in the clear. In `database`/`cp`
> modes the gateway refuses to start a public plaintext admin listener without
> an allowlist (see [docs/configuration.md](docs/configuration.md#admin-api)).

```bash
# Liveness probe (no auth) — always {"status":"ok"}
curl http://localhost:9000/live

# Readiness/health (no auth returns status+ready; full diagnostics need auth)
curl http://localhost:9000/health

# List proxies
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies

# Create a proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/api", "backend_scheme": "http", "backend_host": "backend", "backend_port": 3000}' \
  http://localhost:9000/proxies

# Backup / Restore
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/backup > backup.json
curl -X POST -H "Authorization: Bearer $TOKEN" -d @backup.json "http://localhost:9000/restore?confirm=true"
```

Submit an OpenAPI/Swagger spec to atomically provision a proxy, upstream, and plugins in one call — see [docs/api_specs.md](docs/api_specs.md).

See [docs/admin_api.md](docs/admin_api.md) for the full endpoint reference, and [openapi.yaml](openapi.yaml) for the OpenAPI specification.

## Plugin System

Ferrum ships a large built-in plugin set for request preflight, authentication,
authorization and backend admission, request/response transformation, AI/agent
gateway policy, protocol bridging, stream/WebSocket/UDP handling, and
observability. Plugins execute in a deterministic priority pipeline (lower
priority runs first) and are protocol-aware, so the gateway skips plugins that
do not apply to the current protocol.

The canonical plugin registry and ordering live outside the README to avoid
drift: see [docs/plugins.md](docs/plugins.md) for detailed configuration of each
plugin, and [docs/plugin_execution_order.md](docs/plugin_execution_order.md) for
the full execution order and protocol support matrix.


### AI / LLM Plugins

Plugins for AI and agent gateway use cases — transcript audit, cost visibility, budget enforcement, semantic policy, request policy, PII protection, output guardrails, prompt compression, streaming and non-streaming provider routing, MCP tool routing, and response caching:

- **`ai_token_metrics`** — Extract token usage from LLM responses for observability only (SSE metrics require explicit buffered opt-in)
- **`ai_request_guard`** — Enforce model whitelists, token limits, and request policy
- **`ai_rate_limiter`** — Enforce token budgets with pre-request reservation and response reconciliation (supports centralized Redis mode; compatible with any RESP-protocol server: Redis, Valkey, DragonflyDB, KeyDB, Garnet)
- **`ai_prompt_shield`** — Scan for PII and reject, redact, or warn
- **`ai_prompt_compressor`** — Bounded model-free compression for admitted OpenAI Chat/Text Completions requests (no external models or services); preserves matching-backtick code, URLs, Unicode numbers, common identifiers, and negations, with bounded fail-safe `preserve_tag` marker cleanup
- **`ai_semantic_firewall`** — Semantic prompt/response firewall for prompt injection, jailbreaks, data exfiltration intent, tool abuse, and topic allow/deny policy
- **`ai_semantic_cache`** — LLM response caching with normalized exact-match keys, optional embedding-based semantic similarity, and local or Redis exact-response storage
- **`ai_response_guard`** — Output-side content guardrails: PII detection, blocked phrases, response format validation
- **`ai_tool_governor`** — Deterministic allow/deny/redact/approval policy for AI tool/function calls by name, arguments, JSON Schema, regex, risk, and identity; screens request tool definitions, buffered and streaming response tool calls (held until cleared, then released or cut), and optional MCP/A2A methods, with an optional approval webhook
- **`ai_transcript_audit`** — Controlled AI payload capture for compliance: redacted request/response excerpts, canonical hashes, model/provider, token/guardrail/tool/cache metadata, sampling, and async batched HTTP export; never blocks the hot path unless configured fail-closed
- **`ai_stream_router`** — Streaming counterpart to `ai_federation`: claims `"stream": true` OpenAI Chat Completions, route-overrides to the matched provider, and normalizes provider-native SSE (e.g. Anthropic) to OpenAI `chat.completion.chunk` SSE without buffering
- **`ai_federation`** — HTTP-only AI gateway routing final transformed, non-streaming Chat Completions JSON to supported providers with bounded responses, replay-safe fallback, strict endpoint policy, and provider-native tool/content normalization; matched `"stream": true` requests return `501`
- **`mcp_gateway`** — MCP / Agent Tool Gateway for HTTP JSON-RPC MCP traffic: transparent proxying, aggregate discovery, namespaced tool/resource/prompt routing, session mediation, tool argument validation, and `mcp.*` metadata for downstream Ferrum plugins
- **`a2a_gateway`** — Transparent Agent-to-Agent gateway for HTTP/HTTPS JSON-RPC, HTTP+JSON/REST, and gRPC/grpcs traffic: method detection, lightweight method policy, HTTP Agent Card URL rewriting, streaming-safe pass-through, and `a2a.*` metadata

Auto-detects OpenAI, Anthropic, Google Gemini, Cohere, Mistral, and AWS Bedrock response formats. See [docs/plugins.md](docs/plugins.md#ai--llm-plugins) for configuration and a composition example.

### Centralized Rate Limiting

`rate_limiting` and `ai_rate_limiter` support centralized mode via `sync_mode: "redis"` for coordinated limits across multiple gateway instances. `ws_rate_limiting` also supports `sync_mode: "redis"`, but only to externalize per-connection frame counters under a per-plugin/gateway-instance Redis namespace — budgets are not shared across instances or portable across reconnects/rebuilds. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). Redis TLS uses gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY` settings.

### Custom Plugins

Drop-in custom plugins via `custom_plugins/` directory — auto-discovered at build time. Custom plugins can declare their own database migrations via `plugin_migrations()` for creating and managing private tables, tracked independently from core migrations. See [CUSTOM_PLUGINS.md](CUSTOM_PLUGINS.md).

## Routing

- **Longest prefix match** on `listen_path` with unique path enforcement
- **Host-based routing** with exact and wildcard prefix support (`*.example.com`)
- **Host-only routing** — omit `listen_path` on HTTP proxies to match any path under the specified hosts
- **Regex routes** with auto-anchored full-path matching (prefix with `~`)
- **Method filtering** via `allowed_methods` per-proxy (405 on mismatch)
- **Path forwarding**: `strip_listen_path` (default: true; no-op on host-only proxies), optional `backend_path` prefix

See [docs/routing.md](docs/routing.md) for detailed routing behavior.

### Protocol-Specific Proxying

| Protocol | Config | Notes |
|----------|--------|-------|
| **HTTP/1.1** | `backend_scheme: http` / `https` | Default, with connection pooling |
| **HTTP/2** | ALPN-negotiated on `https` | Automatic via `pool_enable_http2: true`; startup capability classification decides when the direct H2 pool is used |
| **HTTP/3** | `backend_scheme: https` | Startup capability classification probes HTTPS backends for H3 support and plain HTTP traffic uses QUIC automatically when supported |
| **WebSocket** | Runtime-detected from `Upgrade: websocket` (H1.1) or `:protocol=websocket` Extended CONNECT (H2 RFC 8441, H3 RFC 9220) on any HTTP-family proxy | `backend_scheme: http` → `ws://` upstream; `https` → `wss://`. Same plugin pipeline across all three frontends; H3 sessions controlled by `FERRUM_HTTP3_WEBSOCKET_ENABLED` (default on) |
| **gRPC** | Runtime-detected from `content-type: application/grpc*` on any HTTP-family proxy | HTTP/2 with trailer support on both `http` (h2c) and `https` (ALPN) schemes |
| **TCP** | `backend_scheme: tcp` / `tcps` | Dedicated-port stream proxy (plaintext or TLS) |
| **UDP** | `backend_scheme: udp` / `dtls` | Datagram proxy with session tracking (plaintext or DTLS) |

See [docs/tcp_udp_proxy.md](docs/tcp_udp_proxy.md) for TCP/UDP/DTLS proxy configuration.

## Load Balancing & Resilience

- **Six algorithms**: Round Robin, Weighted Round Robin, Least Connections, Least Latency, Consistent Hashing, Random
- **Health checks**: Active probes (HTTP, TCP SYN, UDP) and passive monitoring
- **Circuit breaker**: Three-state pattern (Closed/Open/Half-Open)
- **Retry**: Connection and HTTP-level retries with fixed/exponential backoff
- **Service discovery**: DNS-SD, Kubernetes, and Consul providers
- **Config caching**: All modes maintain in-memory config cache for resilience during source outages
- **Startup failover**: `FERRUM_DB_CONFIG_BACKUP_PATH` for DB outage recovery in Kubernetes
- **Multi-URL failover**: `FERRUM_DB_FAILOVER_URLS` for database high availability

See [docs/load_balancing.md](docs/load_balancing.md), [docs/retry.md](docs/retry.md), and [docs/error_classification.md](docs/error_classification.md).

## Connection Pooling

Lock-free connection reuse with per-proxy pool keys and HTTP/2 flow control tuning. Hybrid configuration with global defaults and per-proxy overrides. Startup pool warmup pre-establishes backend connections after DNS warmup to eliminate first-request cold-start latency.

See [docs/connection_pooling.md](docs/connection_pooling.md) for sizing guidance, pool warmup, and configuration.

## Security

### TLS

- **Frontend TLS/mTLS**: Proxy and admin HTTPS with optional client certificate verification — [docs/frontend_tls.md](docs/frontend_tls.md)
- **Backend mTLS**: Per-proxy client certificates for backend authentication — [docs/backend_mtls.md](docs/backend_mtls.md)
- **Database TLS**: PostgreSQL and MySQL TLS/mTLS connections — [docs/database_tls.md](docs/database_tls.md)
- **TLS hardening**: Configurable cipher suites, key exchange groups, and protocol versions — [docs/frontend_tls.md](docs/frontend_tls.md#tls-policy-hardening)

### Client IP Resolution

Secure originating IP detection via trusted proxy configuration with `X-Forwarded-For` right-to-left walk. See [docs/client_ip_resolution.md](docs/client_ip_resolution.md).

### DNS

In-memory async DNS cache with startup warmup, stale-while-revalidate, per-proxy TTL overrides, and static overrides. See [docs/dns_resolver.md](docs/dns_resolver.md).

## Performance

Historical small-payload multi-protocol benchmark results from
`tests/performance/multi_protocol/` (local macOS Apple Silicon run, 200
concurrent, 10s, 64-byte payload; run date not recorded in this summary):

| Protocol | Gateway RPS | Gw P50 | Gw P99 | Direct RPS | Direct P50 | Direct P99 | Overhead |
|----------|------------|--------|--------|------------|------------|------------|----------|
| HTTP/1.1 | 102,183 | 1.89ms | 3.85ms | 209,910 | 939μs | 1.81ms | ~51% |
| HTTP/1.1+TLS | 101,317 | 1.90ms | 3.84ms | 209,361 | 941μs | 1.81ms | ~52% |
| HTTP/2 | 108,138 | 1.67ms | 6.38ms | 355,544 | 486μs | 1.53ms | ~70% |
| HTTP/3 (QUIC) | 53,085 | 3.51ms | 5.87ms | 83,592 | 2.38ms | 2.80ms | ~37% |
| gRPC | 68,352 | 2.53ms | 12.02ms | 205,927 | 821μs | 3.15ms | ~67% |
| WebSocket | 103,830 | 1.88ms | 3.15ms | 207,507 | 952μs | 1.72ms | ~50% |
| TCP | 108,841 | 1.83ms | 2.59ms | 214,113 | 928μs | 1.65ms | ~49% |
| TCP+TLS | 107,340 | 1.84ms | 2.68ms | 207,103 | 949μs | 1.78ms | ~48% |
| UDP | 82,042 | 2.46ms | 2.93ms | 276,526 | 682μs | 1.27ms | ~70% |
| UDP+DTLS | 76,107 | 2.61ms | 3.69ms | 101,839 | 1.96ms | 2.47ms | ~25% |

**Adaptive buffer sizing** (enabled by default) dynamically tunes TCP/WebSocket tunnel copy buffers and UDP batch limits per proxy based on observed traffic patterns. Small-message proxies get smaller buffers (saves memory), bulk transfer proxies get larger buffers (reduces syscalls). See `FERRUM_ADAPTIVE_BUFFER_*` env vars for tuning.

**Linux socket tuning**: (`TCP_FASTOPEN`, `IP_BIND_ADDRESS_NO_PORT`), TLS handshake offload to dedicated runtimes, thread-local Date header caching, lazy timeout initialization, frequency-aware router cache eviction (Count-Min Sketch), RED-style adaptive load shedding, and a cacheability predictor for the response cache plugin. See [FEATURES.md](FEATURES.md) for details.

For current suite methodology and dated result tables, see
[`tests/performance/`](tests/performance/) and
[`tests/performance/multi_protocol/README.md`](tests/performance/multi_protocol/README.md).

### Production tuning

**File descriptor limit**. On Unix, Ferrum Edge calls `setrlimit(RLIMIT_NOFILE, rlim_cur=rlim_max)` once at startup, raising the soft cap to whatever the hard cap allows. The call never asks for privileges the process does not already have, so a sandboxed/seccomp-restricted run is a silent no-op rather than a failure. The *hard* cap must be set externally — Ferrum Edge cannot raise it. Recommended floor for production: **65,536**.

| Environment | How to raise the hard cap |
|---|---|
| systemd unit | `LimitNOFILE=1048576` in the `[Service]` section |
| Docker / Podman | `--ulimit nofile=1048576:1048576` |
| Kubernetes | Configure nofile on the node/container runtime (for example containerd/runc or the kubelet/systemd service); Pod `securityContext` does not expose ulimit/nofile. |
| Bare shell (dev) | `ulimit -n 1048576` before launching the binary |
| `/etc/security/limits.conf` | `* hard nofile 1048576` (and matching soft line) |

When the effective soft cap after startup is below 65,536, Ferrum Edge emits one structured `warn!` line at startup (greppable as `"soft FD limit"`) and continues. Below the floor, the gateway will still serve, but its 95% FD-critical threshold will trigger earlier under load.

**Concurrency planning**. Each inbound TCP/TLS connection consumes ~1 FD; HTTP/2 multiplexes many requests onto one. Linux `splice(2)` adds 2 pipe FDs per TCP relay. Plan for ~2–4× the target concurrent-connection count when sizing `nofile`.

### Gateway Comparison

Historical local comparison summary (macOS Apple Silicon, 100 concurrent, 30s;
run date not recorded in this summary):

All gateways run in Docker containers for apples-to-apples comparison:

| Gateway | Key-Auth req/s | Key-Auth Latency | vs Ferrum |
|---------|---------------|-----------------|-----------|
| **Ferrum Edge** | **27,979** | **3.44 ms** | — |
| Envoy 1.37 (Lua filter) | 26,787 | 3.64 ms | Ferrum 4% faster |
| Kong 3.14 | 25,009 | 3.91 ms | Ferrum 12% faster |
| Tyk v5.12 | 19,186 | 5.08 ms | Ferrum 46% faster |

Ferrum also **won the E2E TLS /api/users test outright** — 29,808 req/s, the highest throughput of any gateway in any scenario, beating Envoy by 13%. Ferrum's authentication adds effectively **zero overhead** — authenticated requests match unauthenticated throughput thanks to the pre-computed `ConsumerIndex` with `Arc<Consumer>` zero-copy credential resolution and lock-free `ArcSwap` reads. See [`comparison/README.md`](comparison/README.md) and [`comparison/run_comparison.sh`](comparison/run_comparison.sh) for the reproducible Docker gateway comparison harness, and [`tests/performance/README.md`](tests/performance/README.md) for the benchmark provenance checklist.

## Troubleshooting

| Issue | Solution |
|---|---|
| `FERRUM_MODE not set` | Set the `FERRUM_MODE` environment variable |
| `duplicate listen_path` | Ensure all proxy `listen_path` values are unique |
| `Database connection failed` | Verify `FERRUM_DB_TYPE` and `FERRUM_DB_URL` |
| `401 on Admin API` | Check JWT is signed with `FERRUM_ADMIN_JWT_SECRET` |
| `404 on proxy request` | Verify request path matches a configured `listen_path` |
| `502 Bad Gateway` | Backend unreachable — check `X-Gateway-Error` header for details |
| `504 Gateway Timeout` | Increase `backend_read_timeout_ms` |
| `429 Too Many Requests` | Rate limit exceeded — check plugin config |
| DP not receiving config | Verify `FERRUM_CP_DP_GRPC_JWT_SECRET` matches on both CP and DP |

## Documentation

| Topic | Link |
|-------|------|
| Full configuration reference | [docs/configuration.md](docs/configuration.md) |
| Plugin reference | [docs/plugins.md](docs/plugins.md) |
| Transaction log schema customization | [docs/log_schema.md](docs/log_schema.md) |
| Admin API | [docs/admin_api.md](docs/admin_api.md) |
| Connection pooling | [docs/connection_pooling.md](docs/connection_pooling.md) |
| Load balancing | [docs/load_balancing.md](docs/load_balancing.md) |
| CP/DP distributed mode | [docs/cp_dp_mode.md](docs/cp_dp_mode.md) |
| Kubernetes deployment | [docs/kubernetes_deployment.md](docs/kubernetes_deployment.md) |
| SPIRE deployment for mesh identity | [docs/spire_deployment.md](docs/spire_deployment.md) |
| TCP/UDP/DTLS proxy | [docs/tcp_udp_proxy.md](docs/tcp_udp_proxy.md) |
| Frontend TLS/mTLS | [docs/frontend_tls.md](docs/frontend_tls.md) |
| Backend mTLS | [docs/backend_mtls.md](docs/backend_mtls.md) |
| Database TLS | [docs/database_tls.md](docs/database_tls.md) |
| DNS resolver | [docs/dns_resolver.md](docs/dns_resolver.md) |
| Routing | [docs/routing.md](docs/routing.md) |
| Retry logic | [docs/retry.md](docs/retry.md) |
| Response streaming | [docs/response_body_streaming.md](docs/response_body_streaming.md) |
| Plugin execution order | [docs/plugin_execution_order.md](docs/plugin_execution_order.md) |
| Infrastructure sizing | [docs/infrastructure_sizing.md](docs/infrastructure_sizing.md) |
| Docker deployment | [docs/docker.md](docs/docker.md) |
| CI/CD pipeline | [docs/ci_cd.md](docs/ci_cd.md) |
| Database migrations | [docs/migrations.md](docs/migrations.md) |
| Custom plugins | [CUSTOM_PLUGINS.md](CUSTOM_PLUGINS.md) |
| Feature list | [FEATURES.md](FEATURES.md) |
| OpenAPI spec | [openapi.yaml](openapi.yaml) |
| Gateway API conformance | [docs/gateway_api_conformance.md](docs/gateway_api_conformance.md) (canonical) — indexed from [CONFORMANCE.md](CONFORMANCE.md) |
| Istio + xDS conformance matrix | [CONFORMANCE.md](CONFORMANCE.md) (run `cargo test --test conformance_tests` to refresh `target/conformance/coverage.md`) |

## CI/CD

On every push to `main` and PR: format check, tests (unit + integration + E2E), clippy, and performance regression testing. Version tags trigger multi-platform release builds with Docker images.

See [docs/ci_cd.md](docs/ci_cd.md) for pipeline details.

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`cargo test --all-features`)
5. Run `cargo clippy --all-targets --all-features -- -D warnings` and `cargo fmt`
6. Submit a pull request

## License

Copyright (c) 2026 Ferrum Edge

Licensed under the [PolyForm Noncommercial License 1.0.0](LICENSE).

**TL;DR**: Free to use as long as you're not reselling our technology. Hobbyists, students, researchers, nonprofits — go wild. Companies evaluating Ferrum for a proof-of-concept or demo? Also totally fine, kick the tires. But if you're dropping this into your production network stack, we kindly ask that you grab a [commercial license](LICENSE-COMMERCIAL.md) and help fund our caffeine supply. Open source doesn't run on exposure — it runs on coffee, and coffee costs money.
