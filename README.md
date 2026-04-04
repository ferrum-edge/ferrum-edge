# Ferrum Edge

A high-performance edge proxy built in Rust

## Overview

Ferrum Edge is a lightweight, extensible edge proxy designed for modern microservice architectures. It provides dynamic routing, multi-protocol support, a robust plugin system, and multiple deployment topologies — from single-node file-based setups to distributed Control Plane / Data Plane architectures.

**Key highlights:**

- **Multi-protocol**: HTTP/1.1, HTTP/2, HTTP/3 (QUIC), WebSocket, gRPC, raw TCP/UDP with TLS/DTLS
- **37 built-in plugins**: Authentication, authorization, rate limiting, transformation, serverless functions, AI/LLM-specific plugins, and observability
- **Four operating modes**: Database, File, Control Plane, Data Plane
- **Lock-free hot path**: All request-path reads use `ArcSwap` or `DashMap` — no mutexes on the proxy path
- **Zero-downtime config reloads**: Atomic config swap via DB polling, SIGHUP, or CP push

For the full feature list, see [FEATURES.md](FEATURES.md).

## Operating Modes

| Mode | Env Var | Description | Admin API | Proxy |
|------|---------|-------------|-----------|-------|
| **Database** | `FERRUM_MODE=database` | Single-instance, DB-backed (PostgreSQL/MySQL/SQLite) | Read/Write | Yes |
| **File** | `FERRUM_MODE=file` | Single-instance, YAML/JSON config, SIGHUP reload | Read-only | Yes |
| **Control Plane** | `FERRUM_MODE=cp` | Centralized config authority, gRPC distribution to DPs | Read/Write | No |
| **Data Plane** | `FERRUM_MODE=dp` | Horizontally scalable traffic processing nodes | Read-only | Yes |
| **Migrate** | `FERRUM_MODE=migrate` | Runs DB schema migrations then exits | No | No |

See [docs/cp_dp_mode.md](docs/cp_dp_mode.md) for distributed deployment details.

## Prerequisites

- **Rust** toolchain (stable 1.85+)
- **protoc** (Protocol Buffers compiler) for gRPC code generation
- **Database** (optional): PostgreSQL, MySQL, or SQLite (for database and CP modes)

## Installation

### From Source

```bash
git clone https://github.com/QuickLaunchWeb/ferrum-edge.git
cd ferrum-edge
cargo build --release
# Binary: target/release/ferrum-edge
```

### Pre-built Binaries

Download from [GitHub Releases](https://github.com/QuickLaunchWeb/ferrum-edge/releases) for Linux x86_64/ARM64 and macOS x86_64/ARM64.

### Docker

```bash
docker pull ghcr.io/quicklaunchweb/ferrum-edge:latest

docker run -d --name ferrum-edge \
  -p 8000:8000 -p 9000:9000 \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=sqlite \
  -e FERRUM_DB_URL="sqlite:////data/ferrum.db?mode=rwc" \
  -e FERRUM_ADMIN_JWT_SECRET="dev-secret" \
  -v ferrum_data:/data \
  ghcr.io/quicklaunchweb/ferrum-edge:latest
```

See [docs/docker.md](docs/docker.md) for Docker Compose examples and production deployment.

## Getting Started

### File Mode (quickest start)

```bash
FERRUM_MODE=file \
FERRUM_FILE_CONFIG_PATH=tests/config.yaml \
FERRUM_LOG_LEVEL=info \
cargo run --release
```

### Database Mode (SQLite)

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="my-super-secret-jwt-key" \
FERRUM_LOG_LEVEL=info \
cargo run --release
```

### Database Mode (PostgreSQL)

```bash
FERRUM_MODE=database \
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL="postgres://user:pass@localhost/ferrum" \
FERRUM_ADMIN_JWT_SECRET="my-super-secret-jwt-key" \
cargo run --release
```

### Control Plane + Data Plane

```bash
# Control Plane
FERRUM_MODE=cp \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="admin-secret" \
FERRUM_CP_GRPC_LISTEN_ADDR="0.0.0.0:50051" \
FERRUM_CP_GRPC_JWT_SECRET="grpc-secret" \
cargo run --release

# Data Plane
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URL="http://localhost:50051" \
FERRUM_DP_GRPC_AUTH_TOKEN="<HS256-JWT-signed-with-grpc-secret>" \
cargo run --release
```

For production CP/DP with TLS, see [docs/cp_dp_mode.md](docs/cp_dp_mode.md#transport-security-tlsmtls).

## Default Ports

| Port | Protocol | Purpose |
|------|----------|---------|
| `8000` | HTTP | Proxy traffic |
| `8443` | HTTPS | Proxy traffic (TLS) |
| `9000` | HTTP | Admin API |
| `9443` | HTTPS | Admin API (TLS) |
| `50051` | gRPC | Control Plane → Data Plane sync |

All ports are configurable via environment variables (`FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`, `FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`, `FERRUM_CP_GRPC_LISTEN_ADDR`).

## Configuration

Ferrum Edge is configured through environment variables, with an optional `ferrum.conf` file for defaults. Environment variables take precedence.

### Essential Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MODE` | **Yes** | — | `database`, `file`, `cp`, `dp`, `migrate` |
| `FERRUM_LOG_LEVEL` | No | `error` | `error`, `warn`, `info`, `debug`, `trace` |
| `FERRUM_PROXY_HTTP_PORT` | No | `8000` | HTTP proxy port |
| `FERRUM_PROXY_HTTPS_PORT` | No | `8443` | HTTPS proxy port |
| `FERRUM_ADMIN_HTTP_PORT` | No | `9000` | Admin API HTTP port |
| `FERRUM_ADMIN_JWT_SECRET` | DB/CP | — | HS256 secret for Admin API |
| `FERRUM_DB_TYPE` | DB/CP | — | `postgres`, `mysql`, `sqlite` |
| `FERRUM_DB_URL` | DB/CP | — | Database connection string |
| `FERRUM_FILE_CONFIG_PATH` | File mode | — | Path to YAML/JSON config file |

For the full list of 90+ environment variables, see [docs/configuration.md](docs/configuration.md).

Operational note: keep application logs on `stdout`/`stderr` by default. In containers, let the container runtime or platform collect and rotate the stream. On VMs, prefer running Ferrum Edge under `systemd` or another supervisor and let `journald`, `rsyslog`, `logrotate`, or a host log agent handle retention and rotation. Only add application-level file logging if you have a specific requirement for local log files.

### File Mode Config Format

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api/v1"
    backend_protocol: http
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
        key: "alice-api-key"

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

```bash
# Health check (no auth required)
curl http://localhost:9000/health

# List proxies
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies

# Create a proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/api", "backend_protocol": "http", "backend_host": "backend", "backend_port": 3000}' \
  http://localhost:9000/proxies

# Backup / Restore
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/backup > backup.json
curl -X POST -H "Authorization: Bearer $TOKEN" -d @backup.json "http://localhost:9000/restore?confirm=true"
```

See [docs/admin_api.md](docs/admin_api.md) for the full endpoint reference, and [openapi.yaml](openapi.yaml) for the OpenAPI specification.

## Plugin System

Plugins execute in a defined pipeline with priority ordering (lower = runs first):

| Phase | Plugins |
|-------|---------|
| **Tracing** (25) | `otel_tracing` |
| **Early** (100) | `cors`, `ip_restriction`, `bot_detection` |
| **Authentication** (950-1400) | `mtls_auth`, `jwks_auth`, `jwt_auth`, `key_auth`, `basic_auth`, `hmac_auth` |
| **gRPC** (275) | `grpc_method_router` |
| **Authorization** (2000-2900) | `access_control`, `tcp_connection_throttle`, `graphql`, `rate_limiting` |
| **AI Pre-proxy** (2925-2975) | `ai_prompt_shield`, `ai_request_guard` |
| **Transform** (3000-3050) | `request_transformer`, `serverless_function`, `body_validator` (JSON/XML/protobuf), `request_size_limiting`, `request_termination`, `grpc_deadline` |
| **WebSocket** (2810-2910) | `ws_message_size_limiting`, `ws_rate_limiting` |
| **Response** (4000-4200) | `response_transformer`, `response_size_limiting`, `ai_token_metrics`, `ai_rate_limiter` |
| **Logging** (9000-9300) | `stdout_logging`, `ws_frame_logging`, `http_logging`, `transaction_debugger`, `correlation_id`, `prometheus_metrics` |

Plugins are protocol-aware — the gateway automatically skips plugins that don't apply to the current protocol (e.g., CORS is never invoked on TCP streams).

See [docs/plugins.md](docs/plugins.md) for detailed configuration of each plugin, and [docs/plugin_execution_order.md](docs/plugin_execution_order.md) for the full protocol support matrix.


### AI / LLM Plugins

Four plugins for AI gateway use cases — cost visibility, budget enforcement, request policy, and PII protection:

- **`ai_token_metrics`** — Extract token usage from LLM responses for observability
- **`ai_request_guard`** — Enforce model whitelists, token limits, and request policy
- **`ai_rate_limiter`** — Rate-limit by token consumption instead of request count (supports centralized Redis mode; compatible with any RESP-protocol server: Redis, Valkey, DragonflyDB, KeyDB, Garnet)
- **`ai_prompt_shield`** — Scan for PII and reject, redact, or warn

Auto-detects OpenAI, Anthropic, Google Gemini, Cohere, Mistral, and AWS Bedrock response formats. See [docs/plugins.md](docs/plugins.md#ai--llm-plugins) for configuration and a composition example.

### Centralized Rate Limiting

All three rate limiting plugins (`rate_limiting`, `ai_rate_limiter`, `ws_rate_limiting`) support centralized mode via `sync_mode: "redis"` for coordinated limits across multiple gateway instances. Compatible with any RESP-protocol server (Redis, Valkey, DragonflyDB, KeyDB, Garnet). Redis TLS uses gateway-level `FERRUM_TLS_CA_BUNDLE_PATH` and `FERRUM_TLS_NO_VERIFY` settings.

### Custom Plugins

Drop-in custom plugins via `custom_plugins/` directory — auto-discovered at build time. See [CUSTOM_PLUGINS.md](CUSTOM_PLUGINS.md).

## Routing

- **Longest prefix match** on `listen_path` with unique path enforcement
- **Host-based routing** with exact and wildcard prefix support (`*.example.com`)
- **Regex routes** with auto-anchored full-path matching (prefix with `~`)
- **Method filtering** via `allowed_methods` per-proxy (405 on mismatch)
- **Path forwarding**: `strip_listen_path` (default: true), optional `backend_path` prefix

See [docs/routing.md](docs/routing.md) for detailed routing behavior.

### Protocol-Specific Proxying

| Protocol | Config | Notes |
|----------|--------|-------|
| **HTTP/1.1** | `backend_protocol: http` / `https` | Default, with connection pooling |
| **HTTP/2** | ALPN-negotiated on TLS | Automatic via `pool_enable_http2: true` |
| **HTTP/3** | `FERRUM_ENABLE_HTTP3=true` | QUIC on HTTPS port, requires TLS |
| **WebSocket** | `backend_protocol: ws` / `wss` | Transparent HTTP upgrade + bidirectional proxy |
| **gRPC** | `backend_protocol: grpc` / `grpcs` | HTTP/2 with trailer support, all auth plugins work |
| **TCP** | `backend_protocol: tcp` / `tcp_tls` | Dedicated-port stream proxy |
| **UDP** | `backend_protocol: udp` / `dtls` | Datagram proxy with session tracking |

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

Lock-free connection reuse with per-proxy pool keys and HTTP/2 flow control tuning. Hybrid configuration with global defaults and per-proxy overrides.

See [docs/connection_pooling.md](docs/connection_pooling.md) for sizing guidance and configuration.

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

Multi-protocol benchmark results (macOS Apple Silicon, 200 concurrent, 10s):

| Protocol | Gateway RPS | Direct RPS | Overhead |
|----------|------------|------------|----------|
| HTTP/1.1 | 88,773 | 100,112 | ~11% |
| HTTP/1.1+TLS | 85,210 | 98,935 | ~14% |
| HTTP/2 | 49,223 | 109,162 | ~55% |
| HTTP/3 (QUIC) | 39,581 | 67,866 | ~42% |
| gRPC | 34,470 | 118,650 | ~71% |
| WebSocket | 104,465 | 219,620 | ~52% |
| TCP | 108,332 | 215,646 | ~50% |

See `tests/performance/` for the full benchmark suite.


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
| DP not receiving config | Verify `FERRUM_DP_GRPC_AUTH_TOKEN` JWT is signed with `FERRUM_CP_GRPC_JWT_SECRET` |

## Documentation

| Topic | Link |
|-------|------|
| Full configuration reference | [docs/configuration.md](docs/configuration.md) |
| Plugin reference | [docs/plugins.md](docs/plugins.md) |
| Admin API | [docs/admin_api.md](docs/admin_api.md) |
| Connection pooling | [docs/connection_pooling.md](docs/connection_pooling.md) |
| Load balancing | [docs/load_balancing.md](docs/load_balancing.md) |
| CP/DP distributed mode | [docs/cp_dp_mode.md](docs/cp_dp_mode.md) |
| Kubernetes deployment | [docs/kubernetes_deployment.md](docs/kubernetes_deployment.md) |
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
