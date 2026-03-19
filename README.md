# Ferrum Gateway

A high-performance API Gateway and Reverse Proxy built in Rust, powered by `tokio` and `hyper`.

## Overview

Ferrum Gateway is a lightweight, extensible API gateway designed for modern microservice architectures. It provides dynamic routing, protocol flexibility (HTTP, WebSocket, gRPC), a robust plugin system with authentication, authorization, rate limiting, and request/response transformation capabilities. It supports multiple deployment topologies through its operating modes — from single-node file-based setups to distributed Control Plane / Data Plane architectures.

## Features

- **Multiple Operating Modes**: Database, File, Control Plane (CP), and Data Plane (DP) modes
- **Protocol Support**: HTTP/1.1, HTTP/2 (ALPN-negotiated on TLS), HTTP/3, WebSocket (`ws`/`wss`), and gRPC proxying
- **Connection Pooling**: Lock-free connection reuse with per-proxy pool keys, AtomicU64 cleanup, HTTP/2 via ALPN (no forced h2c)
- **Router Cache**: Pre-sorted route table with bounded O(1) path cache; rebuilt atomically on config changes, never on hot path
- **Longest Prefix Match Routing**: Efficient route matching with wildcard path-suffix forwarding and unique `listen_path` enforcement
- **Dynamic Configuration**: Zero-downtime configuration reloads via DB polling, SIGHUP signals, or CP push
- **Plugin System**: Extensible pipeline with lifecycle hooks for authentication, authorization, transformation, rate limiting, and logging
- **Multi-Authentication**: Chain multiple auth plugins with first-match consumer identification
- **TLS/mTLS Support**: Frontend TLS termination and backend mTLS with configurable certificate verification
- **DNS Caching**: In-memory async DNS cache with startup warmup, background refresh at 75% TTL, per-proxy TTL overrides, and static overrides
- **Admin REST API**: Full CRUD for Proxies, Consumers, and Plugin Configs with JWT-protected endpoints
- **Admin Read-Only Mode**: Configurable read-only mode for Admin API with automatic DP mode protection
- **Rate Limiting**: In-memory per-consumer or per-IP rate limiting with configurable windows
- **Graceful Shutdown**: SIGTERM/SIGINT handling with active request draining
- **Observability**: Structured JSON logging via `tracing` ecosystem and runtime metrics endpoint

## Operating Modes

### Database Mode (`FERRUM_MODE=database`)

A single gateway instance reads configuration from a database, handles proxy traffic, and serves the Admin API.

**Use case**: Single-node or small-scale deployments where simplicity is preferred.

- Connects to PostgreSQL, MySQL, or SQLite
- Polls the database periodically for configuration changes
- Maintains an in-memory cache for resilience during DB outages
- Serves both proxy traffic and Admin API

### File Mode (`FERRUM_MODE=file`)

A gateway instance reads its entire configuration from a local YAML or JSON file. No Admin API is exposed.

**Use case**: Development, testing, or immutable infrastructure deployments (e.g., Kubernetes ConfigMaps).

- Reads config from `FERRUM_FILE_CONFIG_PATH`
- Reloads on `SIGHUP` signal
- Failed reloads keep the previous valid configuration
- Only proxy traffic listeners are active

### Control Plane Mode (`FERRUM_MODE=cp`)

Acts as the centralized configuration authority. Reads from the database, serves the Admin API, and pushes configuration to Data Plane nodes via gRPC. Does **not** handle proxy traffic.

**Use case**: Distributed deployments where configuration management is separated from traffic handling.

- Serves Admin API and gRPC config distribution
- Authenticates DP nodes via HS256 JWT
- Pushes config updates to all subscribed DP nodes
- Caches config for resilience during DB outages

### Data Plane Mode (`FERRUM_MODE=dp`)

Handles proxy traffic only, receiving its configuration from a Control Plane node. No database access or Admin API.

**Use case**: Horizontally scalable traffic processing nodes in a distributed deployment.

- Connects to CP via gRPC with JWT authentication
- Receives initial config and subsequent updates
- Continues serving with cached config if CP connection is lost
- Automatically reconnects to CP
- Exposes a read-only Admin API for monitoring

See [docs/cp_dp_mode.md](docs/cp_dp_mode.md) for detailed architecture, protocol, and deployment documentation.

## Admin Read-Only Mode

Ferrum Gateway supports a configurable read-only mode for the Admin API, providing an additional layer of security for production deployments.

### Behavior

- **Read Operations**: All GET endpoints continue to work normally, allowing monitoring and health checks
- **Write Operations**: POST, PUT, and DELETE requests are blocked and return `403 Forbidden`
- **Error Response**: `{"error": "Admin API is in read-only mode"}`

### Configuration

| Environment Variable | Default | Description |
|---|---|---|
| `FERRUM_ADMIN_READ_ONLY` | `false` | Set Admin API to read-only mode (DP mode defaults to `true`) |

### Mode-Specific Behavior

- **Control Plane (CP)**: Respects the `FERRUM_ADMIN_READ_ONLY` environment variable
- **Data Plane (DP)**: **Always** read-only regardless of environment variable
- **Database/File Modes**: Respect the `FERRUM_ADMIN_READ_ONLY` environment variable

### Use Cases

- **Production Safety**: Prevent accidental configuration changes in production environments
- **DP Mode Security**: Ensure data plane nodes cannot modify configuration
- **Compliance**: Meet security requirements for immutable infrastructure
- **Maintenance**: Allow monitoring without risking configuration changes

## Prerequisites

- **Rust** toolchain (latest stable, 1.75+)
- **Database** (optional): PostgreSQL, MySQL, or SQLite (for database and CP modes)
- **protoc** (Protocol Buffers compiler) for gRPC code generation

## Installation

### From Source

```bash
# Clone the repository
git clone https://github.com/your-org/ferrum-gateway.git
cd ferrum-gateway

# Build in release mode
cargo build --release

# The binary is at target/release/ferrum-gateway
```

### From Release Binaries

Download pre-built binaries for your platform from the [GitHub Releases](https://github.com/your-org/ferrum-gateway/releases) page:

```bash
# Download the latest release for your platform
# Linux x86_64
wget https://github.com/your-org/ferrum-gateway/releases/download/v0.1.0/ferrum-gateway-linux-x86_64
chmod +x ferrum-gateway-linux-x86_64

# macOS x86_64 (Intel)
wget https://github.com/your-org/ferrum-gateway/releases/download/v0.1.0/ferrum-gateway-macos-x86_64
chmod +x ferrum-gateway-macos-x86_64

# macOS ARM64 (Apple Silicon)
wget https://github.com/your-org/ferrum-gateway/releases/download/v0.1.0/ferrum-gateway-macos-aarch64
chmod +x ferrum-gateway-macos-aarch64

# Verify checksum
sha256sum -c ferrum-gateway-linux-x86_64.sha256
```

### Using Docker

```bash
# Pull and run the latest Docker image
docker pull your-registry/ferrum-gateway:latest

docker run -d \
  --name ferrum-gateway \
  -p 8000:8000 \
  -p 9000:9000 \
  -e FERRUM_MODE=database \
  -e FERRUM_DB_TYPE=sqlite \
  -e FERRUM_DB_URL="sqlite:////data/ferrum.db?mode=rwc" \
  -e FERRUM_ADMIN_JWT_SECRET="dev-secret" \
  -v ferrum_data:/data \
  your-registry/ferrum-gateway:latest
```

See [Docker Deployment Guide](docs/docker.md) for comprehensive Docker and Docker Compose examples.

## Getting Started

### File Mode (quickest start)

```bash
# Run with the example configuration
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

**Control Plane:**
```bash
FERRUM_MODE=cp \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL="sqlite://ferrum.db?mode=rwc" \
FERRUM_ADMIN_JWT_SECRET="admin-secret" \
FERRUM_CP_GRPC_LISTEN_ADDR="0.0.0.0:50051" \
FERRUM_CP_GRPC_JWT_SECRET="grpc-secret" \
cargo run --release
```

**Data Plane:**
```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URL="http://localhost:50051" \
FERRUM_DP_GRPC_AUTH_TOKEN="<HS256-JWT-signed-with-grpc-secret>" \
cargo run --release
```

## Docker Deployment

Ferrum Gateway can be deployed using Docker or Docker Compose for development, testing, and production.

### Quick Start with Docker Compose

**SQLite Single-Node** (simplest):
```bash
docker-compose up ferrum-sqlite
```

**PostgreSQL Single-Node** (production-ready):
```bash
docker-compose --profile postgres up ferrum-postgres
```

**CP/DP Distributed** (horizontal scaling):
```bash
docker-compose --profile cp-dp up
```

### Building Docker Image

```bash
# Build locally
docker build -t ferrum-gateway:latest .

# Build for specific platform
docker buildx build --platform linux/amd64,linux/arm64 -t ferrum-gateway:latest .
```

**Image Features**:
- Multi-stage build for minimal size (~200MB)
- Non-root user execution
- Health check endpoint
- Comprehensive metadata labels

See [Docker Deployment Guide](docs/docker.md) for detailed examples, configuration, and production best practices.

## CI/CD Pipeline

Ferrum Gateway includes automated CI/CD workflows for testing, building, and releasing.

### Automated Testing & Builds

On every push to `main` and pull request:
- Run all tests (`cargo test`)
- Check code quality (clippy, fmt)
- Build release binaries for Linux x86_64, macOS x86_64, and macOS ARM64
- Build Docker image (pushed to registry on main branch only)

### Automated Releases

When you create a version tag (e.g., `v0.2.0`):
1. Builds optimized binaries for all platforms (Linux x86_64/ARM64, macOS x86_64/ARM64)
2. Generates SHA256 checksums
3. Creates GitHub Release with binaries, checksums, and release notes
4. Builds Docker image with version tag

### Creating a Release

```bash
# 1. Update version in Cargo.toml
# 2. Commit changes to main branch
# 3. Create and push version tag
git tag -a v0.2.0 -m "Release version 0.2.0"
git push origin v0.2.0

# Binaries automatically available at:
# https://github.com/your-org/ferrum-gateway/releases/tag/v0.2.0
```

See [CI/CD Documentation](docs/ci_cd.md) for complete pipeline overview, secrets configuration, and customization.

## Configuration

### Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MODE` | **Yes** | — | Operating mode: `database`, `file`, `cp`, `dp` |
| `FERRUM_LOG_LEVEL` | No | `info` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace` |
| `FERRUM_PROXY_HTTP_PORT` | No | `8000` | HTTP proxy listener port |
| `FERRUM_PROXY_HTTPS_PORT` | No | `8443` | HTTPS proxy listener port |
| `FERRUM_PROXY_TLS_CERT_PATH` | If HTTPS | — | Path to proxy TLS certificate |
| `FERRUM_PROXY_TLS_KEY_PATH` | If HTTPS | — | Path to proxy TLS private key |
| `FERRUM_ADMIN_HTTP_PORT` | No | `9000` | Admin API HTTP port |
| `FERRUM_ADMIN_HTTPS_PORT` | No | `9443` | Admin API HTTPS port |
| `FERRUM_ADMIN_TLS_CERT_PATH` | If HTTPS | — | Path to admin TLS certificate |
| `FERRUM_ADMIN_TLS_KEY_PATH` | If HTTPS | — | Path to admin TLS private key |
| `FERRUM_ADMIN_JWT_SECRET` | DB/CP modes | — | HS256 secret for Admin API JWT auth |
| `FERRUM_ADMIN_READ_ONLY` | All modes | `false` | Set Admin API to read-only mode (DP mode defaults to true) |
| `FERRUM_DB_TYPE` | DB/CP modes | — | Database type: `postgres`, `mysql`, `sqlite` |
| `FERRUM_DB_URL` | DB/CP modes | — | Database connection string |
| `FERRUM_DB_POLL_INTERVAL` | No | `30` | Seconds between DB config polls |
| `FERRUM_DB_POLL_CHECK_INTERVAL` | No | `5` | Seconds between DB connectivity checks |
| `FERRUM_DB_INCREMENTAL_POLLING` | No | `true` | Enable incremental (delta) DB polling |
| `FERRUM_DB_TLS_ENABLED` | No | `false` | Enable TLS for database connections |
| `FERRUM_DB_TLS_CA_CERT_PATH` | No | — | Path to CA certificate for database TLS verification |
| `FERRUM_DB_TLS_CLIENT_CERT_PATH` | No | — | Path to client certificate for database mTLS |
| `FERRUM_DB_TLS_CLIENT_KEY_PATH` | No | — | Path to client private key for database mTLS |
| `FERRUM_DB_TLS_INSECURE` | No | `false` | Skip certificate verification for database TLS (testing only) |
| `FERRUM_DB_SSL_MODE` | No | — | Database SSL mode: `disable`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `FERRUM_DB_SSL_ROOT_CERT` | No | — | Path to CA certificate for database server verification |
| `FERRUM_DB_SSL_CLIENT_CERT` | No | — | Path to client certificate for database mTLS |
| `FERRUM_DB_SSL_CLIENT_KEY` | No | — | Path to client private key for database mTLS |
| `FERRUM_FILE_CONFIG_PATH` | File mode | — | Path to YAML/JSON config file |
| `FERRUM_CP_GRPC_LISTEN_ADDR` | CP mode | — | gRPC listen address (e.g., `0.0.0.0:50051`) |
| `FERRUM_CP_GRPC_JWT_SECRET` | CP mode | — | HS256 secret for DP node authentication |
| `FERRUM_DP_CP_GRPC_URL` | DP mode | — | Control Plane gRPC URL |
| `FERRUM_DP_GRPC_AUTH_TOKEN` | DP mode | — | Pre-signed HS256 JWT for CP authentication |
| `FERRUM_MAX_HEADER_SIZE_BYTES` | No | `32768` | Maximum total request header size (all headers combined) |
| `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` | No | `16384` | Maximum size of any single request header (name + value) |
| `FERRUM_MAX_BODY_SIZE_BYTES` | No | `10485760` | Maximum request body size (0=unlimited) |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | No | `10485760` | Maximum response body size from backends (0=unlimited) |
| `FERRUM_DNS_CACHE_TTL_SECONDS` | No | `300` | Default DNS cache TTL |
| `FERRUM_DNS_OVERRIDES` | No | `{}` | JSON map of hostname→IP static overrides |
| `FERRUM_DNS_RESOLVER_ADDRESS` | No | resolv.conf | Comma-separated nameservers (ip[:port]) |
| `FERRUM_DNS_RESOLVER_HOSTS_FILE` | No | `/etc/hosts` | Path to custom hosts file |
| `FERRUM_DNS_ORDER` | No | `CACHE,SRV,A,CNAME` | Record type query order (comma-separated) |
| `FERRUM_DNS_VALID_TTL` | No | response TTL | Override TTL (seconds) for positive records |
| `FERRUM_DNS_STALE_TTL` | No | `3600` | Stale data usage time (seconds) during refresh |
| `FERRUM_DNS_ERROR_TTL` | No | `1` | TTL (seconds) for errors/empty responses |
| `FERRUM_BACKEND_TLS_CA_BUNDLE_PATH` | No | — | Path to CA bundle for backend TLS verification |
| `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH` | No | — | Path to client certificate for backend mTLS |
| `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH` | No | — | Path to client private key for backend mTLS |
| `FERRUM_PROXY_TLS_CERT_PATH` | No | — | Path to server TLS certificate for HTTPS |
| `FERRUM_PROXY_TLS_KEY_PATH` | No | — | Path to server TLS private key for HTTPS |
| `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` | No | — | Path to client CA bundle for mTLS verification |
| `FERRUM_ADMIN_TLS_CERT_PATH` | No | — | Path to admin TLS certificate for HTTPS |
| `FERRUM_ADMIN_TLS_KEY_PATH` | No | — | Path to admin TLS private key for HTTPS |
| `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` | No | — | Path to admin client CA bundle for mTLS verification |
| `FERRUM_ADMIN_TLS_NO_VERIFY` | No | `false` | Disable admin TLS certificate verification (testing only) |
| `FERRUM_BACKEND_TLS_NO_VERIFY` | No | `false` | Disable backend TLS certificate verification (testing only) |
| `FERRUM_ENABLE_HTTP3` | No | `false` | Enable HTTP/3 (QUIC) listener on the HTTPS port |
| `FERRUM_HTTP3_IDLE_TIMEOUT` | No | `30` | HTTP/3 connection idle timeout in seconds |
| `FERRUM_HTTP3_MAX_STREAMS` | No | `100` | Maximum concurrent HTTP/3 streams per connection |

### Configuration File Format (File Mode)

Configuration files can be YAML or JSON. See `tests/config.yaml` for a complete example.

```yaml
proxies:
  - id: "my-api"
    name: "My Backend API"
    listen_path: "/api/v1"
    backend_protocol: http
    backend_host: "backend-service"
    backend_port: 3000
    strip_listen_path: true
    preserve_host_header: false
    backend_connect_timeout_ms: 5000
    backend_read_timeout_ms: 30000
    backend_write_timeout_ms: 30000
    # Connection pooling settings (optional - override global defaults)
    pool_max_idle_per_host: 25          # Override global default (10)
    pool_idle_timeout_seconds: 120      # Override global default (90)
    # pool_enable_http_keep_alive and pool_enable_http2 use global defaults
    auth_mode: single
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

## Connection Pooling

Ferrum Gateway includes enterprise-grade connection pooling that significantly improves performance by reusing HTTP/HTTPS/WebSocket connections. This reduces TCP handshake overhead, lowers latency, and increases throughput.

### Hybrid Configuration Approach

Connection pooling uses a **hybrid configuration** with global defaults and per-proxy overrides:

#### Global Environment Variables
```bash
# Set global defaults (optional - shown with defaults)
FERRUM_POOL_MAX_IDLE_PER_HOST=10
FERRUM_POOL_IDLE_TIMEOUT_SECONDS=90
FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true
FERRUM_POOL_ENABLE_HTTP2=true
FERRUM_POOL_TCP_KEEPALIVE_SECONDS=60
FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS=30
FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS=45
```

#### Per-Proxy Overrides (Optional)
```yaml
proxies:
  - id: "high-traffic-api"
    # Override specific settings for this proxy
    pool_max_idle_per_host: 50
    pool_enable_http2: false
    pool_tcp_keepalive_seconds: 30
    pool_http2_keep_alive_interval_seconds: 15
    pool_http2_keep_alive_timeout_seconds: 5
    # Other settings use global defaults
```

### Benefits

- **2-3x Higher Throughput**: Connection reuse eliminates setup overhead
- **Lower Latency**: Persistent connections avoid TCP handshakes
- **Resource Efficiency**: Fewer file descriptors and memory usage
- **Protocol Support**: HTTP/1.1 keep-alive, HTTP/2, HTTPS, WebSocket (WS/WSS)
- **Flexible Configuration**: Global defaults with per-proxy fine-tuning

### Configuration

| Setting | Global Default | Description |
|---------|----------------|-------------|
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | `10` | Maximum idle connections per backend host |
| `FERRUM_POOL_IDLE_TIMEOUT_SECONDS` | `90` | Seconds before idle connections are closed |
| `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` | `true` | Enable HTTP keep-alive for connection reuse |
| `FERRUM_POOL_ENABLE_HTTP2` | `true` | Enable HTTP/2 multiplexing when supported |
| `FERRUM_POOL_TCP_KEEPALIVE_SECONDS` | `60` | TCP keep-alive interval in seconds |
| `FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS` | `30` | HTTP/2 keep-alive ping interval in seconds |
| `FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS` | `45` | HTTP/2 keep-alive timeout in seconds |

### Timeout Mechanisms Explained

**Different Layers of Connection Management:**

1. **TCP Keep-Alive** (Transport Layer)
   - Prevents connection drops by NAT/firewalls
   - Sends packets every N seconds when idle
   - Applies to ALL connections (HTTP/1.1, HTTP/2, WebSocket)

2. **HTTP/2 Keep-Alive** (Application Layer)
   - Detects dead HTTP/2 connections via PING frames
   - Only applies to HTTP/2 connections
   - More responsive than TCP keep-alive for HTTP/2

3. **HTTP Timeouts** (Request Layer)
   - Controls request/response processing time
   - `backend_connect_timeout_ms`: Connection establishment (default: 5000ms)
   - `backend_read_timeout_ms`: Request processing (default: 30000ms)
   - Applies during active requests

**Recommended Relationships:**
- HTTP/2 timeout should be **1.5x** the TCP keep-alive interval
- HTTP read timeout should be **2-3x** the HTTP/2 timeout
- TCP keep-alive should be **1.2-1.5x** the HTTP/2 interval

### Protocol-Specific Recommendations

#### HTTP/HTTPS APIs
```bash
# Global environment
FERRUM_POOL_MAX_IDLE_PER_HOST=25
FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120
FERRUM_POOL_ENABLE_HTTP2=true
```

#### WebSocket Services
```yaml
# Per-proxy override for WS/WSS
pool_max_idle_per_host: 10
pool_idle_timeout_seconds: 300
pool_enable_http2: false  # HTTP/1.1 recommended for WebSockets
```

#### Auth-Protected APIs
```yaml
# Per-proxy override for auth-heavy services
pool_max_idle_per_host: 15
pool_enable_http2: false  # Better compatibility with auth plugins
```

### Performance Impact

In performance tests, connection pooling provides:
- **~150,000 RPS** vs ~56,000 RPS direct backend access
- **~600μs latency** vs ~1.6ms without pooling
- **Zero errors** under sustained load

### Performance Testing

Ferrum Gateway includes a comprehensive performance testing suite in the `perftest/` directory:

```bash
# Quick performance test
cd perftest && ./quick_test.sh

# Full performance test suite with HTML report
cd perftest && ./run_perf_test.sh

# Custom test parameters
WRK_DURATION=60s WRK_THREADS=12 WRK_CONNECTIONS=200 ./run_perf_test.sh
```

The testing suite provides:
- **Automated backend server** with multiple endpoints
- **Gateway vs direct backend comparison**
- **HTML performance reports** with visual analysis
- **Configurable load testing** with wrk
- **Protocol support** for HTTP, HTTPS, and WebSockets

See `perftest/README.md` for detailed usage instructions.

### Database Schema

When using Database or CP modes, Ferrum auto-creates the following tables on startup:

- **`proxies`**: Proxy route definitions (with `UNIQUE` constraint on `listen_path`)
- **`consumers`**: API consumer/user definitions
- **`plugin_configs`**: Plugin configurations (global or per-proxy scoped)
- **`proxy_plugins`**: Many-to-many linking proxies to plugin configs

## Admin API

### Authentication

All Admin API endpoints (except `/health`) require a valid HS256 JWT in the `Authorization: Bearer <token>` header, verified against `FERRUM_ADMIN_JWT_SECRET`.

Generate a token:
```bash
# Using any JWT library; payload can be minimal
# Example using Node.js jsonwebtoken:
node -e "console.log(require('jsonwebtoken').sign({sub:'admin'}, 'my-super-secret-jwt-key'))"
```

### Endpoints

#### Proxies

```bash
# List all proxies
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies

# Create a proxy
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "listen_path": "/new-api",
    "backend_protocol": "http",
    "backend_host": "backend",
    "backend_port": 3000,
    "strip_listen_path": true
  }' \
  http://localhost:9000/proxies

# Get a proxy
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies/{proxy_id}

# Update a proxy
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"listen_path": "/new-api", "backend_host": "new-backend", "backend_port": 4000, "backend_protocol": "http"}' \
  http://localhost:9000/proxies/{proxy_id}

# Delete a proxy
curl -X DELETE -H "Authorization: Bearer $TOKEN" http://localhost:9000/proxies/{proxy_id}
```

#### Consumers

```bash
# List consumers
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/consumers

# Create consumer
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"username": "alice", "credentials": {"keyauth": {"key": "my-key"}}}' \
  http://localhost:9000/consumers

# Update consumer credentials
curl -X PUT -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"key": "new-api-key"}' \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth

# Delete a credential type
curl -X DELETE -H "Authorization: Bearer $TOKEN" \
  http://localhost:9000/consumers/{consumer_id}/credentials/keyauth
```

#### Plugin Configs

```bash
# List available plugin types
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/plugins

# List all plugin configs
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/plugins/config

# Create plugin config
curl -X POST -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "plugin_name": "rate_limiting",
    "config": {"limit_by": "ip", "requests_per_minute": 60},
    "scope": "global",
    "enabled": true
  }' \
  http://localhost:9000/plugins/config
```

#### Metrics

```bash
curl -H "Authorization: Bearer $TOKEN" http://localhost:9000/admin/metrics
```

Returns:
```json
{
  "mode": "database",
  "config_last_updated_at": "2025-01-15T10:30:00Z",
  "config_source_status": "online",
  "proxy_count": 5,
  "consumer_count": 10,
  "requests_per_second_current": 150,
  "status_codes_last_second": {"200": 145, "404": 3, "429": 2}
}
```

#### Health Check (Unauthenticated)

```bash
curl http://localhost:9000/health
# or equivalently:
curl http://localhost:9000/status
# Returns: {"status": "ok", "timestamp": "...", "mode": "database"}
```

Both `/health` and `/status` return the same response and do not require JWT authentication, making them suitable for load balancer health probes and monitoring systems.

## Plugin System

### Lifecycle Hooks

Plugins execute in a defined pipeline for each request:

1. **`on_request_received`** — Called immediately when a request arrives (rate limiting executes here)
2. **`authenticate`** — Identifies the consumer (JWT, API Key, Basic Auth, OAuth2)
3. **`authorize`** — Checks consumer permissions (Access Control)
4. **`before_proxy`** — Modifies the request before forwarding (Request Transformer)
5. **`after_proxy`** — Modifies the response from the backend (Response Transformer)
6. **`log`** — Logs the transaction summary (Stdout/HTTP Logging)

### Global vs. Proxy Scope

- **Global** plugins apply to all proxies
- **Proxy-scoped** plugins apply only to a specific proxy and override globals of the same plugin type

### Multi-Authentication Mode

When a proxy has `auth_mode: multi`, all attached authentication plugins execute sequentially. The first plugin that successfully identifies a consumer attaches that consumer's context. Subsequent auth plugins cannot overwrite it. After all auth plugins run, the Access Control plugin verifies that at least one consumer was identified.

### Available Plugins

#### `stdout_logging`

Logs a JSON transaction summary to stdout for each request.

**Config**: None required.

```yaml
plugin_name: stdout_logging
config: {}
```

#### `http_logging`

Sends the transaction summary as JSON to an external HTTP endpoint.

**Config**:
| Parameter | Type | Description |
|---|---|---|
| `endpoint_url` | String | URL to POST transaction logs to |
| `authorization_header` | String (optional) | Authorization header value for the logging endpoint |

```yaml
plugin_name: http_logging
config:
  endpoint_url: "https://logging-service.example.com/ingest"
  authorization_header: "Bearer log-token-123"
```

#### `transaction_debugger`

Logs verbose request/response details to stdout. Enable per-proxy only for debugging.

**Config**:
| Parameter | Type | Default | Description |
|---|---|---|---|
| `log_request_body` | bool | `false` | Log incoming request body |
| `log_response_body` | bool | `false` | Log backend response body |

#### `jwt_auth`

Authenticates requests using HS256 JWT Bearer tokens matched against consumer credentials.

**Config**:
| Parameter | Type | Default | Description |
|---|---|---|---|
| `token_lookup` | String | `header:Authorization` | Where to find the token (`header:<name>` or `query:<name>`) |
| `consumer_claim_field` | String | `sub` | JWT claim identifying the consumer |

**Consumer credential** (`jwt`):
```yaml
credentials:
  jwt:
    secret: "consumer-specific-hs256-secret"
```

#### `key_auth`

Authenticates requests using an API key matched against consumer credentials.

**Config**:
| Parameter | Type | Default | Description |
|---|---|---|---|
| `key_location` | String | `header:X-API-Key` | Where to find the key (`header:<name>` or `query:<name>`) |

**Consumer credential** (`keyauth`):
```yaml
credentials:
  keyauth:
    key: "the-api-key-value"
```

#### `basic_auth`

Authenticates using HTTP Basic credentials with bcrypt-hashed password verification.

**Config**: None required.

**Consumer credential** (`basicauth`):
```yaml
credentials:
  basicauth:
    password_hash: "$2b$12$..." # bcrypt hash
```

#### `oauth2_auth`

Authenticates using OAuth2 Bearer tokens via introspection or local JWKS-style validation.

**Config**:
| Parameter | Type | Description |
|---|---|---|
| `validation_mode` | String | `introspection` or `jwks` |
| `introspection_url` | String | Token introspection endpoint URL |
| `jwks_uri` | String | JWKS URI for key retrieval |
| `expected_issuer` | String (optional) | Expected JWT issuer |
| `expected_audience` | String (optional) | Expected JWT audience |

#### `access_control`

Authorizes requests based on IP address, CIDR range, and/or the identified consumer's username. Blocked IPs take precedence over allowed IPs. If `allowed_ips` is specified, only IPs in that list are permitted; all others are rejected.

**Config**:
| Parameter | Type | Description |
|---|---|---|
| `allowed_ips` | String[] | IP addresses or CIDR ranges allowed (e.g., `["10.0.0.0/8", "192.168.1.1"]`) |
| `blocked_ips` | String[] | IP addresses or CIDR ranges explicitly denied |
| `allowed_consumers` | String[] | Usernames allowed access (empty = allow all) |
| `disallowed_consumers` | String[] | Usernames explicitly denied |

#### `request_transformer`

Modifies request headers and query parameters before proxying.

**Config**:
```yaml
config:
  rules:
    - operation: add     # add, remove, update
      target: header     # header, query
      key: "X-Custom"
      value: "my-value"
```

#### `response_transformer`

Modifies response headers before sending to the client.

**Config**:
```yaml
config:
  rules:
    - operation: add
      key: "X-Powered-By"
      value: "Ferrum-Gateway"
```

#### `rate_limiting`

Enforces request rate limits per time window. State is maintained in-memory per node.

**Config**:
| Parameter | Type | Default | Description |
|---|---|---|---|
| `limit_by` | String | `ip` | Rate limit key: `consumer` or `ip` |
| `requests_per_second` | u64 (optional) | — | Max requests per second |
| `requests_per_minute` | u64 (optional) | — | Max requests per minute |
| `requests_per_hour` | u64 (optional) | — | Max requests per hour |

Returns HTTP `429 Too Many Requests` when exceeded.

## Proxying Behavior

### Routing

Ferrum uses **longest prefix matching** on `listen_path` values. All paths must be unique. If no proxy matches, the gateway returns `404 Not Found`.

### Path Forwarding

- **`strip_listen_path: true`** (default): Strips the matched prefix, forwarding only the remainder
  - Request: `/api/v1/users` with `listen_path: /api/v1` → Backend receives `/users`
- **`strip_listen_path: false`**: Forwards the full original path
  - Request: `/api/v1/users` → Backend receives `/api/v1/users`
- **`backend_path`**: Optional prefix prepended to the forwarded path

### WebSocket Proxying

Set `backend_protocol: ws` or `wss`. Ferrum handles the HTTP Upgrade and proxies the bidirectional stream.

### gRPC Proxying

Set `backend_protocol: grpc`. Ferrum proxies gRPC requests over HTTP/2.

## Resilience & Caching

### Configuration Caching

All modes maintain an in-memory cache of the last valid configuration. If the configuration source (database or CP) becomes unavailable, the gateway continues operating with the cached config.

### Database Outage (Database/CP Modes)

- Proxy traffic continues using cached configuration
- Admin API write operations return `503 Service Unavailable`
- Warnings are logged about the connection status
- Automatic reconnection on next poll interval

### CP Outage (DP Mode)

- DP continues serving with its last known configuration
- Periodic reconnection attempts (every 5 seconds)
- Full config resynchronization on reconnect

### DNS Resolver

- Built on [hickory-resolver](https://github.com/hickory-dns/hickory-dns) with full configurability
- Configurable nameservers, custom hosts file, and DNS record type query ordering
- In-memory DashMap cache with stale-while-revalidate (serve stale data during background refresh)
- Error caching prevents hammering DNS for non-existent domains
- Proactive background refresh at 75% TTL keeps entries warm
- Per-proxy TTL override via `dns_cache_ttl_seconds`
- Static overrides: global (`FERRUM_DNS_OVERRIDES`) and per-proxy (`dns_override`)
- Respects system `RES_OPTIONS` and `LOCALDOMAIN` environment variables
- Non-blocking startup warmup resolves all backend hostnames
- See [docs/dns_resolver.md](docs/dns_resolver.md) for full configuration reference

### HTTP/3 (QUIC) Support

Ferrum supports HTTP/3 over QUIC on the same port as HTTPS. HTTP/3 requires TLS to be configured.

```bash
FERRUM_PROXY_TLS_CERT_PATH=/path/to/cert.pem \
FERRUM_PROXY_TLS_KEY_PATH=/path/to/key.pem \
FERRUM_ENABLE_HTTP3=true \
FERRUM_HTTP3_IDLE_TIMEOUT=30 \
FERRUM_HTTP3_MAX_STREAMS=100
```

When enabled, the gateway listens for QUIC connections on `FERRUM_PROXY_HTTPS_PORT` alongside the standard HTTPS listener. Clients that support HTTP/3 (e.g., `curl --http3`) can connect via QUIC for lower-latency connections with built-in multiplexing and improved head-of-line blocking behavior.

## Security

### TLS Configuration

Ferrum supports TLS on both proxy and admin listeners:

```bash
FERRUM_PROXY_TLS_CERT_PATH=/path/to/cert.pem \
FERRUM_PROXY_TLS_KEY_PATH=/path/to/key.pem \
FERRUM_ADMIN_TLS_CERT_PATH=/path/to/admin-cert.pem \
FERRUM_ADMIN_TLS_KEY_PATH=/path/to/admin-key.pem
```

### Database TLS/SSL

Ferrum supports TLS encryption for PostgreSQL and MySQL database connections. There are two configuration approaches — use whichever fits your workflow.

#### Option 1: `FERRUM_DB_SSL_*` variables (recommended)

These variables give you granular control over SSL mode and are translated into connection string parameters automatically, so you don't need to embed them in `FERRUM_DB_URL`.

**PostgreSQL with server certificate verification:**
```bash
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL="postgres://user:pass@db.example.com/ferrum" \
FERRUM_DB_SSL_MODE=verify-ca \
FERRUM_DB_SSL_ROOT_CERT=/certs/ca.pem
```

**PostgreSQL with mutual TLS (mTLS):**
```bash
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL="postgres://user:pass@db.example.com/ferrum" \
FERRUM_DB_SSL_MODE=verify-full \
FERRUM_DB_SSL_ROOT_CERT=/certs/ca.pem \
FERRUM_DB_SSL_CLIENT_CERT=/certs/client.pem \
FERRUM_DB_SSL_CLIENT_KEY=/certs/client-key.pem
```

**MySQL with TLS:**
```bash
FERRUM_DB_TYPE=mysql \
FERRUM_DB_URL="mysql://user:pass@db.example.com/ferrum" \
FERRUM_DB_SSL_MODE=require \
FERRUM_DB_SSL_ROOT_CERT=/certs/ca.pem
```

**SSL mode values:**

| Mode | Description |
|------|-------------|
| `disable` | No SSL |
| `prefer` | Try SSL, fall back to plain |
| `require` | Require SSL, skip CA verification |
| `verify-ca` | Require SSL, verify server CA certificate |
| `verify-full` | Require SSL, verify CA and hostname |

> **Note:** SQLite connections ignore SSL settings (file-based, no network TLS). MySQL mode values are automatically mapped to the MySQL-native format (e.g., `require` → `REQUIRED`, `verify-ca` → `VERIFY_CA`).

#### Option 2: `FERRUM_DB_TLS_*` variables

A simpler toggle-based approach. Set `FERRUM_DB_TLS_ENABLED=true` to enable TLS with `sslmode=require` (PostgreSQL) or `ssl-mode=REQUIRED` (MySQL), then optionally provide certificate paths.

```bash
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL="postgres://user:pass@db.example.com/ferrum" \
FERRUM_DB_TLS_ENABLED=true \
FERRUM_DB_TLS_CA_CERT_PATH=/certs/ca.pem \
FERRUM_DB_TLS_CLIENT_CERT_PATH=/certs/client.pem \
FERRUM_DB_TLS_CLIENT_KEY_PATH=/certs/client-key.pem
```

Set `FERRUM_DB_TLS_INSECURE=true` to skip certificate verification (testing only).

> **Note:** If both `FERRUM_DB_SSL_*` and `FERRUM_DB_TLS_*` variables are set, the SSL parameters are appended to the connection URL first, then the TLS layer applies on top. Use one approach or the other to avoid confusion.

### Frontend mTLS (Client Certificate Verification)

Ferrum can require clients to present a valid TLS certificate when connecting to the proxy HTTPS listener. This is configured by providing a CA bundle containing the trusted certificate authorities used to verify client certificates.

```bash
# Enable frontend mTLS on the proxy listener
FERRUM_PROXY_TLS_CERT_PATH=/certs/server.pem \
FERRUM_PROXY_TLS_KEY_PATH=/certs/server-key.pem \
FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH=/certs/client-ca-bundle.pem
```

Clients must then present a valid certificate signed by one of the CAs in the bundle:

```bash
curl --cert /certs/client.pem --key /certs/client-key.pem \
  https://gateway.example.com:8443/api/v1/resource
```

The admin API supports the same pattern with `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` for mTLS on the admin HTTPS listener.

### Backend mTLS

Configure per-proxy for mutual TLS to backends:
```yaml
backend_tls_client_cert_path: "/path/to/client-cert.pem"
backend_tls_client_key_path: "/path/to/client-key.pem"
backend_tls_verify_server_cert: true
backend_tls_server_ca_cert_path: "/path/to/ca.pem"
```

### JWT Secrets

- Use strong, randomly generated secrets for `FERRUM_ADMIN_JWT_SECRET` and `FERRUM_CP_GRPC_JWT_SECRET`
- Store secrets securely (environment variables, secret managers)
- Rotate secrets by updating the environment variable and restarting

### Credential Hashing

Consumer passwords (for `basic_auth`) are stored as bcrypt hashes. The Admin API automatically hashes plaintext passwords on creation/update.

## Troubleshooting

| Issue | Solution |
|---|---|
| `Configuration validation failed: duplicate listen_path` | Ensure all proxy `listen_path` values are unique |
| `FERRUM_MODE not set` | Set the `FERRUM_MODE` environment variable |
| `Database connection failed` | Verify `FERRUM_DB_TYPE` and `FERRUM_DB_URL` are correct |
| `401 Unauthorized on Admin API` | Check that your JWT is signed with `FERRUM_ADMIN_JWT_SECRET` |
| `404 Not Found on proxy request` | Verify the request path matches a configured `listen_path` prefix |
| `502 Bad Gateway` | Backend is unreachable; check `backend_host`, `backend_port`, DNS, and timeouts |
| `429 Too Many Requests` | Rate limit exceeded; check `rate_limiting` plugin config |
| DP not receiving config | Verify `FERRUM_DP_GRPC_AUTH_TOKEN` is a valid JWT signed with `FERRUM_CP_GRPC_JWT_SECRET` |

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Write tests for new functionality
4. Ensure all tests pass (`cargo test`)
5. Run `cargo clippy` and `cargo fmt`
6. Submit a pull request

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
