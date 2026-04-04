# Configuration Reference

Ferrum Edge is configured primarily through environment variables. An optional `ferrum.conf` file can provide defaults.

## Environment Variables

### Core Settings

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_CONF_PATH` | No | `./ferrum.conf` | Path to optional conf file (provides defaults; env vars override) |
| `FERRUM_MODE` | **Yes** | — | Operating mode: `database`, `file`, `cp`, `dp`, `migrate` |
| `FERRUM_LOG_LEVEL` | No | `error` | Log verbosity: `error`, `warn`, `info`, `debug`, `trace` |

### Proxy Listener

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_PROXY_HTTP_PORT` | No | `8000` | HTTP proxy listener port |
| `FERRUM_PROXY_HTTPS_PORT` | No | `8443` | HTTPS proxy listener port |
| `FERRUM_PROXY_BIND_ADDRESS` | No | `0.0.0.0` | Bind address for proxy listeners (HTTP, HTTPS, HTTP/3). Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_FRONTEND_TLS_CERT_PATH` | If HTTPS | — | PEM certificate the gateway presents to incoming clients (HTTPS, WebSocket, gRPC, TCP/TLS) |
| `FERRUM_FRONTEND_TLS_KEY_PATH` | If HTTPS | — | PEM private key for the gateway's frontend TLS certificate |

### Admin API

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ADMIN_HTTP_PORT` | No | `9000` | Admin API HTTP port |
| `FERRUM_ADMIN_HTTPS_PORT` | No | `9443` | Admin API HTTPS port |
| `FERRUM_ADMIN_BIND_ADDRESS` | No | `0.0.0.0` | Bind address for admin listeners (HTTP, HTTPS). Set to `::` for dual-stack IPv4+IPv6 |
| `FERRUM_ADMIN_TLS_CERT_PATH` | If HTTPS | — | Path to admin TLS certificate |
| `FERRUM_ADMIN_TLS_KEY_PATH` | If HTTPS | — | Path to admin TLS private key |
| `FERRUM_ADMIN_JWT_SECRET` | DB/CP modes | — | HS256 secret for Admin API JWT auth |
| `FERRUM_ADMIN_READ_ONLY` | No | `false` | Set Admin API to read-only mode (DP mode defaults to true) |
| `FERRUM_ADMIN_RESTORE_MAX_BODY_SIZE_MIB` | No | `100` | Max request body size in MiB for `POST /restore` |

### Database

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DB_TYPE` | DB/CP modes | — | Database type: `postgres`, `mysql`, `sqlite` |
| `FERRUM_DB_URL` | DB/CP modes | — | Database connection string |
| `FERRUM_DB_POLL_INTERVAL` | No | `30` | Seconds between DB config polls. Incremental polling is always enabled with automatic fallback to full reload on error. |
| `FERRUM_DB_POLL_CHECK_INTERVAL` | No | `5` | Seconds between DB connectivity checks |
| `FERRUM_DB_CONFIG_BACKUP_PATH` | No | — | Path to externally provided JSON config backup. Used as startup fallback when the database is unreachable. |
| `FERRUM_DB_FAILOVER_URLS` | No | — | Comma-separated failover database URLs |
| `FERRUM_DB_READ_REPLICA_URL` | No | — | Read replica URL for config polling |

### Database TLS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DB_TLS_ENABLED` | No | `false` | Enable TLS for database connections |
| `FERRUM_DB_TLS_CA_CERT_PATH` | No | — | Path to CA certificate for database TLS verification |
| `FERRUM_DB_TLS_CLIENT_CERT_PATH` | No | — | Path to client certificate for database mTLS |
| `FERRUM_DB_TLS_CLIENT_KEY_PATH` | No | — | Path to client private key for database mTLS |
| `FERRUM_DB_TLS_INSECURE` | No | `false` | Skip certificate verification for database TLS (testing only) |
| `FERRUM_DB_SSL_MODE` | No | — | Database SSL mode: `disable`, `prefer`, `require`, `verify-ca`, `verify-full` |
| `FERRUM_DB_SSL_ROOT_CERT` | No | — | Path to CA certificate for database server verification |
| `FERRUM_DB_SSL_CLIENT_CERT` | No | — | Path to client certificate for database mTLS |
| `FERRUM_DB_SSL_CLIENT_KEY` | No | — | Path to client private key for database mTLS |

See [database_tls.md](database_tls.md) for detailed configuration examples and SSL mode descriptions.

### File Mode

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_FILE_CONFIG_PATH` | File mode | — | Path to YAML/JSON config file |

### Control Plane / Data Plane

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_CP_GRPC_LISTEN_ADDR` | CP mode | — | gRPC listen address (e.g., `0.0.0.0:50051`) |
| `FERRUM_CP_GRPC_JWT_SECRET` | CP mode | — | HS256 secret for DP node authentication |
| `FERRUM_DP_CP_GRPC_URL` | DP mode | — | Control Plane gRPC URL |
| `FERRUM_DP_GRPC_AUTH_TOKEN` | DP mode | — | Pre-signed HS256 JWT for CP authentication |

See [cp_dp_mode.md](cp_dp_mode.md) for CP/DP TLS environment variables (`FERRUM_CP_GRPC_TLS_*`, `FERRUM_DP_GRPC_TLS_*`).

### Size Limits

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_MAX_HEADER_SIZE_BYTES` | No | `32768` | Maximum total request header size (all headers combined) |
| `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` | No | `16384` | Maximum size of any single request header (name + value) |
| `FERRUM_MAX_HEADER_COUNT` | No | `100` | Max number of request headers allowed (0=unlimited) |
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | No | `10485760` | Maximum request body size (0=unlimited) |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | No | `10485760` | Maximum response body size from backends (0=unlimited) |
| `FERRUM_MAX_URL_LENGTH_BYTES` | No | `8192` | Maximum URL length in bytes (path + query string, 0=unlimited) |
| `FERRUM_MAX_QUERY_PARAMS` | No | `100` | Maximum number of query parameters allowed (0=unlimited) |
| `FERRUM_MAX_GRPC_RECV_SIZE_BYTES` | No | `4194304` | Maximum total received gRPC payload size in bytes (0=unlimited) |
| `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` | No | `16777216` | Maximum WebSocket frame size in bytes; max message size = 4x frame size |

See [size_limits.md](size_limits.md) for detailed sizing guidance.

### DNS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_DNS_CACHE_TTL_SECONDS` | No | `300` | Default DNS cache TTL |
| `FERRUM_DNS_OVERRIDES` | No | `{}` | JSON map of hostname→IP static overrides |
| `FERRUM_DNS_RESOLVER_ADDRESS` | No | resolv.conf | Comma-separated nameservers (ip[:port]) |
| `FERRUM_DNS_RESOLVER_HOSTS_FILE` | No | `/etc/hosts` | Path to custom hosts file |
| `FERRUM_DNS_ORDER` | No | `CACHE,SRV,A,CNAME` | Record type query order (comma-separated) |
| `FERRUM_DNS_VALID_TTL` | No | response TTL | Override TTL (seconds) for positive records |
| `FERRUM_DNS_STALE_TTL` | No | `3600` | Stale data usage time (seconds) during refresh |
| `FERRUM_DNS_ERROR_TTL` | No | `5` | TTL (seconds) for errors/empty responses |
| `FERRUM_DNS_WARMUP_CONCURRENCY` | No | `500` | Maximum concurrent DNS warmup resolutions during startup/config reload |
| `FERRUM_DNS_SLOW_THRESHOLD_MS` | No | Disabled | Log slow DNS resolutions above this threshold (ms) |

See [dns_resolver.md](dns_resolver.md) for full configuration reference.

### TLS / mTLS

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_TLS_CA_BUNDLE_PATH` | No | — | Path to PEM CA bundle for all outbound TLS verification |
| `FERRUM_BACKEND_TLS_CLIENT_CERT_PATH` | No | — | Path to client certificate for backend mTLS |
| `FERRUM_BACKEND_TLS_CLIENT_KEY_PATH` | No | — | Path to client private key for backend mTLS |
| `FERRUM_FRONTEND_TLS_CLIENT_CA_BUNDLE_PATH` | No | — | Path to client CA bundle for mTLS verification |
| `FERRUM_ADMIN_TLS_CLIENT_CA_BUNDLE_PATH` | No | — | Path to admin client CA bundle for mTLS verification |
| `FERRUM_ADMIN_TLS_NO_VERIFY` | No | `false` | Disable admin TLS certificate verification (testing only) |
| `FERRUM_TLS_NO_VERIFY` | No | `false` | Disable outbound TLS verification for all connections (testing only) |
| `FERRUM_TLS_MIN_VERSION` | No | `1.2` | Minimum TLS protocol version, inbound + outbound (`1.2` or `1.3`) |
| `FERRUM_TLS_MAX_VERSION` | No | `1.3` | Maximum TLS protocol version, inbound + outbound (`1.2` or `1.3`) |
| `FERRUM_TLS_CIPHER_SUITES` | No | *(secure defaults)* | Comma-separated cipher suites, inbound + outbound (see [TLS Policy Hardening](frontend_tls.md#tls-policy-hardening)) |
| `FERRUM_TLS_CURVES` | No | `X25519,secp256r1` | Comma-separated key exchange groups, inbound + outbound |
| `FERRUM_TLS_PREFER_SERVER_CIPHER_ORDER` | No | `true` | Prefer server cipher order during TLS 1.2 negotiation (inbound only) |
| `FERRUM_TLS_SESSION_CACHE_SIZE` | No | `4096` | TLS session resumption cache size (inbound only, TLS 1.2 stateful session IDs) |

These TLS policy settings apply uniformly to both inbound (frontend) and outbound (backend) connections across all TLS-capable protocols (HTTP/1.1, HTTP/2, HTTP/3, gRPC, WebSocket, TCP-TLS). DTLS uses a separate library and is not affected. See [frontend_tls.md](frontend_tls.md) and [backend_mtls.md](backend_mtls.md) for detailed TLS configuration guides.

### HTTP/3 (QUIC)

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ENABLE_HTTP3` | No | `false` | Enable HTTP/3 (QUIC) listener on the HTTPS port |
| `FERRUM_HTTP3_IDLE_TIMEOUT` | No | `30` | HTTP/3 connection idle timeout in seconds |
| `FERRUM_HTTP3_MAX_STREAMS` | No | `1000` | Maximum concurrent HTTP/3 streams per connection |
| `FERRUM_HTTP3_STREAM_RECEIVE_WINDOW` | No | `8388608` | HTTP/3 per-stream receive window in bytes (default: 8 MiB) |
| `FERRUM_HTTP3_RECEIVE_WINDOW` | No | `33554432` | HTTP/3 connection-level receive window in bytes (default: 32 MiB) |
| `FERRUM_HTTP3_SEND_WINDOW` | No | `8388608` | HTTP/3 per-connection send window in bytes (default: 8 MiB) |

### Stream Proxy (TCP/UDP/DTLS)

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_STREAM_PROXY_BIND_ADDRESS` | No | `0.0.0.0` | Bind address for TCP/UDP/DTLS stream proxy listeners |
| `FERRUM_DTLS_CERT_PATH` | No | — | PEM certificate for frontend DTLS termination (ECDSA P-256 or Ed25519 only) |
| `FERRUM_DTLS_KEY_PATH` | No | — | PEM private key for frontend DTLS termination |
| `FERRUM_DTLS_CLIENT_CA_CERT_PATH` | No | — | PEM CA certificate for verifying DTLS client certs (frontend mTLS) |

See [tcp_udp_proxy.md](tcp_udp_proxy.md) for full TCP/UDP proxy documentation.

### Authentication

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_BASIC_AUTH_HMAC_SECRET` | No | `ferrum-edge-change-me-in-production` | Server secret for HMAC-SHA256 password verification (~1μs). The Admin API stores `hmac_sha256:<hex>` hashes. Existing bcrypt hashes remain valid. **Must be changed in production** — using the default allows anyone who knows it to compute valid credential hashes. |
| `FERRUM_TRUSTED_PROXIES` | No | — | Comma-separated trusted proxy CIDRs/IPs for client IP resolution via `X-Forwarded-For` |
| `FERRUM_REAL_IP_HEADER` | No | — | Authoritative real-IP header name (e.g., `CF-Connecting-IP`, `X-Real-IP`) |

See [client_ip_resolution.md](client_ip_resolution.md) for the security model and deployment examples.

### Observability

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING` | No | `false` | Track streaming response total latency (adds per-stream overhead) |
| `FERRUM_PLUGIN_HTTP_SLOW_THRESHOLD_MS` | No | `1000` | Threshold (ms) for logging slow plugin outbound HTTP calls |
| `FERRUM_PLUGIN_HTTP_MAX_RETRIES` | No | `0` | Retry count for safe plugin outbound HTTP calls on transport failures (JWKS/OIDC fetches, etc.) |
| `FERRUM_PLUGIN_HTTP_RETRY_DELAY_MS` | No | `100` | Delay between plugin HTTP transport retry attempts |

### Runtime Tuning

| Variable | Required | Default | Description |
|---|---|---|---|
| `FERRUM_WORKER_THREADS` | No | CPU cores | Tokio async worker threads |
| `FERRUM_BLOCKING_THREADS` | No | `512` | Max tokio blocking threads for file/DNS I/O |
| `FERRUM_MAX_CONNECTIONS` | No | `100000` | Max concurrent proxy connections; queues when full, `0` = unlimited |
| `FERRUM_TCP_LISTEN_BACKLOG` | No | `2048` | TCP listen backlog size (min 128); raise `net.core.somaxconn` to match |
| `FERRUM_SERVER_HTTP2_MAX_CONCURRENT_STREAMS` | No | `1000` | Server-side HTTP/2 max concurrent streams per inbound connection |

See [infrastructure_sizing.md](infrastructure_sizing.md) for detailed tuning guidance.

The full list of 90+ environment variables is defined in `src/config/env_config.rs`.

## Configuration File (`ferrum.conf`)

As an alternative to environment variables, the gateway supports a `ferrum.conf` configuration file for setting reasonable defaults. Environment variables **take precedence** over values in the conf file, allowing operators to define baseline configuration in the file and override specific values per deployment via env vars.

**File location:**
- Default: `./ferrum.conf` (current working directory)
- Override with the `FERRUM_CONF_PATH` environment variable (the only setting that must remain an env var)
- If the file does not exist at the default path, it is silently skipped

**Format:** Simple key-value pairs using the same `FERRUM_*` names as environment variables:

```conf
# Operating mode
FERRUM_MODE = file
FERRUM_FILE_CONFIG_PATH = /etc/ferrum/config.yaml
FERRUM_LOG_LEVEL = info

# Proxy ports
FERRUM_PROXY_HTTP_PORT = 8080
FERRUM_PROXY_HTTPS_PORT = 8443

# TLS hardening
FERRUM_TLS_MIN_VERSION = 1.3

# Quoted values for paths with spaces
FERRUM_FRONTEND_TLS_CERT_PATH = "/path/with spaces/cert.pem"
```

- Lines starting with `#` are comments
- Inline comments are supported: `KEY = value # comment`
- Values can be quoted with double or single quotes (quotes are stripped)
- Empty lines are ignored

A reference `ferrum.conf` with all available fields and descriptions is included in the repository root.

**Precedence order:** environment variables > `ferrum.conf` > built-in defaults

## File Mode Configuration Format

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
    # Response body mode: "stream" (default) or "buffer"
    # response_body_mode: stream
    # Connection pooling settings (optional - override global defaults)
    pool_idle_timeout_seconds: 120
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

### Stream Proxy (TCP/UDP/DTLS)

Stream proxies use `listen_port` instead of `listen_path` and bind to dedicated ports:

```yaml
proxies:
  # TCP proxy with TLS origination to backend
  - id: "postgres-proxy"
    listen_path: ""
    listen_port: 5432
    backend_protocol: tcp_tls
    backend_host: "db.internal"
    backend_port: 5432

  # UDP proxy with DTLS encryption to backend
  - id: "iot-proxy"
    listen_path: ""
    listen_port: 5684
    backend_protocol: dtls
    backend_host: "iot-backend.internal"
    backend_port: 5684
    backend_tls_verify_server_cert: false
    udp_idle_timeout_seconds: 120

  # Full DTLS e2e: DTLS client → gateway → DTLS backend
  - id: "secure-iot"
    listen_path: ""
    listen_port: 5685
    backend_protocol: dtls
    backend_host: "secure-iot.internal"
    backend_port: 5684
    frontend_tls: true
    backend_tls_verify_server_cert: false
```

**Port validation:** Each `listen_port` must be unique across all stream proxies and must not conflict with gateway reserved ports (`FERRUM_PROXY_HTTP_PORT`, `FERRUM_PROXY_HTTPS_PORT`, `FERRUM_ADMIN_HTTP_PORT`, `FERRUM_ADMIN_HTTPS_PORT`, CP gRPC port). In database mode, the Admin API also probes OS-level port availability before accepting the config. See [tcp_udp_proxy.md](tcp_udp_proxy.md) for full documentation including per-mode behavior.

### Service Discovery

Upstreams can discover targets dynamically using a `service_discovery` block. Three providers are supported:

**DNS-SD** (DNS Service Discovery):
```yaml
upstreams:
  - id: "my-upstream"
    targets: []
    algorithm: round_robin
    service_discovery:
      provider: dns_sd
      dns_sd:
        service_name: "_http._tcp.my-service.local"
        poll_interval_seconds: 30
```

**Kubernetes**:
```yaml
upstreams:
  - id: "k8s-upstream"
    targets: []
    algorithm: least_connections
    service_discovery:
      provider: kubernetes
      kubernetes:
        namespace: "default"
        service_name: "my-service"
        port_name: "http"
        poll_interval_seconds: 15
```

**Consul**:
```yaml
upstreams:
  - id: "consul-upstream"
    targets:
      - host: "fallback.example.com"
        port: 8080
        weight: 1
    algorithm: round_robin
    service_discovery:
      provider: consul
      consul:
        address: "http://consul.internal:8500"
        service_name: "my-service"
        datacenter: "dc1"
        poll_interval_seconds: 10
        token: "consul-acl-token"
```

Discovered targets are merged with any statically defined `targets`. If the provider is unreachable, the upstream keeps its last-known targets to maintain availability.

## Database Schema

When using Database or CP modes, Ferrum auto-creates the following tables on startup:

- **`proxies`** — Proxy route definitions (with `UNIQUE` constraint on `listen_path`)
- **`consumers`** — API consumer/user definitions
- **`plugin_configs`** — Plugin configurations (global or per-proxy scoped)
- **`proxy_plugins`** — Many-to-many linking proxies to plugin configs
- **`upstreams`** — Upstream groups for load-balanced backends (targets stored as JSON, with algorithm and health check configuration)

See [migrations.md](migrations.md) for schema migration details.
