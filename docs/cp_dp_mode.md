# Control Plane / Data Plane Mode

Ferrum Gateway supports a distributed CP/DP architecture where one Control Plane instance manages configuration and multiple Data Plane instances handle traffic. The CP pushes configuration to DPs via gRPC server-streaming, enabling centralized management with horizontally scaled traffic handling.

## Architecture

```
                          ┌──────────────────────┐
                          │    Control Plane      │
                          │                       │
                          │  ┌─────────────────┐  │
        ┌─────────────────┤  │   Database /     │  │
        │  Admin API      │  │   File Config    │  │
        │  (read/write)   │  └────────┬────────┘  │
        └─────────────────┤           │            │
                          │  ┌────────▼────────┐  │
                          │  │  gRPC Server     │  │
                          │  │  (ConfigSync)    │  │
                          │  └──┬─────────┬──┘  │
                          └─────┼─────────┼─────┘
                                │         │
                    gRPC Subscribe    gRPC Subscribe
                    (streaming)       (streaming)
                                │         │
                    ┌───────────▼──┐  ┌───▼───────────┐
                    │  Data Plane  │  │  Data Plane    │
                    │  Instance 1  │  │  Instance 2    │
                    │              │  │                │
                    │  ┌────────┐  │  │  ┌────────┐   │
                    │  │ Cached │  │  │  │ Cached │   │
                    │  │ Config │  │  │  │ Config │   │
                    │  └────┬───┘  │  │  └────┬───┘   │
                    │       │      │  │       │       │
                    │  Proxy Traffic│  │  Proxy Traffic│
                    │  (HTTP/S/H3) │  │  (HTTP/S/H3)  │
                    │              │  │               │
                    │  Admin API   │  │  Admin API    │
                    │  (read-only) │  │  (read-only)  │
                    └──────────────┘  └───────────────┘
```

## Communication Protocol

### gRPC with Protocol Buffers

CP and DP communicate via the `ConfigSync` gRPC service defined in `proto/ferrum.proto`:

- **`Subscribe(SubscribeRequest) -> stream ConfigUpdate`** — Server-streaming RPC. The DP subscribes and receives an initial full config snapshot followed by streaming updates whenever the CP detects config changes.
- **`GetFullConfig(FullConfigRequest) -> FullConfigResponse`** — Unary RPC for on-demand full config retrieval.

### Authentication

All gRPC calls are authenticated with JWT HS256 tokens:
- The CP validates the `authorization` header (Bearer token) on every RPC
- The DP sends its auth token in the gRPC metadata on every request
- Both CP and DP use the same shared secret for JWT signing/verification

### Config Sync Flow

1. DP connects to CP's gRPC endpoint with JWT authentication
2. CP sends an immediate `ConfigUpdate` with the full current config (type=FULL_SNAPSHOT)
3. CP polls the database at `FERRUM_DB_POLL_INTERVAL` seconds
4. When config changes are detected, CP broadcasts a `ConfigUpdate` to all subscribed DPs
5. DPs atomically update their cached config (router cache, plugin cache, consumer index)

### Resilience

The CP/DP architecture is designed so that data source outages are invisible to API consumers:

- **Auto-reconnect**: If the CP connection drops, the DP retries every 5 seconds
- **Cached config**: DPs continue serving traffic with their last known config indefinitely during CP outages
- **Connect timeout**: DP uses a 10-second connect timeout per attempt
- **CP database outage**: If the CP's database goes offline, the CP continues serving its cached config to DPs via gRPC. It does not broadcast stale updates — DPs simply retain their last known config. When the database recovers, the next poll picks up any changes and broadcasts them.
- **Admin API fallback**: Both CP and DP admin API read endpoints fall back to the in-memory cached config when the database is unavailable. Responses served from cache include an `X-Data-Source: cached` header. Write operations require a live database and return `503` if unavailable.
- **Health visibility**: The `/health` endpoint reports `cached_config` status (available, loaded_at, proxy/consumer counts) so operators can see whether the node is running on cached data.

## Environment Variables

### Control Plane

| Variable | Required | Description |
|----------|----------|-------------|
| `FERRUM_MODE` | Yes | Set to `cp` |
| `FERRUM_CP_GRPC_LISTEN_ADDR` | Yes | gRPC listen address (e.g., `0.0.0.0:50051`) |
| `FERRUM_CP_GRPC_JWT_SECRET` | Yes | Shared secret for JWT authentication |
| `FERRUM_ADMIN_JWT_SECRET` | Yes | JWT secret for the Admin API |
| `FERRUM_DB_TYPE` | Yes | Database type (`sqlite` or `postgres`) |
| `FERRUM_DB_URL` | Yes | Database connection URL |
| `FERRUM_DB_POLL_INTERVAL` | No | Config poll interval in seconds (default: 30) |

### Data Plane

| Variable | Required | Description |
|----------|----------|-------------|
| `FERRUM_MODE` | Yes | Set to `dp` |
| `FERRUM_DP_CP_GRPC_URL` | Yes | CP gRPC endpoint URL (e.g., `http://cp-host:50051`) |
| `FERRUM_DP_GRPC_AUTH_TOKEN` | Yes | JWT token for authenticating with CP |
| `FERRUM_ADMIN_JWT_SECRET` | Yes | JWT secret for the read-only Admin API |
| `FERRUM_PROXY_HTTP_PORT` | No | HTTP proxy port (default: 8000) |
| `FERRUM_PROXY_HTTPS_PORT` | No | HTTPS proxy port (default: 8443) |

## Example Deployment

### Generate JWT Token

The DP auth token must be a valid JWT signed with the CP's `FERRUM_CP_GRPC_JWT_SECRET`:

```bash
# Using a JWT tool or library, create a token with HS256:
# Header: {"alg": "HS256", "typ": "JWT"}
# Payload: {"sub": "dp-node", "role": "data_plane"}
# Secret: <same as FERRUM_CP_GRPC_JWT_SECRET>
```

### Control Plane

```bash
FERRUM_MODE=cp \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL=sqlite://ferrum.db \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051 \
FERRUM_CP_GRPC_JWT_SECRET=grpc-shared-secret \
FERRUM_DB_POLL_INTERVAL=10 \
./ferrum-gateway
```

### Data Plane

```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URL=http://cp-host:50051 \
FERRUM_DP_GRPC_AUTH_TOKEN=<jwt-token-signed-with-grpc-shared-secret> \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
FERRUM_PROXY_HTTP_PORT=8000 \
FERRUM_PROXY_HTTPS_PORT=8443 \
./ferrum-gateway
```

## DP Admin API

The Data Plane exposes a read-only Admin API for monitoring:
- All write operations (create/update/delete proxies, consumers, plugins) return `403 Forbidden`
- Read operations (list proxies, consumers, plugin configs, health checks) are served from the DP's in-memory cached config
- Responses include `X-Data-Source: cached` header to indicate the data comes from the cache rather than a live database
- The `/health` endpoint includes `cached_config` details (availability, loaded_at, proxy/consumer counts)
- The admin API always reflects the DP's currently cached config received from the CP
