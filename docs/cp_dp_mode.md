# Control Plane / Data Plane Mode

Ferrum Edge supports a distributed CP/DP architecture where one Control Plane instance manages configuration and multiple Data Plane instances handle traffic. The CP pushes configuration to DPs via gRPC server-streaming, enabling centralized management with horizontally scaled traffic handling.

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

### Transport Security (TLS/mTLS)

The gRPC channel between CP and DP supports three security modes:

| Mode | CP Configuration | DP Configuration | Use Case |
|------|-----------------|-----------------|----------|
| **Plaintext** | No TLS env vars | `http://` URL | Development, trusted networks |
| **One-way TLS** | `FERRUM_CP_GRPC_TLS_CERT_PATH` + `_KEY_PATH` | `https://` URL + `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | DP verifies CP identity |
| **Mutual TLS (mTLS)** | Above + `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` | Above + `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` + `_KEY_PATH` | Both sides verify identity |

**One-way TLS**: The CP presents a server certificate; the DP verifies it against a trusted CA. This encrypts the channel and prevents MITM attacks on the JWT token and config data.

**Mutual TLS**: In addition to server verification, the CP requires a client certificate from the DP, verified against a trusted CA. This provides certificate-based DP identity in addition to JWT authentication.

### Config Sync Flow

1. DP connects to CP's gRPC endpoint with JWT authentication
2. CP sends an immediate `ConfigUpdate` with the full current config (type=FULL_SNAPSHOT)
3. CP polls the database incrementally at `FERRUM_DB_POLL_INTERVAL` seconds using indexed `updated_at` queries
4. When changes are detected, CP broadcasts a `ConfigUpdate` with type=DELTA containing only the added/modified/removed resources
5. DPs apply the delta surgically — only affected caches (router, plugin, consumer, load balancer) are updated
6. If the incremental poll fails, CP falls back to a full database reload and broadcasts a FULL_SNAPSHOT

### Update Types

The `ConfigUpdate` proto message carries an `UpdateType` discriminator:

| Type | Value | When | Content |
|------|-------|------|---------|
| `FULL_SNAPSHOT` | 0 | Initial subscription, fallback | Entire `GatewayConfig` as JSON |
| `DELTA` | 1 | Incremental database changes | `IncrementalResult` with only changed resources |

DPs handle both types transparently: full snapshots replace the entire config; deltas are applied via `ProxyState::apply_incremental()` which patches the in-memory config and performs surgical cache updates.

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
| `FERRUM_CP_GRPC_TLS_CERT_PATH` | No | PEM certificate for gRPC TLS |
| `FERRUM_CP_GRPC_TLS_KEY_PATH` | No | PEM private key for gRPC TLS |
| `FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH` | No | PEM CA for verifying DP client certs (mTLS) |
| `FERRUM_ADMIN_JWT_SECRET` | Yes | JWT secret for the Admin API |
| `FERRUM_DB_TYPE` | Yes | Database type (`sqlite` or `postgres`) |
| `FERRUM_DB_URL` | Yes | Database connection URL |
| `FERRUM_DB_POLL_INTERVAL` | No | Config poll interval in seconds (default: 30) |

### Data Plane

| Variable | Required | Description |
|----------|----------|-------------|
| `FERRUM_MODE` | Yes | Set to `dp` |
| `FERRUM_DP_CP_GRPC_URL` | Yes | CP gRPC endpoint URL (`http://` or `https://`) |
| `FERRUM_DP_GRPC_AUTH_TOKEN` | Yes | JWT token for authenticating with CP |
| `FERRUM_DP_GRPC_TLS_CA_CERT_PATH` | No | PEM CA cert for verifying CP server cert |
| `FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH` | No | PEM client cert for mTLS |
| `FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH` | No | PEM client key for mTLS |
| `FERRUM_DP_GRPC_TLS_NO_VERIFY` | No | Skip TLS verification (testing only) |
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

### Control Plane (Plaintext)

```bash
FERRUM_MODE=cp \
FERRUM_DB_TYPE=sqlite \
FERRUM_DB_URL=sqlite://ferrum.db \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051 \
FERRUM_CP_GRPC_JWT_SECRET=grpc-shared-secret \
FERRUM_DB_POLL_INTERVAL=10 \
./ferrum-edge
```

### Data Plane (Plaintext)

```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URL=http://cp-host:50051 \
FERRUM_DP_GRPC_AUTH_TOKEN=<jwt-token-signed-with-grpc-shared-secret> \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
FERRUM_PROXY_HTTP_PORT=8000 \
FERRUM_PROXY_HTTPS_PORT=8443 \
./ferrum-edge
```

### Control Plane (mTLS)

```bash
FERRUM_MODE=cp \
FERRUM_DB_TYPE=postgres \
FERRUM_DB_URL=postgres://user:pass@db:5432/ferrum \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
FERRUM_CP_GRPC_LISTEN_ADDR=0.0.0.0:50051 \
FERRUM_CP_GRPC_JWT_SECRET=grpc-shared-secret \
FERRUM_CP_GRPC_TLS_CERT_PATH=/certs/server.pem \
FERRUM_CP_GRPC_TLS_KEY_PATH=/certs/server-key.pem \
FERRUM_CP_GRPC_TLS_CLIENT_CA_PATH=/certs/ca.pem \
./ferrum-edge
```

### Data Plane (mTLS)

```bash
FERRUM_MODE=dp \
FERRUM_DP_CP_GRPC_URL=https://cp-host:50051 \
FERRUM_DP_GRPC_AUTH_TOKEN=<jwt-token> \
FERRUM_DP_GRPC_TLS_CA_CERT_PATH=/certs/ca.pem \
FERRUM_DP_GRPC_TLS_CLIENT_CERT_PATH=/certs/dp-client.pem \
FERRUM_DP_GRPC_TLS_CLIENT_KEY_PATH=/certs/dp-client-key.pem \
FERRUM_ADMIN_JWT_SECRET=admin-secret-key \
./ferrum-edge
```

## DP Admin API

The Data Plane exposes a read-only Admin API for monitoring:
- All write operations (create/update/delete proxies, consumers, plugins) return `403 Forbidden`
- Read operations (list proxies, consumers, plugin configs, health checks) are served from the DP's in-memory cached config
- Responses include `X-Data-Source: cached` header to indicate the data comes from the cache rather than a live database
- The `/health` endpoint includes `cached_config` details (availability, loaded_at, proxy/consumer counts)
- The admin API always reflects the DP's currently cached config received from the CP
