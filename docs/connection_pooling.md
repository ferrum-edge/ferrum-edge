# Connection Pooling

Ferrum Edge includes enterprise-grade connection pooling that significantly improves performance by reusing HTTP/HTTPS/WebSocket connections. Pool key generation uses thread-local `String` buffers so that cache hits (99%+ of requests) incur zero heap allocation — only the cold path (first request per unique proxy config) allocates for DashMap insertion.

## Hybrid Configuration

Connection pooling uses a **hybrid configuration** with global defaults and per-proxy overrides.

### Global Environment Variables

```bash
# Set global defaults (optional - shown with defaults)
FERRUM_POOL_MAX_IDLE_PER_HOST=64
FERRUM_POOL_IDLE_TIMEOUT_SECONDS=90
FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE=true
FERRUM_POOL_ENABLE_HTTP2=true
FERRUM_POOL_TCP_KEEPALIVE_SECONDS=60
FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS=30
FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS=45
# HTTP/2 flow control tuning
FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE=8388608       # 8 MiB
FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE=33554432   # 32 MiB
FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW=false
FERRUM_POOL_HTTP2_MAX_FRAME_SIZE=65535
FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS=1000
FERRUM_GRPC_POOL_READY_WAIT_MS=1
```

### Per-Proxy Overrides

```yaml
proxies:
  - id: "high-traffic-api"
    pool_enable_http2: false
    pool_tcp_keepalive_seconds: 30
    pool_http2_keep_alive_interval_seconds: 15
    pool_http2_keep_alive_timeout_seconds: 5
    pool_http2_initial_stream_window_size: 16777216   # 16 MiB
    pool_http2_initial_connection_window_size: 67108864  # 64 MiB
    pool_http2_adaptive_window: true
```

## Configuration Reference

| Setting | Global Default | Description |
|---------|----------------|-------------|
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | `64` | Maximum idle connections per backend host (min: 4, max: 1024) |
| `FERRUM_POOL_IDLE_TIMEOUT_SECONDS` | `90` | Seconds before idle connections are closed |
| `FERRUM_POOL_ENABLE_HTTP_KEEP_ALIVE` | `true` | Enable HTTP keep-alive for connection reuse |
| `FERRUM_POOL_ENABLE_HTTP2` | `true` | Enable HTTP/2 multiplexing when supported |
| `FERRUM_POOL_TCP_KEEPALIVE_SECONDS` | `60` | TCP keep-alive interval in seconds |
| `FERRUM_POOL_HTTP2_KEEP_ALIVE_INTERVAL_SECONDS` | `30` | HTTP/2 keep-alive ping interval in seconds |
| `FERRUM_POOL_HTTP2_KEEP_ALIVE_TIMEOUT_SECONDS` | `45` | HTTP/2 keep-alive timeout in seconds |
| `FERRUM_POOL_HTTP2_INITIAL_STREAM_WINDOW_SIZE` | `8388608` | HTTP/2 per-stream flow-control window (bytes). Default: 8 MiB |
| `FERRUM_POOL_HTTP2_INITIAL_CONNECTION_WINDOW_SIZE` | `33554432` | HTTP/2 connection-level flow-control window (bytes). Default: 32 MiB |
| `FERRUM_POOL_HTTP2_ADAPTIVE_WINDOW` | `true` | Enable adaptive flow-control (BDP probing) |
| `FERRUM_POOL_HTTP2_MAX_FRAME_SIZE` | `1048576` | Maximum HTTP/2 frame payload (bytes). Range: 16384–1048576. Default: 1 MiB |
| `FERRUM_POOL_HTTP2_MAX_CONCURRENT_STREAMS` | `1000` | Max concurrent HTTP/2 streams per backend connection |
| `FERRUM_GRPC_POOL_READY_WAIT_MS` | `1` | Milliseconds the dedicated gRPC pool waits for a free H2 stream before opening another backend connection |

## Sizing `FERRUM_POOL_MAX_IDLE_PER_HOST`

This is the single most important pool setting for performance and reliability. It controls how many idle backend connections are kept alive per host.

**Safety bounds:** Minimum **4**, maximum **1024**. Values outside this range are clamped with a warning.

### Recommended Values by Workload

| Workload | Expected Concurrency | Recommended Value | Notes |
|----------|---------------------|-------------------|-------|
| Low-traffic internal API | < 20 concurrent | `16`-`32` | Default of 64 is fine |
| Standard production API | 20-100 concurrent | `64`-`128` | Match peak concurrency per backend |
| High-traffic public API | 100-500 concurrent | `128`-`256` | Monitor backend capacity |
| Health checks / monitoring | Low volume | `16`-`32` | Small responses, fewer idle connections needed |
| WebSocket services | Long-lived connections | `16`-`64` | Pool mainly holds upgrade handshakes |

### How to Choose

1. **Start with the default (64).** This handles most workloads well.
2. **Match your expected peak concurrency.** If your gateway handles 200 concurrent requests to a single backend, set the value to at least `200`.
3. **Monitor for connection churn.** If your logs show frequent "Backend request failed" errors under load, increase this value.
4. **Do not exceed your backend's capacity.** Setting this to 1024 does not help if your backend can only handle 100 concurrent connections.

## Timeout Mechanisms

### TCP Keep-Alive (Transport Layer)
- Prevents connection drops by NAT/firewalls
- Sends packets every N seconds when idle
- Applies to ALL connections (HTTP/1.1, HTTP/2, WebSocket)

### HTTP/2 Keep-Alive (Application Layer)
- Detects dead HTTP/2 connections via PING frames
- Only applies to HTTP/2 connections
- More responsive than TCP keep-alive for HTTP/2

### HTTP Timeouts (Request Layer)
- `backend_connect_timeout_ms`: Connection establishment (default: 5000ms)
- `backend_read_timeout_ms`: Request processing (default: 30000ms)
- Applies during active requests

**Recommended Relationships:**
- HTTP/2 timeout should be **1.5x** the TCP keep-alive interval
- HTTP read timeout should be **2-3x** the HTTP/2 timeout
- TCP keep-alive should be **1.2-1.5x** the HTTP/2 interval

## Protocol-Specific Recommendations

### HTTP/HTTPS APIs
```bash
FERRUM_POOL_MAX_IDLE_PER_HOST=128
FERRUM_POOL_IDLE_TIMEOUT_SECONDS=120
FERRUM_POOL_ENABLE_HTTP2=true
```

### WebSocket Services
```yaml
pool_idle_timeout_seconds: 300
pool_enable_http2: false  # HTTP/1.1 recommended for WebSockets
```

### Auth-Protected APIs
```yaml
pool_enable_http2: false  # Better compatibility with auth plugins
```

## gRPC Saturation Tuning

`FERRUM_GRPC_POOL_READY_WAIT_MS` only affects the dedicated `GrpcConnectionPool`. When all existing gRPC HTTP/2 senders are live but temporarily out of stream capacity, Ferrum waits this long before opening another backend connection.

The default is `1ms`. In one back-to-back local multi-protocol benchmark comparison (`10s`, `200` concurrency, unary echo), `1ms` improved gRPC throughput by about `3.8%` versus `5ms` (`64,278` -> `66,734` requests/sec). Treat that as workload-specific guidance rather than a universal guarantee.

## Performance Impact

In performance tests (8 threads, 100 connections, 30 seconds):

| Test | Requests/sec | Avg Latency | Max Latency |
|------|-------------|-------------|-------------|
| Health Check (gateway) | 88,489 | 1.10ms | 23.80ms |
| Users API (gateway) | 77,010 | 1.24ms | 12.69ms |
| Direct Backend (baseline) | 59,912 | 1.51ms | 3.40ms |

*Results from local run on macOS Apple Silicon, release build, 8 threads, 100 connections, 30s duration.*

## Connection Pool Warmup

By default, Ferrum Edge **pre-establishes backend connections** at startup after DNS warmup completes. This eliminates first-request latency spikes caused by TCP/TLS/QUIC handshakes.

### How It Works

1. After DNS warmup resolves all backend hostnames, the gateway iterates every configured proxy.
2. For each HTTP-family proxy (HTTP, HTTPS, WebSocket, gRPC, H2, H3), it creates connections in the appropriate pool:
   - **Reqwest pool** (HTTP/1.1, HTTPS, WS, WSS): Creates the `reqwest::Client` with full TLS configuration, then sends a lightweight HEAD request to each backend host:port to force TCP/TLS connection establishment. The HTTP response status is ignored — only the transport connection matters.
   - **gRPC pool** (Grpc/Grpcs): Establishes TCP + TLS + HTTP/2 connections (shard 0).
   - **HTTP/2 direct pool** (HTTPS with `enable_http2`): Establishes TCP + TLS + HTTP/2 connections (shard 0).
   - **HTTP/3 pool**: Establishes QUIC + TLS 1.3 connections (shard 0).
3. For upstream-backed proxies, every target in the upstream is warmed individually across all pool types. reqwest internally pools connections by URL host:port, so each target gets its own warmed TCP/TLS connection.
4. **TCP/UDP stream proxies are skipped** — they create per-session connections with no persistent pool to warm.

### Configuration

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_POOL_WARMUP_ENABLED` | `true` | Enable connection pool warmup at startup |
| `FERRUM_POOL_WARMUP_CONCURRENCY` | `500` | Maximum concurrent connection warmup attempts |

### Behavior

- **Best-effort**: Failed warmup connections are logged as warnings but never block startup.
- **Deduplicated**: Multiple proxies sharing the same backend and TLS config produce only one warmup attempt per unique pool key.
- **Uses proxy TLS settings**: Each warmup connection uses the proxy's configured CA cert, mTLS client cert, and server cert verification settings — identical to what the first real request would use.
- **Respects DNS overrides**: Proxies with `dns_override` use the static IP during warmup, just like production traffic.
- **DP mode**: Warmup runs in database and file modes. In Data Plane mode, pools warm naturally when the first config arrives from the Control Plane.

### Disabling Warmup

```bash
# Disable pool warmup (first requests will pay handshake latency)
FERRUM_POOL_WARMUP_ENABLED=false
```

This may be useful in development or when backends are not yet available at gateway startup time.

## Database Pool Observability

The admin `/status` (and `/health`) endpoint includes database connection pool statistics when the database is connected. This helps operators monitor pool utilization and tune `FERRUM_DB_POOL_*` settings.

```json
{
  "database": {
    "status": "connected",
    "type": "postgres",
    "pool": {
      "size": 10,
      "idle": 8,
      "active": 2,
      "max_connections": 10,
      "min_connections": 1,
      "read_replica": {
        "size": 5,
        "idle": 5,
        "active": 0
      }
    }
  }
}
```

| Field | Description |
|-------|-------------|
| `size` | Current number of connections managed by the pool (idle + active) |
| `idle` | Connections available for checkout |
| `active` | Connections currently in use |
| `max_connections` | Configured maximum (`FERRUM_DB_POOL_MAX_CONNECTIONS`) |
| `min_connections` | Configured minimum idle (`FERRUM_DB_POOL_MIN_CONNECTIONS`) |
| `read_replica` | Present only when `FERRUM_DB_READ_REPLICA_URL` is configured |

**MongoDB**: Pool stats are not available (the MongoDB driver manages pooling internally). The `pool` field is omitted from the response.

**Tuning guidance**: If `active` consistently equals `max_connections`, increase `FERRUM_DB_POOL_MAX_CONNECTIONS`. If `idle` is consistently high, consider reducing `min_connections` to save resources.

## Benefits

- **2-3x Higher Throughput**: Connection reuse eliminates setup overhead
- **Lower Latency**: Persistent connections avoid TCP handshakes; pool warmup eliminates first-request cold start
- **Resource Efficiency**: Fewer file descriptors and memory usage
- **Protocol Support**: HTTP/1.1 keep-alive, HTTP/2, HTTP/3, HTTPS, WebSocket (WS/WSS), gRPC (dedicated H2 pool)
- **Flexible Configuration**: Global defaults with per-proxy fine-tuning
