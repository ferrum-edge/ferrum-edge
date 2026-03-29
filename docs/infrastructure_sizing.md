# Infrastructure Sizing Guide

This guide helps you estimate the CPU and memory resources needed to run Ferrum Gateway based on your expected workload. Use it to right-size your deployment — whether on bare metal, VMs, containers, or Kubernetes.

## Key Factors That Affect Resource Usage

| Factor | Impact |
|--------|--------|
| **Number of configured proxies/routes** | Memory (route table, plugin cache, connection pool entries) |
| **Requests per second (RPS)** | CPU (TLS handshakes, routing, plugin execution, proxying) |
| **Request/response payload size** | Memory (buffering), network bandwidth |
| **Number of concurrent connections** | Memory (per-connection state), file descriptors |
| **TLS termination** | CPU (especially with RSA keys; ECDSA is lighter) |
| **Active plugins** | CPU (auth, rate limiting, CORS add per-request overhead) |
| **Response body mode** | Memory — streaming (default) vs buffered changes peak memory profile |
| **Load balancing algorithm** | Memory (consistent hashing uses hash rings; least-connections tracks counters) |
| **Custom plugins** | CPU and memory depending on plugin logic |
| **HTTP/2 multiplexing** | Reduces connection count, slightly increases per-connection memory |
| **HTTP/3 (QUIC)** | Higher CPU for encryption, lower latency on lossy networks |

## Sizing Tiers

The tables below provide starting-point recommendations. Actual requirements vary based on plugin complexity, upstream latency, payload sizes, and TLS configuration.

### Small Workloads

| Metric | Value |
|--------|-------|
| Proxies/routes | 1–10 |
| Requests per second | Up to 1,000 |
| Avg payload size | Up to 10 KB |
| Concurrent connections | Up to 500 |

**Recommended resources:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 1 vCPU | 2 vCPUs |
| Memory | 64 MB | 128 MB |
| File descriptors | 4,096 | 8,192 |

Suitable for development, staging, or low-traffic internal APIs.

### Medium Workloads

| Metric | Value |
|--------|-------|
| Proxies/routes | 10–100 |
| Requests per second | 1,000–10,000 |
| Avg payload size | 10–100 KB |
| Concurrent connections | 500–5,000 |

**Recommended resources:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 2 vCPUs | 4 vCPUs |
| Memory | 128 MB | 512 MB |
| File descriptors | 16,384 | 65,536 |

Suitable for production workloads with moderate traffic.

### Large Workloads

| Metric | Value |
|--------|-------|
| Proxies/routes | 100–1,000 |
| Requests per second | 10,000–50,000 |
| Avg payload size | 10–100 KB |
| Concurrent connections | 5,000–50,000 |

**Recommended resources:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 4 vCPUs | 8 vCPUs |
| Memory | 512 MB | 2 GB |
| File descriptors | 65,536 | 262,144 |

Suitable for high-traffic production APIs. Consider running multiple instances behind a load balancer.

### Extra-Large Workloads

| Metric | Value |
|--------|-------|
| Proxies/routes | 1,000+ |
| Requests per second | 50,000+ |
| Avg payload size | Variable |
| Concurrent connections | 50,000+ |

**Recommended resources:**

| Resource | Minimum | Recommended |
|----------|---------|-------------|
| CPU | 8 vCPUs | 16+ vCPUs |
| Memory | 2 GB | 4–8 GB |
| File descriptors | 262,144 | 1,048,576 |

At this scale, use the [Control Plane / Data Plane](cp_dp_mode.md) deployment mode with multiple Data Plane instances for horizontal scaling.

## How Payload Size Affects Memory

Ferrum Gateway supports two response body modes configured per proxy: **streaming** (default) and **buffered**. The mode significantly affects memory usage.

- **Streaming mode** (default): Response bodies flow through the gateway without being fully buffered in memory. Only the current chunk is held at any time. This is the most memory-efficient option and is suitable for most workloads.
- **Buffered mode**: The entire response body is collected in memory before forwarding to the client. Required when plugins need to inspect or modify the full response body. HTTP/3 and gRPC proxying always use buffered mode.

Plugins that declare `requires_response_body_buffering()` will automatically switch their proxy to buffered mode regardless of the per-proxy setting.

Request bodies are always collected (buffered) for size enforcement and forwarding.

**Worst-case per-request memory:**

| Mode | Formula |
|------|---------|
| Streaming (default) | request body (up to limit) + current response chunk |
| Buffered | request body (up to limit) + full response body (up to limit) |

| Scenario | Body Limit | Mode | Memory per 100 concurrent requests |
|----------|-----------|------|-------------------------------------|
| Small JSON APIs | 64 KB | Streaming | ~6 MB (request bodies only) |
| Small JSON APIs | 64 KB | Buffered | ~12 MB |
| Standard APIs (default) | 10 MB | Streaming | ~1 GB (request bodies only) |
| Standard APIs (default) | 10 MB | Buffered | ~2 GB |
| File upload service | 100 MB | Streaming | ~10 GB (request bodies only) |
| Streaming / unlimited | 0 (unlimited) | Streaming | Bounded by request body sizes |
| Buffered / unlimited | 0 (unlimited) | Buffered | Unbounded — avoid in production |

See [Response Body Streaming](response_body_streaming.md) for full details on streaming vs buffered behavior.

**Recommendations:**
- Use streaming mode (the default) unless plugins require full response body access.
- Set `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` and `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` to the smallest values your workload allows.
- For file upload proxies, dedicate separate proxy routes with higher limits rather than raising the global default.
- When body limits are set to 0 (unlimited), memory usage is bounded only by client behavior — always set explicit limits in production.

### Relevant environment variables

| Variable | Default | Description |
|----------|---------|-------------|
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | 10 MB | Maximum request body size |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | 10 MB | Maximum response body size |
| `FERRUM_MAX_HEADER_SIZE_BYTES` | 32 KB | Maximum total header size |
| `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` | 16 KB | Maximum single header value size |

See [Size Limits](size_limits.md) for full details on enforcement layers.

## How Connection Pooling Affects Resources

The connection pool maintains persistent connections to upstream backends, reducing latency from repeated TCP/TLS handshakes. Each idle connection consumes a file descriptor and a small amount of memory (~10–30 KB depending on TLS state).

| Pool setting | Default | Sizing impact |
|--------------|---------|---------------|
| `FERRUM_POOL_MAX_IDLE_PER_HOST` | 64 | Max idle connections per upstream host |
| `FERRUM_POOL_IDLE_TIMEOUT_SECONDS` | 90 | How long idle connections persist |
| `FERRUM_POOL_ENABLE_HTTP2` | true | HTTP/2 multiplexing reduces connection count |

**Connection pool memory estimate:**

```
pool_memory ≈ num_upstream_hosts × max_idle_per_host × 20 KB
```

| Upstream hosts | Max idle/host | Estimated pool memory |
|----------------|---------------|----------------------|
| 5 | 64 | ~6 MB |
| 50 | 64 | ~64 MB |
| 200 | 128 | ~512 MB |
| 200 | 32 | ~128 MB |

**Recommendations:**
- With HTTP/2 enabled, a single connection can multiplex many requests — reduce `max_idle_per_host` to 4–16.
- For backends with bursty traffic patterns, increase `max_idle_per_host` to avoid connection churn.
- Lower `idle_timeout` if your backends aggressively close idle connections.

## How Load Balancing Affects Resources

The load balancer maintains per-upstream state that varies by algorithm. This is generally lightweight but worth considering at scale.

| Algorithm | Per-upstream memory | Notes |
|-----------|-------------------|-------|
| Round-robin | ~64 bytes | Single atomic counter |
| Weighted round-robin | ~64 bytes per target | Atomic weight counters per target |
| Least-connections | ~128 bytes per target | Active connection counter per target via DashMap |
| Consistent hashing | ~3.6 KB per target | 150 virtual nodes per target in the hash ring |
| Random | ~0 bytes | Stateless |

**Memory estimate for consistent hashing:**

```
hash_ring_memory ≈ num_upstreams × targets_per_upstream × 150 × 24 bytes
```

For 50 upstreams with 10 targets each using consistent hashing: ~1.8 MB. Negligible for most deployments.

All load balancer state is pre-computed at config load time — no per-request allocation. See [Load Balancing](load_balancing.md) for algorithm details.

## CPU Breakdown by Operation

Understanding where CPU cycles are spent helps you optimize for your specific workload.

| Operation | Relative CPU cost | Notes |
|-----------|-------------------|-------|
| TLS handshake (RSA 2048) | High | ~1 ms per handshake; amortized by keep-alive |
| TLS handshake (ECDSA P-256) | Medium | ~0.3 ms per handshake; prefer for throughput |
| TLS record encryption | Low–Medium | Proportional to payload size |
| Route matching (cache hit) | Very low | O(1) DashMap lookup |
| Route matching (cache miss) | Low | Pre-sorted prefix scan, result cached |
| Plugin execution (JWT/key auth) | Low | Local validation against secrets, no external calls |
| Plugin execution (JWKS auth) | Low | Local JWT validation using cached IdP public keys |
| Plugin execution (rate limit) | Very low | In-memory atomic counters |
| Plugin execution (custom plugins) | Variable | Depends on plugin logic; see [Custom Plugins](../CUSTOM_PLUGINS.md) |
| Load balancer target selection | Very low | Atomic operations; consistent hashing does one hash per request |
| DNS resolution (cache hit) | Very low | In-memory, background-refreshed at 75% TTL |
| HTTP/2 frame processing | Low | Multiplexing reduces total connection overhead |
| HTTP/3 (QUIC) encryption | Medium–High | Per-packet encryption vs per-record in TLS |
| Body proxying | Low | Streaming with minimal copying |
| Health checks (active) | Very low | Periodic background probes |

**Recommendations:**
- Use ECDSA certificates instead of RSA to reduce TLS CPU overhead by ~70%.
- Enable HTTP/2 and connection keep-alive to amortize handshake costs across many requests.
- For CPU-bound workloads, scale the Tokio runtime by setting `TOKIO_WORKER_THREADS` (defaults to number of CPU cores).

## Scaling Strategies

### Vertical Scaling

Add more CPU and memory to a single instance. Ferrum Gateway's async, lock-free architecture scales well across cores.

- **CPU**: Tokio's work-stealing scheduler distributes work across all available cores automatically.
- **Memory**: Increase when you need larger body limits or more pooled connections.

### Horizontal Scaling

Run multiple Ferrum Gateway instances behind an external load balancer.

- Use **Control Plane / Data Plane mode** for centralized configuration with distributed traffic handling.
- Data Plane instances are stateless (config fetched from Control Plane) and can be autoscaled based on CPU or RPS metrics.
- Rate limiting and least-connections load balancing state is per-instance — use external solutions for globally consistent behavior across instances.
- Consistent hashing load balancing works well across instances when all instances share the same upstream target configuration (achieved automatically in CP/DP mode).

### Kubernetes Sizing Example

```yaml
# Small / staging
resources:
  requests:
    cpu: 250m
    memory: 64Mi
  limits:
    cpu: "2"
    memory: 256Mi

# Medium / production
resources:
  requests:
    cpu: "1"
    memory: 256Mi
  limits:
    cpu: "4"
    memory: 1Gi

# Large / high-traffic production
resources:
  requests:
    cpu: "4"
    memory: 1Gi
  limits:
    cpu: "8"
    memory: 4Gi
```

Use a Horizontal Pod Autoscaler targeting 60–70% average CPU utilization.

## OS-Level Tuning

For medium and larger workloads, verify these OS-level settings:

| Setting | Recommended value | Why |
|---------|-------------------|-----|
| File descriptor limit (`ulimit -n`) | 65,536+ | Each connection uses a file descriptor |
| `net.core.somaxconn` | 4,096+ | TCP listen backlog for burst acceptance |
| `net.ipv4.tcp_tw_reuse` | 1 | Reuse TIME_WAIT sockets for upstream connections |
| `net.ipv4.ip_local_port_range` | `1024 65535` | Maximize available ephemeral ports |
| `net.core.rmem_max` / `wmem_max` | 16 MB+ | Socket buffer sizes for large payloads |

## Quick Reference: Sizing Formula

For a rough estimate of total memory:

```
total_memory ≈ base (30 MB)
             + route_table (proxies × 5 KB)
             + connection_pool (upstream_hosts × max_idle_per_host × 20 KB)
             + request_buffers (concurrent_requests × avg_request_payload)
             + response_buffers (concurrent_requests × avg_response_payload)  [buffered mode only]
             + load_balancer (upstreams × targets × algorithm_overhead)
             + dns_cache (unique_hosts × 1 KB)
             + plugin_state (rate_limit_keys × 0.5 KB)
```

Note: With the default streaming response mode, response buffer memory is minimal (only the current chunk per request). The `response_buffers` line applies only to proxies configured with `response_body_mode: buffer` or those using plugins that require full response body access.

For CPU, a single modern core can typically handle 5,000–15,000 simple proxy requests per second (small payloads, connection reuse, cached routes). TLS termination, large payloads, and plugin processing reduce this.

## Monitoring Recommendations

Track these metrics to validate your sizing and identify when to scale:

- **CPU utilization**: Sustained >70% indicates need for more cores or instances
- **Memory RSS**: Growing steadily may indicate a connection or buffer leak
- **Open file descriptors**: Approaching the limit causes connection failures
- **Connection pool size**: High churn (creates/closes) suggests pool is undersized
- **Request latency (p99)**: Increasing latency under stable RPS suggests resource contention
- **Active connections**: Approaching OS or pool limits
