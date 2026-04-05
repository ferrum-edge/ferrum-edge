# Request & Response Size Limits

Ferrum Edge enforces configurable size limits on request headers, request bodies, and response bodies to protect against memory exhaustion (OOM) attacks, oversized payloads, and misbehaving backends. Limits are enforced at multiple layers — the protocol layer (hyper) and the application layer — ensuring defense in depth.

## Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FERRUM_MAX_HEADER_SIZE_BYTES` | `usize` | `32768` (32KB) | Maximum total size of all request headers combined. Enforced at both the hyper protocol layer (HTTP/1.1 `max_buf_size`, HTTP/2 `max_header_list_size`) and the application layer. |
| `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` | `usize` | `16384` (16KB) | Maximum size of any single request header (name + value in bytes). Prevents individual oversized headers. |
| `FERRUM_MAX_HEADER_COUNT` | `usize` | `100` | Maximum number of request headers allowed. Set to `0` for unlimited. |
| `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES` | `usize` | `10485760` (10MB) | Maximum request body size. Set to `0` for unlimited. Checked via `Content-Length` header (fast reject) and enforced during body collection via `http_body_util::Limited`. |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | `usize` | `10485760` (10MB) | Maximum response body size from backends. Set to `0` for unlimited. Protects against backends sending unexpectedly large responses. |
| `FERRUM_MAX_URL_LENGTH_BYTES` | `usize` | `8192` (8KB) | Maximum URL length in bytes (path + query string). Set to `0` for unlimited. |
| `FERRUM_MAX_QUERY_PARAMS` | `usize` | `100` | Maximum number of query parameters allowed. Set to `0` for unlimited. |
| `FERRUM_MAX_GRPC_RECV_SIZE_BYTES` | `usize` | `4194304` (4MB) | Maximum total received gRPC payload size in bytes. For unary RPCs this is effectively a per-message limit. For streaming RPCs it caps the cumulative body size. Set to `0` for unlimited. |
| `FERRUM_MAX_WEBSOCKET_FRAME_SIZE_BYTES` | `usize` | `16777216` (16MB) | Maximum WebSocket frame size in bytes. Also sets max message size to 4x frame size. |

## Enforcement Layers

### Layer 1: Protocol Layer (hyper)

For **HTTP/1.1**, `max_buf_size` is set on the hyper HTTP/1.1 builder. This limits the internal buffer used for reading request headers. When the header block exceeds this size, hyper automatically rejects the request before the application layer ever sees it.

For **HTTP/2**, `max_header_list_size` is set via the hyper-util auto builder. This controls the maximum size of the HPACK-decoded header list. HTTP/2 clients exceeding this limit receive a protocol-level error.

### Layer 2: Application Layer (header validation)

After headers are parsed by hyper, the gateway validates:
- **Each individual header** against `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES`
- **Total header size** (sum of all header name + value lengths) against `FERRUM_MAX_HEADER_SIZE_BYTES`

This provides a second line of defense and enables per-header size limits that hyper doesn't natively support.

### Layer 3: Request Body Enforcement

Request body limits are enforced in two stages:
1. **Content-Length fast path**: If the `Content-Length` header exceeds `FERRUM_MAX_REQUEST_BODY_SIZE_BYTES`, the request is rejected immediately (413) without reading any body data.
2. **Streaming enforcement**: Uses `http_body_util::Limited` to wrap the body stream. If the body exceeds the limit during collection, the stream is aborted and a 413 is returned.

### Layer 4: Response Body Enforcement

Response body limits protect against backends sending unexpectedly large payloads:
1. **Content-Length fast path**: If the backend's `Content-Length` header exceeds `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, a 502 is returned immediately.
2. **Streaming enforcement**: Response bytes are collected in chunks with a running size counter. If the accumulated size exceeds the limit, collection stops and a 502 is returned.

### Interaction with Response Body Streaming

When `response_body_mode: stream` is configured (the default), the gateway can forward response chunks to the client as they arrive without buffering the full body. However, response size limits still apply:

- **With `Content-Length` header**: If the backend sends a `Content-Length` that exceeds `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, the request is rejected immediately with 502 before any streaming begins. If the Content-Length is within the limit, the response is streamed directly.
- **Without `Content-Length` header**: The gateway **falls back to buffering** because it cannot verify the response size upfront. This ensures size limits are always enforced, even when streaming is configured.
- **When `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0`** (unlimited): Responses are streamed without any size checks, regardless of whether `Content-Length` is present.

See [docs/response_body_streaming.md](response_body_streaming.md) for full details on streaming vs buffering behavior.

## HTTP/3 (QUIC) Enforcement

The same size limits apply to HTTP/3 connections:
- Header validation (per-header and total) is performed on the parsed request headers
- Body collection tracks accumulated size during `recv_data()` calls
- Response body limits are enforced identically to HTTP/1.1 and HTTP/2

## Admin API Body Limit

The Admin API enforces a **1 MiB** (1,048,576 bytes) request body size limit on all endpoints. This is a fixed limit independent of the proxy size limits above. Requests exceeding this limit receive a `413 Payload Too Large` response.

## Error Responses

All error responses are JSON with `Content-Type: application/json`.

| Condition | Status Code | Response Body |
|-----------|-------------|---------------|
| Single header too large | `431 Request Header Fields Too Large` | `{"error":"Request header '{name}' exceeds maximum size of {n} bytes"}` |
| Total headers too large | `431 Request Header Fields Too Large` | `{"error":"Total request headers exceed maximum size"}` |
| Request body too large (Content-Length) | `413 Content Too Large` | `{"error":"Request body exceeds maximum size"}` |
| Request body too large (streaming) | `413 Content Too Large` | `{"error":"Request body exceeds maximum size"}` |
| Admin API body too large | `413 Payload Too Large` | Request rejected by body size middleware |
| Response body too large | `502 Bad Gateway` | `{"error":"Backend response body exceeds maximum size"}` |

**Why 502 for response body?** The backend sent a response that violates the gateway's configured limits. The client is not at fault — the backend is misbehaving. This matches HTTP semantics: 502 indicates the gateway received an invalid response from the upstream server.

## Example Configurations

### API Gateway (conservative limits)

```bash
# Small headers, moderate body limit
FERRUM_MAX_HEADER_SIZE_BYTES=16384
FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES=8192
FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=1048576    # 1MB
FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=5242880  # 5MB
```

### File Upload Gateway (large body limits)

```bash
# Allow large request bodies for file uploads
FERRUM_MAX_HEADER_SIZE_BYTES=32768
FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES=16384
FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=104857600  # 100MB
FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=104857600  # 100MB
```

### Unlimited Body Mode

```bash
# No body size limits (use with caution — vulnerable to OOM)
FERRUM_MAX_REQUEST_BODY_SIZE_BYTES=0
FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0
```

## Configuration Field Limits

Beyond request/response size limits, the Admin API enforces validation on all configuration fields. These limits protect database storage, prevent misconfigurations, and reject malformed input (including control characters).

### Resource IDs (all resource types)

| Constraint | Limit | Description |
|------------|-------|-------------|
| Max length | 254 chars | All resource IDs (proxy, consumer, upstream, plugin_config) |
| Format | `^[a-zA-Z0-9][a-zA-Z0-9._-]*$` | Must start with alphanumeric, then alphanumeric/dots/underscores/hyphens |

### Proxy Fields

| Field | Limit | Description |
|-------|-------|-------------|
| `name` | 255 chars | Optional proxy name |
| `listen_path` (non-regex) | 500 chars | Path prefix for route matching |
| `listen_path` (regex) | 1024 chars | Maximum regex pattern length (e.g., `~^/api/v\d+`) |
| `backend_host` | 255 chars | Backend hostname (matches DNS spec max of 253) |
| `backend_path` | 2048 chars | Backend path prefix |
| `hosts` | 100 entries, 253 chars each | Hostname list with format validation |
| `backend_connect_timeout_ms` | 1–86,400,000 | Connect timeout (max 24 hours) |
| `backend_read_timeout_ms` | 1–86,400,000 | Read timeout (max 24 hours) |
| `backend_write_timeout_ms` | 1–86,400,000 | Write timeout (max 24 hours) |
| `dns_override` | 255 chars | DNS resolution override |
| `dns_cache_ttl_seconds` | 1–86,400 | DNS cache TTL (max 24 hours) |
| `pool_idle_timeout_seconds` | 1–3,600 | Connection pool idle timeout (max 1 hour) |
| `pool_tcp_keepalive_seconds` | 1–86,400 | TCP keepalive interval |
| `pool_http2_keep_alive_interval_seconds` | 1–86,400 | HTTP/2 PING interval |
| `pool_http2_keep_alive_timeout_seconds` | 1–86,400 | HTTP/2 PING timeout |
| `pool_http2_initial_stream_window_size` | 65,535–134,217,728 | HTTP/2 per-stream window (64 KiB – 128 MiB) |
| `pool_http2_initial_connection_window_size` | 65,535–134,217,728 | HTTP/2 connection window (64 KiB – 128 MiB) |
| `pool_http2_max_frame_size` | 16,384–1,048,576 | HTTP/2 frame size (16 KiB – 1 MiB) |
| `pool_http2_max_concurrent_streams` | ≥ 1 | HTTP/2 max concurrent streams |
| `pool_http3_connections_per_backend` | 1–256 | QUIC connections per backend |
| `backend_tls_client_cert_path` | 4096 chars | mTLS client certificate path |
| `backend_tls_client_key_path` | 4096 chars | mTLS client key path |
| `backend_tls_server_ca_cert_path` | 4096 chars | Custom CA bundle path |
| `allowed_methods` | Valid HTTP methods | Must be GET, POST, PUT, PATCH, DELETE, HEAD, OPTIONS, TRACE, or CONNECT |
| `udp_idle_timeout_seconds` | 1–3,600 | UDP session idle timeout (max 1 hour) |

### Consumer Fields

| Field | Limit | Description |
|-------|-------|-------------|
| `username` | 255 chars | Consumer username |
| `custom_id` | 255 chars | Optional custom identifier |
| `credentials` (total JSON) | 64 KiB | Total serialized size of credentials object |
| `credentials` (per value) | 4096 chars | Individual credential string values |
| Credential type key | 64 chars | Credential type name (e.g., `keyauth`, `basicauth`) |

### Upstream Fields

| Field | Limit | Description |
|-------|-------|-------------|
| `name` | 255 chars | Optional upstream name |
| `hash_on` | 255 chars | Consistent hashing key source (`ip`, `header:<name>`, `cookie:<name>`) |
| `hash_on_cookie_config.path` | 2048 chars | Cookie `Path` attribute |
| `hash_on_cookie_config.domain` | 253 chars | Cookie `Domain` attribute |
| `hash_on_cookie_config.ttl_seconds` | ≤ 86,400 | Cookie `Max-Age` in seconds |
| `hash_on_cookie_config.same_site` | `Strict` / `Lax` / `None` | Cookie `SameSite` attribute |
| `targets` | 1000 entries | Maximum targets per upstream |
| `targets[].host` | 255 chars | Target hostname |
| `targets[].port` | ≥ 1 | Target port (non-zero) |
| `targets[].weight` | 1–65,535 | Target weight |
| `targets[].path` | 2048 chars | Optional per-target backend path override |
| `targets[].tags` | 50 entries, 255 chars key/value | Target metadata tags |

### Upstream Health Check Fields

| Field | Limit | Description |
|-------|-------|-------------|
| `active.http_path` | 2048 chars | Health check probe path |
| `active.interval_seconds` | 1–3,600 | Probe interval (max 1 hour) |
| `active.timeout_ms` | 1–86,400,000 | Probe timeout |
| `active.healthy_threshold` | 1–10,000 | Healthy transition threshold |
| `active.unhealthy_threshold` | 1–10,000 | Unhealthy transition threshold |
| `active.healthy_status_codes` | 50 entries, 100–599 | Valid HTTP status code range |
| `active.udp_probe_payload` | 2048 chars | UDP probe hex payload |
| `passive.unhealthy_status_codes` | 50 entries, 100–599 | Valid HTTP status code range |
| `passive.unhealthy_threshold` | 1–10,000 | Failure threshold |
| `passive.unhealthy_window_seconds` | 1–86,400 | Sliding window duration |
| `passive.healthy_after_seconds` | 0–86,400 | Auto-recovery timer (0 = disabled) |

### Upstream Service Discovery Fields

| Field | Limit | Description |
|-------|-------|-------------|
| `default_weight` | 1–65,535 | Default weight for discovered targets |
| `dns_sd.service_name` | 255 chars, non-empty | DNS SRV record name |
| `dns_sd.poll_interval_seconds` | 1–3,600 | DNS poll interval |
| `kubernetes.namespace` | 255 chars | K8s namespace |
| `kubernetes.service_name` | 255 chars, non-empty | K8s service name |
| `kubernetes.port_name` | 255 chars | Optional EndpointSlice port name |
| `kubernetes.label_selector` | 1024 chars | Optional label selector |
| `kubernetes.poll_interval_seconds` | 1–3,600 | K8s poll interval |
| `consul.address` | 2048 chars, non-empty | Consul HTTP API address |
| `consul.service_name` | 255 chars, non-empty | Consul service name |
| `consul.datacenter` | 255 chars | Optional datacenter filter |
| `consul.tag` | 255 chars | Optional service tag filter |
| `consul.token` | 4096 chars | Optional ACL token |
| `consul.poll_interval_seconds` | 1–3,600 | Consul poll interval |

### Plugin Config Fields

| Field | Limit | Description |
|-------|-------|-------------|
| `plugin_name` | 255 chars | Plugin name |
| `config` (JSON size) | 1 MiB | Maximum serialized config size |
| `config` (nesting depth) | 10 levels | Maximum JSON nesting |

### Circuit Breaker Fields

| Field | Limit | Description |
|-------|-------|-------------|
| `failure_threshold` | 1–10,000 | Failures before opening |
| `success_threshold` | 1–10,000 | Successes to close |
| `timeout_seconds` | 1–86,400 | Open-state duration |
| `half_open_max_requests` | 1–10,000 | Probe requests in half-open |
| `failure_status_codes` | 50 entries, 100–599 | Status codes that count as failure |

### Retry Config Fields

| Field | Limit | Description |
|-------|-------|-------------|
| `max_retries` | 0–100 | Maximum retry attempts |
| `retryable_status_codes` | 50 entries, 100–599 | Status codes eligible for retry |
| `retryable_methods` | 9 entries max | Must be valid HTTP methods (GET, POST, PUT, etc.) |
| `backoff.delay_ms` (fixed) | 0–300,000 | Fixed backoff delay (max 5 minutes) |
| `backoff.base_ms` (exponential) | 0–300,000 | Exponential base delay |
| `backoff.max_ms` (exponential) | 0–300,000 | Exponential max delay (must be ≥ base_ms) |

### Cross-Resource Validation

All string fields reject ASCII control characters (null bytes, escape sequences, etc.) to prevent log injection. Additionally:

- **Uniqueness**: Proxy IDs, consumer IDs, upstream IDs, plugin_config IDs, proxy names, upstream names, consumer usernames, consumer custom_ids, and consumer credentials are validated for uniqueness
- **Referential integrity**: Proxy `upstream_id` must reference an existing upstream
- **Plugin multiplicity**: A proxy may have multiple instances of the same plugin type (e.g., two `http_logging` for different destinations). Use `priority_override` to control execution order when needed
- **Host/path uniqueness**: No two proxies can share overlapping host + listen_path combinations
- **Stream proxy rules**: TCP/UDP proxies require `listen_port`; HTTP proxies must not set it. In database mode, `listen_port` is also validated against gateway reserved ports (proxy/admin/gRPC) and checked for OS-level availability. In CP mode, local port checks are skipped since proxies run on remote DP nodes

These limits are enforced during:
- Admin API `POST`/`PUT` operations on all resource types
- `PUT`/`DELETE` on `/consumers/{id}/credentials/{type}`
- `POST /restore` — validation fails before any data is deleted
- File config loading (YAML/JSON) and SIGHUP reload
- Database incremental polling — invalid configs are rejected before applying
