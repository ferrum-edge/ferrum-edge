# Request & Response Size Limits

Ferrum Gateway enforces configurable size limits on request headers, request bodies, and response bodies to protect against memory exhaustion (OOM) attacks, oversized payloads, and misbehaving backends. Limits are enforced at multiple layers — the protocol layer (hyper) and the application layer — ensuring defense in depth.

## Environment Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FERRUM_MAX_HEADER_SIZE_BYTES` | `usize` | `32768` (32KB) | Maximum total size of all request headers combined. Enforced at both the hyper protocol layer (HTTP/1.1 `max_buf_size`, HTTP/2 `max_header_list_size`) and the application layer. |
| `FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES` | `usize` | `16384` (16KB) | Maximum size of any single request header (name + value in bytes). Prevents individual oversized headers. |
| `FERRUM_MAX_BODY_SIZE_BYTES` | `usize` | `10485760` (10MB) | Maximum request body size. Set to `0` for unlimited. Checked via `Content-Length` header (fast reject) and enforced during body collection via `http_body_util::Limited`. |
| `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` | `usize` | `10485760` (10MB) | Maximum response body size from backends. Set to `0` for unlimited. Protects against backends sending unexpectedly large responses. |

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
1. **Content-Length fast path**: If the `Content-Length` header exceeds `FERRUM_MAX_BODY_SIZE_BYTES`, the request is rejected immediately (413) without reading any body data.
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
FERRUM_MAX_BODY_SIZE_BYTES=1048576    # 1MB
FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=5242880  # 5MB
```

### File Upload Gateway (large body limits)

```bash
# Allow large request bodies for file uploads
FERRUM_MAX_HEADER_SIZE_BYTES=32768
FERRUM_MAX_SINGLE_HEADER_SIZE_BYTES=16384
FERRUM_MAX_BODY_SIZE_BYTES=104857600  # 100MB
FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=104857600  # 100MB
```

### Unlimited Body Mode

```bash
# No body size limits (use with caution — vulnerable to OOM)
FERRUM_MAX_BODY_SIZE_BYTES=0
FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0
```

## Configuration Field Limits

Beyond request/response size limits, the Admin API enforces limits on individual configuration fields:

| Field | Limit | Description |
|-------|-------|-------------|
| Proxy `listen_path` (regex) | 1024 chars | Maximum pattern length for regex routes (e.g., `~^/api/v\d+`) |
| Consumer `username` | 255 chars | Maximum length for consumer usernames |
| Credential type | Whitelist | Only `basicauth`, `keyauth`, `jwt`, `hmac_auth`, `oauth2`, `mtls_auth` |

These limits are enforced during:
- Admin API `POST`/`PUT` operations on proxies and consumers
- `PUT`/`DELETE` on `/consumers/{id}/credentials/{type}`
- `POST /restore` — validation fails before any data is deleted
- Database incremental polling — invalid configs are rejected before applying
