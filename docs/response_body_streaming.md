# Response Body Streaming

Ferrum Edge supports two modes for handling backend response bodies: **streaming** (default) and **buffering**. This is configurable per-proxy via the `response_body_mode` field and can be overridden by plugins that need access to the full response body.

## Table of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [How Streaming Works](#how-streaming-works)
- [Plugin Buffering Override](#plugin-buffering-override)
- [Interaction with Retry Logic](#interaction-with-retry-logic)
- [Interaction with Response Size Limits](#interaction-with-response-size-limits)
- [Protocol-Specific Behavior](#protocol-specific-behavior)
- [ProxyBody Type](#proxybody-type)
- [When to Use Buffer Mode](#when-to-use-buffer-mode)
- [Examples](#examples)

## Overview

| Mode | Behavior | Latency | Memory |
|------|----------|---------|--------|
| **stream** (default) | Response chunks are forwarded to the client as they arrive from the backend | Lower — first byte arrives immediately | Lower — no full body in memory |
| **buffer** | The entire response body is collected in memory before forwarding to the client | Higher — client waits for full response | Higher — full body held in memory |

Streaming is the default because it provides better latency and memory characteristics for the majority of use cases. Buffering is required only when a plugin needs to inspect or transform the complete response body.

## Configuration

### Per-Proxy Setting

```yaml
proxies:
  - id: "my-api"
    listen_path: "/api"
    backend_protocol: http
    backend_host: "backend-service"
    backend_port: 3000
    response_body_mode: stream  # "stream" (default) or "buffer"
```

The field is optional. When omitted, it defaults to `stream`.

### JSON (Admin API)

```json
{
  "id": "my-api",
  "listen_path": "/api",
  "backend_protocol": "http",
  "backend_host": "backend-service",
  "backend_port": 3000,
  "response_body_mode": "buffer"
}
```

## How Streaming Works

When `response_body_mode: stream` is active and no plugin requires buffering, the gateway:

1. Sends the backend request and receives the response status and headers.
2. Immediately begins forwarding the response to the client **without waiting for the full body**.
3. Each chunk from the backend is forwarded to the client as it arrives via a `StreamBody` wrapper over `reqwest::Response::bytes_stream()`.

This means the client sees the first byte of the response as soon as the backend sends it, rather than waiting for the entire response to be collected.

### Decision Flow

```
response_body_mode = buffer?
    └─ Yes → buffer entire response
    └─ No (stream) →
        Any plugin requires buffering?
            └─ Yes → buffer entire response
            └─ No →
                Response size limit enabled?
                    └─ Yes →
                        Content-Length present?
                            └─ Yes, within limit → stream
                            └─ Yes, exceeds limit → reject (502)
                            └─ No Content-Length → buffer (can't verify size)
                    └─ No (unlimited) → stream
```

## Plugin Buffering Override

Plugins can force buffering by implementing `requires_response_body_buffering()` on the `Plugin` trait:

```rust
impl Plugin for MyPlugin {
    fn name(&self) -> &str { "my_body_plugin" }

    fn requires_response_body_buffering(&self) -> bool {
        true  // Forces response buffering
    }
}
```

By default this method returns `false`. When any plugin attached to a proxy returns `true`, the gateway buffers the response regardless of `response_body_mode`.

This is **pre-computed at config load time** in `PluginCache` and looked up per-request via O(1) HashMap access, avoiding per-request iteration over the plugin list:

```rust
let should_stream = match proxy.response_body_mode {
    ResponseBodyMode::Buffer => false,
    ResponseBodyMode::Stream => !state.plugin_cache.requires_response_body_buffering(&proxy.id),
};
```

### Built-in Plugin Compatibility

All built-in plugins work with streaming mode because they only modify response **headers**, not the body:

| Plugin | Modifies Response Body? | Requires Buffering? |
|--------|------------------------|-------------------|
| `response_transformer` | No (headers only) | No |
| `cors` | No (headers only) | No |
| `stdout_logging` | No | No |
| `http_logging` | No | No |
| `transaction_debugger` | No | No |

## Interaction with Retry Logic

When retry is configured on a proxy, the gateway must be able to inspect the response status code before deciding whether to retry. This creates an interaction with streaming:

- **During retry attempts**: The response is always **buffered**, because the gateway needs to check the status code and potentially discard the response and retry.
- **Final attempt**: If streaming is enabled, the final response (after all retries are exhausted or the response is successful) is **streamed** to the client.

This ensures retry logic works correctly while still providing streaming benefits for the final response.

```
Attempt 1: buffer → check status → retry needed? → discard body
Attempt 2: buffer → check status → retry needed? → discard body
Attempt 3 (final): stream → forward directly to client
```

## Interaction with Response Size Limits

When `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` is set (non-zero), the gateway enforces the size limit on backend responses. This interacts with streaming:

| Scenario | Size Limit | Content-Length | Behavior |
|----------|-----------|---------------|----------|
| Stream mode | Enabled | Present, within limit | Stream directly |
| Stream mode | Enabled | Present, exceeds limit | Reject with 502 |
| Stream mode | Enabled | Absent | Fall back to buffering (can't verify size upfront) |
| Stream mode | Disabled (0) | Any | Stream directly |
| Buffer mode | Any | Any | Buffer and check size |

When streaming falls back to buffering due to a missing `Content-Length`, the buffered body is still checked against the size limit during collection.

See [docs/size_limits.md](size_limits.md) for the full size limit enforcement architecture.

## Protocol-Specific Behavior

### HTTP/1.1 and HTTP/2

Both protocols support streaming. By default, streaming responses use `ProxyBody::Stream` — a zero-overhead passthrough with no per-frame tracking. When `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=true`, the gateway uses `ProxyBody::Tracked` instead, which wraps the byte stream with lightweight completion tracking via `StreamingMetrics` (one atomic store per frame, plus one deferred `tokio::spawn` per streaming request).

### HTTP/3 (QUIC)

HTTP/3 responses are always **buffered** regardless of `response_body_mode`. The h3 crate's API requires collecting the full body before constructing the response. This is a limitation of the current h3 integration, not a design choice.

### gRPC

gRPC responses are always **buffered** because gRPC uses HTTP/2 trailers (`grpc-status`, `grpc-message`) which must be forwarded after the body. The gateway's gRPC proxy path collects the full body and trailers before constructing the response.

### WebSocket

WebSocket connections are bidirectional streams and do not use `response_body_mode`. After the HTTP Upgrade handshake, data flows directly between client and backend.

## ProxyBody Type

The streaming architecture is built on the `ProxyBody` enum in `src/proxy/body.rs`:

```rust
pub enum ProxyBody {
    Full(Full<Bytes>),     // Buffered: complete body in memory
    Stream(Pin<Box<...>>), // Streaming: zero-overhead passthrough (default)
    Tracked(TrackedBody),  // Streaming: with completion tracking (opt-in)
}
```

`ProxyBody` implements `http_body::Body`, so it is transparent to hyper's response machinery. The `Full` variant is zero-cost (no allocation beyond the data). The `Stream` variant is a simple passthrough with no per-frame tracking overhead — used by default. The `Tracked` variant wraps a streaming body with a shared `Arc<StreamingMetrics>` that records the last-frame timestamp via a single atomic store per frame — enabling accurate backend total latency measurement. It is only used when `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=true`.

Helper constructors:
- `ProxyBody::full(data)` — Create a buffered body from bytes
- `ProxyBody::from_string(s)` — Create a buffered body from a string
- `ProxyBody::empty()` — Create an empty body
- `ProxyBody::streaming(response)` — Create a streaming body with zero tracking overhead
- `ProxyBody::streaming_tracked(response, baseline)` — Create a streaming body with completion tracking, returning `(ProxyBody, Arc<StreamingMetrics>)`

## When to Use Buffer Mode

Use `response_body_mode: buffer` when:

- A plugin needs to inspect or transform the **response body** (not just headers)
- You need to guarantee response body size limits are enforced even when backends omit `Content-Length`
- You are debugging response content with `transaction_debugger` and `log_response_body: true`
- Your responses are small and the latency difference is negligible

Use `response_body_mode: stream` (default) when:

- Responses are large (file downloads, media, large JSON payloads)
- Low time-to-first-byte matters
- Memory efficiency is important
- No plugin needs the full response body

## Examples

### Streaming API with Large Responses

```yaml
proxies:
  - id: "file-download"
    listen_path: "/files"
    backend_protocol: http
    backend_host: "storage-service"
    backend_port: 8080
    response_body_mode: stream  # default, shown for clarity
```

### Buffered API with Response Body Inspection

```yaml
proxies:
  - id: "data-api"
    listen_path: "/data"
    backend_protocol: http
    backend_host: "data-service"
    backend_port: 3000
    response_body_mode: buffer  # required for body inspection plugins
    plugins:
      - plugin_config_id: "response-body-plugin"
```

### Mixed Configuration

```yaml
proxies:
  # High-throughput proxy — stream for performance
  - id: "public-api"
    listen_path: "/api"
    backend_protocol: https
    backend_host: "api.example.com"
    backend_port: 443
    # response_body_mode defaults to stream

  # Auth-protected proxy — buffer for response validation
  - id: "internal-api"
    listen_path: "/internal"
    backend_protocol: http
    backend_host: "internal-service"
    backend_port: 3000
    response_body_mode: buffer
    plugins:
      - plugin_config_id: "auth-plugin"
      - plugin_config_id: "response-validator"
```
