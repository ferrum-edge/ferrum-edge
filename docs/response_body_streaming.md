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
    backend_scheme: http
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
  "backend_scheme": "http",
  "backend_host": "backend-service",
  "backend_port": 3000,
  "response_body_mode": "buffer"
}
```

## How Streaming Works

When `response_body_mode: stream` is active and no plugin requires buffering, the gateway:

1. Sends the backend request and receives the response status and headers.
2. Checks whether the response qualifies for **adaptive buffering** (see below).
3. If not buffered, begins forwarding the response to the client **without waiting for the full body** via a `CoalescingBody` adapter that batches small backend chunks (typically 8–32 KB) into larger 128 KB frames for efficient forwarding.

This means the client sees the first byte of the response as soon as the backend sends it, rather than waiting for the entire response to be collected — unless adaptive buffering applies.

### Small Response Buffering

When a backend response has a known `Content-Length ≤ 64 KiB` (configurable), the gateway collects the entire body into a single allocation via `response.bytes().await` instead of streaming through the async coalescing adapter. For typical JSON API payloads, this single allocation is cheaper than spinning up `CoalescingBody` with its `BytesMut` buffer and poll loop. Responses without `Content-Length` or with `Content-Length` above the cutoff always stream.

SSE responses (`Content-Type: text/event-stream`) **always stream** regardless of `Content-Length`, since they represent inherently unbounded or latency-sensitive streams.

| Env Var | Default | Description |
|---------|---------|-------------|
| `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` | `65536` (64 KiB) | Responses with known Content-Length ≤ this value are eagerly buffered. `0` = disabled (always stream). |

This optimization **only activates when no plugins require response body buffering** — when plugins need the body, the existing plugin-forced buffering path takes precedence.

### Response Body Coalescing

For responses that stream (either below the adaptive buffer minimum or above the threshold), the gateway uses coalescing adapters that accumulate small backend chunks into 128 KB frames before yielding to hyper's HTTP encoder. `CoalescingBody` handles reqwest-backed HTTP/1.1 responses, while `CoalescingH2Body` handles hyper HTTP/2 `Incoming` bodies (gRPC streaming and HTTP/2 direct pool paths). This reduces the number of write syscalls by ~8–16× for large responses compared to forwarding each small chunk individually. The H2 adapter is trailer-safe — gRPC trailers are stashed while buffered data is flushed, then returned on the next poll.

### Decision Flow

```
response_body_mode = buffer?
    └─ Yes → buffer entire response
    └─ No (stream) →
        Config-time: any plugin requires buffering?
            └─ Yes → per-request: should_buffer_response_body(ctx)?
                └─ Yes → buffer entire response
                └─ No (all plugins skip for this request) → stream
            └─ No →
                Retries configured?
                    └─ Yes → buffer (all attempts except final)
                    └─ No → continue
                Response size limit enabled?
                    └─ Yes →
                        Content-Length present?
                            └─ Yes, exceeds limit → reject (502)
                            └─ Yes, CL ≤ cutoff & not SSE? → buffer (small response)
                            └─ Yes, CL > cutoff → stream (with coalescing)
                            └─ No Content-Length → stream (SizeLimitedStreamingResponse)
                    └─ No (unlimited) →
                        Content-Length present, CL ≤ cutoff & not SSE?
                            └─ Yes → buffer (small response)
                            └─ No → stream (with coalescing)
```

## Plugin Buffering Override

Response body buffering uses a **two-tier check** mirroring the request-body pattern:

1. **Config-time upper bound** — `requires_response_body_buffering()` is pre-computed in `PluginCache` at config load time. O(1) HashMap lookup per request.
2. **Per-request refinement** — `should_buffer_response_body(&RequestContext)` lets plugins skip buffering when the request context makes it irrelevant.

```rust
impl Plugin for MyPlugin {
    fn name(&self) -> &str { "my_body_plugin" }

    // Config-time: this proxy MAY need response buffering
    fn requires_response_body_buffering(&self) -> bool {
        true
    }

    // Per-request: only buffer for POST+JSON requests (e.g., AI API calls)
    fn should_buffer_response_body(&self, ctx: &RequestContext) -> bool {
        ctx.method == "POST"
            && ctx.headers.get("content-type")
                .is_some_and(|ct| ct.to_ascii_lowercase().contains("json"))
    }
}
```

The default `should_buffer_response_body()` returns `self.requires_response_body_buffering()` — plugins that don't override it behave as before.

Built-in plugins with per-request refinement:

| Plugin | Skips buffering when |
|--------|---------------------|
| `compression` | `Accept-Encoding` header is absent (nothing to compress) |
| `ai_token_metrics` | Request is not POST+JSON (not an AI API call) |
| `ai_rate_limiter` | Request is not POST+JSON |
| `ai_response_guard` | Request is not POST+JSON |

The decision in code:

```rust
let should_stream = match proxy.response_body_mode {
    ResponseBodyMode::Buffer => false,
    ResponseBodyMode::Stream => {
        let maybe_requires = state.plugin_cache.requires_response_body_buffering(&proxy.id);
        if maybe_requires {
            !plugins.iter().any(|p| p.should_buffer_response_body(&ctx))
        } else {
            true
        }
    }
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
| `tcp_logging` | No | No |
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
| Stream mode | Enabled | Present, within limit | Stream directly (or buffer if ≤ cutoff) |
| Stream mode | Enabled | Present, exceeds limit | Reject with 502 (before reading body) |
| Stream mode | Enabled | Absent | Stream with `SizeLimitedStreamingResponse` — frame-by-frame enforcement |
| Stream mode | Disabled (0) | Any | Stream directly |
| Buffer mode | Any | Any | Buffer and check size |

When Content-Length is absent, the `SizeLimitedStreamingResponse` adapter in `src/proxy/body.rs` wraps the response byte stream and counts bytes as they flow through. If the accumulated size exceeds the limit, it yields an error. This is the response-side equivalent of `SizeLimitedIncoming` for request bodies — it prevents OOM on large chunked responses that exceed the limit without buffering the entire body into memory.

See [docs/size_limits.md](size_limits.md) for the full size limit enforcement architecture.

## Protocol-Specific Behavior

### HTTP/1.1 and HTTP/2

Both protocols support streaming. By default, streaming responses use `ProxyBody::Stream` — a zero-overhead passthrough with no per-frame tracking. When `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=true`, the gateway uses `ProxyBody::Tracked` instead, which wraps the byte stream with lightweight completion tracking via `StreamingMetrics` (one atomic store per frame, plus one deferred `tokio::spawn` per streaming request).

### HTTP/3 (QUIC)

HTTP/3 responses support **streaming** across two distinct paths:

**H3 frontend → H3 backend** (in `http3/server.rs`): The H3 server's dedicated proxy path uses `Http3ConnectionPool::request_streaming()` to return a live `RequestStream`, then forwards response chunks directly to the QUIC client via `send_data()` with backpressure-aware adaptive coalescing (8–32 KiB accumulation, 2ms time-based flushing).

**H1/H2 frontend → H3 backend** (in `proxy/mod.rs`): When `stream_response=true`, the dispatch path uses `Http3ConnectionPool::request_streaming()` and returns `ResponseBody::StreamingH3`. The response body builder wraps the h3 `RequestStream` in `CoalescingH3Body` (configurable coalesce target) or `DirectH3Body` (zero-overhead passthrough), bridging h3's `recv_data()` async API to `http_body::Body` for hyper to forward to the HTTP/1.1 or H2 client. This eliminates the previous full-body buffering that occurred on this cross-protocol path.

When plugins require response body access (e.g., `ai_token_metrics`, `response_transformer`) or retries are configured, HTTP/3 responses fall back to **buffered** mode via `Http3ConnectionPool::request()` with full `on_response_body` and `transform_response_body` plugin hook support.

### gRPC

gRPC supports **full bidirectional streaming** of both request and response bodies when no plugins need body access and no retries are configured.

**Request body streaming**: The `GrpcConnectionPool` uses a `GrpcBody` sum type (`Buffered(Full<Bytes>)` | `Streaming(Incoming)`) so the same pool handles both buffered and streaming request bodies. When `proxy_grpc_request_streaming()` is used, the `Incoming` body is wrapped in `GrpcBody::Streaming` and forwarded frame-by-frame — each H2 DATA frame is sent to the backend immediately, with memory bounded by the H2 flow-control window size. When retries or plugins require the body, `proxy_grpc_request()` collects via `BodyExt::collect()` into `GrpcBody::Buffered`.

**Response body streaming**: HTTP/2 DATA frames are forwarded as they arrive from the backend, wrapped in `CoalescingH2Body` for efficient batching. HTTP/2 trailers (`grpc-status`, `grpc-message`) are forwarded automatically via hyper's `Incoming` body framing.

When plugins require response body access (e.g., `ai_token_metrics`) or retries are configured, gRPC falls back to **buffered** mode for both request and response — the full body and trailers are collected before constructing the response.

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
- `body::coalescing_body(response, content_length)` — Create a streaming body with chunk coalescing (128 KB target). Default for reqwest-backed HTTP/1.1 responses
- `body::coalescing_h2_body(body, content_length, coalesce_target)` — Create a streaming body with H2 DATA frame coalescing. Used for gRPC streaming and HTTP/2 direct pool. Trailer-safe: stashes gRPC trailers while flushing buffered data
- `body::coalescing_h3_body(recv_stream, content_length, coalesce_target)` — Create a streaming body that bridges h3's `recv_data()` API to `http_body::Body` with chunk coalescing. Used for H1/H2 frontend → H3 backend streaming via `ResponseBody::StreamingH3`
- `body::direct_streaming_h3_body(recv_stream, content_length)` — Zero-overhead passthrough for H3 response data. Used when no coalescing/size limits apply
- `body::size_limited_streaming_body(response, max_bytes, content_length)` — Streaming body with frame-by-frame size enforcement via `SizeLimitedStreamingResponse` + coalescing. Used when `max_response_body_size_bytes > 0` and Content-Length is absent
- `ProxyBody::streaming_tracked(response, baseline)` — Create a streaming body with completion tracking, returning `(ProxyBody, Arc<StreamingMetrics>)`

## When to Use Buffer Mode

Use `response_body_mode: buffer` when:

- A plugin needs to inspect or transform the **response body** (not just headers)
- You are debugging response content with `transaction_debugger` and `log_response_body: true`
- Your responses are small and the latency difference is negligible

Note: response body size limits are now enforced via `SizeLimitedStreamingResponse` even when Content-Length is absent — explicit buffer mode is no longer required for size enforcement.

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
    backend_scheme: http
    backend_host: "storage-service"
    backend_port: 8080
    response_body_mode: stream  # default, shown for clarity
```

### Buffered API with Response Body Inspection

```yaml
proxies:
  - id: "data-api"
    listen_path: "/data"
    backend_scheme: http
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
    backend_scheme: https
    backend_host: "api.example.com"
    backend_port: 443
    # response_body_mode defaults to stream

  # Auth-protected proxy — buffer for response validation
  - id: "internal-api"
    listen_path: "/internal"
    backend_scheme: http
    backend_host: "internal-service"
    backend_port: 3000
    response_body_mode: buffer
    plugins:
      - plugin_config_id: "auth-plugin"
      - plugin_config_id: "response-validator"
```
