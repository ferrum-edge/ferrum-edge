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

For `ProxyBody`-backed responses that stream (either below the adaptive buffer minimum or above the threshold), the gateway uses a **single protocol-agnostic coalescing adapter** that accumulates small backend chunks into larger frames before yielding to the protocol writer. `Coalescing<S: FrameSource>` in `src/proxy/body.rs` is generic over a `FrameSource` trait with three production implementations:

| Source | Used for | Builder |
|--------|----------|---------|
| `ReqwestFrameSource` | reqwest streams (HTTP/1.1, HTTP/2-via-reqwest) | `coalescing_body`, `size_limited_streaming_body` |
| `Incoming` (hyper) | direct HTTP/2 pool, gRPC pool | `coalescing_h2_body` |
| `H3FrameSource` | native H3 backend pool | `coalescing_h3_body` |

For those `ProxyBody` builders, the coalescing logic — buffer accumulation, large-frame pass-through, opportunistic flush on `Pending`, optional time-based flush, trailer/error stashing — lives entirely in the generic adapter. There is no separate H1/H2/H3 `ProxyBody` coalescer to keep in sync. The H2/H3 adapters are trailer-safe: gRPC trailers (`grpc-status`, `grpc-message`) and h3 trailers are stashed while buffered data is flushed, then returned on the next poll.

The H3 frontend → non-H3 backend cross-protocol bridge is the exception because it writes directly to the QUIC stream instead of returning a `ProxyBody`. Its response loops live in `src/http3/cross_protocol.rs::stream_reqwest_response` / `stream_hyper_incoming` and use local `BytesMut` coalescing, while sharing the H3 coalescing knobs below so native-H3 and cross-protocol H3 produce the same QUIC frame cadence.

This reduces the number of write syscalls by ~8–16× for large responses compared to forwarding each small chunk individually.

#### Direct HTTP/2 Large-Response Bypass

Direct HTTP/2 responses have a narrow large-response bypass — `direct_streaming_h2_body` is used in place of `coalescing_h2_body` — to avoid a copy when coalescing cannot help:

- `Content-Length` must be present, so the gateway can make the decision once before streaming.
- The response must fit within `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, or that limit must be disabled.
- The body must be at least 512 KiB. At that size, direct-H2 backend frames are already large enough that coalescing adds a copy before the existing large-frame fast path returns the original frame.

Unknown-size responses keep the coalescer because it is also the streaming size-enforcement path when `Content-Length` is absent. Small and mid-sized known responses below 512 KiB also keep the coalescer because they may arrive as multiple smaller backend DATA frames where write amortization still helps.

gRPC streaming responses intentionally stay on `coalescing_h2_body`; preserving trailers and large-payload batching matters more there.

#### Operator-Tunable Knobs

Each protocol has its own coalesce knob with bounds tuned for its native framing characteristics. The bounds intentionally differ — H3 chunks are QUIC-packet-sized (~1.5 KiB) so a 1 KiB floor is meaningful; H2 inbound DATA frames are typically ≥ 16 KiB (RFC 9113 default) so a smaller floor would just disable coalescing.

| Env Var | Default | Clamp Range | Path |
|---------|---------|-------------|------|
| `FERRUM_H2_COALESCE_TARGET_BYTES` | `131_072` (128 KiB) | `[16 KiB, 1 MiB]` | Direct H2 pool, gRPC pool |
| `FERRUM_HTTP3_COALESCE_MIN_BYTES` | `32_768` (32 KiB) | `[H3_COALESCE_MIN_FLOOR=1 KiB, H3_COALESCE_MAX_CAP=1 MiB]` | H3 native + cross-protocol bridge |
| `FERRUM_HTTP3_COALESCE_MAX_BYTES` | `32_768` (32 KiB) | same as above | H3 native + cross-protocol bridge |
| `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` | `200` | `[50 µs, 100 ms]` | H3 time-based flush deadline |

The H1/H2-via-reqwest path uses a fixed 128 KiB target (`COALESCE_TARGET` in `body.rs`) — there is no env-var knob for it because `Pending` opportunistically flushes the buffer on every poll-wakeup gap, so SSE / trickle-style backends are not held back regardless of target size.

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

Custom plugin authors should also read [Streaming-safe response plugins](../CUSTOM_PLUGINS.md#streaming-safe-response-plugins) for complete-body buffering, incremental `ResponseStreamInspector` hooks, `Content-Type` relabel safety, and the current transport limitations.

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
| `compression` | The client's `Accept-Encoding` selects no supported nonzero coding — identity, unsupported-only, or all-`q=0` requests (nothing to compress) — or the request is `HEAD` / request `no-transform`. It also skips (streams identity) when `before_proxy` negotiated a supported coding but could not reserve bounded response-buffer admission, or when `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` is unlimited (`0`) or above the fixed 32 MiB compression safety ceiling. The buffered population never exceeds the dedicated response-buffer semaphore, while codec CPU admission remains independent, and every compression-induced full-body collection has an absolute per-response bound. |
| `ai_token_metrics` | Request is native gRPC, or the client asked for a stream (`Accept: text/event-stream` / a `stream: true` request) without `buffer_streaming_responses: true` (pre-header); additionally, after headers, when the response content type is not JSON, or is `text/event-stream` without `buffer_streaming_responses: true` |
| `ai_rate_limiter` | Never for active HTTP/gRPC responses; response usage reconciliation needs the body. Its pre-request reservation path only buffers request bodies for JSON `POST` requests. |
| `ai_response_guard` | Never from request-side intent. An active guard buffers conservatively until pristine backend headers are known. A genuine backend event stream is then decided before header commit: enforcing/redacting/structural policies reject with 502 because they cannot inspect an unbounded stream completely, while a warn-only guard records the uninspectable stream and permits it. |
| `body_validator` response rules | Never from request-side intent. A genuine backend event stream is rejected with 502 before header commit while response validation is active. After headers, media types outside configured JSON/XML `response_content_types` (including malformed/ambiguous values that cannot match), and gRPC without applicable protobuf response validation, are released to stream; a missing type, matching JSON/XML, and applicable gRPC stay buffered. |
| `openapi_validator` response rules | Never from request-side intent. A genuine backend event stream follows the configured response-mismatch posture: `block` rejects before commit; `log_only` records the mismatch and permits the stream. |
| `waf` response-body rules | Never from request-side intent. A genuine backend event stream follows `on_body_too_large`: explicit `skip` permits it uninspected, `block` rejects in enforce mode, and `scan_truncated` rejects when an enforcing response-body rule or scoring policy would otherwise claim inspection (monitor-only policy records and permits it). |
| `response_size_limiting` with `require_buffered_check: true` | Never from request-side intent. A genuine backend event stream is rejected with 502 before commit because the strict route ceiling is a whole-body policy; without strict buffering, the global streaming byte counter remains the applicable bound. |
| `response_transformer` body rules | Never from request-side SSE intent: `Accept: text/event-stream` is client controlled, so pre-header buffering remains conservative. After backend headers, a response that actually declares `text/event-stream` is released; JSON, missing, and ambiguous types remain buffered. |

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

### Response-Header-Aware Downgrade (after response headers)

The pre-flight decision above runs *before* the backend request is sent, so it
cannot see the response headers and conservatively buffers whenever any
plugin *might* need the body. Once the backend response headers arrive, the
gateway re-checks the decision per response: if **no** plugin needs the body for
the actual status, `Content-Type`, `Content-Encoding`, and other representation
metadata, a response that was going to be buffered is
**downgraded to streaming** instead. The main beneficiary is `waf` with
`response_body_inspection` enabled — a non-allowlisted/binary response
(`application/octet-stream`, images, video, …) is streamed rather than buffered
and then skipped, saving memory and latency for bodies the WAF would not scan.

This downgrade is **narrowing-only**: it never forces buffering, so plugins that
need the body (caching, compression, response transforms, or `waf` for an
allowlisted type) are unaffected. With retries configured, ordinary responses
stay buffered. An active buffering plugin may explicitly opt an inherently
streaming representation out after headers arrive only when every other active
buffering plugin reports that it does not need that content type; the MCP and
A2A gateways use this for `text/event-stream`, whose retry decision is complete
from status and headers and whose body must not be collected to EOF.

Outbound body-policy plugins never use `Accept: text/event-stream` or an
internal request-streaming marker as authority to waive inspection. The Accept
parser treats `q=0`, malformed/bare `q`, duplicate `q`, and invalid qvalues as
non-affirmative even for non-policy streaming hints. The policy decision uses
the pristine backend `Content-Type` stamped before `after_proxy`; a later header
plugin cannot manufacture, erase, or relabel that evidence. A stamped missing
or ambiguous type is therefore never accepted as proof of SSE: each plugin's
ordinary non-SSE eligibility rules still apply. In particular, WAF may release a
type that is explicitly outside its configured response-body scan scope, while
the JSON/XML validators and strict response-size policies continue to claim it.
When several buffering plugins are active, release still requires every one of
them to agree; any plugin that claims the representation pins it to buffering or
returns its configured pre-commit rejection.

Because this check can only release a previously buffered response, complete-body
inspectors must treat opaque representation metadata conservatively. For example,
`ai_semantic_firewall` keeps eligible complete origin responses with any
non-identity `Content-Encoding` buffered even when `Content-Type` is missing or
non-JSON. Its final hook then decodes supported gzip/Brotli within the inspection
cap and routes empty, malformed, unsupported, or oversized encodings through the
configured `on_error` policy (fail-closed by default). Partial responses (`206`
or `Content-Range`) follow the same bounded encoded-body decision as complete
responses: decodable governed content remains inspectable, while malformed
fragments follow the configured uninspectable-body policy. Unencoded JSON
partials also remain subject to normal inspection. Unencoded unrelated event
streams also keep streaming; complete origin-encoded event streams stay buffered
for bounded decode because stream inspectors cannot parse compressed wire bytes.
After decoding, an SSE media type keeps SSE frame parsing unless the complete
payload is a valid standalone JSON document; this preserves later `data:` frames
after JSON-looking SSE preludes while still inspecting bare JSON mislabeled as
SSE. Once an encoded event stream is governed, every assembled non-empty,
non-`[DONE]` `data:` payload must parse as JSON; one unparseable frame makes the
decoded representation uninspectable and routes the whole response through
`on_error` instead of inspecting only its parseable subset. No encoding (or an
identity-only encoding list) still lets ordinary non-AI text stream, and a
gateway-planned compression transform is not mistaken for already-encoded
origin bytes, including when a later header hook switches between supported gzip
and Brotli output.

**Protocol coverage.** The downgrade applies on the HTTP/1.1 + HTTP/2 (reqwest),
direct-HTTP/2, HBONE, native-HTTP/3 header-first, and HTTP/3 cross-protocol
backend paths. Native HTTP/3 opens a streaming response to obtain the headers,
then either retains that stream for bounded collection or releases it to the
client. **gRPC** keeps the pre-flight buffering decision so its framing and
trailer semantics remain intact.

**Content-Type relabel safety.** The downgrade keys off the **backend's**
response `Content-Type`, but it is suppressed when an active plugin reports that
it may later modify the response `Content-Type` in `after_proxy`. Built-in
plugins use `may_modify_response_content_type()` for their relabel cases:
`response_transformer` covers static `Content-Type` header rules and route-level
response-transform overrides, `sse` covers forced SSE relabeling, and `grpc_web`
covers gRPC-Web response relabeling. As a result, a WAF-inspected response that
starts as `application/octet-stream` and is relabeled to `application/json` by
`response_transformer` stays buffered, so `on_final_response_body` evaluates it
with the final client-visible headers.

For `response_transformer` body rules, a static or route-level header rule that
may change `Content-Type` therefore also keeps a genuine backend event stream on
the conservative buffered path. An unbounded stream in that configuration will
eventually reach the response-body ceiling and return 502; operators should not
combine document body rules with `Content-Type` relabeling on an SSE route.

Custom plugins that change response `Content-Type` in `after_proxy` must also
override `may_modify_response_content_type()`. Otherwise they can recreate the
same backend-header downgrade gap. Operators can still force conservative
behavior for a proxy by setting `response_body_mode: buffer`.

### Built-in Plugin Compatibility

Header-only response plugins remain stream-compatible. Plugins configured to
inspect, transform, cache, or compress the response body participate in the
buffering decision and may narrow that decision by request or response
`Content-Type`.

| Plugin / configuration | Modifies Response Body? | Requires Buffering? |
|------------------------|------------------------|-------------------|
| `response_transformer` header-only rules | No | No |
| `response_transformer` body rules | Yes for JSON; genuine SSE is outside the document policy | Yes before headers; released after headers only for backend `text/event-stream` |
| `ai_response_guard` enforcing/redacting rules | Yes | Yes before headers; genuine backend SSE is rejected with 502 before commit |
| `ai_response_guard` warn-only rules | No mutation | Yes before headers; genuine backend SSE is recorded as uninspectable and may stream only if every other active plugin permits it |
| `body_validator` response rules | Validation only | Yes before headers; genuine backend SSE is rejected with 502 before commit. After headers, non-matching JSON/XML media types and gRPC without applicable protobuf validation are released to stream; matching JSON/XML and applicable gRPC stay buffered. |
| `openapi_validator` response rules | Validation only | Yes before headers; genuine backend SSE is rejected in `block` mode or recorded/allowed in `log_only` mode |
| `waf` response-body rules | Inspection/rejection only | Yes before headers; genuine backend SSE follows the explicit `on_body_too_large` and enforcement/scoring posture |
| strict `response_size_limiting` | Validation only | Yes before headers; genuine backend SSE is rejected because a whole-body route ceiling cannot be proven incrementally |
| `cors` | No (headers only) | No |
| `stdout_logging` | No | No |
| `http_logging` | No | No |
| `tcp_logging` | No | No |
| `transaction_debugger` | No | No |

## Interaction with Retry Logic

When retry is configured on a proxy, the gateway must be able to inspect the response status code before deciding whether to retry. That decision is made entirely at response-header time — `retry::should_retry` consults only the status code, the connection-error flag, the error class, and the request method — so retry does not require reading a response body:

- **Every attempt**: When the proxy is configured for streaming (and no plugin forces buffering), the streaming decision is preserved on the initial attempt *and on every retry attempt*. An attempt whose headers select a retry drops its undrained backend response before a single byte reaches the client, and the next attempt is dispatched with the same streaming intent. A response that succeeds on an earlier attempt — an SSE stream served after one retryable `503`, say — therefore still streams (issue #2949).
- **Buffered proxies**: When `response_body_mode: buffer` or a plugin forces buffering, attempts are buffered instead. Inherently streaming responses may still be released to stream after headers through the all-plugin opt-in described above; a retryable status is discarded before any bytes reach the client.
- **After streaming begins**: On any attempt, a failure that occurs once response bytes have been committed downstream cannot be retried.

```
Attempt 1: headers → retryable status? → drop undrained body → retry
Attempt 2: headers → retryable status? → drop undrained body → retry
Attempt 3: headers → not retryable → stream body directly to client
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

Both protocols support streaming. By default, streaming responses use `ProxyBody::Stream` — a zero-overhead passthrough with no per-frame tracking. When `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=true`, the gateway calls `base_body.into_tracked(backend_start)` on the same base body the regular streaming path produces — so the tracked path inherits coalescing, the small-response eager buffer cutoff, and any `SizeLimitedStreamingResponse` wrapping. There is no separate "tracked + coalesced" or "tracked + size-limited" constructor; tracking is a transformation applied on top of whatever streaming dispatch the regular path picked. Per-frame cost: one atomic store via `StreamingMetrics`, plus one deferred `tokio::spawn` per streaming request.

### HTTP/3 (QUIC)

HTTP/3 responses support **streaming** across three distinct paths. See [docs/http3.md](http3.md) for the full dispatch model.

**H3 frontend → H3 backend** (in `http3/server.rs`, when the concrete HTTPS backend target is already classified as H3-capable): The H3 server's dedicated proxy path uses `Http3ConnectionPool::request_streaming()` to return a live `RequestStream`, then forwards response chunks directly to the QUIC client via `send_data()` with backpressure-aware adaptive coalescing (8–32 KiB accumulation, 2ms time-based flushing).

**H1/H2 frontend → H3 backend** (in `proxy/mod.rs`): When `stream_response=true`, the dispatch path uses `Http3ConnectionPool::request_streaming()` and returns `ResponseBody::StreamingH3`. The response body builder wraps the h3 `RequestStream` in `CoalescingH3Body` (configurable coalesce target) or `DirectH3Body` (zero-overhead passthrough), bridging h3's `recv_data()` async API to `http_body::Body` for hyper to forward to the HTTP/1.1 or H2 client. This eliminates the previous full-body buffering that occurred on this cross-protocol path.

**H3 frontend → non-H3 backend** (in `http3/cross_protocol.rs`, any request whose backend target is not classified as H3-capable or whose flavor != `Plain`): The H3 listener drives the same reqwest / HTTP/2 / gRPC backends as the H1/H2 proxy path:

- **Request body** — streamed via a bounded `tokio::sync::mpsc` bridge into `reqwest::Body::wrap_stream` for `Plain` flavor. Mirrors the H1/H2 plugin-driven policy: stream by default, buffer only when a plugin pre-collected the body. Bridge capacity is `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` (default 32). `Grpc` flavor buffers the request body because the gRPC pool's retry-safe framing expects `Bytes`; unary gRPC bodies are small so this is acceptable.
- **Response body** — streamed frame-by-frame with the same `http3_coalesce_*` window as the native H3 writer, so QUIC frame cadence is identical across dispatch kinds. `Plain` polls `reqwest::Response::chunk()`; `Grpc` polls hyper `Incoming::frame()` so trailer frames split off for `RequestStream::send_trailers()`.

When plugins require response body access (e.g., `ai_token_metrics`, `response_transformer`) or retries are configured, HTTP/3 responses fall back to **buffered** mode via `Http3ConnectionPool::request()` with full `on_response_body` and `transform_response_body` plugin hook support.

### gRPC

gRPC supports **full bidirectional streaming** of both request and response bodies when no plugins need body access and no retries are configured.

**Request body streaming**: The `GrpcConnectionPool` uses a `GrpcBody` sum type (`Buffered(Full<Bytes>)` | `Streaming(Incoming)`) so the same pool handles both buffered and streaming request bodies. When `proxy_grpc_request_streaming()` is used, the `Incoming` body is wrapped in `GrpcBody::Streaming` and forwarded frame-by-frame — each H2 DATA frame is sent to the backend immediately, with memory bounded by the H2 flow-control window size. When retries or plugins require the body, the gateway collects it once into `GrpcBody::Buffered`. A body already collected for an earlier phase such as `hmac_auth` authentication or `request_mirror` is reused with its original method and raw metadata, under the gRPC receive-size and request-body timeout limits. Applicable transforms and final hooks run once after the earliest consumer; an already prepared body is dispatched without a second hook pass. H3 follows the same single-prebuffer contract through its cross-protocol bridge.

**Response body streaming**: HTTP/2 DATA frames are forwarded as they arrive from the backend, wrapped in `CoalescingH2Body` for efficient batching. HTTP/2 trailers (`grpc-status`, `grpc-message`) are forwarded automatically via hyper's `Incoming` body framing.

When native-gRPC-capable plugins require response body access or retries are configured, gRPC falls back to **buffered** mode for both request and response — the full body and trailers are collected before constructing the response. `ai_token_metrics` is HTTP-only: enabling it alone does not alter native gRPC streaming or inspect protobuf frames.

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
- `body::coalescing_body(response, content_length)` — Create a streaming body with chunk coalescing (128 KB target). Default for reqwest-backed HTTP/1.1 responses. Builds `Coalescing<ReqwestFrameSource>`.
- `body::direct_streaming_body(response, content_length)` — Zero-overhead passthrough for reqwest streams. Used when both `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0` and `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0`.
- `body::size_limited_streaming_body(response, max_bytes, content_length)` — Streaming body with frame-by-frame size enforcement via `SizeLimitedStreamingResponse` + coalescing. Used when `max_response_body_size_bytes > 0` and Content-Length is absent.
- `body::coalescing_h2_body(body, content_length, coalesce_target)` — H2 DATA frame coalescing for gRPC streaming and HTTP/2 direct pool. Builds `Coalescing<Incoming>`. Trailer-safe.
- `body::direct_streaming_h2_body(body, content_length)` — Zero-overhead H2 passthrough; used for the large-response bypass and the H2 fast path.
- `body::coalescing_h3_body(recv_stream, content_length, coalesce_min, coalesce_max, flush_interval)` — Bridges h3's `recv_data()` API to `http_body::Body` with chunk coalescing. Builds `Coalescing<H3FrameSource>`. Used for H1/H2 frontend → H3 backend streaming via `ResponseBody::StreamingH3`.
- `body::direct_streaming_h3_body(recv_stream, content_length)` — Zero-overhead passthrough for H3 response data. Used when no coalescing/size limits apply.
- `ProxyBody::into_tracked(self, baseline)` — Wrap any streaming `ProxyBody` (returned by any of the builders above) in completion tracking, returning `(ProxyBody, Arc<StreamingMetrics>)`. No-op on `Full` or already-`Tracked` bodies. Use this so the tracked path picks up the same coalescing / size-limit / SSE-bypass behaviour as the default streaming path — there is no separate "tracked" body builder.

## When to Use Buffer Mode

Use `response_body_mode: buffer` when:

- A plugin needs to inspect or transform the **response body** (not just headers)
- Your responses are small and the latency difference is negligible

`transaction_debugger` does not capture payloads and does not require buffer
mode. It reports final body completion, byte counts, disconnects, and typed
streaming errors from the terminal transaction summary instead.

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
