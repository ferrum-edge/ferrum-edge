# Response Body Streaming

Ferrum Edge supports two modes for handling backend response bodies: **streaming** (default) and **buffering**. This is configurable per-proxy via the `response_body_mode` field and can be overridden by plugins that need access to the full response body.

## Table of Contents

- [Overview](#overview)
- [Configuration](#configuration)
- [How Streaming Works](#how-streaming-works)
- [Plugin Buffering Override](#plugin-buffering-override)
- [Authorization Lifetime of an Admitted Stream](#authorization-lifetime-of-an-admitted-stream)
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

Streaming is the default because it provides better latency and memory characteristics for the majority of use cases. Buffering is required when a plugin needs to inspect or transform the complete response body — and, as one compatibility exception outside body inspection, when a translated gRPC-Web request carries an active plugin that requires the buffered trailer-compatibility policy (see the Decision Flow below).

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
2. Checks whether the response qualifies for **small-response buffering** (see below).
3. If not buffered, begins forwarding the response to the client **without waiting for the full body**, through the generic `Coalescing` adapter that batches small backend chunks into larger frames (see [Response Body Coalescing](#response-body-coalescing)).

This means the client sees the first byte of the response as soon as the backend sends it, rather than waiting for the entire response to be collected — unless small-response buffering applies.

Request-future stack and boxing boundaries are documented in [request_lifetime_dispatch.md](request_lifetime_dispatch.md#request-future-stack-boundaries).

### Small Response Buffering

When a backend response has a known `Content-Length ≤ 64 KiB` (configurable), the gateway collects the entire body into a single bounded allocation instead of streaming it through the coalescing adapter. For typical JSON API payloads this is cheaper than driving the adapter's poll loop and frame accounting. Responses without `Content-Length` or with `Content-Length` above the cutoff always stream.

Body-bearing SSE responses (`Content-Type: text/event-stream`) **always stream** regardless of `Content-Length`, since they represent inherently unbounded or latency-sensitive streams.

Representation metadata on a no-content response is not an uninspectable stream.
Responses to `HEAD`, informational `1xx` responses where response hooks run, and
statuses `204`, `205`, and `304` carry no content regardless of `Content-Type`.
Whole-body policies (`response_size_limiting` in strict mode, `body_validator`,
`openapi_validator`, `ai_response_guard`, and WAF response-body inspection) do not
buffer or refuse those responses as SSE. Response-header policies still run.
A genuine body-bearing SSE response still follows the configured streaming refusal
policy, using the original backend headers even if another plugin relabels it.

| Env Var | Default | Description |
|---------|---------|-------------|
| `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES` | `65536` (64 KiB) | Responses with known Content-Length ≤ this value are eagerly buffered. `0` = disabled (always stream). |

This optimization **only activates when no plugins require response body buffering** — when plugins need the body, the existing plugin-forced buffering path takes precedence.

### Response Body Coalescing

For `ProxyBody`-backed responses that stream (no `Content-Length`, `Content-Length` above the cutoff, or body-bearing SSE), the gateway uses a **single protocol-agnostic coalescing adapter** that accumulates small backend chunks into larger frames before yielding to the protocol writer. `Coalescing<S: FrameSource>` in `src/proxy/body.rs` is generic over a `FrameSource` trait with three production implementations:

| Source | Used for | Builder |
|--------|----------|---------|
| `ReqwestFrameSource` | reqwest streams (HTTP/1.1, HTTP/2-via-reqwest) | `coalescing_body`, `size_limited_streaming_body` |
| `Incoming` (hyper) | direct HTTP/2 pool, gRPC pool | `coalescing_h2_body_strip_hop_by_hop_trailers`, `size_limited_coalescing_h2_body_strip_hop_by_hop_trailers` |
| `H3FrameSource` | native H3 backend pool | `coalescing_h3_body`, `size_limited_streaming_h3_body` |

For those `ProxyBody` builders, the coalescing logic — buffer accumulation, large-frame pass-through, opportunistic flush on `Pending`, optional time-based flush, trailer/error stashing — lives entirely in the generic adapter. There is no separate H1/H2/H3 `ProxyBody` coalescer to keep in sync. The H2/H3 adapters are trailer-safe: gRPC trailers (`grpc-status`, `grpc-message`) and h3 trailers are stashed while buffered data is flushed, then returned on the next poll.

**The accumulator is lazy.** Construction reserves nothing: the adapter holds the first DATA frame's `Bytes` directly and allocates the aggregation `BytesMut` — at the configured capacity — only when a second frame actually has to be merged into it. A response that yields one frame, an idle body that yields none, and a frame at or above the flush target (the large-frame pass-through) therefore reach the client on the backend's own payload storage, with no aggregation allocation and no copy. Merging is where the copy is paid for, once per flushed batch, which is the point of coalescing. Everything else is unchanged: the flush target, the flush on `Pending`, the H3 timed flush, trailer/error stashing, and `size_hint`.

An already-ended backend body also preserves its terminal state before the first
poll. For a gRPC Trailers-Only response, this lets the HTTP/2 writer set
`END_STREAM` on the initial `HEADERS`, retaining `grpc-status`, `grpc-message`
and `grpc-status-details-bin` as terminal metadata. The same rule applies through
the size-limit and trailer-filter wrappers used by direct gRPC, mesh mTLS and
HBONE responses. Buffered data, a pending trailer or a pending error prevents
early completion; a zero content length alone does not establish it.

The H3 frontend → non-H3 backend cross-protocol bridge is the exception because it writes directly to the QUIC stream instead of returning a `ProxyBody`. Its response loops live in `src/http3/cross_protocol.rs::stream_reqwest_response` / `stream_hyper_incoming` and use local `BytesMut` coalescing, while sharing the H3 coalescing knobs below so native-H3 and cross-protocol H3 produce the same QUIC frame cadence.

This reduces the number of write syscalls by ~8–16× for large responses compared to forwarding each small chunk individually.

#### Direct HTTP/2 Large-Response Bypass

Direct HTTP/2 responses have a narrow large-response bypass — `direct_streaming_h2_body_strip_hop_by_hop_trailers` is used in place of the coalescing builder — to avoid a copy when coalescing cannot help:

- `Content-Length` must be present, so the gateway can make the decision once before streaming.
- The response must fit within `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES`, or that limit must be disabled.
- The body must be at least 512 KiB. At that size, direct-H2 backend frames are already large enough that coalescing adds a copy before the existing large-frame fast path returns the original frame.

Unknown-size responses keep the coalescer because it is also the streaming size-enforcement path when `Content-Length` is absent. Small and mid-sized known responses below 512 KiB also keep the coalescer because they may arrive as multiple smaller backend DATA frames where write amortization still helps.

gRPC streaming responses intentionally stay on the coalescing builder; preserving trailers and large-payload batching matters more there.

#### Operator-Tunable Knobs

Each protocol has its own coalesce knob with bounds tuned for its native framing characteristics. The bounds intentionally differ — H3 chunks are QUIC-packet-sized (~1.5 KiB) so a 1 KiB floor is meaningful; H2 inbound DATA frames are typically ≥ 16 KiB (RFC 9113 default) so a smaller floor would just disable coalescing.

| Env Var | Default | Clamp Range | Path |
|---------|---------|-------------|------|
| `FERRUM_H2_COALESCE_TARGET_BYTES` | `131_072` (128 KiB) | `[16 KiB, 1 MiB]` | Direct H2 pool, gRPC pool |
| `FERRUM_HTTP3_COALESCE_MIN_BYTES` | `32_768` (32 KiB) | `[H3_COALESCE_MIN_FLOOR=1 KiB, H3_COALESCE_MAX_CAP=1 MiB]` | H3 native + cross-protocol bridge |
| `FERRUM_HTTP3_COALESCE_MAX_BYTES` | `32_768` (32 KiB) | same as above | H3 native + cross-protocol bridge |
| `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS` | `200` | `[50 µs, 100 ms]` | H3 time-based flush deadline |

The reqwest-backed path uses a fixed 128 KiB target (`COALESCE_TARGET` in `body.rs`). There is no knob for the target because the adapter flushes on every `Pending`, so SSE / trickle-style backends are not held back regardless of target size. `FERRUM_RESPONSE_COALESCE_FLUSH_MS` (default `0` = off, max `1000`) can instead hold sub-target frames for a bounded window on that path, clamped to half of `backend_read_timeout_ms`; it helps bulk transfer and delays low-rate streams, so enable it only on bulk-transfer routes (see [configuration.md](configuration.md)).

### Decision Flow

```
Translated gRPC-Web request + a plugin requires the buffered
trailer-compatibility policy (e.g. response_transformer header rules)?
    └─ Yes → buffer entire response (precedes every branch below; a plain
       grpc_web instance with no such plugin remains streaming)
    └─ No →
response_body_mode = buffer?
    └─ Yes → buffer entire response
    └─ No (stream) →
        Config-time: any plugin requires buffering?
            └─ Yes → per-request: should_buffer_response_body(ctx)?
                └─ Yes → buffer entire response
                └─ No (all plugins skip for this request) → stream
            └─ No →
                Retries configured?
                    └─ Yes → stream on every attempt when the proxy streams
                       (HTTP/1.1 and HTTP/2 frontends; retry decides from
                       headers alone; a retryable attempt drops its undrained
                       body before client commit). Buffer only when
                       response_body_mode/plugins force buffering. The H3
                       cross-protocol bridge behaves the same; when the
                       initial attempt uses the native QUIC pool (plain HTTP
                       to a non-mesh H3 target, not reqwest-forced), the
                       native handler's retry loop
                       buffers its attempts, even ones rotated onto non-H3
                       targets, and plain-HTTP mesh attempts from H3 are
                       always buffered (see Interaction with Retry Logic).
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
| `compression` | The client's `Accept-Encoding` selects no supported nonzero coding — identity, unsupported-only, or all-`q=0` requests (nothing to compress) — or the request is `HEAD` / request `no-transform`. It also skips (streams identity) when `before_proxy` negotiated a supported coding but could not reserve bounded response-buffer admission, or, when `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES` (or the route ceiling) is unlimited (`0`) or above the fixed 32 MiB compression safety ceiling, when the response does not declare a `Content-Length` within that ceiling and the buffered-response fallback (length-gated compression; with retries configured the release still applies). A length-gated native gRPC request never buffers for compression. The buffered population never exceeds the dedicated response-buffer semaphore, while codec CPU admission remains independent, and every compression-induced full-body collection has an absolute per-response bound. |
| `ai_token_metrics` | Request is native gRPC, or the client asked for a stream (`Accept: text/event-stream` / a `stream: true` request) without `buffer_streaming_responses: true` (pre-header); additionally, after headers, when the response status is not 2xx, or the content type is not JSON, or is `text/event-stream` without `buffer_streaming_responses: true`. A released SSE or AWS event-stream response is still metered incrementally by its pass-through stream inspector |
| `ai_rate_limiter` | Its config-time capability remains enabled, but this instance skips response buffering when the request has no AI/deferred-compressed/reservation accounting candidate, or when response headers show a non-2xx status or a missing, non-JSON, or framed-gRPC representation. A candidate successful JSON response stays buffered for usage reconciliation. Other plugins or `response_body_mode: buffer` may still require buffering. Its pre-request reservation path only buffers request bodies for JSON `POST` requests. |
| `ai_response_guard` | Never from request-side intent. An active guard buffers conservatively until pristine backend headers are known. A genuine backend event stream is then decided before header commit: enforcing/redacting/structural policies reject with 502 because they cannot inspect an unbounded stream completely, while a warn-only guard records the uninspectable stream and permits it. Native gRPC is the one request-side exception: a gRPC request whose method is not enrolled in the plugin's `grpc` block is released to stream, because an un-enrolled method has no decodable contract to enforce. |
| `body_validator` response rules | Never from request-side intent. A genuine backend event stream is rejected with 502 before header commit while response validation is active. After headers, media types outside configured JSON/XML `response_content_types` (including malformed/ambiguous values that cannot match), and gRPC without applicable protobuf response validation, are released to stream; a missing type, matching JSON/XML, and applicable gRPC stay buffered. |
| `openapi_validator` response rules | Never from request-side intent. A genuine backend event stream follows the configured response-mismatch posture: `block` rejects before commit; `log_only` records the mismatch and permits the stream. |
| `waf` response-body rules | Never from request-side intent. A genuine backend event stream follows `on_body_too_large`: explicit `skip` permits it uninspected, `block` rejects in enforce mode, and `scan_truncated` rejects when an enforcing response-body rule or scoring policy would otherwise claim inspection (monitor-only policy records and permits it). |
| `response_size_limiting` with `require_buffered_check: true` | Never from request-side intent. A genuine backend event stream is rejected with 502 before commit because the strict route ceiling is a whole-body policy, unless its backend declared one exact `Content-Length` within `max_bytes` and no streaming response inspector on the route can rewrite it (that stream has proven its size and streams under its declared length). The gateway-generated `mcp_gateway` aggregate SSE listener is refused the same way. Without strict buffering, the effective route/global streaming ceiling remains the applicable bound. |
| `response_transformer` body rules | Never from request-side SSE intent: `Accept: text/event-stream` is client controlled, so pre-header buffering remains conservative. After backend headers, a response that actually declares `text/event-stream` is released; JSON, missing, and ambiguous types remain buffered. |

The decision in code:

```rust
// Translated gRPC-Web trailer-policy exception, checked first: an enabled
// response_transformer with header rules requires this policy even though
// its body-buffering vote below is false. A plain grpc_web instance streams.
if request_is_grpc_web_translated(&ctx)
    && plugins.iter().any(|p| p.requires_buffered_grpc_web_trailer_policy(&ctx))
{
    return false; // buffer
}
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
allowlisted type) are unaffected. With retries configured, the downgrade does
not apply to ordinary responses. An active buffering plugin may explicitly opt an inherently
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
| `transaction_debugger` | No | Only with `log_response_body: true`, the `transaction_debug` DEBUG target enabled, and only for an identity-encoded, capturable textual response whose `Content-Length` fits the configured cap. gRPC (typed flavor), WebSocket including H2/H3 Extended CONNECT (typed flavor), SSE, chunked/unknown-length, encoded, oversized, and non-textual responses are released to stream. |

## Authorization Lifetime of an Admitted Stream

Every authenticated stream (SSE, chunked HTTP, native gRPC, gRPC-Web, and request uploads) carries one absolute authorization deadline: the earlier of the accepted credential's expiry and `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS` (default `3600`). Activity never extends it, and unauthenticated streams are untouched. Before the response head is committed, expiry produces a fixed `401` (or trailers-only `grpc-status: 16` for gRPC); after commitment but before any response DATA, native gRPC receives `grpc-status: 16` trailers and gRPC-Web receives its encoded `grpc-status: 16` trailer frame in DATA; every other case ends with a transport error. A gateway-owned response pump and upload pump enforce the deadline even when the client stops reading or the backend is parked on flow control.

The full contract, including termination semantics, the pumps, the final pre-commitment gate, observability, and coverage, is in [stream_authorization_lifetime.md](stream_authorization_lifetime.md).

## Interaction with Retry Logic

When retry is configured on a proxy, the gateway must be able to inspect the response status code before deciding whether to retry. That decision is made entirely at response-header time — `retry::should_retry` consults only the status code, the connection-error flag, the error class, and the request method — so retry does not require reading a response body:

- **Every attempt (HTTP/1.1 and HTTP/2 frontends)**: When the proxy is configured for streaming (and no plugin forces buffering), the streaming decision is preserved on the initial attempt *and on every retry attempt*. An attempt whose headers select a retry drops its undrained backend response before a single byte reaches the client, and the next attempt is dispatched with the same streaming intent. A response that succeeds on an earlier attempt — an SSE stream served after one retryable `503`, say — therefore still streams (issue #2949).
- **Buffered proxies**: When `response_body_mode: buffer` or a plugin forces buffering, attempts are buffered instead. Inherently streaming responses may still be released to stream after headers through the all-plugin opt-in described above; a retryable status is discarded before any bytes reach the client.
- **HTTP/3 frontend**: Which retry loop runs is decided by how the **initial** attempt is dispatched. Unless the H3 handler dispatches the initial attempt on the native QUIC pool (a plain-HTTP request to an H3-capable, non-mesh target that is not deadline-bound gRPC-Web and that no plugin forces onto reqwest), the H3 cross-protocol bridge (`http3/cross_protocol.rs`) runs the retry loop — this includes gRPC, reqwest-forced requests and non-H3 targets, even when the target also supports H3 — decides every attempt from headers, and streams like the H1/H2 frontends — for its reqwest (HTTP/1.1, HTTP/2) and gRPC response paths. Plain-HTTP attempts to mesh targets (HBONE or sidecar mesh-mTLS) are the exception: the bridge sends them through a buffered mesh dispatch, so their responses are collected whole whether or not retries are configured. When the initial attempt is dispatched on the native QUIC pool, the native H3 handler's retry loop runs instead and, with retries configured, buffers each attempt's response — including attempts that rotate onto a non-H3 target, which it sends through the buffered reqwest retry path (or the buffered mesh dispatch for a mesh target). Its one exception is the **initial** attempt, which may still stream an inherently streaming response when every plugin opts in to releasing it after headers; every retry attempt after that is buffered.
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
| Stream mode | Enabled | Absent (backend-observed) | Stream with `SizeLimitedStreamingResponse` — frame-by-frame enforcement |
| Stream mode | Disabled (0) | Any | Stream directly |
| Buffer mode | Any | Any | Buffer and check size |

When the backend did not declare a canonical Content-Length, the `SizeLimitedStreamingResponse` adapter in `src/proxy/body.rs` wraps the response byte stream and counts bytes as they flow through. That decision uses the length captured before `after_proxy`; a hook that inserts or rewrites `Content-Length` cannot suppress the adapter. If the accumulated size exceeds the limit, it yields an error. The response is already committed at that point, so the chain holds the error for one scheduler turn before the frontend sees it. Without that turn, a small over-limit body that arrives in one read trips the limit in the same write pass that queued the head, and the client sees the connection close before any status line. On HTTP/1.1 the held turn ends the connection task's write pass without the error, and the task flushes the status line, headers, and the bytes accepted within the limit as that pass ends. Once the socket accepts the write, the client deterministically sees them before the connection closes mid-body. On HTTP/2 and HTTP/3 the flush runs on another task (h2's connection task, quinn's connection driver), so the turn is best effort: under tokio it almost always lets the HEADERS frame and the accepted data leave before the stream reset, but it does not guarantee it. The direct-H2/gRPC and native-H3 size-limited adapters hold the error the same way. So do the unlimited streaming bodies when the backend errors or resets: reqwest (`coalescing_body`, `direct_streaming_body`), direct HTTP/2 and gRPC (`coalescing_h2_body_strip_hop_by_hop_trailers`, `direct_streaming_h2_body_strip_hop_by_hop_trailers`), and native HTTP/3 (`coalescing_h3_body`, `direct_streaming_h3_body`). The plugin-inspected streaming body (`inspected_streaming_body`) holds the size-limit, backend, and idle-timeout errors its inspection task sends. The hold sits outside the builder-level idle read timeout and gRPC deadline, so a backend error read on the same poll that the idle deadline expires is still reported as the backend error, not as a read timeout. Outer client, route and stream-auth deadlines wrap the finished `ProxyBody` on the generic H2 and H3 paths, so they can still win on the held turn. This is the response-side equivalent of `SizeLimitedIncoming` for request bodies — it prevents OOM on large chunked responses that exceed the limit without buffering the entire body into memory.

**Rewritten streams are bounded on their output.** The source adapters above count the backend's own bytes. A streaming rewrite that changes the byte count is additionally charged on the bytes it releases to the client, through one shared boundary (`response_output_crosses_ceiling` in `src/proxy/body.rs`): every response-inspector driver (`run_response_inspection` for reqwest, `run_proxy_body_response_inspection` for direct HTTP/2, the native HTTP/3 frontend relay in `src/http3/server.rs`, and the HTTP/3 cross-protocol relay) charges every `Forward` window, `Terminate` payload, and `on_end()` flush; the incremental gRPC-Web translator (`into_grpc_web_streaming`, and the native-H3 cross-protocol relay) charges base64 text expansion and the generated trailer frame; and the gateway-generated aggregate MCP SSE body charges its greeting, events, and keepalives. The frame that would cross the effective ceiling is never sent, and the committed body ends with the same `ResponseBodyTooLarge` error; the inspected and aggregate SSE bodies hold it for one scheduler turn like the source adapters do.

See [docs/size_limits.md](size_limits.md) for the full size limit enforcement architecture.

## Protocol-Specific Behavior

### HTTP/1.1 and HTTP/2

Both protocols support streaming. By default, streaming responses use `ProxyBody::Stream` — a zero-overhead passthrough with no per-frame tracking. When `FERRUM_ENABLE_STREAMING_LATENCY_TRACKING=true`, the gateway calls `base_body.into_tracked(backend_start)` on the same base body the regular streaming path produces — so the tracked path inherits coalescing, the small-response eager buffer cutoff, and any `SizeLimitedStreamingResponse` wrapping. There is no separate "tracked + coalesced" or "tracked + size-limited" constructor; tracking is a transformation applied on top of whatever streaming dispatch the regular path picked. Per-frame cost: one atomic store via `StreamingMetrics`, plus one deferred `tokio::spawn` per streaming request.

#### Response trailer contract (HTTP/1.1 and HTTP/2 frontends)

A backend's trailer section reaches the client whenever the client can receive one, whichever internal dispatch path and body mode served the response (issue #5760). The only exceptions are the documented policy drops below.

| Frontend | Backend leg | Streamed response | Buffered response (`response_body_mode: buffer`, a body-buffering plugin, or the small-response eager buffer) |
|----------|-------------|-------------------|------------------------------------------------------------------------|
| HTTP/2 | Direct HTTP/2 pool (`h2_tls = supported`) | Relayed | Relayed after the buffered DATA |
| HTTP/2 | reqwest (`Unknown`/`Unsupported` capability, retries, request-body buffering) | Relayed (HTTP/2 backend, or HTTP/1.1 chunked backend) | Relayed after the buffered DATA |
| HTTP/2 | Native HTTP/3 backend | Relayed | Dropped (the buffered H3 drain keeps the body only) |
| HTTP/2 | Sidecar mTLS | Relayed | Relayed after the buffered DATA (plain HTTP) |
| HTTP/2 | HBONE / Unix socket (inner HTTP/1.1) | Relayed | Relayed after the buffered DATA (chunked trailer fields) |
| HTTP/1.1 | Any | Not sent | Not sent |

HTTP/1.1 clients never receive a trailer section from this handler: hyper writes chunked trailers only for names the response declares in a `Trailer` field, and the final response-header sanitizer strips `Trailer` as a hop-by-hop field. The reqwest relay therefore drops the trailer frame at the source for HTTP/1.1 clients and captures no policy evidence for it. It does the same when the backend response cannot carry a trailer section at all: an HTTP/1.x response framed by `Content-Length` or connection close (only HTTP/2 responses and HTTP/1.1 chunked responses can). Such a response never pays for the pre-policy header snapshot or the final-header clone that the trailer policy boundary needs. Native gRPC keeps its own trailer handling (the direct gRPC pool), and translated gRPC-Web re-encodes terminal metadata as a body frame; neither uses the buffered plain-HTTP trailer section above.

Every relayed section is governed exactly like the direct-HTTP/2 streaming relay's (next section): response-direction hop-by-hop names are stripped, then the response-header policy boundary drops any field the configured policy governs. When nothing in a plain-HTTP section survives, the body ends on its last DATA frame instead of an empty trailer frame (a reqwest gRPC terminal section keeps its frame). A buffered response carries no backend trailers when the gateway replaced the body (plugin reject, a late gateway-selected terminal), for `HEAD`, or for a status that forbids content.

#### Backend trailers on the direct-HTTP/2 streaming path

A direct-H2 streaming response (`ResponseBody::StreamingH2`) commits its initial HEADERS frame before the backend's TRAILERS frame exists, so it crosses the same response-header policy boundary the native-H3 streaming relays cross. Every direct / size-limited / coalescing variant of that arm therefore installs the same reconciliation, described in full in [docs/http3.md → Backend trailers and response header policy](http3.md#backend-trailers-and-response-header-policy): declared `Plugin::response_trailer_policy()` names and prefixes, the observed pre-policy mutation witness, and the fail-closed `Unbounded` arm (`response_transformer`). Without it, `security_headers` configured with `{"remove": ["x-powered-by"]}` is a no-op on the initial header map when the backend sends `x-powered-by` only as a trailer, and the field lands on the wire after the policy already ran. The same absent→absent gap lets a trailer-only `content-encoding`, validator, or `x-amz-checksum-*` reintroduce representation metadata that `ai_stream_router`'s Anthropic SSE normalization already invalidated; that plugin declares the shared exact-name inventory plus the checksum prefixes, preserving unrelated application trailers.

**Native gRPC** on that arm (the mesh-mTLS relay) is governed too, as a gRPC terminal section: only `grpc-status`, `grpc-message`, and `grpc-status-details-bin` are reserved and survive, while the rest of the terminal block is gRPC application metadata crossing the same policy boundary (advisory GHSA-r78v-rc86-6r86). The direct-H2 gRPC pool's own streaming relay (`GrpcResponseKind::Streaming`) installs the identical owned governor on all three of its body constructors. See [docs/http3.md → Native gRPC terminal metadata](http3.md#native-grpc-terminal-metadata).

**Translated gRPC-Web** on that arm is governed as well. Adapting the terminal metadata into a final DATA frame changes the encoding, not the boundary: only a genuine Trailers-Only response carries that metadata in the initial END_STREAM HEADERS block the pristine snapshot already governs, while a non-empty streaming response still delivers it in a later TRAILERS frame. `GrpcWebStreamingBody` wraps the strip/govern wrapper from the outside, so the trailer block is reconciled — as a `NativeGrpcTerminal` section, reserved status fields intact — before it can be collected and encoded. See [docs/http3.md → Translated gRPC-Web terminal frames](http3.md#translated-grpc-web-terminal-frames).

**The native-HTTP/3 backend relay** (`ResponseBody::StreamingH3`, an HTTP/1.1 or HTTP/2 client in front of an H3-capable backend) shares the identical owned governor. Its backend TRAILERS frame reaches the client as HTTP/1.1 chunked trailers or an H2 TRAILERS frame through `body::H3FrameSource`, which applies the reconciliation on that single frame immediately after the hop-by-hop trailer strip — the same crossing, on all three of `direct_streaming_h3_body` / `size_limited_streaming_h3_body` / `coalescing_h3_body`. gRPC-flavored native-H3 dispatch is owned by `dispatch_grpc_native_h3`, so this relay is a plain-response section in practice; the section is still selected structurally from the dispatch (`request_uses_grpc_content_type`) so a future gRPC-over-`StreamingH3` path cannot land on rules that would govern `grpc-status`.

Implementation notes: the whole boundary is skipped when no signal could act — no response-header phase can mutate the headers, no plugin declared a trailer-policy name or prefix, and nothing declared `Unbounded` — exactly as on the native-gRPC streaming arm. Every signal that could drop a trailer keeps the boundary installed, so the shortcut can only skip work the reconciliation would not have done. Otherwise the pre-policy snapshot is taken on the pristine backend header map before any response-header phase runs, and only when a phase can actually mutate it (plugins present, sticky-cookie injection, or a gateway builder-only write). Because the body outlives the request handler, the boundary travels with it as an owned `StreamingResponseTrailerGovernor` — one final-header clone, one pre-policy clone, one `Arc` bump each of the per-reload policy-name and prefix lists, plus an allocation-free per-response bitset of builder fields this response actually wrote, built at most once per governed streaming response. The header view handed to it is the response-header map **plus** the end-to-end fields the gateway writes straight onto the response builder (`via`, `alt-svc`, `X-Gateway-Error`, `X-Gateway-Upstream-Status`); each of those writes is also recorded in the governor's `gateway_owned_headers` so an exact-value pre-seed cannot hide ownership from the mutation witness. A field the gateway did not write on this response stays out of that bitset and remains ungoverned. The drain/overload `connection: close` write is deliberately neither folded into that view nor part of the capture gate or ownership bitset: `connection` is response-direction hop-by-hop, so the trailer strip removes it before the governor runs and it can never reach the reconciliation. The body wrapper touches the governor only on the single TRAILERS frame — DATA frames pay nothing — and it reconciles immediately after the hop-by-hop trailer strip.

### HTTP/3 (QUIC)

HTTP/3 responses support **streaming** across three distinct paths. See [docs/http3.md](http3.md) for the full dispatch model.

**H3 frontend → H3 backend** (in `http3/server.rs`, when the concrete HTTPS backend target is already classified as H3-capable): The H3 server's dedicated proxy path uses `Http3ConnectionPool::request_streaming_under_authorization()` to return a live `RequestStream`, then forwards response chunks directly to the QUIC client via `send_data()` with backpressure-aware coalescing (the `FERRUM_HTTP3_COALESCE_*` window, 32 KiB by default, plus a time-based flush every `FERRUM_HTTP3_FLUSH_INTERVAL_MICROS`, 200 µs by default).

**H1/H2 frontend → H3 backend** (in `proxy/mod.rs`): When `stream_response=true`, the dispatch path uses `Http3ConnectionPool::request_streaming_under_authorization()` and returns `ResponseBody::StreamingH3`. The response body builder wraps the h3 `RequestStream` with `coalescing_h3_body` (`Coalescing<H3FrameSource>`), `size_limited_streaming_h3_body`, or `direct_streaming_h3_body` (zero-overhead passthrough), bridging h3's `recv_data()` API to `http_body::Body` for hyper to forward to the HTTP/1.1 or H2 client.

**H3 frontend → non-H3 backend** (in `http3/cross_protocol.rs`, any request whose backend target is not classified as H3-capable or whose flavor != `Plain`): The H3 listener drives the same reqwest / HTTP/2 / gRPC backends as the H1/H2 proxy path:

- **Request body** — streamed via a bounded `tokio::sync::mpsc` bridge into `reqwest::Body::wrap_stream` for `Plain` flavor. Mirrors the H1/H2 plugin-driven policy: stream by default, buffer only when a plugin pre-collected the body. Bridge capacity is `FERRUM_HTTP3_REQUEST_BODY_CHANNEL_CAPACITY` (default 32). `Grpc` flavor streams request DATA and trailers through a bounded channel into `GrpcBody::Channel` when no retry, body plugin, or pre-buffered body requires replay; otherwise it keeps the buffered representation.
- **Response body** — streamed frame-by-frame with the same `http3_coalesce_*` window as the native H3 writer, so QUIC frame cadence is identical across dispatch kinds. `Plain` polls `reqwest::Response::chunk()`; `Grpc` polls hyper `Incoming::frame()` so trailer frames split off for `RequestStream::send_trailers()`.

On the H3 frontend, when plugins require response body access (e.g., `ai_token_metrics`, `response_transformer`), or when retries are configured and the initial attempt runs on the native H3 handler's retry loop (native QUIC pool), responses fall back to **buffered** mode with full `on_response_body` and `transform_response_body` plugin hook support (subject to the after-headers release described in [Response-Header-Aware Downgrade](#response-header-aware-downgrade-after-response-headers)).

### gRPC

gRPC supports **full bidirectional streaming** of both request and response bodies when no plugins need body access and no retries are configured.

**Request body streaming**: The `GrpcConnectionPool` uses a `GrpcBody` enum (buffered variants, `Streaming` over the client `Incoming`, `Pumped` for the [gateway-owned upload pump](stream_authorization_lifetime.md#the-gateway-owned-upload-pump), and `Channel` for the H3 bridge) so the same pool handles both buffered and streaming request bodies. When `proxy_grpc_request_streaming()` is used, the client body is wrapped in a streaming variant and forwarded frame-by-frame — each H2 DATA frame is sent to the backend immediately, with memory bounded by the H2 flow-control window size. When retries or plugins require the body, the gateway collects it once into `GrpcBody::Buffered`. A body already collected for an earlier phase such as `hmac_auth` authentication or `request_mirror` is reused with its original method and raw metadata, under the gRPC receive-size and request-body timeout limits. Applicable transforms and final hooks run once after the earliest consumer; an already prepared body is dispatched without a second hook pass. H3 follows the same single-prebuffer contract through its cross-protocol bridge.

**Response body streaming**: HTTP/2 DATA frames are forwarded as they arrive from the backend, wrapped in the `Coalescing<Incoming>` adapter for efficient batching. HTTP/2 trailers (`grpc-status`, `grpc-message`) are forwarded automatically via hyper's `Incoming` body framing. The terminal trailer block first crosses the response-header policy boundary: `grpc-status` / `grpc-message` / `grpc-status-details-bin` always survive, while trailer-borne application metadata is reconciled against the policy the response headers already applied — see [docs/http3.md → Native gRPC terminal metadata](http3.md#native-grpc-terminal-metadata).

When retries are configured, gRPC buffers the request body so it can replay
attempts; retry configuration alone does not require buffering the response, and
a response eligible for streaming remains live. Native-gRPC-capable plugins that
require response body access, or explicit `response_body_mode = Buffer`, require
the response body and trailers to be collected before constructing the response.
`ai_token_metrics` is HTTP-only: enabling it alone does not alter native gRPC
streaming or inspect protobuf frames.

### WebSocket

WebSocket connections are bidirectional streams and do not use `response_body_mode`. After the HTTP Upgrade handshake, data flows directly between client and backend.

## ProxyBody Type

The streaming architecture is built on `ProxyBody` in `src/proxy/body.rs`, a struct that carries per-response guards and wraps one of three body kinds:

```rust
enum ProxyBodyKind {
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
- `body::coalescing_body(response, content_length, read_timeout_ms, flush_after, trailers)` — Create a streaming body with chunk coalescing (128 KB target). Default for reqwest-backed HTTP/1.1 responses. Builds `Coalescing<ReqwestFrameSource>` over the response's real frames; `trailers` (`ReqwestResponseTrailers`) relays the governed trailer section or drops it when the client cannot receive one.
- `body::direct_streaming_body(response, content_length, read_timeout_ms, trailers)` — Zero-overhead passthrough for reqwest streams. Used when `FERRUM_RESPONSE_BUFFER_CUTOFF_BYTES=0`, `FERRUM_MAX_RESPONSE_BODY_SIZE_BYTES=0`, and `FERRUM_RESPONSE_COALESCE_FLUSH_MS=0`.
- `body::size_limited_streaming_body(response, max_bytes, content_length, read_timeout_ms, trailers)` — Streaming body with frame-by-frame size enforcement via `SizeLimitedStreamingResponse` + coalescing. Used when `max_response_body_size_bytes > 0` and the **backend** did not declare a canonical Content-Length (captured before `after_proxy`; a hook-authored field cannot skip this constructor).
- `body::coalescing_h2_body_strip_hop_by_hop_trailers(body, content_length, coalesce_target, ..)` — H2 DATA frame coalescing for gRPC streaming and the HTTP/2 direct pool. Builds `Coalescing<Incoming>`. Trailer-safe.
- `body::direct_streaming_h2_body_strip_hop_by_hop_trailers(body, content_length, ..)` — Zero-overhead H2 passthrough; used for the large-response bypass and the H2 fast path.
- `body::coalescing_h3_body(recv_stream, .., coalesce_min_bytes, coalesce_max_bytes, flush_interval, ..)` — Bridges h3's `recv_data()` API to `http_body::Body` with chunk coalescing. Builds `Coalescing<H3FrameSource>`. Used for H1/H2 frontend → H3 backend streaming via `ResponseBody::StreamingH3`.
- `body::direct_streaming_h3_body(recv_stream, ..)` — Zero-overhead passthrough for H3 response data. Used when no coalescing/size limits apply.
- `ProxyBody::into_tracked(self, baseline)` — Wrap any streaming `ProxyBody` (returned by any of the builders above) in completion tracking, returning `(ProxyBody, Arc<StreamingMetrics>)`. No-op on `Full` or already-`Tracked` bodies. Use this so the tracked path picks up the same coalescing / size-limit / SSE-bypass behaviour as the default streaming path — there is no separate "tracked" body builder.

## When to Use Buffer Mode

Use `response_body_mode: buffer` when:

- A plugin needs to inspect or transform the **response body** (not just headers)
- Your responses are small and the latency difference is negligible

`transaction_debugger` requires buffer mode only when `log_response_body` is
enabled, the `transaction_debug` DEBUG target is actually enabled (otherwise no
capture record could be emitted and the body is released to stream), *and* the
concrete response passes its bounded-capture screen (identity encoding,
capturable textual `Content-Type`, and a `Content-Length` within the configured
cap). With capture disabled — the default — it requires no buffering
at all and reports final body completion, byte counts, disconnects, and typed
streaming errors from the terminal transaction summary instead. Its header-time
refinement only ever downgrades buffer to stream, so no long-lived or
unknown-length response is pinned onto the buffered path by enabling the
debugger. On a retry-enabled proxy it applies the same screen through the
after-headers retry opt-in, so a response it will not sample is released to
stream there too; only the responses it actually captures stay buffered and
mid-body retryable.

Note: buffer mode is not required for response size enforcement. `SizeLimitedStreamingResponse` enforces the limit on streams whose backend omitted `Content-Length`, and a post-`after_proxy` `Content-Length` cannot suppress that adapter.

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
