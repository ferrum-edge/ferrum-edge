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
                    └─ Yes → stream on every attempt when the proxy streams
                       (retry decides from headers alone; a retryable attempt
                       drops its undrained body before client commit). Buffer
                       only when response_body_mode/plugins force buffering.
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
| `ai_rate_limiter` | Never for active HTTP responses (HTTP-only plugin; native gRPC is not in the protocol view); response usage reconciliation needs the body. Its pre-request reservation path only buffers request bodies for JSON `POST` requests. |
| `ai_response_guard` | Never from request-side intent. An active guard buffers conservatively until pristine backend headers are known. A genuine backend event stream is then decided before header commit: enforcing/redacting/structural policies reject with 502 because they cannot inspect an unbounded stream completely, while a warn-only guard records the uninspectable stream and permits it. Native gRPC is the one request-side exception: a gRPC request whose method is not enrolled in the plugin's `grpc` block is released to stream, because an un-enrolled method has no decodable contract to enforce. |
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
| `transaction_debugger` | No | Only with `log_response_body: true`, the `transaction_debug` DEBUG target enabled, and only for an identity-encoded, capturable textual response whose `Content-Length` fits the configured cap. gRPC (typed flavor), WebSocket including H2/H3 Extended CONNECT (typed flavor), SSE, chunked/unknown-length, encoded, oversized, and non-textual responses are released to stream. |

## Authorization Lifetime of an Admitted Stream

Idle timeouts, per-frame read timeouts, and RPC deadlines answer "is this stream
still making progress". They are **independent** of the question this section
answers: "is the credential that admitted this stream still valid".

Ferrum streams SSE, chunked HTTP, native gRPC, and gRPC-Web bodies without
buffering, and authentication runs once, at request admission. Without an
explicit bound, a client could present a token with seconds of validity left,
open a long-lived stream, and keep receiving protected data long after a *new*
request with the same credential would be rejected. Issue #3815 tracks that gap;
issue #3816 tracks the same gap for client certificates.

### The contract

Every authenticated stream carries one **absolute, monotonic authorization
deadline**, anchored when the request was admitted. It is the **earliest** of:

| Bound | Source |
|-------|--------|
| The accepted credential's authoritative expiry | JWT / JWKS `exp` plus that provider's configured leeway; OIDC session expiry; OAuth2 introspection `exp` / `active_until` / `expires_in`, converted once at validation so a cache hit cannot slide it; the `mtls_auth` leaf certificate's `notAfter`, converted once at first successful evaluation so a connection-cache hit cannot slide it |
| The finite fallback maximum | `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS` (default `3600`, valid `1`–`86400`) |

That deadline then composes with every other bound the protocol already
enforces — the client `grpc-timeout`, listener replacement / route drain,
process shutdown, and idle/read timeouts — on the same earliest-wins basis.

Three properties are load-bearing:

- **Activity never extends it.** DATA frames, SSE events, gRPC messages, and
  keep-alives do not reset the timer. It is armed once and checked on every
  poll, so a backend that streams continuously (and therefore never yields a
  `Pending` poll to drive an idle check) is still bounded.
- **There is no unbounded configuration.** A credential admitted without an
  authoritative expiry — `key_auth`, `basic_auth`, `hmac_auth`, LDAP — is
  bounded by the fallback maximum alone. `0` is rejected in every mode.
- **Unauthenticated streams are untouched.** No principal was admitted, so
  there is no authorization lifetime to enforce. A public SSE endpoint behaves
  exactly as before.

### Termination semantics

| Point | Behavior |
|-------|----------|
| Before the credential is accepted | Ordinary authentication rejection — a fixed `401`. An expired JWT/JWKS/OIDC/introspection credential fails at validation; an `mtls_auth` leaf outside its validity interval fails the per-request temporal check, including on a reused H1 keep-alive connection and on new H2/H3 streams over an existing transport connection |
| After acceptance, before the downstream response head is committed | A fixed terminal chosen once, at the single point where every H1/H2 dispatch path converges: plain HTTP, SSE, and chunked responses get a fixed `401` with the compiled-in `{"error":"Unauthorized"}` body; native gRPC gets HTTP 200 with trailers-only `grpc-status: 16` (`UNAUTHENTICATED`); gRPC-Web gets the equivalent bounded terminal through the shared translation. This is the terminal a **request-upload** expiry produces, because the upload seam fires while the backend is still withholding response headers |
| After the response head is committed, before any response DATA | Native gRPC receives `grpc-status: 16` (`UNAUTHENTICATED`) trailers; gRPC-Web receives the equivalent bounded trailer frame in DATA. Ordinary HTTP and SSE have **no** terminal status metadata, so the body ends with a transport error instead — a `grpc-status` trailer is never synthesized for a client that did not speak gRPC, and the body never ends cleanly, which would be indistinguishable from a complete response |
| After response DATA is committed | The body ends with a transport error, which resets the HTTP/2 or HTTP/3 stream and terminates an HTTP/1.1 or SSE body deterministically. A complete gRPC message boundary cannot be proven at that point, so a terminal status is **never fabricated** |

When the deadline fires, the wrapper drops the inner backend body immediately —
before the downstream is polled again — so upstream work is cancelled, the
opposite relay direction is torn down, and no detached producer remains. The
request guard, per-IP guard, circuit-breaker and load-balancer accounting,
backend-admission permits, and body-buffer budget are released exactly once
through the same deferred machinery every other terminal path uses.

### The gateway-owned response pump

The response-body adapter only acts when the transport **polls** it, and hyper
does not always poll a response body:

- **HTTP/2.** `PipeToSendStream` reserves stream send capacity and awaits
  `SendStream::poll_capacity` *before* it polls the body. A client that
  advertises `SETTINGS_INITIAL_WINDOW_SIZE: 0` — or that simply stops issuing
  `WINDOW_UPDATE` — parks that pipe for as long as it likes.
- **HTTP/1.1.** the dispatcher flushes a connection that can no longer buffer
  before it polls the body, so a client that stops reading parks the write.

Both are client-controlled, so a body-only bound is not an enforceable
authorization lifetime. Authenticated streaming responses therefore move the
backend body into a gateway-owned **response pump**
(`src/proxy/response_watchdog.rs`), which mirrors what
[the upload pump](#the-gateway-owned-upload-pump) does for the request
direction.

**Ownership.** The pump is the upstream body's sole owner and sole poller. The
client-visible body holds only the receiving end of a bounded channel. Nothing
is shared between them except that channel, a handful of write-once flags, and
the terminal-owner CAS below, so there is **no lock on the response path** — the
hot-path invariant forbids one, and a
lock would also let a task enforcing the deadline block behind somebody else's
inner `poll_frame`.

**One winner, decided by a CAS — not by who is scheduled first.** The pump and
the protocol adapter wrapped around it (`TotalDeadlineBody`, which owns the
client-visible terminal *shapes*: native `grpc-status: 16` trailers, the bounded
gRPC-Web frame, the deterministic HTTP/SSE transport error, plus the
deferred-accounting classification) are two independently scheduled observers of
one response. Exactly one of them settles it, and which one may not depend on
the runtime's scheduling order. Three shapes are all unsound:

- A **boolean** "did it expire?" flag. The adapter reads it, the pump then
  publishes an expiry and closes the channel, and the adapter — in the same poll
  — delivers the protected frame the pump had already queued, or the pump's
  internal released-upstream error instead of the protocol-correct terminal.
- A **timer in the adapter**, in the other direction. The pump can reach a clean
  upstream EOF (or an upstream error) well before the deadline and queue that
  terminal, while a downstream parked on flow control does not poll it until
  long after; an independent sleep would then overwrite that completed response
  with an authorization terminal, set the classification flag, and record the
  shared latch for a stream this contract never terminated.
- Reading **neither**, and deferring to the pump. A poll that arrives at or
  after the deadline then depends on the pump's timer task having been scheduled
  first — which the client, not the gateway, decides.

`AuthorizationTerminalOwner` resolves all three. It is one shared
compare-and-swap over `{Open, InnerCompletion, AuthorizationExpiry}` carrying
the single absolute deadline instant, so either observer may claim the bound the
moment the clock reaches it (one atomic load, one monotonic clock read, no
timer and no allocation); the upstream's own terminal is claimable **only** while
the clock is still before the deadline, so a completion can never overtake an
elapsed bound because a tokio timer had not fired yet; and the first claim is
final, so `fired`, the shared latch, and the fixed-cardinality counter describe
exactly one outcome. A claimed expiry is visible before the channel closure that
wakes a parked receiver, and every observer reads the owner **before** it reads
the channel, so a frame queued before the bound is never delivered after it. At
the exact deadline instant the security bound wins, deterministically. The
client `grpc-timeout` wrapper installed *inside* this one keeps its own timer and
is unchanged.

**Backpressure.** The channel bound is one frame, and the pump reserves capacity
*before* it reads the next frame, so at most one frame is ever in flight and the
backend feels the downstream's backpressure almost exactly as it did when hyper
polled it directly. A full channel parks the pump on `reserve()`, which is
precisely why the deadline arm is biased ahead of it: backpressure delays
delivery, it never delays enforcement.

**Ordering.** Frames, trailers, and the terminal travel in order through one
FIFO channel. An upstream error is delivered as an error, never collapsed into a
clean end of stream, and an expiry closes the channel *without* a terminal so
the downstream cannot mistake it for a complete response either.

The two guarantees the pump provides:

1. **Upstream cancellation.** At the deadline the pump drops the backend body it
   owns. From that instant the gateway reads no further protected byte, and the
   backend stream, its pooled connection, and every guard rooted in that body
   are released — whatever the transport is parked on. A cancelled or dropped
   pump reaches the same state through the ordinary task drop, so no detached
   producer can survive the response body.
2. **Transport close.** Dropping the upstream does not release what the response
   body itself owns: the request guard, the per-IP guard, circuit-breaker and
   load-balancer accounting, backend-admission permits, and the deferred
   transaction logger all live in `ProxyBody`, which hyper owns. If the
   downstream still has not drained the terminal a bounded grace after the
   deadline, the pump asks the connection task to close the client connection.
   hyper then drops the response body, releasing all of the above exactly once
   through the ordinary `Drop` path, and the client observes a protocol-visible
   termination — a `GOAWAY` then a close on HTTP/2, and a chunked or SSE body
   that ends **without** its terminating chunk on HTTP/1.1.

A client that *is* draining never reaches step 2: the adapter's own terminal is
delivered on the next poll, the body is dropped, and the pump is aborted with
it. The steady-state cost is one `Sleep`, one task, and one one-slot channel on
authenticated streaming responses only; an unauthenticated or buffered response
never constructs any of it.

**Deliberate trade-off.** HTTP/2 gives a server no way to reset one stream from
outside hyper — the `SendStream` is owned by the parked pipe — so the transport
close is connection-scoped and sibling streams end with it. It is preceded by
`graceful_shutdown` (a `GOAWAY`, then a bounded settle window in which siblings
can still complete), and it is only ever reached for a connection that is
demonstrably refusing to drain an already-expired authenticated stream. Leaving
that stream parked instead would let a hostile client retain a request slot, a
per-IP slot, an admission permit, and a load-balancer connection indefinitely.

### The final pre-commitment gate

Buffered response collection, every awaited pre-commitment response phase
(`after_proxy`, the buffered normalize / inspect / transform hooks, the final
client-visible body and header policies, and the response-committed hook), and
one last authoritative check immediately before the response head is committed
are all bounded by the same absolute plan. Before that composition those phases
were bounded only by the client RPC deadline, which is absent for an ordinary
HTTP request — so a slow hook could carry an admitted credential past its own
expiry and then commit a **protected** response head, or commit a streaming head
only to terminal-error it immediately afterwards when the fixed pre-commitment
terminal was still available.

Composing the two owners into one instant is not enough on its own, because the
two owners want different outcomes. Each awaited phase therefore carries the
authorization **plan** beside the composed instant
(`RequestContext::precommit_response_phase_bound`), and an elapsed bound is
resolved by `PrecommitPhaseResult`:

- **Client RPC deadline.** Unchanged, byte for byte: gateway deadline
  provenance is marked and the canonical `grpc-status: 4` terminal is selected.
- **Authorization lifetime.** The phase is cancelled, the request's shared
  termination latch records the bounded class **exactly once**, no RPC-deadline
  provenance is marked — the plugin that was running and the backend that
  answered are blameless, and that marker would otherwise drive `grpc-status: 4`
  terminal write bias in the protocol writers — and the only selectable terminal
  is the fixed, redacted pre-commitment one. A tie is attributed to
  authorization, matching every relay's biased select ordering.

Attribution comes from the **captured composition**, never from re-reading the
clock once the bound has fired. Asking "is the authorization deadline in the
past?" after the fact is a scheduling race: a phase that is not polled again
until after the *later* of the two instants sees both as elapsed, and a strictly
earlier client `grpc-timeout` would be reattributed to the gateway's security
decision — silently changing client `grpc-timeout` behavior. The winning owner
is decided in `ComposedAuthBound::compose`, where both instants are known, and
survives arbitrary observation delay; the clock is still consulted for the
authorization case, so a bound that fired for some other reason can never
fabricate an expiry.

Every composed HTTP/3 seam carries that same typed bound, because a write parked
in QUIC flow control — and a dispatch phase parked on a backend that withholds
its response head — is exactly the case that is not observed again until after
both instants have passed: the native-H3 gRPC dispatch (backend open plus
response-head wait), the native-H3 response-head write, the native-H3 buffered
and streaming downstream write seams, and the cross-protocol plain, terminal,
and streaming write seams.

The committed-response observer is the one phase where an elapsed bound used to
mean "continue in the background". That detach survives only for the
client-owned RPC deadline. When the authorization bound wins, the pending hook —
which owns a **clone of the request context and the protected response body** —
is dropped rather than spawned, and every remaining observer is skipped: a
detached continuation is precisely a protected-data side effect running after
the credential stopped being authorized. An already-elapsed bound is decided
before the observer is constructed at all, so no clone is ever handed out.

When the **client's** RPC deadline is the earlier bound the hook is still
detached — but the credential's own lifetime does not stop mattering, because
the detached invocation keeps holding that context clone and that protected body.
The detached cleanup therefore runs under the **earliest** of the fixed
five-second post-response timeout and the admitted credential's absolute
authorization deadline, so the pending hook and every remaining observer are
cancelled and dropped no later than that instant.

That bound is deliberately **not** `tokio::time::timeout_at`, which polls its
inner future before it observes the timer: a chain whose pending observer and
remaining hooks are all ready on their first poll would run to completion even
when the bound elapsed before the task was ever scheduled, and spawning is not
running — an unbounded amount of time can pass between `tokio::spawn` and the
first poll on a loaded runtime. The cleanup therefore starts with an explicit
past-deadline **refusal** that polls nothing at all, and then races a
deadline-biased `select!` whose per-poll clock gate re-checks the same instant
before every resumption. The chain is never first-polled, and never resumed,
at or after the authorization bound. The client's RPC terminal is
untouched — this is post-terminal observer work — and nothing here records an
authorization termination: the stream's terminal was decided by another bound,
so counting one would be a false, and on a bidirectional stream a double,
termination. An unauthenticated request carries no bound and keeps exactly the
fixed timeout it always had.

Native HTTP/3 gRPC has its own equivalents, because that relay writes its own
response head instead of returning a `ProxyBody`. A gate runs immediately before
the first client-visible terminal the relay can produce (the declared-size
refusal), and again after every response-header hook and policy, immediately
before the response HEADERS are written. Either gate turns an expired credential
into the fixed trailers-only `grpc-status: 16` through the bounded write-grace
path, retires (cancels and joins) the gateway-owned upload pump, releases the
admission permits exactly once, and leaves the circuit breaker, passive health,
and the adaptive limiter to record the backend's own status with no error class.
The response-header write itself is bounded by the earliest of the client RPC
deadline and the authorization deadline; a downstream that cannot accept the
HEADERS by expiry is reset rather than waited on again or misreported as
`DEADLINE_EXCEEDED`.

#### The buffered terminal summary is the gate's own decision

On the buffered H1/H2 path the gate is also the **audit** boundary, because the
transaction summary and the client-visible response must describe the same
outcome. The gate runs before the summary is built, so the summary it feeds
carries the terminal status, the buffered (non-streamed) classification, and the
bounded `authorization.termination_reason` the gate latched — there is no earlier
protected summary to retract.

Terminal transaction logging is therefore **not awaited** for a request that
carries an authorization plan. Awaiting the logging chain would reopen exactly
the window the gate closed: the credential could expire while one logging plugin
blocked, after earlier plugins in the chain had already recorded the still
protected outcome. A later gate can repair the *response*, but nothing can
retract an audit record that has already been emitted, so the client would see a
fixed `401` / `grpc-status: 16` while the audit trail claimed the protected
status. The single summary is instead handed to the same bounded
observability-delivery cleanup the client-RPC-deadline path already used: every
applicable logging plugin receives it, in configured order, **exactly once**,
inside one finite-budget task that counts against
`FERRUM_LOG_DELIVERY_MAX_TASKS` and is drained at shutdown. Nothing detached
here is unbounded, and the request task itself awaits nothing between the gate
and the response it hands to hyper.

A request with **no** authorization plan has no decision to protect and keeps the
historical sequential, awaited logging contract byte for byte. The predicate is
the gate's own `effective_request_auth_deadline`, so the two can never disagree
about which requests those are.

### Observability

Expiry is classified as a **policy** termination, not a backend fault, so error
rate alerts stay meaningful:

- Deferred backend accounting records it health-neutral (the backend did nothing
  wrong), exactly like a client-chosen `grpc-timeout` expiry.
- The transaction summary carries a bounded
  `authorization.termination_reason` metadata value — `credential_expired` or
  `authenticated_stream_max_lifetime` — stamped exactly once: inside the
  single-fire deferred logger for a streaming response, and by the
  pre-commitment gate before the summary is built for a buffered one. Either
  way one summary is delivered for the exchange, and it is the one that
  describes the response the client actually received.
- `GET /metrics/runtime` exposes `authorization_lifetime`, a fixed-cardinality
  counter pair whose only label dimension is a closed protocol family (`http`,
  `grpc`, `grpc_web`, `stream_tcp`, `stream_udp`). WebSocket is deliberately
  **not** a family here: WebSocket sessions are bounded by their own
  `FERRUM_WEBSOCKET_MAX_LIFETIME_SECONDS` policy (issue #3738) and reported
  through `websocket.termination_reason`, so publishing a `websocket` series
  under `authenticated_stream_max_lifetime` would name a different operator
  knob and could only ever read zero.

No token, claim, subject identifier, certificate field, provider response, or
absolute expiry value reaches a log, a metric, a trailer, or a response body.
The `grpc-message` and the internal termination text are compiled-in literals.

### Coverage

| Surface | Enforced |
|---------|----------|
| Generic HTTP/1.1 and HTTP/2 streaming responses, including SSE | Yes — two mechanisms, armed from the same absolute plan. The body adapter emits the protocol-correct terminal when the transport polls it, and a **gateway-owned response pump** owns and polls the backend body, releases it at the deadline — and, after a bounded grace, closes the client connection — when the transport does not. See [The gateway-owned response pump](#the-gateway-owned-response-pump) |
| HTTP/1.1 and HTTP/2 streaming and bidirectional request **uploads** | Yes — two mechanisms, armed from the same absolute plan. The client body adapter every streaming dispatch path installs (reqwest, direct-H2, mesh mTLS, HBONE, Unix socket, and the fully-streamed native-gRPC body) refuses to hand the transport another client byte after expiry, and a **gateway-owned upload pump** owns the inbound body in a task the gateway schedules, so the bound fires — and the client body is released — even while the backend transport is parked on flow control and is polling nothing. See [The gateway-owned upload pump](#the-gateway-owned-upload-pump) |
| HTTP/1.1 and HTTP/2 request uploads the gateway **buffers** before dispatch | Yes — a body a request-body plugin, a gRPC-Web translation, or retry replay forces into memory never reaches those adapters, so the collect itself carries the plan (`collect_request_body_under_authorization`). Covers the reqwest buffered arms, the H3-backend bridge's buffered arms, and both buffered native-gRPC arms |
| The response-**header** wait on every H1/H2 dispatch path | Yes — reqwest (initial attempt and retry), direct-H2, mesh mTLS, HBONE, and Unix socket compose the plan over the client RPC deadline and `backend_read_timeout_ms`, so a backend that withholds its response head cannot hold an authenticated request open past expiry even when both of those bounds are disabled |
| The direct-H2 **early-response** upload join | Yes — the upload-completion gate is installed whenever a request-size limit is configured **or** the request carries an authorization lifetime, the join waits under the composed plan, and the handler then `cancel_and_join()`s the gateway-owned pump before returning, so no gateway-owned upload survives the handler and no early backend response is committed while an authenticated upload is still running past expiry |
| Native gRPC server-, client-, and bidirectional streaming | Yes |
| gRPC-Web streaming, binary and text | Yes |
| HTTP/3 backend responses relayed to an H1/H2 downstream (`StreamingH3`) | Yes |
| Native HTTP/3 frontend streaming responses, including backend SSE relays and inspected streams | Yes — the relay resets the H3 stream at the deadline rather than fabricating a clean finish |
| Native HTTP/3 aggregate MCP SSE listener (`send_h3_aggregate_sse_response`) | Yes — the broker listener lifetime is composed with the captured authorization plan (earliest wins; an exact tie is attributed to authorization). HEADERS and every flow-control-blocked DATA/FIN write are bounded by that composition. Authorization before the 200/event-stream head commits writes the fixed redacted `401` under the post-deadline grace, otherwise the stream is reset; after commitment the stream is reset rather than finished cleanly. Listener-lifetime expiry keeps its existing non-authorization outcome and does not increment authorization counters; a clean FIN attempt after the listener deadline is still bounded by the same post-deadline grace, with a reset fallback if flow control blocks past that grace. Unauthenticated listeners are unchanged |
| Native HTTP/3 gRPC server-, client-, and bidirectional streaming | Yes — clean `grpc-status: 16` trailers while no response byte is client-visible, otherwise a stream reset; the request-upload pump is retired by its guard in the same step |
| H3 cross-protocol relays to HTTP/1.1, HTTP/2, and gRPC backends, gRPC-Web translation included | Yes, in both directions: the request-upload bridge terminates with a fixed `401` before response headers are committed, and the response relay resets or emits the bounded terminal after commitment |
| Inspected / latency-tracked streaming bodies | Yes |
| WebSocket over H1, H2 Extended CONNECT, and H3 Extended CONNECT | Yes, through the pre-existing WebSocket deadline arbiter (issue #3738), which uses the same `credential_deadline_at`. Its absolute maximum is `FERRUM_WEBSOCKET_MAX_LIFETIME_SECONDS`, a different knob from `FERRUM_AUTHENTICATED_STREAM_MAX_LIFETIME_SECONDS`, and it reports through `websocket.termination_reason` — so it is deliberately **not** a family of the `authorization_lifetime` counters |
| TCP+TLS stream sessions on the userspace relay | Yes — armed at `on_stream_connect` admission and enforced across every post-admission setup stage (DNS resolution, retry backoff, backend connect and TLS handshake, the outbound PROXY v2 header, and the inspected first-bytes forward) as well as the relay itself, so no backend or application byte is written on an expired credential |
| DTLS-terminating stream sessions | Yes — armed at accept-time admission and composed over every post-admission setup stage (DNS resolution, backend connect, backend DTLS handshake), then raced against relay completion, the idle watchdog, and drain; both directions are closed and the backend connection is torn down |
| Plain-UDP stream sessions | Yes — a plain-UDP listener runs the same `on_stream_connect` admission chain, so it can admit a Consumer, an external identity, and a credential deadline exactly like DTLS. The maximum is anchored at **first-datagram session admission**, before the epoch resolve, the mesh egress decision, and the admission chain, so a slow stream-connect plugin cannot buy extra authorized lifetime. Every post-admission setup stage that awaits is bounded (the first-datagram `on_udp_datagram` policy hooks, DNS resolution, the backend bind/connect and backend DTLS handshake), and the plan is re-read before the session is committed — before any backend success is recorded, before the session map insert, before the reply task exists, and before the first backend send. Both directions are then enforced: the client→backend forward (inline path, `last_client` fast path, and the bounded hook-ingress worker) and the backend reply task's deadline arm. See the note below |
| CP/DP configuration streams | Yes, through the separate control-plane lifetime enforcement |

The native HTTP/3 frontend and the H3 cross-protocol bridge own the QUIC
request and response halves directly rather than going through `ProxyBody`, so
each relay loop races its own copy of the same absolute deadline. The deadline
is captured once from the accepted request context before the relay takes
ownership and is never recomputed from relay activity; the arm is placed ahead
of the client `grpc-timeout` arm so the security bound is the one attributed
when both are ready, and each arm breaks its relay loop, so exactly one
completion and one counter increment occur per terminated stream. The bounded
termination class is latched on the request and reaches the H3
`BodyOutcome` / response-stream termination hooks and the transaction summary
through the ordinary path.

Deliberate scope notes:

- The Linux **kTLS splice** frontend leg cannot be wrapped by the relay-side
  deadline. Eligibility is therefore decided before the frontend handshake: a
  TLS-terminating TCP listener that can admit an authenticated stream principal
  declines the kTLS handoff and is relayed on the buffered userspace path, where
  the deadline is enforced. See
  [Kernel TLS and the stream authorization deadline](frontend_tls.md#kernel-tls-and-the-stream-authorization-deadline).
- **Plaintext TCP** stream sessions carry no gateway-verified credential from a
  built-in mechanism, so no deadline is derived for them.
- A **plain-UDP** session is bounded whenever its `on_stream_connect` chain
  admitted a principal, and is otherwise untouched: an unauthenticated session
  has no plan at all, so its datagram path reads no clock, takes no lock,
  registers no timer, and behaves byte for byte as it did before. The
  authenticated path costs one additional monotonic instant comparison per
  datagram — deliberately not a per-datagram timer, mutex, map walk,
  allocation, or formatted string. An elapsed deadline **refuses the datagram
  inline** rather than waiting for the reply task's timer to be scheduled, and
  the first observer wakes the reply task, which owns the single teardown:
  the generation is marked expired before any cache or map reuse, only that
  exact generation is removed, the backend socket / DTLS connection and the
  hook-ingress channel are closed (which cancels an in-flight datagram hook),
  and the overload connection guard and the listener's active-session slot are
  released exactly once. A setup-phase expiry releases a claimed HALF_OPEN
  circuit-breaker probe slot **neutrally** and records no backend outcome. The
  disconnect summary reports a client-side, backend-health-neutral decision
  (`RecvError` / `ClientToBackend` / `RequestError`) carrying only the bounded
  `authorization.termination_reason` class — no identity, credential,
  certificate field, expiry instant, or source address.
- **Ordinary expiry is logged at `debug!`, never `warn!`.** It is expected
  lifecycle and client-triggerable, and the counters plus the transaction
  summary already carry it, so warning-level logging would only give a client a
  log-amplification lever. Warning and error levels stay for genuinely
  anomalous cleanup, write, and invariant failures.
- A TCP setup-phase expiry is a **client-side, health-neutral** refusal
  (`StreamSetupKind::AuthorizationExpired`): the half-open circuit-breaker probe
  slot and the per-target backend-inflight slot are released without recording a
  backend outcome, so the breaker, passive health, and the adaptive buffer
  tracker are untouched. Retries and backoff sleeps cannot refresh the absolute
  deadline — it is re-checked at the top of every connect attempt.
- A **buffered H1/H2 upload** is bounded by the collect, not by a body adapter:
  the plan composes over the client RPC deadline and the operator whole-upload
  stall timeout, and the authorization arm is biased first, so a plan that has
  already elapsed fails closed without polling the collect at all. When the
  authorization bound is the one that elapsed, the dispatch returns a
  health-neutral outcome and the single pre-commitment terminal decides the
  client-visible shape; a buffered **native-gRPC** upload takes the equivalent
  trailers-only `grpc-status: 16` terminal through the shared reject pipeline,
  which releases the half-open circuit-breaker probe slot and any body-phase
  admission preacquisition first.
- **Direct-H2 early responses and hyper's detached upload pipe.** When
  `send_request` yields a response head, hyper moves the client body into a
  detached HTTP/2 pipe task, and h2 resets a stream only once *every* reference
  to it is dropped — the pipe holds one, and hyper closes its own cancellation
  channel as soon as the response head resolves. The gateway therefore cannot
  force an immediate `RST_STREAM` from outside without tearing down the whole
  pooled multiplexed connection and its sibling requests. The upload pump is
  what makes the lifecycle enforceable anyway: the gateway, not hyper, owns the
  inbound body, so expiry releases it and terminates the transport body with an
  error regardless of the pipe's state, and `cancel_and_join()` gives the
  handler an actual join before it returns.
- An H3 request body that is **buffered before dispatch** composes the
  authorization deadline with the optional client RPC deadline into one
  `auth_lifetime::ComposedAuthBound` (`http3::server::h3_upload_authorization_bound`)
  and drains under it through
  `http3::server::collect_h3_request_body_under_authorization`, so a
  continuously active trickle upload cannot outlive the credential either. The
  operator whole-upload guard (`backend_read_timeout_ms`) composes on top and
  keeps its own precedence: when it is strictly earlier the drain is a plain
  read timeout with no authorization attribution at all. Only when the composed
  ABSOLUTE bound fires is the owner consulted, and it is the one captured at
  composition rather than a fresh read of the clock — so a drain observed after
  BOTH instants passed still reports the client's own strictly earlier
  `grpc-timeout` as the client's. When the authorization bound is the captured
  winner, the terminal is the fixed redacted `401` (gRPC keeps
  `grpc-status: 16`) rather than the deadline contract.

### The gateway-owned upload pump

Every H1/H2 backend transport hands the client request body to a hyper client
and lets that client's own connection task drive it. For HTTP/2 the task is
`PipeToSendStream`, which **reserves and awaits stream send capacity before it
polls the body**. Two consequences follow, and together they defeat any bound
that lives only inside a body adapter:

* A pipe parked in `poll_capacity` polls nothing, so a cancellation channel or
  a `Sleep` armed *inside* the body cannot be observed until flow-control
  credit, a reset, or a connection close arrives.
* Once the response head resolves, hyper's own cancellation sender is gone, so
  the detached pipe can keep owning the inbound body — and the request
  accounting rooted in it — indefinitely.

The same detachment exists on the HTTP/1.1 pooled clients (mesh mTLS, HBONE's
inner client, the Unix-socket pool) and inside reqwest, whose connection task
owns the body the same way and parks on socket writability, or on HTTP/2
capacity when it negotiates HTTP/2.

`proxy::upload_pump` closes that gap for **authenticated** streaming uploads.
The inbound `hyper::body::Incoming` moves into a gateway-owned task, and the
transport is handed a bounded bridge instead. The task selects, biased, over an
explicit dispatcher cancellation, the admitted stream's absolute authorization
deadline, and the next unit of work (bridge capacity, then one source frame).
Arms one and two are polled by the gateway's own task, so they fire while the
backend transport is parked and polling nothing.

What this enforces, exactly:

- After the deadline the gateway polls no further client body, hands the
  transport no further client byte, and **discards** anything still queued in
  the bridge.
- The transport body ends in an **error**, never a clean end of stream, so the
  backend resets rather than accepting a truncated upload as a complete request.
- The inbound body is dropped **before** the pump publishes its outcome, so a
  dispatcher that awaits `cancel_and_join()` has an actual join: once it
  returns, no gateway-owned upload task or client-body ownership survives.
- Direct-H2 — the one H1/H2 dispatcher whose upload is scoped to the handler,
  because its completion gate already withholds an early backend response until
  the upload terminates — joins at every bounded exit and arms cancel-on-drop so
  residual early returns still release the upload promptly. The
  streaming-response transports (reqwest, mesh mTLS, HBONE, Unix socket, native
  gRPC) return while the response is still streaming, so their upload's lifetime
  is the transport body's: the pump's abort guard ends the task when the
  transport drops that body, and the pump self-terminates at the deadline
  regardless.

What this deliberately does **not** claim: bytes the pump handed to the
transport *before* expiry may already sit in that transport's buffers and may
still reach the wire afterwards. Those bytes are no longer the gateway's to
recall, and the pump makes no statement about them.

Cost and invariants:

- The bridge holds **one** in-flight frame, and capacity is reserved before the
  source is read, so the backpressure the transport used to apply directly to
  `Incoming` is preserved rather than replaced by buffering. Native gRPC keeps
  full-duplex semantics — this is not a buffer-first collect.
- Frames move by `Bytes` handle; no per-chunk copy or allocation is introduced.
- Byte counting, the request-size ceiling, and gRPC length-prefixed message
  counting stay in the adapter above the bridge, so they remain authoritative
  and unchanged. The client body's `size_hint` is snapshotted before the move
  and decremented as frames cross, so `Content-Length` framing survives.
- Unauthenticated requests construct no pump at all: no task, no channel, no
  timer. That path is unchanged.
- Termination messages are compiled-in literals from a closed set, and the
  fixed-cardinality counter is recorded through the request's shared once-only
  latch, so an upload and a response body racing the same plan still count
  exactly one termination.

### A downstream that stops reading

`send_data` / `finish` park until QUIC flow-control credit arrives, so a client
that stops consuming keeps a relay loop out of its own `select!` and its timer
is never polled. The H3 native-gRPC and gRPC-Web relay therefore races the
**earliest** of the client `grpc-timeout` and the authorization deadline around
every downstream write, and resets the stream when the authorization bound is
the one that elapsed — a client `grpc-timeout` is optional, so the client
deadline alone would leave the common case unbounded. A stalled downstream
receives no post-expiry bytes in any case, because it is not reading.

**Every** H3 downstream write shares that seam, not only the gRPC ones. A single
helper, `http3::stream_util::await_authorized_response_write`, races one
`send_data` / `send_trailers` / `finish` against the admitted stream's absolute
authorization plan and reports one of three outcomes (written, client write
failed, authorization expired); it is the sole recorder of the
fixed-cardinality counter for a parked write. It is used by:

- `http3::server`'s inline native-H3 → native-H3 streaming relay, including the
  plugin-inspected and SSE variants and the terminal
  `finish_h3_response_with_backend_trailers`;
- `http3::server::stream_h3_open_response_to_client` and
  `proxy_to_backend_h3_streaming` (the refined native-H3 relays);
- `http3::cross_protocol::stream_reqwest_response` and
  `stream_inspected_reqwest_response` (the H3 → H1/H2 plain, inspected, and SSE
  relays).

The remaining writers reach the same plan through
`auth_lifetime::ComposedAuthBound`, which folds the authorization deadline into
whatever absolute bound the protocol already had: the native-H3 gRPC relay
(`dispatch_grpc_native_h3`), the buffered native-H3 writer, the seven native-H3
buffered request-upload drains, and the cross-protocol plain bridge's header,
buffered-body, and post-relay trailer/FIN writes.

Attribution is uniform, and it is taken at COMPOSITION, where both instants are
still known — never by re-reading the clock once the bound has fired. A parked
write, a backend that withholds its response head, and a continuously active
buffered upload are all routinely observed only after BOTH instants have passed;
asking "is the authorization deadline in the past?" there would report the
gateway's security decision for a phase the client's own strictly earlier
deadline actually bounded, changing the client-visible terminal, the recorded
class, and the fixed-cardinality counter. A genuine tie still resolves to
authorization, matching the biased `select!` ordering. There is deliberately no
projection helper that composes the two and returns only the instant: a seam
that composes always keeps the value that can name its owner
(`ComposedAuthBound::deadline` is taken from it, not instead of it).

The terminal follows commitment state: a fixed redacted `401` (gRPC
`grpc-status: 16`) before response headers commit, a deterministic reset
afterwards. A gateway policy expiry is health-neutral everywhere: it never moves
the circuit breaker, passive health, or the H3 capability registry.

### Live acceptance coverage

`tests/functional/functional_h3_auth_lifetime_test.rs` exercises this contract
end to end against a real QUIC listener with a real short-lived HS256 JWT: the
native-H3 streaming response relay, the H3 streaming request-upload bridge
(fixed `401` before commitment), native gRPC before and after response DATA
(`grpc-status: 16` versus deterministic reset), gRPC-Web's bounded trailer
frame, and four non-reading / continuously-active regressions: a stalled gRPC
downstream, a stalled **plain/SSE** native-H3 response, a stalled **plain/SSE**
cross-protocol response (both with a 4 KiB per-stream receive window so the
gateway's first `send_data` provably parks in flow control), and a
continuously active request upload. Each case proves the stream is usable
before the deadline, terminates inside a bounded grace despite continued
backend activity or a client that never reads, and increments the
fixed-cardinality `credential_expired` counter for its protocol family exactly
once.

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

#### Backend trailers on the direct-HTTP/2 streaming path

A direct-H2 streaming response (`ResponseBody::StreamingH2`) commits its initial HEADERS frame before the backend's TRAILERS frame exists, so it crosses the same response-header policy boundary the native-H3 streaming relays cross. Every direct / size-limited / coalescing variant of that arm therefore installs the same reconciliation, described in full in [docs/http3.md → Backend trailers and response header policy](http3.md#backend-trailers-and-response-header-policy): declared `Plugin::response_trailer_policy()` names and prefixes, the observed pre-policy mutation witness, and the fail-closed `Unbounded` arm (`response_transformer`). Without it, `security_headers` configured with `{"remove": ["x-powered-by"]}` is a no-op on the initial header map when the backend sends `x-powered-by` only as a trailer, and the field lands on the wire after the policy already ran. The same absent→absent gap lets a trailer-only `content-encoding`, validator, or `x-amz-checksum-*` reintroduce representation metadata that `ai_stream_router`'s Anthropic SSE normalization already invalidated; that plugin declares the shared exact-name inventory plus the checksum prefixes, preserving unrelated application trailers.

**Native gRPC** on that arm (the mesh-mTLS relay) is governed too, as a gRPC terminal section: only `grpc-status`, `grpc-message`, and `grpc-status-details-bin` are reserved and survive, while the rest of the terminal block is gRPC application metadata crossing the same policy boundary (advisory GHSA-r78v-rc86-6r86). The direct-H2 gRPC pool's own streaming relay (`GrpcResponseKind::Streaming`) installs the identical owned governor on all three of its body constructors. See [docs/http3.md → Native gRPC terminal metadata](http3.md#native-grpc-terminal-metadata).

**Translated gRPC-Web** on that arm is governed as well. Adapting the terminal metadata into a final DATA frame changes the encoding, not the boundary: only a genuine Trailers-Only response carries that metadata in the initial END_STREAM HEADERS block the pristine snapshot already governs, while a non-empty streaming response still delivers it in a later TRAILERS frame. `GrpcWebStreamingBody` wraps the strip/govern wrapper from the outside, so the trailer block is reconciled — as a `NativeGrpcTerminal` section, reserved status fields intact — before it can be collected and encoded. See [docs/http3.md → Translated gRPC-Web terminal frames](http3.md#translated-grpc-web-terminal-frames).

**The native-HTTP/3 backend relay** (`ResponseBody::StreamingH3`, an HTTP/1.1 or HTTP/2 client in front of an H3-capable backend) shares the identical owned governor. Its backend TRAILERS frame reaches the client as HTTP/1.1 chunked trailers or an H2 TRAILERS frame through `body::H3FrameSource`, which applies the reconciliation on that single frame immediately after the hop-by-hop trailer strip — the same crossing, on all three of `direct_streaming_h3_body` / `size_limited_streaming_h3_body` / `coalescing_h3_body`. gRPC-flavored native-H3 dispatch is owned by `dispatch_grpc_native_h3`, so this relay is a plain-response section in practice; the section is still selected structurally from the dispatch (`request_uses_grpc_content_type`) so a future gRPC-over-`StreamingH3` path cannot land on rules that would govern `grpc-status`.

Implementation notes: the whole boundary is skipped when no signal could act — no response-header phase can mutate the headers, no plugin declared a trailer-policy name or prefix, and nothing declared `Unbounded` — exactly as on the native-gRPC streaming arm. Every signal that could drop a trailer keeps the boundary installed, so the shortcut can only skip work the reconciliation would not have done. Otherwise the pre-policy snapshot is taken on the pristine backend header map before any response-header phase runs, and only when a phase can actually mutate it (plugins present, sticky-cookie injection, or a gateway builder-only write). Because the body outlives the request handler, the boundary travels with it as an owned `StreamingResponseTrailerGovernor` — one final-header clone, one pre-policy clone, one `Arc` bump each of the per-reload policy-name and prefix lists, plus an allocation-free per-response bitset of builder fields this response actually wrote, built at most once per governed streaming response. The header view handed to it is the response-header map **plus** the end-to-end fields the gateway writes straight onto the response builder (`via`, `alt-svc`, `X-Gateway-Error`, `X-Gateway-Upstream-Status`); each of those writes is also recorded in the governor's `gateway_owned_headers` so an exact-value pre-seed cannot hide ownership from the mutation witness. A field the gateway did not write on this response stays out of that bitset and remains ungoverned. The drain/overload `connection: close` write is deliberately neither folded into that view nor part of the capture gate or ownership bitset: `connection` is response-direction hop-by-hop, so the trailer strip removes it before the governor runs and it can never reach the reconciliation. The body wrapper touches the governor only on the single TRAILERS frame — DATA frames pay nothing — and it reconciles immediately after the hop-by-hop trailer strip.

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

**Response body streaming**: HTTP/2 DATA frames are forwarded as they arrive from the backend, wrapped in `CoalescingH2Body` for efficient batching. HTTP/2 trailers (`grpc-status`, `grpc-message`) are forwarded automatically via hyper's `Incoming` body framing. The terminal trailer block first crosses the response-header policy boundary: `grpc-status` / `grpc-message` / `grpc-status-details-bin` always survive, while trailer-borne application metadata is reconciled against the policy the response headers already applied — see [docs/http3.md → Native gRPC terminal metadata](http3.md#native-grpc-terminal-metadata).

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
