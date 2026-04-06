# Plugin Execution Order

Ferrum Edge executes plugins in a deterministic order based on two dimensions: **lifecycle phases** and **priority within each phase**.

## Lifecycle Phases

Every HTTP-family request passes through nine main request/response phases in strict order. WebSocket connections optionally enter a tenth frame phase after the HTTP upgrade completes. Plugins only run in the phases they implement:

```
Request In
    │
    ▼
┌─────────────────────────┐
│ 1. on_request_received  │  Pre-processing: CORS preflight
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 2. authenticate         │  Identity verification: mTLS, JWKS, JWT, API key, Basic
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 3. authorize            │  Access control, consumer rate limiting
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 4. before_proxy         │  Request transformation before backend call
└────────────┬────────────┘
             │
             ▼
       ┌───────────┐
       │  Backend   │  Actual HTTP call to upstream
       └─────┬─────┘
             │
             ▼
┌─────────────────────────┐
│ 5. after_proxy          │  Response headers, fast-path rejection, CORS
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 6. on_response_body     │  Raw buffered backend body inspection
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 7. transform_response_body │ Buffered body rewrites
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 8. on_final_response_body │ Final client-visible body validation/storage
└────────────┬────────────┘
             │
             ▼
┌─────────────────────────┐
│ 9. log                  │  Logging & observability (fire-and-forget)
└─────────────────────────┘
```

Any plugin can short-circuit the pipeline by returning a `Reject` result. For example, CORS returns a `204` preflight response in phase 1 without ever reaching authentication. Rate limiting returns `429` in the authorize phase (phase 3) after the consumer is identified.

For gateway-generated rejection responses, a small set of header-only `after_proxy` plugins opt in to still run. This preserves headers such as `Access-Control-Allow-Origin`, `traceparent`, and request IDs on rejected responses without treating them as backend responses.

`after_proxy` rejections are also honored before anything is sent downstream. This matters for plugins like `response_size_limiting`, whose `Content-Length` fast path now replaces oversized backend responses instead of only logging a warning.

## Stream Proxy Lifecycle (TCP/UDP)

TCP and UDP stream proxies use a separate two-phase lifecycle. Since there is no HTTP request/response structure, only protocol-agnostic plugins (those declaring `ALL_PROTOCOLS`) and protocol-specific plugins (e.g., `tcp_connection_throttle` for TCP, `udp_rate_limiting` for UDP) participate.

```
Connection/Session In
    │
    ▼
┌─────────────────────────┐
│ 1. on_stream_connect    │  Gating: IP restriction, rate limiting, ID assignment
└────────────┬────────────┘
             │
             ▼
       ┌───────────┐
       │  Proxy     │  Bidirectional stream copy (TCP) or datagram forwarding (UDP)
       └─────┬─────┘
             │
             ▼
┌─────────────────────────┐
│ 2. on_stream_disconnect │  Logging, metrics, tracing (fire-and-forget)
└─────────────────────────┘
```

Body-aware `before_proxy` plugins such as `graphql`, request-side `body_validator`, `ai_request_guard`, and `ai_prompt_shield` now pre-buffer only matching request bodies (for example JSON `POST` requests). Non-matching requests can continue on the faster streaming path.

**Phase 1 — `on_stream_connect`**: Runs after the client connection is accepted (TCP) or the first datagram from a new client creates a session (UDP). For TCP+TLS listeners it runs after the frontend TLS handshake, so plugins can inspect the client certificate. Plugins can reject to close the connection immediately. Plugins can also insert metadata (e.g., correlation ID, trace ID) into `ctx.metadata`, which is carried through to `on_stream_disconnect`.

**Phase 2 — `on_stream_disconnect`**: Runs after the stream completes (TCP connection closed, or a UDP/DTLS session expires, is cleaned up, or otherwise ends). Receives a `StreamTransactionSummary` with bytes transferred, duration, error info, and metadata from the connect phase. Fire-and-forget — does not block cleanup.

### Stream Hook Implementations by Plugin

| Plugin | `on_stream_connect` | `on_stream_disconnect` | Behavior |
|--------|:-------------------:|:----------------------:|----------|
| `ip_restriction` | ✓ | | Rejects connections from denied IPs |
| `mtls_auth` | ✓ | | Maps the client certificate to a Consumer on TCP+TLS or UDP+DTLS |
| `access_control` | ✓ | | Applies consumer and group allow/deny rules once a stream Consumer exists |
| `tcp_connection_throttle` | ✓ | ✓ | Caps active TCP connections per Consumer, else per client IP |
| `rate_limiting` | ✓ | | Consumer-aware rate limiting when a stream identity exists, else IP-based |
| `correlation_id` | ✓ | | Assigns a UUID request ID to metadata |
| `otel_tracing` | ✓ | ✓ | Generates trace/span IDs; emits structured trace log |
| `stdout_logging` | | ✓ | JSON access log for stream connections |
| `statsd_logging` | | ✓ | Sends stream connection metrics to StatsD over UDP |
| `http_logging` | | ✓ | Sends stream connection logs to webhook endpoint |
| `tcp_logging` | | ✓ | Sends stream connection logs to TCP/TLS endpoint |
| `udp_logging` | | ✓ | Sends stream connection logs to UDP/DTLS endpoint |
| `ws_logging` | | ✓ | Sends stream connection logs to WebSocket endpoint |
| `prometheus_metrics` | | ✓ | Records `ferrum_stream_connections_total` counter and `ferrum_stream_duration_ms` histogram |
| `transaction_debugger` | | ✓ | Prints debug info for stream connections |

### When Hooks Fire

| Protocol | `on_stream_connect` fires | `on_stream_disconnect` fires |
|----------|--------------------------|------------------------------|
| **TCP** | After `accept()`, before backend connection | After bidirectional copy completes |
| **TCP+TLS** | After TLS handshake, before backend connection | After bidirectional copy completes |
| **UDP** | On first datagram from new client (session creation) | When session is cleaned up (idle timeout) |
| **UDP+DTLS** | After DTLS `accept()`, before backend connection | When DTLS handler exits |

## WebSocket Frame Lifecycle (`on_ws_frame`)

WebSocket connections go through the normal HTTP plugin pipeline during the upgrade handshake — authentication, authorization, rate limiting, and all other HTTP phases execute before the connection is upgraded. Once the WebSocket upgrade completes, the frame-level hooks kick in.

The `on_ws_frame` phase fires for every **Text**, **Binary**, and **Ping** frame in both directions:

```
WebSocket Upgrade (HTTP pipeline: authenticate → authorize → before_proxy → ...)
    │
    ▼
┌─────────────────────────────────────┐
│  Frame Forwarding Loop              │
│                                     │
│  ┌───────────────────────────────┐  │
│  │ on_ws_frame (ClientToBackend) │──┼── For each Text/Binary/Ping from client
│  └───────────────────────────────┘  │
│                                     │
│  ┌───────────────────────────────┐  │
│  │ on_ws_frame (BackendToClient) │──┼── For each Text/Binary/Ping from backend
│  └───────────────────────────────┘  │
│                                     │
└─────────────────────────────────────┘
```

### Connection Tracking

Each WebSocket connection is assigned a `connection_id` — a monotonic `u64` counter unique per WebSocket connection. Plugins use this identifier for per-connection state tracking (e.g., per-connection rate limit buckets, per-connection frame counters).

### Frame Rejection

Plugins can return `Some(Message::Close(...))` to close the connection in both directions. When a plugin returns a close frame, the gateway sends it to both client and backend and tears down the connection.

### Execution Order

Plugins execute in priority order (lower number runs first):

| # | Plugin | Priority | Behavior |
|---|--------|----------|----------|
| 1 | `ws_message_size_limiting` | 2810 | Rejects frames exceeding max payload size |
| 2 | `ws_rate_limiting` | 2910 | Per-connection token-bucket frame rate limiting |
| 3 | `ws_frame_logging` | 9050 | Logs frame metadata (direction, opcode, payload size) |

### Zero-Overhead Opt-In

When no plugins on a proxy return `true` from `requires_ws_frame_hooks()`, the frame forwarding loop has zero overhead — frames are forwarded directly without entering the plugin pipeline. The `requires_ws_frame_hooks` flag is pre-computed per-proxy in `PluginCache` at config reload time.

## UDP Datagram Lifecycle (`on_udp_datagram`)

UDP proxies support per-datagram plugin hooks that fire before each client→backend datagram is forwarded. This is separate from the `on_stream_connect`/`on_stream_disconnect` lifecycle, which fires once per session.

```
Session Established (on_stream_connect already ran)
    │
    ▼
┌─────────────────────────────────────┐
│  Datagram Forwarding Loop           │
│                                     │
│  ┌───────────────────────────────┐  │
│  │ on_udp_datagram               │──── For each client→backend datagram
│  │ (returns Forward or Drop)     │
│  └───────────────────────────────┘  │
│                                     │
└─────────────────────────────────────┘
```

### Execution Order

| # | Plugin | Priority | Behavior |
|---|--------|----------|----------|
| 1 | `udp_rate_limiting` | 2915 | Per-client-IP datagram and byte rate limiting |

### Silent Drop Semantics

Unlike HTTP plugins which return status codes and response bodies, UDP datagram plugins return `UdpDatagramVerdict::Drop` to silently discard the datagram. This is standard UDP behavior — there is no error response to send.

### Zero-Overhead Opt-In

When no plugins on a proxy return `true` from `requires_udp_datagram_hooks()`, the datagram forwarding loop has zero overhead — datagrams are forwarded directly without entering the plugin pipeline. The flag is checked once at listener startup.

Both plain UDP and DTLS frontend paths support per-datagram hooks.

## Priority Bands

Within each lifecycle phase, plugins are sorted by **priority** (lower number runs first). Each plugin has a built-in priority constant, but this can be overridden per plugin-config via the `priority_override` field (0–10000). When two plugins share the same effective priority, their relative order is stable (based on config order) but not explicitly controllable — use `priority_override` to guarantee ordering.

Multiple instances of the same plugin type are supported on a single proxy (e.g., two `http_logging` instances for different log destinations). When merging global and proxy-scoped plugins, a proxy-scoped plugin replaces only the **global** plugin of the same name — other proxy-scoped instances of the same type are preserved. See [Plugin Scope](plugins.md#global-vs-proxy-scoped-merging) for the full merging rules and examples.

Priority bands are spaced with gaps so future plugins can slot in without renumbering:

| Band | Priority Range | Purpose | Plugins |
|------|---------------|---------|---------|
| **Early** | 0–949 | Tracing, IDs, preflight, and request short-circuiting before auth | `otel_tracing` (25), `correlation_id` (50), `cors` (100), `request_termination` (125), `ip_restriction` (150), `bot_detection` (200), `sse` (250), `grpc_web` (260), `grpc_method_router` (275) |
| **AuthN** | 950–1999 | Authentication / identity verification | `mtls_auth` (950), `jwks_auth` (1000), `jwt_auth` (1100), `key_auth` (1200), `ldap_auth` (1250), `basic_auth` (1300), `hmac_auth` (1400), `soap_ws_security` (1500) |
| **Admission** | 2000–2999 | Authorization, validation, and request admission control | `access_control` (2000), `tcp_connection_throttle` (2050), `request_size_limiting` (2800), `ws_message_size_limiting` (2810), `graphql` (2850), `rate_limiting` (2900), `ws_rate_limiting` (2910), `udp_rate_limiting` (2915), `ai_prompt_shield` (2925), `body_validator` (2950), `ai_request_guard` (2975) |
| **Transform** | 3000–3999 | Request shaping and response buffering decisions | `request_transformer` (3000), `serverless_function` (3025), `response_mock` (3030), `grpc_deadline` (3050), `request_mirror` (3075), `response_size_limiting` (3490), `response_caching` (3500) |
| **Response** | 4000–4999 | Response transformation, compression, and AI accounting | `response_transformer` (4000), `compression` (4050), `ai_token_metrics` (4100), `ai_rate_limiter` (4200) |
| **Custom** | 5000 | Default for unrecognized/custom plugins | _(future plugins)_ |
| **Logging** | 9000–9999 | Observability and frame logging | `stdout_logging` (9000), `ws_frame_logging` (9050), `statsd_logging` (9075), `http_logging` (9100), `tcp_logging` (9125), `loki_logging` (9155), `udp_logging` (9160), `ws_logging` (9175), `transaction_debugger` (9200), `prometheus_metrics` (9300) |

## Complete Execution Order

Given all built-in plugins enabled, the execution order is:

| # | Plugin | Priority | Active Phases |
|---|--------|----------|---------------|
| 1 | `otel_tracing` | 25 | on_request_received, on_stream_connect, before_proxy, after_proxy, log, on_stream_disconnect |
| 2 | `correlation_id` | 50 | on_request_received, before_proxy, after_proxy, on_stream_connect |
| 3 | `cors` | 100 | on_request_received, after_proxy |
| 4 | `request_termination` | 125 | on_request_received |
| 5 | `ip_restriction` | 150 | on_request_received, on_stream_connect |
| 6 | `bot_detection` | 200 | on_request_received |
| 7 | `sse` | 250 | on_request_received, before_proxy, after_proxy, transform_response_body |
| 8 | `grpc_web` | 260 | on_request_received, before_proxy, transform_request_body, after_proxy, transform_response_body |
| 9 | `grpc_method_router` | 275 | on_request_received, before_proxy |
| 10 | `mtls_auth` | 950 | authenticate, on_stream_connect |
| 11 | `jwks_auth` | 1000 | authenticate |
| 12 | `jwt_auth` | 1100 | authenticate |
| 13 | `key_auth` | 1200 | authenticate |
| 14 | `ldap_auth` | 1250 | authenticate |
| 15 | `basic_auth` | 1300 | authenticate |
| 16 | `hmac_auth` | 1400 | authenticate |
| 17 | `soap_ws_security` | 1500 | before_proxy |
| 18 | `access_control` | 2000 | authorize, on_stream_connect |
| 19 | `tcp_connection_throttle` | 2050 | on_stream_connect, on_stream_disconnect |
| 20 | `request_size_limiting` | 2800 | on_request_received, before_proxy, on_final_request_body |
| 21 | `ws_message_size_limiting` | 2810 | on_ws_frame |
| 22 | `graphql` | 2850 | before_proxy |
| 23 | `rate_limiting` | 2900 | on_request_received (IP mode), authorize (consumer mode), on_stream_connect |
| 24 | `ws_rate_limiting` | 2910 | on_ws_frame |
| 25 | `udp_rate_limiting` | 2915 | on_udp_datagram |
| 26 | `ai_prompt_shield` | 2925 | before_proxy, transform_request_body |
| 27 | `body_validator` | 2950 | before_proxy, on_final_request_body, on_final_response_body |
| 28 | `ai_request_guard` | 2975 | before_proxy, transform_request_body |
| 29 | `request_transformer` | 3000 | before_proxy, transform_request_body |
| 30 | `serverless_function` | 3025 | before_proxy |
| 31 | `response_mock` | 3030 | before_proxy |
| 32 | `grpc_deadline` | 3050 | before_proxy |
| 33 | `request_mirror` | 3075 | before_proxy |
| 34 | `response_size_limiting` | 3490 | after_proxy, on_final_response_body |
| 35 | `response_caching` | 3500 | before_proxy, after_proxy, on_final_response_body |
| 36 | `response_transformer` | 4000 | after_proxy, transform_response_body |
| 37 | `compression` | 4050 | before_proxy, after_proxy, transform_request_body, transform_response_body |
| 38 | `ai_token_metrics` | 4100 | on_response_body |
| 39 | `ai_rate_limiter` | 4200 | before_proxy, after_proxy, on_response_body |
| 40 | `stdout_logging` | 9000 | log, on_stream_disconnect |
| 41 | `ws_frame_logging` | 9050 | on_ws_frame |
| 42 | `statsd_logging` | 9075 | log, on_stream_disconnect |
| 43 | `http_logging` | 9100 | log, on_stream_disconnect |
| 44 | `tcp_logging` | 9125 | log, on_stream_disconnect |
| 45 | `kafka_logging` | 9150 | log, on_stream_disconnect |
| 46 | `loki_logging` | 9155 | log, on_stream_disconnect |
| 47 | `udp_logging` | 9160 | log, on_stream_disconnect |
| 48 | `ws_logging` | 9175 | log, on_stream_disconnect |
| 49 | `transaction_debugger` | 9200 | on_request_received, after_proxy, log, on_stream_disconnect |
| 50 | `prometheus_metrics` | 9300 | log, on_stream_disconnect |

## Why This Order Matters

### Response caching runs after response size limiting (3490 -> 3500)

`response_size_limiting` gets the first chance to reject oversized backend payloads before anything is written into cache. `response_caching` then records the surviving final representation in `on_final_response_body`, after all response-body transforms have completed.

That ordering has a few practical effects:
- Cache entries include the final client-visible body and headers, not the raw backend response.
- Backend `Vary` headers are respected when building the cache key, so variants such as `Accept-Encoding: gzip` stay isolated from uncompressed responses.
- Fresh cached validators (`ETag`, `Last-Modified`) can satisfy conditional requests at the edge with a `304 Not Modified` response.
- The `compression` plugin (4050) can generate gzip/brotli responses at the gateway. When both `response_caching` and `compression` are enabled, the cache stores the uncompressed backend response (since `response_caching` at 3500 runs before `compression` at 4050). Compression is applied after cache retrieval. The `body_validator` plugin separately decompresses gzip-compressed gRPC frames for protobuf validation — this is internal to the validation path and does not affect the forwarded body.

### OTel tracing runs first (priority 25)

OpenTelemetry tracing runs at priority 25 — the earliest of any plugin — so it can capture trace context before any other plugin runs. This ensures accurate timing: the gateway span's start time reflects the true moment the request was received, not the time after CORS/auth/etc. have executed. The `before_proxy` phase injects traceparent into backend requests, `after_proxy` echoes it to clients, and `log` exports the completed span to the OTLP collector.

### CORS runs next (priority 100)

Browser preflight (`OPTIONS`) requests must be answered before authentication. If an auth plugin ran first, it would reject the preflight with `401` and the browser would never complete the CORS handshake. CORS at priority 100 ensures preflight responses are returned immediately.

### Request termination runs immediately after CORS (priority 125)

`request_termination` still short-circuits before authentication, but it now sits behind CORS so maintenance and mock responses do not break browser preflight. That keeps browser clients functional while preserving the low-cost fast path for intentionally terminated requests.

### Authentication before authorization (1000s before 2000s)

Authentication plugins identify *who* the caller is (setting `ctx.identified_consumer` and/or `ctx.authenticated_identity`). Authorization plugins like `access_control` then decide *whether* that identity is allowed — by consumer username, ACL group membership, or both. Running auth first is required — ACL checks are meaningless without a verified identity.

After all plugin phases complete, the gateway automatically injects `X-Consumer-Username` (and `X-Consumer-Custom-Id` when set) headers into the request forwarded to the backend, so upstream services can identify the authenticated caller. `X-Consumer-Username` uses the mapped Consumer username when available, otherwise an external auth header/display identity (for example from `jwks_auth`), otherwise the raw external authenticated identity.

### Rate limiting runs after auth (priority 2900)

Rate limiting sits at the end of the AuthZ band (priority 2900) so it can enforce limits by **authenticated identity**, not just by IP address. When `limit_by: "consumer"`, the plugin uses the mapped Consumer username when available, otherwise external `ctx.authenticated_identity`; those values only exist after the authenticate phase.

**Dual-phase behavior:**
- `limit_by: "ip"` — enforces IP-based limits in `on_request_received` (phase 1, before auth). This protects auth endpoints from brute-force attacks.
- `limit_by: "consumer"` — enforces identity-based limits in `authorize` (phase 3, after auth). Uses mapped Consumer username first, then external `authenticated_identity`, and falls back to IP-based keying only when no authenticated identity exists.

**Header exposure** (`expose_headers: true`): When enabled, the plugin injects `x-ratelimit-limit`, `x-ratelimit-remaining`, `x-ratelimit-window`, and `x-ratelimit-identity` headers on both upstream requests (`before_proxy`) and downstream responses (`after_proxy`). This lets backends and clients see current rate-limit state without additional lookups. Disabled by default so gateway admins control whether limit details are exposed.

**Redis mode** (`sync_mode: "redis"`): `rate_limiting` and `ai_rate_limiter` use Redis for coordinated counters across multiple gateway instances. `ws_rate_limiting` also supports Redis, but only to externalize its per-connection counters; because WebSocket connection IDs are process-local, it namespaces keys per gateway instance to avoid cross-instance collisions rather than sharing a portable connection budget across reconnects. When Redis is unavailable, all three plugins automatically fall back to local in-memory state and switch back when connectivity is restored. The Redis backend uses native RESP protocol commands (no Lua scripts), so it works with Redis, Valkey, DragonflyDB, KeyDB, or Garnet.

### AI Plugins: PII shield before guard, metrics before rate limiter (2925–4200)

The four AI plugins are ordered to compose correctly:

1. **`ai_prompt_shield` (2925)** runs first in the pre-proxy flow — PII must be detected/redacted before the request reaches any other validation or the backend. It sits right after `rate_limiting` so brute-force protection applies first.
2. **`ai_request_guard` (2975)** runs after PII scanning — it validates model names, max_tokens, message counts, and temperature. If the prompt shield already rejected or redacted the request, the guard validates the cleaned version.
3. **`ai_token_metrics` (4100)** runs after the response comes back from the backend — it parses the LLM response body to extract token usage (prompt, completion, total, model) and writes it to `ctx.metadata`. This metadata flows into `TransactionSummary` for all downstream logging plugins.
4. **`ai_rate_limiter` (4200)** runs after `ai_token_metrics` — it reads the token count from the response body and accumulates it against the consumer's token budget. On the pre-proxy side, it checks whether the consumer has exceeded their token limit before allowing the request through. The pre-proxy check uses historical accumulation, while the post-proxy hook records new usage.

### Transforms after auth (3000+)

Request transformers run after authentication and authorization, so they only modify requests that are already permitted. This prevents wasted transformation work on requests that will be rejected.

`request_size_limiting` participates again after request transforms on buffered requests, so transformed bodies are re-checked before backend dispatch.

### Compression runs after response transformation (4050)

The `compression` plugin runs at priority 4050 — after `response_transformer` (4000) so it compresses the final transformed response body, and before `ai_token_metrics` (4100) and `ai_rate_limiter` (4200) so AI plugins see the uncompressed body. In `before_proxy`, it optionally strips `Accept-Encoding` from the backend request so the backend sends uncompressed responses for the gateway to compress. Response body buffering is required when this plugin is enabled.

### Logging runs last (9000+)

Logging plugins run in phase 7 (`log`) which is fire-and-forget after the response is sent to the client. They are outside the hot path and do not affect request latency. Their relative ordering within the logging band (9000–9300) does not impact behavior.

All logging plugins receive the `TransactionSummary` struct which includes an `error_class` field for failed transactions. This field classifies gateway-level errors (e.g., `ConnectionTimeout`, `TlsError`, `DnsLookupError`) to help operators quickly identify root causes. See [docs/error_classification.md](error_classification.md) for the full list of error classes and debugging guidance.

## Adding a New Plugin

When implementing a new plugin, choose a priority that places it in the correct band:

```rust
impl Plugin for MyPlugin {
    fn name(&self) -> &str { "my_plugin" }

    fn priority(&self) -> u16 {
        // Pick a value in the appropriate band:
        // 0-999: pre-processing (before auth)
        // 1000-1999: authentication
        // 2000-2999: authorization / post-auth enforcement
        // 3000-3999: request transformation
        // 4000-4999: response transformation
        // 9000-9999: logging
        500  // Example: runs after CORS (100), before auth (1000+)
    }

    // Declare which protocols this plugin supports.
    // Default is HTTP_ONLY_PROTOCOLS. Use one of the predefined constants:
    //   ALL_PROTOCOLS           — HTTP, gRPC, WebSocket, TCP, UDP
    //   HTTP_FAMILY_PROTOCOLS   — HTTP, gRPC, WebSocket
    //   HTTP_GRPC_PROTOCOLS     — HTTP, gRPC
    //   HTTP_ONLY_PROTOCOLS     — HTTP only (default)
    //   GRPC_ONLY_PROTOCOLS     — gRPC only
    fn supported_protocols(&self) -> &'static [ProxyProtocol] {
        ALL_PROTOCOLS  // Example: this plugin works with all protocols
    }

    // If your plugin makes outbound HTTP calls to a configured endpoint,
    // override warmup_hostnames() so the endpoint is pre-resolved at startup
    // via the gateway's shared DNS cache:
    fn warmup_hostnames(&self) -> Vec<String> {
        vec!["my-endpoint.example.com".to_string()]
    }
}
```

### Response Body Buffering

If your plugin needs access to the full response body (e.g., for body-level transformation or inspection), override `requires_response_body_buffering()` to return `true`. This forces the gateway to buffer the entire backend response before forwarding it to the client, even when the proxy's `response_body_mode` is set to `stream`.

```rust
impl Plugin for MyBodyPlugin {
    fn name(&self) -> &str { "my_body_plugin" }

    fn requires_response_body_buffering(&self) -> bool {
        true  // Forces response buffering for this proxy
    }
}
```

By default, this method returns `false`. When `response_transformer` has body transformation rules configured (`target: "body"`), it automatically returns `true` from this method, forcing buffering so the JSON body can be parsed and rewritten. When only header rules are configured, it returns `false` and works with streaming mode. See [docs/response_body_streaming.md](response_body_streaming.md) for the full streaming architecture.

Add the constant to `src/plugins/mod.rs` in the `priority` module for discoverability:

```rust
pub mod priority {
    pub const MY_PLUGIN: u16 = 500;
    // ...
}
```

The default priority is `5000` (the Custom band), which runs after all transforms but before logging. This is a safe default for plugins that don't have strong ordering requirements.

## Protocol Support

Each plugin declares which proxy protocols it supports via `supported_protocols()`. The gateway skips plugins that don't support the current proxy's protocol — for example, CORS is never invoked for a TCP stream proxy.

TLS/DTLS are transport-layer concerns, not separate protocols. A plugin that supports `Tcp` also supports TCP+TLS, and a plugin that supports `Udp` also supports UDP+DTLS.

| Protocol | Description |
|----------|-------------|
| `Http` | HTTP/1.1, HTTP/2, HTTP/3 (includes HTTPS) |
| `Grpc` | gRPC / gRPCs (HTTP/2-based RPC) |
| `WebSocket` | WS / WSS |
| `Tcp` | Raw TCP stream proxy (includes TLS termination/origination) |
| `Udp` | Raw UDP datagram proxy (includes DTLS termination/origination) |

### Per-Plugin Protocol Matrix

| Plugin | Http | Grpc | WebSocket | Tcp | Udp | Rationale |
|--------|:----:|:----:|:---------:|:---:|:---:|-----------|
| `cors` | ✓ | | | | | HTTP-only concept (Origin/ACAO headers) |
| `ip_restriction` | ✓ | ✓ | ✓ | ✓ | ✓ | IP filtering is protocol-agnostic |
| `bot_detection` | ✓ | ✓ | ✓ | | | Needs User-Agent header |
| `sse` | ✓ | | | | | SSE is HTTP-only (text/event-stream over chunked transfer) |
| `mtls_auth` | ✓ | ✓ | ✓ | ✓ | ✓ | Requires TLS/DTLS client certificate |
| `jwks_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `jwt_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `key_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `ldap_auth` | ✓ | ✓ | ✓ | | | Requires HTTP Basic auth header; authenticates against LDAP directory |
| `basic_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `hmac_auth` | ✓ | ✓ | ✓ | | | Requires HTTP headers |
| `soap_ws_security` | ✓ | | | | | SOAP XML body parsing (text/xml, application/soap+xml) |
| `access_control` | ✓ | ✓ | ✓ | ✓ | | Needs authenticated identity from an auth plugin; supports consumer username and ACL group allow/deny lists |
| `tcp_connection_throttle` | | | | ✓ | | Tracks active TCP connections per Consumer or client IP |
| `grpc_web` | ✓ | ✓ | | | | Translates gRPC-Web (browser) ↔ native gRPC (HTTP/2) |
| `grpc_method_router` | | ✓ | | | | gRPC method-level access control and rate limiting |
| `grpc_deadline` | | ✓ | | | | gRPC timeout enforcement and propagation |
| `graphql` | ✓ | | | | | GraphQL is HTTP-only (JSON body parsing) |
| `request_size_limiting` | ✓ | ✓ | | | | Enforces per-proxy request body size limits |
| `rate_limiting` | ✓ | ✓ | ✓ | ✓ | ✓ | Connection/session rate applies everywhere |
| `request_transformer` | ✓ | ✓ | | | | Modifies HTTP headers/query/body |
| `request_mirror` | ✓ | ✓ | | | | Duplicates traffic to a shadow destination for validation |
| `serverless_function` | ✓ | ✓ | | | | Invokes cloud functions (AWS Lambda, Azure Functions, GCP Cloud Functions) |
| `response_mock` | ✓ | ✓ | | | | Returns mock responses for API testing before backends are ready |
| `body_validator` | ✓ | ✓ | | | | Validates request and response bodies |
| `request_termination` | ✓ | ✓ | ✓ | | | Returns HTTP error response |
| `response_size_limiting` | ✓ | ✓ | | | | Enforces per-proxy response body size limits |
| `response_transformer` | ✓ | ✓ | | | | Modifies HTTP response headers/body |
| `compression` | ✓ | | | | | HTTP response compression and request decompression (gzip, brotli) |
| `ai_prompt_shield` | ✓ | ✓ | | | | Scans JSON request bodies for PII |
| `ai_request_guard` | ✓ | ✓ | | | | Validates JSON request bodies |
| `ai_token_metrics` | ✓ | ✓ | | | | Parses JSON response bodies for token usage |
| `ai_rate_limiter` | ✓ | ✓ | | | | Parses JSON response bodies for token counts |
| `ws_message_size_limiting` | | | ✓ | | | Enforces max frame size on WebSocket connections |
| `ws_rate_limiting` | | | ✓ | | | Per-connection frame rate limiting for WebSocket |
| `ws_frame_logging` | | | ✓ | | | Logs WebSocket frame metadata |
| `udp_rate_limiting` | | | | | ✓ | Per-client-IP datagram and byte rate limiting for UDP proxies |
| `stdout_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `statsd_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `correlation_id` | ✓ | ✓ | ✓ | ✓ | ✓ | ID assignment is protocol-agnostic |
| `http_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `tcp_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `kafka_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `udp_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `ws_logging` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `transaction_debugger` | ✓ | ✓ | ✓ | ✓ | ✓ | Observability applies everywhere |
| `prometheus_metrics` | ✓ | ✓ | ✓ | ✓ | ✓ | Metrics for all protocols |
| `otel_tracing` | ✓ | ✓ | ✓ | ✓ | ✓ | Tracing for all protocols |

Protocol-filtered plugin lists are pre-computed in `PluginCache` at config reload time, so there is zero filtering cost on the hot path.

## Body Transformation

Both `request_transformer` and `response_transformer` support JSON body field manipulation using dot-notation paths. Use `"target": "body"` in the rules array alongside existing header and query rules.

### Configuration

```json
{
  "rules": [
    {"operation": "rename", "target": "body", "key": "user.old_field", "new_key": "user.new_field"},
    {"operation": "remove", "target": "body", "key": "internal.debug_info"},
    {"operation": "add", "target": "body", "key": "metadata.version", "value": "v2"},
    {"operation": "update", "target": "body", "key": "user.role", "value": "admin"}
  ]
}
```

### Dot-Notation Paths

Fields are referenced using dot-delimited paths that navigate nested JSON objects:

| Path | Targets |
|------|---------|
| `name` | `{"name": "..."}` |
| `user.email` | `{"user": {"email": "..."}}` |
| `a.b.c.d` | `{"a": {"b": {"c": {"d": "..."}}}}` |

### Operations

| Operation | Behavior |
|-----------|----------|
| `add` | Insert field only if it doesn't already exist. Creates intermediate objects as needed. |
| `update` | Always set the field value (overwrites if exists, creates if not). |
| `remove` | Delete the field at the given path. |
| `rename` | Move the value from `key` path to `new_key` path (both use dot notation). |

### Value Parsing

String values in the `"value"` field are parsed as JSON when possible:
- `"42"` → number `42`
- `"true"` → boolean `true`
- `"{\"a\":1}"` → object `{"a": 1}`
- `"hello"` → string `"hello"` (not valid JSON, kept as string)

Non-string JSON values (numbers, booleans, objects, arrays) in the config are used directly.

### Content-Type Awareness

Body transformation only applies to JSON bodies (detected by `Content-Type` containing `application/json` or `+json`). Non-JSON bodies are passed through unchanged.

### Performance Notes

- Body rules are parsed once at config load time, not per-request.
- When `response_transformer` has body rules, it automatically enables response body buffering for the proxy. Without body rules, responses stream through with zero overhead.
- `request_transformer` body transformation runs after the request body is collected and before it is sent to the backend (HTTP/1.1 and HTTPS paths).
- Header, query, and body rules can be mixed in a single plugin configuration.

## gRPC Compatibility

All plugins in the execution pipeline work transparently with gRPC requests. gRPC metadata maps directly to HTTP/2 headers, so:

- **Authentication plugins** (JWKS, JWT, API key, Basic) inspect the `authorization` header, which gRPC clients send as metadata.
- **Rate limiting** works identically for gRPC — keyed by IP or consumer identity.
- **Request/Response transformers** can add, modify, or remove gRPC metadata (HTTP/2 headers).
- **Logging plugins** receive the same `TransactionSummary` with the gRPC path (e.g., `/my.Service/MyMethod`) and HTTP status. For gateway-generated gRPC errors, `metadata.grpc_status` and `metadata.grpc_message` are also populated so sinks can distinguish gRPC failures despite the HTTP `200`.
- **Plugin rejections** are translated into trailers-only gRPC errors (`HTTP 200` with `grpc-status` / `grpc-message`) unless a plugin already supplied explicit gRPC error metadata.

gRPC requests are detected by their `content-type: application/grpc` header and routed to the dedicated gRPC proxy path, which uses hyper's HTTP/2 client for trailer forwarding. The plugin pipeline runs before and after the gRPC backend call, just like HTTP requests.
